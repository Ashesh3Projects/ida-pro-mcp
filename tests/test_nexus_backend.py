import asyncio
import threading
from types import SimpleNamespace

import pytest

from ida_nexus import DatabaseInstance, InstanceState
from ida_pro_mcp.instance_contract import Invocation, InstanceBinding, RoutingError
from ida_pro_mcp.nexus_backend import NexusProvider


def record(key="record-a", path="/a.i64"):
    return DatabaseInstance(
        record_id=key,
        backend="gui",
        pid=42,
        port=13337,
        _token="secret",
        version=1,
        idb_path=path,
        idb_key="a",
        exe_path="/a.exe",
        managed=False,
        started_at=1.0,
    )


class Handle:
    def __init__(self, instance):
        self.instance = instance
        self.connected = True
        self.closed = False
        self.executed = []

    def execute_python(self, code, **kwargs):
        self.executed.append(code)
        return {
            "result": {
                "host": "127.0.0.1",
                "port": 13337,
                "token": "secret",
                "generation": "a" * 16,
                "version": 2,
                "idb_path": self.instance.idb_path,
            }
        }

    def close(self, **kwargs):
        self.closed = True

    def cancel_operation(self, op):
        return True


def test_discovery_does_not_acquire_and_attach_uses_exact_record(monkeypatch):
    from ida_pro_mcp import nexus_backend

    exact = record()
    handles = []
    monkeypatch.setattr(
        nexus_backend,
        "discover_databases",
        lambda: [SimpleNamespace(instance=exact, state=InstanceState.READY)],
    )

    def attach(instance, **kwargs):
        assert instance is exact
        handle = Handle(instance)
        handles.append(handle)
        return handle

    monkeypatch.setattr(nexus_backend.DatabaseHandle, "attach", attach)
    monkeypatch.setattr(
        nexus_backend.DatabaseHandle,
        "open",
        lambda *a, **kw: pytest.fail("must not open by path"),
    )

    async def scenario():
        provider = NexusProvider()
        identities = await provider.discover()
        assert handles == []
        invocation = Invocation(InstanceBinding("b" * 16, identities[0]))
        session = await provider.attach(identities[0], invocation)
        assert session.identity.key == exact.record_id
        assert session.runtime_generation == "a" * 16
        assert len(handles) == 1

    asyncio.run(scenario())


def test_disappeared_record_cannot_resolve_replacement(monkeypatch):
    from ida_pro_mcp import nexus_backend

    exact = record()
    records = [SimpleNamespace(instance=exact, state=InstanceState.READY)]
    monkeypatch.setattr(nexus_backend, "discover_databases", lambda: records)
    monkeypatch.setattr(
        nexus_backend.DatabaseHandle,
        "attach",
        lambda *a, **kw: pytest.fail("old record must fail"),
    )

    async def scenario():
        provider = NexusProvider()
        old = (await provider.discover())[0]
        records[:] = [
            SimpleNamespace(instance=record("record-b"), state=InstanceState.READY)
        ]
        await provider.discover()
        with pytest.raises(RoutingError):
            await provider.attach(old, Invocation(InstanceBinding("b" * 16, old)))

    asyncio.run(scenario())


def test_router_cancellation_reaches_bootstrap_before_attachment_finishes(monkeypatch):
    from ida_pro_mcp import nexus_backend
    from ida_pro_mcp.instance_router import InstanceRouter

    entered, finished = threading.Event(), threading.Event()
    cancelled = []

    class BlockingHandle(Handle):
        def execute_python(self, code, **kwargs):
            self.operation_id = kwargs["operation_id"]
            entered.set()
            assert finished.wait(5)
            return super().execute_python(code, **kwargs)

        def cancel_operation(self, operation_id):
            cancelled.append(operation_id)
            finished.set()
            return True

    handle = BlockingHandle(record())
    monkeypatch.setattr(
        nexus_backend,
        "UnifiedBridge",
        lambda *a, **kw: SimpleNamespace(shutdown=lambda: None),
    )
    monkeypatch.setattr(
        nexus_backend,
        "discover_databases",
        lambda: [
            SimpleNamespace(instance=handle.instance, state=InstanceState.READY),
        ],
    )
    monkeypatch.setattr(nexus_backend.DatabaseHandle, "attach", lambda *a, **kw: handle)

    async def scenario():
        router = InstanceRouter(NexusProvider())
        target = (await router.list_instances())["instances"][0]["instance_id"]
        call = asyncio.create_task(
            router.request(
                target,
                "tools/call",
                {
                    "name": "server_health",
                    "arguments": {},
                },
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            call.cancel()
            done, _ = await asyncio.wait({call}, timeout=1)
            assert call in done, "bootstrap never received cancellation"
            with pytest.raises(asyncio.CancelledError):
                await call
            assert cancelled and set(cancelled) == {handle.operation_id}
            assert handle.closed
        finally:
            finished.set()
            await asyncio.gather(call, return_exceptions=True)
            await router.shutdown()

    asyncio.run(scenario())

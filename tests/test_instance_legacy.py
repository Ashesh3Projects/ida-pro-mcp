import asyncio
from contextlib import contextmanager
import importlib
import threading

import pytest

from fastmcp import Client

from _mcp_spec_support import load_ida_rpc_module
from ida_pro_mcp import instance_runtime
from ida_pro_mcp.instance_runtime import RuntimeIdentity
from ida_pro_mcp.instance_router import InstanceRouter
from ida_pro_mcp.proxy_backend import ProxyProvider, ProxySession
from ida_pro_mcp.instance_contract import InstanceBinding, Invocation
from ida_pro_mcp.fastmcp_frontend import create_server


@contextmanager
def backend(monkeypatch, configure=None):
    rpc = load_ida_rpc_module()
    module = importlib.import_module(rpc.__package__ + ".instance_dispatch")
    state = RuntimeIdentity()
    generation = state.activate("a.exe", "a.i64")
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    server = rpc.McpServer("test-backend")
    calls = []

    @server.tool
    def decompile(addr: str) -> dict:
        calls.append(addr)
        return {"addr": addr, "code": "file-a"}

    if configure is not None:
        configure(server)
    module.install_instance_dispatch(server)
    server.serve("127.0.0.1", 0, threaded=True)
    port = server._http_server.server_port
    info = {
        "instance_id": generation,
        "generation": generation,
        "identity_version": 1,
        "host": "127.0.0.1",
        "port": port,
        "pid": 42,
        "binary": "a.exe",
        "binary_path": "a.exe",
        "idb_path": "a.i64",
    }
    try:
        yield info, calls, state
    finally:
        server.stop()


def test_proxy_routes_exact_generation_and_never_follows_port_reuse(monkeypatch):
    with backend(monkeypatch) as (info, calls, state):

        async def scenario():
            provider = ProxyProvider(discover=lambda: [info])
            router = InstanceRouter(provider)
            target = (await router.list_instances())["instances"][0]["instance_id"]
            result = await router.request(
                target,
                "tools/call",
                {"name": "decompile", "arguments": {"addr": "0x1000"}},
            )
            assert result["structuredContent"]["code"] == "file-a"
            state.activate("b.exe", "b.i64")
            result = await router.request(
                target,
                "tools/call",
                {"name": "decompile", "arguments": {"addr": "0x2000"}},
            )
            assert result["isError"] and calls == ["0x1000"]
            await router.shutdown()

        asyncio.run(scenario())


def test_proxy_endpoint_constraint_does_not_supply_implicit_target(monkeypatch):
    with backend(monkeypatch) as (info, calls, state):

        async def scenario():
            p = ProxyProvider(
                endpoint=(info["host"], info["port"]), discover=lambda: []
            )
            async with Client(create_server(InstanceRouter(p))) as client:
                error = await client.call_tool_mcp("decompile", {"addr": "0x1000"})
                assert error.is_error and calls == []
                rows = (await client.call_tool("list_instances", {})).data["instances"]
                assert len(rows) == 1
                result = await client.call_tool_mcp(
                    "decompile",
                    {"addr": "0x1000", "instance_id": rows[0]["instance_id"]},
                )
                assert result.structured_content["code"] == "file-a"

        asyncio.run(scenario())


def test_incompatible_record_is_listed_without_usable_id():
    async def scenario():
        p = ProxyProvider(
            discover=lambda: [
                {"host": "127.0.0.1", "port": 1, "pid": 42, "binary": "old.exe"}
            ]
        )
        router = InstanceRouter(p)
        row = (await router.list_instances())["instances"][0]
        assert row["status"] == "incompatible" and row["instance_id"] is None
        await router.shutdown()

    asyncio.run(scenario())


def test_proxy_timeout_cannot_acknowledge_close_or_mint_replacement_id(monkeypatch):
    entered, finished = threading.Event(), threading.Event()

    def configure(server):
        @server.tool
        def blocked_mutation() -> dict:
            entered.set()
            assert finished.wait(5)
            return {"done": True}

    with backend(monkeypatch, configure) as (info, _, _):

        async def scenario():
            provider = ProxyProvider(discover=lambda: [info], timeout=0.15)
            router = InstanceRouter(provider)
            target = (await router.list_instances())["instances"][0]["instance_id"]
            try:
                with pytest.raises(TimeoutError):
                    await router.request(
                        target,
                        "tools/call",
                        {
                            "name": "blocked_mutation",
                            "arguments": {},
                        },
                    )
                assert entered.is_set() and not finished.is_set()
                with pytest.raises((TimeoutError, RuntimeError)):
                    await router.close_database(target)
                rows = (await router.list_instances())["instances"]
                assert rows[0]["instance_id"] == target
                assert rows[0]["status"] == "closing"
            finally:
                finished.set()
                provider.timeout = 2
                await router.shutdown()

        asyncio.run(scenario())


def test_proxy_close_releases_client_namespace_for_more_than_capacity(monkeypatch):
    rpc = load_ida_rpc_module()
    dispatch = importlib.import_module(rpc.__package__ + ".instance_dispatch")
    context = importlib.import_module(rpc.__package__ + ".execution_context")
    monkeypatch.setattr(context, "_sessions", {})
    state = RuntimeIdentity()
    generation = state.activate("a.exe", "a.i64")
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    server = rpc.McpServer("namespace-lifetime")

    @server.tool
    def remember() -> dict:
        context.get_python_namespace({})["callback"] = lambda: 1
        return {"ok": True}

    dispatch.install_instance_dispatch(server)

    class LocalSession(ProxySession):
        def rpc(self, method, params, request_id):
            server._transport_session_id.data = f"http:{self.client_id}"
            try:
                response = server.registry.dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": method,
                        "params": params,
                    }
                )
            finally:
                server._transport_session_id.data = None
            assert "error" not in response, response
            return response["result"]

    async def scenario():
        provider = ProxyProvider(discover=lambda: [])
        record = {
            "host": "127.0.0.1",
            "port": 1,
            "generation": generation,
            "identity_version": 1,
        }
        identity = provider._identity(record)
        for _ in range(context.MAX_BRIDGE_CLIENTS + 1):
            session = LocalSession(record, provider, identity)
            result = await session.request(
                Invocation(InstanceBinding("a" * 16, identity)),
                "tools/call",
                {"name": "remember", "arguments": {}},
            )
            assert not result.get("isError"), result
            await session.close()
            assert context._sessions == {}, (
                "closed client retained its Python namespace"
            )

    asyncio.run(scenario())

"""Client contracts tested against an authenticated loopback backend, without IDA."""

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest


class Backend:
    def __init__(self):
        self.calls = []
        self.cancelled = []
        self.released = []
        self.entered = threading.Event()
        self.finish = threading.Event()
        self.cancel_received = threading.Event()
        self.result = {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"result": [1, 2]},
            "isError": False,
        }
        self.output = '{"value":"original database"}'
        self.block = False
        self.fail = False
        self.release_fail = False
        self.release_block = False
        self.release_entered = threading.Event()
        self.release_finish = threading.Event()
        self.auth = []
        self.retired_clients = set()


@contextmanager
def backend_server():
    backend = Backend()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            backend.auth.append(self.headers.get("Authorization"))
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, params = request["method"], request.get("params", {})
            if method == "notifications/cancelled":
                backend.cancelled.append(params)
                backend.cancel_received.set()
                self.send_response(202)
                self.end_headers()
                return
            if method == "bridge/release_session":
                backend.release_entered.set()
                if backend.release_block:
                    assert backend.release_finish.wait(10)
                if backend.release_fail:
                    self.send_response(503)
                    self.end_headers()
                    return
                backend.released.append(params)
                backend.retired_clients.add(params["client_id"])
                result = {}
            else:
                if params["_meta"]["ida_pro_mcp_client"] in backend.retired_clients:
                    self.send_response(410)
                    self.end_headers()
                    return
                backend.calls.append(request)
                backend.entered.set()
                if backend.block:
                    assert backend.finish.wait(10)
                if backend.fail:
                    self.send_response(503)
                    self.end_headers()
                    return
                result = backend.result
            body = json.dumps(
                {"jsonrpc": "2.0", "id": request["id"], "result": result}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            backend.auth.append(self.headers.get("Authorization"))
            body = backend.output.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    backend.descriptor = {
        "host": "127.0.0.1",
        "port": server.server_port,
        "token": "test-secret",
        "version": 2,
        "generation": "a" * 16,
    }
    try:
        yield backend
    finally:
        backend.finish.set()
        backend.release_finish.set()
        server.shutdown()
        server.server_close()
        thread.join()


class Manager:
    def __init__(self, targets):
        self.targets = targets
        self.current = next(iter(targets))
        self.bootstraps = []
        self.closed = []

    def resolve_instance_id(self, instance_id):
        target = instance_id or self.current
        if target not in self.targets:
            raise ValueError("unknown target")
        return target

    def execute_python(self, code, instance_id, **kwargs):
        self.bootstraps.append((code, instance_id, kwargs))
        return {
            "result": self.targets[instance_id].descriptor,
            "stdout": "",
            "stderr": "",
        }

    def close_database(self, instance_id):
        self.closed.append(instance_id)
        return {"closed": True}

    def shutdown(self, **kwargs):
        self.closed.extend(self.targets)


def test_native_envelope_bootstrap_once_and_unique_client_ids():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(backend):
        manager = Manager({"A": backend})
        first, second = UnifiedBridge(manager), UnifiedBridge(manager)
        assert await first.call_tool("list_funcs", {}, "A") == backend.result
        assert await first.call_tool("list_funcs", {}, "A") == backend.result
        assert await second.call_tool("list_funcs", {}, "A") == backend.result
        assert len(manager.bootstraps) == 2
        assert all(item[2]["persist_globals"] is True for item in manager.bootstraps)
        assert len({item["id"] for item in backend.calls}) == 3
        clients = [
            item["params"]["_meta"]["ida_pro_mcp_client"] for item in backend.calls
        ]
        assert clients[0] == clients[1] and clients[0] != clients[2]
        assert backend.auth == ["Bearer test-secret"] * 3

    with backend_server() as backend:
        asyncio.run(scenario(backend))


def test_cancellation_pins_original_target_and_waits_for_unwind():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(first, second):
        first.block = True
        manager = Manager({"A": first, "B": second})
        bridge = UnifiedBridge(manager)
        task = asyncio.create_task(bridge.call_tool("py_eval", {"code": "slow()"}, "A"))
        assert await asyncio.to_thread(first.entered.wait, 3)
        manager.current = "B"
        task.cancel()
        assert await asyncio.to_thread(first.cancel_received.wait, 3)
        await asyncio.sleep(0.03)
        assert not task.done(), "cancellation must wait until the IDA request returns"
        first.finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert first.cancelled[0]["requestId"] == first.calls[0]["id"]
        assert first.cancelled[0]["_meta"] == first.calls[0]["params"]["_meta"]
        assert not second.calls and not second.cancelled

    with backend_server() as first, backend_server() as second:
        asyncio.run(scenario(first, second))


def test_failed_mutation_is_not_replayed():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    with backend_server() as backend:
        backend.fail = True
        with pytest.raises(Exception, match="503"):
            asyncio.run(UnifiedBridge(Manager({"A": backend})).call_tool("patch", {}, "A"))
        assert len(backend.calls) == 1


def test_output_is_owned_by_original_target_and_has_bounded_continuation():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(first, second):
        manager = Manager({"A": first, "B": second})
        bridge = UnifiedBridge(manager)
        first.result = {
            "content": [
                {"type": "text", "text": "preview"},
                {
                    "type": "text",
                    "text": "curl http://localhost:13337/output/backend-id.json",
                },
            ],
            "structuredContent": {"value": "preview"},
            "isError": False,
            "_meta": {
                "ida_mcp": {
                    "output_id": "backend-id",
                    "download_url": "http://localhost:13337/output/backend-id.json",
                    "download_hint": "curl bad-url",
                    "total_chars": 100,
                }
            },
        }
        result = await bridge.call_tool("strings", {}, "A")
        assert "http://" not in json.dumps(result)
        output_id = result["_meta"]["ida_mcp"]["output_id"]
        manager.current = "B"
        chunk = await bridge.read_output(output_id, limit=10)
        assert chunk["text"] == first.output[:10]
        assert chunk["next_offset"] == 10 and chunk["instance_id"] == "A"
        rest = await bridge.read_output(output_id, offset=10, limit=32000)
        assert chunk["text"] + rest["text"] == first.output
        assert rest["next_offset"] is None
        assert second.auth == []
        with pytest.raises(ValueError):
            await bridge.read_output(output_id, limit=32001)
        with pytest.raises(ValueError):
            await bridge.read_output("unowned")

    with backend_server() as first, backend_server() as second:
        asyncio.run(scenario(first, second))


def test_close_waits_for_bridge_call_and_only_releases_owned_context():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(backend):
        backend.block = True
        bridge = UnifiedBridge(Manager({"A": backend}))
        task = asyncio.create_task(bridge.call_tool("py_eval", {}, "A"))
        assert await asyncio.to_thread(backend.entered.wait, 3)
        close = asyncio.create_task(asyncio.to_thread(bridge.release_target, "A"))
        assert await asyncio.to_thread(backend.cancel_received.wait, 3)
        await asyncio.sleep(0.03)
        assert not close.done() and not backend.released
        backend.finish.set()
        await task
        await close
        assert backend.released == [
            {
                "client_id": bridge.client_id,
                "_meta": {"ida_pro_mcp_client": bridge.client_id, "ida_pro_mcp_generation": "a" * 16},
            }
        ]
        with pytest.raises(ValueError, match="closed"):
            await bridge.call_tool("py_eval", {}, "A")

    with backend_server() as backend:
        asyncio.run(scenario(backend))


def test_manager_close_preserves_peer_and_reopen_gets_fresh_bridge_session():
    from ida_pro_mcp.unified_bridge import bridge_manager_class

    class LifecycleManager(Manager):
        def __init__(self, *, targets, idle_timeout=None):
            super().__init__(targets)

        def open_database(self, path, **kwargs):
            self.current = path
            return {"instance_id": path}

    async def scenario(backend):
        manager_type = bridge_manager_class(LifecycleManager)
        first = manager_type(targets={"A": backend})
        second = manager_type(targets={"A": backend})
        await first.unified_bridge.call_tool("py_eval", {}, "A")
        await second.unified_bridge.call_tool("py_eval", {}, "A")
        first.close_database("A")
        assert len(backend.released) == 1
        assert backend.released[0]["client_id"] != second.unified_bridge.client_id
        await second.unified_bridge.call_tool("py_eval", {}, "A")
        first.open_database("A", set_current=True)
        await first.unified_bridge.call_tool("py_eval", {}, "A")
        assert len(first.bootstraps) == 2
        first.shutdown()
        second.shutdown()

    with backend_server() as backend:
        asyncio.run(scenario(backend))


def test_bootstrap_rejects_a_different_cached_installation(tmp_path):
    import sys
    from types import ModuleType
    from unittest.mock import patch
    from ida_pro_mcp.unified_bridge import bootstrap_expression

    module = ModuleType("ida_pro_mcp.bridge_runtime")
    module.__file__ = str(tmp_path / "old-install" / "bridge_runtime.py")
    module.runtime_identity = lambda: "older-source-fingerprint"
    module.ensure_bridge = lambda: pytest.fail("old bridge must never start")
    with patch.dict(sys.modules, {module.__name__: module}):
        with pytest.raises(RuntimeError, match="installation"):
            eval(bootstrap_expression())


@pytest.mark.parametrize("modified", [False, True])
def test_bootstrap_accepts_identical_copy_and_rejects_changed_package(tmp_path, modified):
    import json
    from pathlib import Path
    import shutil
    import subprocess
    import sys
    import ida_pro_mcp
    from ida_pro_mcp.unified_bridge import bootstrap_expression

    source = Path(ida_pro_mcp.__file__).parent
    copied = tmp_path / "ida_pro_mcp"
    shutil.copytree(source, copied, ignore=shutil.ignore_patterns("__pycache__"))
    if modified:
        with (copied / "ida_mcp" / "api_analysis.py").open("a", encoding="utf-8") as stream:
            stream.write("\n# different installed implementation\n")
    script = f'''
import json, sys
sys.path.insert(0, {str(tmp_path)!r})
from ida_pro_mcp import bridge_runtime
bridge_runtime.ensure_bridge = lambda: {{"copied": True}}
namespace = {{"__builtins__": __builtins__, "official_state": object()}}
before = dict(namespace)
try:
    result = eval({bootstrap_expression()!r}, namespace)
except RuntimeError as error:
    result = {{"error": str(error)}}
assert namespace == before
print(json.dumps(result))
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    if modified:
        assert "installation" in actual["error"]
    else:
        assert actual == {"copied": True}


def test_close_retains_nexus_lease_until_backend_drain_acknowledges():
    from ida_pro_mcp.unified_bridge import bridge_manager_class

    class LifecycleManager(Manager):
        def __init__(self, *, targets, idle_timeout=None):
            super().__init__(targets)

    with backend_server() as backend:
        manager = bridge_manager_class(LifecycleManager)(targets={"A": backend})
        asyncio.run(manager.unified_bridge.call_tool("py_eval", {}, "A"))
        backend.release_fail = True
        with pytest.raises(RuntimeError, match="503"):
            manager.close_database("A")
        assert manager.closed == []
        backend.release_fail = False
        assert manager.close_database("A") == {"closed": True}
        assert manager.closed == ["A"]
        assert len(backend.released) == 1


def test_cancel_after_transport_loss_waits_for_session_drain_ack():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(backend):
        backend.block = backend.fail = backend.release_block = True
        bridge = UnifiedBridge(Manager({"A": backend}))
        task = asyncio.create_task(bridge.call_tool("py_eval", {}, "A"))
        assert await asyncio.to_thread(backend.entered.wait, 3)
        task.cancel()
        assert await asyncio.to_thread(backend.cancel_received.wait, 3)
        backend.finish.set()
        assert await asyncio.to_thread(backend.release_entered.wait, 3)
        assert not task.done(), (
            "failed HTTP response does not prove IDA request unwound"
        )
        backend.release_finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(ValueError, match="closed"):
            await bridge.call_tool("py_eval", {}, "A")

    with backend_server() as backend:
        asyncio.run(scenario(backend))


def test_startup_resolution_does_not_hold_bridge_lock():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    with backend_server() as backend:

        class StartupManager(Manager):
            def resolve_instance_id(self, instance_id):
                completed = threading.Event()
                thread = threading.Thread(
                    target=lambda: (bridge.reopen_target("A"), completed.set())
                )
                thread.start()
                ready = completed.wait(0.3)
                if not ready:
                    raise ValueError("startup blocked on bridge lock")
                thread.join()
                return "A"

        bridge = UnifiedBridge(StartupManager({"A": backend}))
        assert asyncio.run(bridge.call_tool("py_eval", {}, "A")) == backend.result


def test_bootstrap_cancellation_retries_until_operation_registers():
    from ida_pro_mcp.unified_bridge import UnifiedBridge

    async def scenario(backend):
        entered, cancelled = threading.Event(), threading.Event()

        class DelayedManager(Manager):
            attempts = 0

            def execute_python(self, code, instance_id, **kwargs):
                self.operation_id = kwargs["operation_id"]
                entered.set()
                if not cancelled.wait(1):
                    raise ValueError(
                        "bootstrap cancellation was lost before registration"
                    )
                return super().execute_python(code, instance_id, **kwargs)

            def cancel_operation(self, target, operation_id):
                assert target == "A" and operation_id == self.operation_id
                self.attempts += 1
                if self.attempts == 1:
                    return False
                cancelled.set()
                return True

        manager = DelayedManager({"A": backend})
        task = asyncio.create_task(UnifiedBridge(manager).call_tool("py_eval", {}, "A"))
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled.is_set(), (
            "request-specific cancellation must survive delayed registration"
        )
        assert not backend.calls

    with backend_server() as backend:
        asyncio.run(scenario(backend))


def test_shutdown_releases_healthy_target_when_peer_drain_fails_and_can_retry():
    from ida_pro_mcp.unified_bridge import bridge_manager_class

    class LifecycleManager(Manager):
        def __init__(self, *, targets, idle_timeout=None):
            super().__init__(targets)
            self.base_shutdowns = 0

        def shutdown(self, **kwargs):
            self.base_shutdowns += 1

        def open_database(self, path, **kwargs):
            return {"instance_id": path}

    with backend_server() as first, backend_server() as second:
        manager = bridge_manager_class(LifecycleManager)(targets={"A": first, "B": second})
        manager.open_database("C", set_current=False)
        asyncio.run(manager.unified_bridge.call_tool("py_eval", {}, "A"))
        asyncio.run(manager.unified_bridge.call_tool("py_eval", {}, "B"))
        first.release_fail = True
        with pytest.raises(Exception):
            manager.shutdown()
        assert manager.closed == ["B", "C"]
        assert len(second.released) == 1 and not first.released
        assert manager.base_shutdowns == 0
        first.release_fail = False
        manager.shutdown()
        assert manager.closed == ["B", "C", "A"]
        assert manager.base_shutdowns == 1
        assert len(first.released) == 1 and len(second.released) == 1

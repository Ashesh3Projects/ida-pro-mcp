import importlib
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from _mcp_spec_support import load_ida_rpc_module
from ida_pro_mcp import instance_runtime
from ida_pro_mcp.instance_runtime import RuntimeIdentity, check_request_generation


@pytest.fixture
def endpoint(monkeypatch):
    rpc = load_ida_rpc_module()
    module = importlib.import_module(rpc.__package__ + ".instance_dispatch")
    server = rpc.McpServer("direct-test")
    state = RuntimeIdentity()
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    generation = state.activate("a.exe", "a.i64")
    calls = []

    @server.tool
    def analyze(value: int = 1) -> dict:
        check_request_generation()
        calls.append(value)
        return {"value": value}

    @server.resource("ida://idb/metadata")
    def metadata() -> dict:
        check_request_generation()
        return {"file": "a.exe"}

    module.install_instance_dispatch(server)
    return server, state, generation, calls


def call(server, arguments):
    return server.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "analyze", "arguments": arguments},
        }
    )


def test_missing_id_does_not_reach_tool(endpoint):
    server, _, _, calls = endpoint
    response = call(server, {"value": 2})
    assert response["result"]["isError"]
    assert (
        response["result"]["_meta"]["ida_mcp"]["error_code"] == "INSTANCE_ID_REQUIRED"
    )
    assert calls == []


def test_direct_id_is_consumed_and_response_id_preserved(endpoint):
    server, _, generation, calls = endpoint
    response = call(server, {"instance_id": generation, "value": 3})
    assert response["id"] == 7
    assert response["result"]["structuredContent"] == {"value": 3}
    assert calls == [3]


def test_stale_id_fails_after_database_replacement(endpoint):
    server, state, generation, calls = endpoint
    state.activate("b.exe", "b.i64")
    response = call(server, {"instance_id": generation})
    assert response["result"]["isError"]
    assert response["result"]["_meta"]["ida_mcp"]["error_code"] == "INSTANCE_CHANGED"
    assert calls == []


def test_direct_catalog_and_discovery_are_explicit(endpoint):
    server, _, generation, _ = endpoint
    tools = server.registry.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )["result"]["tools"]
    analyze = next(t for t in tools if t["name"] == "analyze")
    assert "instance_id" in analyze["inputSchema"]["required"]
    result = server.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_instances", "arguments": {}},
        }
    )
    assert (
        result["result"]["structuredContent"]["instances"][0]["instance_id"]
        == generation
    )


def test_resource_requires_one_id_and_restores_uri(endpoint):
    server, _, generation, _ = endpoint
    uri = f"ida://idb/metadata?instance_id={generation}"
    response = server.registry.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}}
    )
    assert response["result"]["contents"][0]["uri"] == uri
    for bad in ["ida://idb/metadata", uri + "&instance_id=" + generation]:
        response = server.registry.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": bad},
            }
        )
        assert "error" in response


def test_release_is_client_scoped_and_rejects_late_requests(endpoint):
    server, _, generation, calls = endpoint
    server._transport_session_id.data = "http:client-a"
    assert not call(server, {"instance_id": generation})["result"]["isError"]
    response = server.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": "release",
            "method": "instance/release",
            "params": {"instance_id": generation},
        }
    )
    assert response.get("result") == {"released": True}
    assert call(server, {"instance_id": generation})["result"]["isError"]
    server._transport_session_id.data = "http:client-b"
    assert not call(server, {"instance_id": generation})["result"]["isError"]
    assert calls == [1, 1]


def test_database_retirement_clears_obsolete_direct_namespaces(endpoint):
    server, state, generation, _ = endpoint
    context = importlib.import_module(
        server.__class__.__module__.rsplit(".", 2)[0] + ".execution_context"
    )
    # The RPC loader uses an isolated package so the real IDA package is not imported.
    server._transport_session_id.data = "http:retiring-client"
    call(server, {"instance_id": generation})
    key = f"direct:http:retiring-client:{generation}"
    assert key in context._sessions
    state.invalidate()
    server._retire_instance_generation(generation)
    assert key not in context._sessions


def test_drain_fences_not_yet_admitted_request_without_expiry(endpoint, monkeypatch):
    server, _, generation, calls = endpoint
    module = importlib.import_module(
        server.__class__.__module__.rsplit(".", 2)[0] + ".instance_dispatch"
    )
    server._transport_session_id.data = "http:delayed-client"
    response = server.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": "drain",
            "method": "instance/drain",
            "params": {"instance_id": generation, "request_ids": [7]},
        }
    )
    assert response["result"] == {"drained": True}
    # A transport delay must not revive an operation after drain acknowledged it.
    monkeypatch.setattr(module.time, "monotonic", lambda: 10**15)
    response = call(server, {"instance_id": generation})
    assert response["result"]["isError"]
    assert calls == []


def test_retirement_before_context_entry_cannot_leak_namespace(endpoint, monkeypatch):
    server, state, generation, _ = endpoint
    package = server.__class__.__module__.rsplit(".", 2)[0]
    module = importlib.import_module(package + ".instance_dispatch")
    context = importlib.import_module(package + ".execution_context")
    entered, ready = threading.Event(), threading.Event()
    original = module.bridge_context

    @contextmanager
    def delayed(client, event):
        entered.set()
        assert ready.wait(3)
        with original(client, event):
            yield

    monkeypatch.setattr(module, "bridge_context", delayed)

    def request():
        server._transport_session_id.data = "http:retire-race"
        return call(server, {"instance_id": generation})

    with ThreadPoolExecutor() as executor:
        future = executor.submit(request)
        try:
            assert entered.wait(2)
            state.invalidate()
            server._retire_instance_generation(generation)
        finally:
            ready.set()
        response = future.result(3)
    assert response["result"]["isError"]
    assert f"direct:http:retire-race:{generation}" not in context._sessions

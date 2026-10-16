import importlib
import json

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
    return server.registry.dispatch({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                     "params": {"name": "analyze", "arguments": arguments}})


def test_missing_id_does_not_reach_tool(endpoint):
    server, _, _, calls = endpoint
    response = call(server, {"value": 2})
    assert response["result"]["isError"]
    assert response["result"]["_meta"]["ida_mcp"]["error_code"] == "INSTANCE_ID_REQUIRED"
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
    tools = server.registry.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    analyze = next(t for t in tools if t["name"] == "analyze")
    assert "instance_id" in analyze["inputSchema"]["required"]
    result = server.registry.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_instances", "arguments": {}}})
    assert result["result"]["structuredContent"]["instances"][0]["instance_id"] == generation


def test_resource_requires_one_id_and_restores_uri(endpoint):
    server, _, generation, _ = endpoint
    uri = f"ida://idb/metadata?instance_id={generation}"
    response = server.registry.dispatch({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}})
    assert response["result"]["contents"][0]["uri"] == uri
    for bad in ["ida://idb/metadata", uri + "&instance_id=" + generation]:
        response = server.registry.dispatch({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": bad}})
        assert "error" in response

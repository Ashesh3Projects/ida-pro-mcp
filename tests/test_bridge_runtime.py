"""Real HTTP/registry tests; IDA itself is only needed by the bootstrap loader."""

import concurrent.futures
import http.client
import importlib
import json
import threading

import pytest

from _mcp_spec_support import load_ida_rpc_module


@pytest.fixture
def runtime(monkeypatch):
    from ida_pro_mcp import bridge_runtime
    from ida_pro_mcp import instance_runtime

    state = instance_runtime.RuntimeIdentity()
    state.activate("fixture.exe", "fixture.i64")
    monkeypatch.setattr(instance_runtime, "_runtime", state)

    rpc = load_ida_rpc_module()
    context = importlib.import_module(rpc.__package__ + ".execution_context")
    monkeypatch.setattr(bridge_runtime, "_load_runtime", lambda: (rpc, context))
    old_tools = rpc.MCP_SERVER.tools.methods.copy()
    old_extensions = rpc.MCP_EXTENSIONS.copy()
    descriptor = bridge_runtime.ensure_bridge()
    yield bridge_runtime, rpc, context, descriptor
    bridge_runtime._bridge.close()
    bridge_runtime._bridge = None
    rpc.MCP_SERVER.tools.methods = old_tools
    rpc.MCP_EXTENSIONS.clear()
    rpc.MCP_EXTENSIONS.update(old_extensions)


def request(runtime, method="POST", path="/mcp", *, body=None, headers=None, auth=True):
    descriptor = runtime[3]
    connection = http.client.HTTPConnection(
        descriptor["host"], descriptor["port"], timeout=4
    )
    actual_headers = {"Content-Type": "application/json"}
    actual_headers["X-IDA-MCP-Generation"] = descriptor["generation"]
    if isinstance(body, dict) and body.get("method") in {
        "tools/call",
        "resources/read",
    }:
        body.setdefault("params", {}).setdefault("_meta", {}).setdefault(
            "ida_pro_mcp_generation", descriptor["generation"]
        )
    if auth:
        actual_headers["Authorization"] = "Bearer " + descriptor["token"]
    actual_headers.update(headers or {})
    try:
        connection.request(
            method, path, json.dumps(body) if body is not None else None, actual_headers
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def call(client="one", request_id=1, name="identify", arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments or {},
            "_meta": {"ida_pro_mcp_client": client},
        },
    }


def test_authenticated_listener_starts_once_and_dispatches_actual_registry(runtime):
    module, rpc, context, descriptor = runtime

    @rpc.tool
    def identify() -> dict:
        return {"client": context.get_bridge_client()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        descriptors = list(pool.map(lambda _: module.ensure_bridge(), range(16)))
    assert all(item == descriptor for item in descriptors)
    assert descriptor["host"] == "127.0.0.1"
    assert descriptor["version"] == 2
    status, data = request(runtime, body=call())
    assert status == 200
    assert json.loads(data)["result"]["structuredContent"] == {"client": "one"}
    assert context.get_bridge_client() is None


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/mcp"),
        ("GET", "/output/abc.json"),
        ("GET", "/config.html"),
        ("OPTIONS", "/mcp"),
    ],
)
def test_every_route_requires_token(runtime, method, path):
    assert request(runtime, method, path, auth=False)[0] == 401
    assert (
        request(runtime, method, path, headers={"Authorization": "Bearer incorrect"})[0]
        == 401
    )


def test_wrong_generation_never_reaches_backend(runtime):
    calls = []

    @runtime[1].tool
    def identify() -> dict:
        calls.append(True)
        return {}

    body = call()
    body["params"]["_meta"]["ida_pro_mcp_generation"] = "0" * 16
    _, data = request(runtime, body=body)
    assert json.loads(data)["error"]["data"]["error_code"] == "INSTANCE_CHANGED"
    assert calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.invalid"},
        {"Origin": "https://attacker.invalid"},
        {"Origin": "null"},
        {"Host": "localhost:1"},
    ],
)
def test_host_and_origin_checks_cannot_be_relaxed_by_legacy_cors(runtime, headers):
    runtime[1].MCP_SERVER.cors_allowed_origins = "*"
    assert request(runtime, body=call(), headers=headers)[0] == 403


def test_even_same_origin_and_fetch_metadata_are_rejected(runtime):
    port = runtime[3]["port"]
    assert (
        request(runtime, body=call(), headers={"Origin": f"http://127.0.0.1:{port}"})[0]
        == 403
    )
    assert (
        request(runtime, body=call(), headers={"Sec-Fetch-Site": "same-origin"})[0]
        == 403
    )


def test_malformed_optional_context_is_a_jsonrpc_error(runtime):
    status, body = request(
        runtime,
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
            "params": {"_meta": {"ida_pro_mcp_client": []}},
        },
    )
    assert status == 200
    assert json.loads(body)["error"]["code"] == -32602


def test_output_requires_token_and_configuration_is_not_exposed(runtime):
    from ida_pro_mcp.instance_runtime import generation_context

    with generation_context(runtime[3]["generation"]):
        runtime[1]._cache_output("a123", {"complete": "value"})
    status, body = request(runtime, "GET", "/output/a123.json")
    assert status == 200
    assert json.loads(body) == {"complete": "value"}
    assert request(runtime, "GET", "/config.html")[0] == 404
    assert request(runtime, "POST", "/config", body={})[0] == 404


def test_debugger_extensions_are_enabled_only_on_bridge_dispatch(runtime):
    _, rpc, _, _ = runtime

    @rpc.tool
    @rpc.ext("dbg")
    def debugger_probe() -> dict:
        return {"enabled": True}

    status, data = request(runtime, body=call(name="debugger_probe"))
    assert status == 200
    assert json.loads(data)["result"]["structuredContent"] == {"enabled": True}
    assert rpc.MCP_SERVER.registry.methods["tools/call"]("debugger_probe")["isError"]


def test_cancellation_is_scoped_to_client_even_with_equal_request_ids(runtime):
    _, rpc, context, _ = runtime
    entered = {"one": threading.Event(), "two": threading.Event()}
    release = threading.Event()

    @rpc.tool
    def wait_for_cancel() -> dict:
        event = context.get_bridge_cancel_event()
        entered[context.get_bridge_client()].set()
        while not release.is_set() and not event.wait(0.01):
            pass
        return {"cancelled": event.is_set()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(request, runtime, body=call("one", 7, "wait_for_cancel"))
        two = pool.submit(request, runtime, body=call("two", 7, "wait_for_cancel"))
        try:
            assert entered["one"].wait(2) and entered["two"].wait(2)
            status, _ = request(
                runtime,
                body={
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": 7, "_meta": {"ida_pro_mcp_client": "one"}},
                },
            )
            assert status == 202
            assert json.loads(one.result(2)[1])["result"]["structuredContent"] == {
                "cancelled": True
            }
            assert not two.done()
        finally:
            release.set()
        assert json.loads(two.result(2)[1])["result"]["structuredContent"] == {
            "cancelled": False
        }


def test_early_cancellation_is_remembered_and_session_release_is_scoped(runtime):
    _, rpc, context, _ = runtime

    @rpc.tool
    def identify() -> dict:
        return {"cancelled": context.get_bridge_cancel_event().is_set()}

    request(
        runtime,
        body={
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "early", "_meta": {"ida_pro_mcp_client": "one"}},
        },
    )
    _, body = request(runtime, body=call("one", "early"))
    assert json.loads(body)["result"]["structuredContent"]["cancelled"]
    _, body = request(
        runtime,
        body={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "bridge/release_session",
            "params": {"client_id": "two", "_meta": {"ida_pro_mcp_client": "one"}},
        },
    )
    assert json.loads(body)["error"]["code"] == -32602
    _, body = request(
        runtime,
        body={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "bridge/release_session",
            "params": {"client_id": "one", "_meta": {"ida_pro_mcp_client": "one"}},
        },
    )
    assert json.loads(body)["result"] == {"released": True}


def test_baseexception_returns_error_and_next_request_still_works(runtime):
    @runtime[1].tool
    def terminate() -> dict:
        raise SystemExit(2)

    _, body = request(runtime, body=call(name="terminate"))
    assert json.loads(body)["error"]["code"] == -32603
    status, body = request(runtime, body={"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert status == 200
    assert json.loads(body)["result"] == {}


def test_release_cancels_and_drains_own_calls_before_acknowledging(runtime):
    _, rpc, context, _ = runtime
    entered = threading.Event()
    cancelled = threading.Event()
    unwind = threading.Event()

    @rpc.tool
    def blocking() -> dict:
        entered.set()
        assert context.get_bridge_cancel_event().wait(2)
        cancelled.set()
        assert unwind.wait(2)
        return {"unwound": True}

    @rpc.tool
    def identify() -> dict:
        return {"client": context.get_bridge_client()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(request, runtime, body=call("one", 5, "blocking"))
        assert entered.wait(2)
        releasing = pool.submit(
            request,
            runtime,
            body={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "bridge/release_session",
                "params": {"client_id": "one", "_meta": {"ida_pro_mcp_client": "one"}},
            },
        )
        try:
            assert cancelled.wait(1), "release did not cancel its active operation"
            assert not releasing.done(), "release acknowledged before execution unwound"
            _, body = request(runtime, body=call("two", 5))
            assert json.loads(body)["result"]["structuredContent"] == {"client": "two"}
            _, body = request(runtime, body=call("one", 7))
            assert "error" in json.loads(body), "released client accepted new execution"
        finally:
            unwind.set()
        assert json.loads(running.result(2)[1])["result"]["structuredContent"] == {
            "unwound": True
        }
        assert json.loads(releasing.result(2)[1])["result"] == {"released": True}
    _, body = request(runtime, body=call("one", 8))
    assert "error" in json.loads(body), "released context was resurrected"

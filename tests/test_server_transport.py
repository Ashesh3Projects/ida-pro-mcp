"""Proxy dispatch preserves explicit destination and never retries mutations."""

import json
import pytest
from ida_pro_mcp.proxy_backend import ProxyProvider, ProxySession


@pytest.mark.parametrize("failure", ["connect", "read", "status", "id"])
def test_proxy_failure_is_not_replayed(monkeypatch, failure):
    calls = []

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("127.0.0.1", 13338)
            assert timeout == 130

        def request(self, method, path, body, headers):
            calls.append((path, json.loads(body), headers))
            if failure == "connect":
                raise ConnectionRefusedError("refused")

        def getresponse(self):
            if failure == "read":
                raise TimeoutError("timeout")
            return self

        status = 503 if failure == "status" else 200

        def read(self, count):
            return b'{"jsonrpc":"2.0","id":"wrong","result":{}}'

        def close(self):
            pass

    monkeypatch.setattr(
        "ida_pro_mcp.proxy_backend.http.client.HTTPConnection", Connection
    )
    provider = ProxyProvider(discover=lambda: [], extensions={"dbg"})
    session = ProxySession(
        {"host": "127.0.0.1", "port": 13338, "generation": "a" * 16}, provider, None
    )
    with pytest.raises((OSError, ValueError, RuntimeError)):
        session.rpc(
            "tools/call",
            {"name": "patch", "arguments": {"instance_id": "a" * 16}},
            "op",
        )
    assert len(calls) == 1
    assert calls[0][0] == "/mcp?ext=dbg"
    assert calls[0][1]["params"]["arguments"]["instance_id"] == "a" * 16
    assert calls[0][2]["Mcp-Session-Id"] == session.client_id

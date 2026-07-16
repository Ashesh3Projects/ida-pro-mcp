import time
import unittest
from unittest.mock import patch

from ida_pro_mcp import server


class _FakeResponse:
    def __init__(self, status=200, reason="OK", body=b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'):
        self.status = status
        self.reason = reason
        self._body = body

    def read(self):
        return self._body


class _BaseFakeConnection:
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_calls = 0
        self.closed = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.request_calls += 1

    def close(self):
        self.closed = True


class _ResponseFailureConnection(_BaseFakeConnection):
    def getresponse(self):
        raise TimeoutError("read timeout")


class _Http503Connection(_BaseFakeConnection):
    def getresponse(self):
        return _FakeResponse(status=503, reason="Service Unavailable", body=b"busy")


class _ConnectFailureConnection(_BaseFakeConnection):
    def request(self, method, path, body, headers):
        super().request(method, path, body, headers)
        raise ConnectionRefusedError("refused")


class DispatchProxyTransportTests(unittest.TestCase):
    def setUp(self):
        _ResponseFailureConnection.reset()
        _Http503Connection.reset()
        _ConnectFailureConnection.reset()
        self._old_host = server.IDA_HOST
        self._old_port = server.IDA_PORT
        self._old_session = getattr(server.mcp._transport_session_id, "data", None)
        self._old_targets = server._session_proxy_targets.copy()
        self._old_target_last_seen = server._session_proxy_last_seen.copy()
        self._old_target_ttl = server.SESSION_PROXY_TARGET_TTL_SEC
        self._old_target_max = server.SESSION_PROXY_TARGET_MAX_SIZE
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        server._session_proxy_targets.clear()
        server._session_proxy_last_seen.clear()
        server.mcp._transport_session_id.data = None

    def tearDown(self):
        server.IDA_HOST = self._old_host
        server.IDA_PORT = self._old_port
        server._session_proxy_targets.clear()
        server._session_proxy_targets.update(self._old_targets)
        server._session_proxy_last_seen.clear()
        server._session_proxy_last_seen.update(self._old_target_last_seen)
        server.SESSION_PROXY_TARGET_TTL_SEC = self._old_target_ttl
        server.SESSION_PROXY_TARGET_MAX_SIZE = self._old_target_max
        server.mcp._transport_session_id.data = self._old_session

    def test_proxy_request_forwards_external_base_header(self):
        original_getter = server.get_current_request_external_base_url

        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.path = path
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.get_current_request_external_base_url = lambda: "https://mcp.example.com/base"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_ida(b"{}")
        finally:
            server.get_current_request_external_base_url = original_getter

        self.assertEqual(len(_RecordingConnection.instances), 1)
        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("X-IDA-MCP-External-Base"),
            "https://mcp.example.com/base",
        )

    def test_proxy_to_ida_targets_module_default(self):
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.IDA_HOST = "10.0.0.50"
        server.IDA_PORT = 24680
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
            server._proxy_to_ida(b"{}")
        self.assertEqual(
            (_RecordingConnection.instances[0].host, _RecordingConnection.instances[0].port),
            ("10.0.0.50", 24680),
        )
        self.assertEqual(
            _RecordingConnection.instances[0].timeout,
            server.IDA_PROXY_TIMEOUT_SEC,
        )

    def test_select_instance_is_scoped_to_transport_session(self):
        instances = [
            {
                "instance_id": "aaaa1111",
                "host": "127.0.0.1",
                "port": 11111,
                "pid": 101,
                "binary": "first.dll",
                "binary_path": "C:/bins/first.dll",
                "idb_path": "C:/bins/first.i64",
            },
            {
                "instance_id": "bbbb2222",
                "host": "127.0.0.1",
                "port": 22222,
                "pid": 202,
                "binary": "second.dll",
                "binary_path": "C:/bins/second.dll",
                "idb_path": "C:/bins/second.i64",
            },
        ]
        with (
            patch("ida_pro_mcp.server.discover_instances", return_value=instances),
            patch("ida_pro_mcp.server.probe_instance", return_value=True),
        ):
            server.mcp._transport_session_id.data = "http:session-a"
            selected_a = server.select_instance("aaaa1111")
            self.assertTrue(selected_a["success"])

            server.mcp._transport_session_id.data = "http:session-b"
            selected_b = server.select_instance("second.dll")
            self.assertTrue(selected_b["success"])

            server.mcp._transport_session_id.data = "http:session-a"
            self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 11111))

            server.mcp._transport_session_id.data = "http:session-b"
            self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 22222))

    def test_list_instances_preserves_fork_compatible_fields(self):
        instances = [
            {
                "instance_id": "abc12345",
                "host": "127.0.0.1",
                "port": 13338,
                "pid": 123,
                "binary": "sample.dll",
                "binary_path": "C:/bins/sample.dll",
                "idb_path": "C:/bins/sample.i64",
            }
        ]
        server.mcp._transport_session_id.data = "stdio:default"
        server._set_active_ida_target("127.0.0.1", 13338)
        with patch("ida_pro_mcp.server.discover_instances", return_value=instances):
            result = server.list_instances()

        self.assertEqual(result["selected_instance"], "abc12345")
        self.assertEqual(result["instances"][0]["binary_name"], "sample.dll")
        self.assertEqual(
            result["instances"][0]["binary_path"], "C:/bins/sample.dll"
        )
        self.assertTrue(result["instances"][0]["active"])

    def test_session_scoped_targets_are_bounded_and_expire(self):
        server.SESSION_PROXY_TARGET_MAX_SIZE = 2
        server.SESSION_PROXY_TARGET_TTL_SEC = 0
        for session, port in (("a", 11111), ("b", 22222), ("c", 33333)):
            server.mcp._transport_session_id.data = f"http:{session}"
            server._set_active_ida_target("127.0.0.1", port)

        self.assertNotIn("http:a", server._session_proxy_targets)
        self.assertIn("http:b", server._session_proxy_targets)
        self.assertIn("http:c", server._session_proxy_targets)

        server.SESSION_PROXY_TARGET_TTL_SEC = 1
        server._session_proxy_last_seen["http:b"] = time.monotonic() - 10
        server.mcp._transport_session_id.data = "http:b"
        self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 13337))
        self.assertNotIn("http:b", server._session_proxy_targets)

    def test_dispatch_proxy_does_not_retry_post_send_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ResponseFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("not retried automatically", response["error"]["message"])
        self.assertIn("read timeout", response["error"]["data"])
        self.assertEqual(len(_ResponseFailureConnection.instances), 1)
        self.assertEqual(_ResponseFailureConnection.instances[0].request_calls, 1)
        self.assertTrue(_ResponseFailureConnection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_http_503(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _Http503Connection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("HTTP 503 Service Unavailable", response["error"]["data"])
        self.assertEqual(len(_Http503Connection.instances), 1)
        self.assertEqual(_Http503Connection.instances[0].request_calls, 1)
        self.assertTrue(_Http503Connection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_connection_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ConnectFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("refused", response["error"]["data"])
        self.assertEqual(len(_ConnectFailureConnection.instances), 1)
        self.assertEqual(_ConnectFailureConnection.instances[0].request_calls, 1)


if __name__ == "__main__":
    unittest.main()

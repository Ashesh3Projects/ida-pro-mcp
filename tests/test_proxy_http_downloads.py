"""Exercise the fork's output-download route over real HTTP/1.1 sockets."""

import http.client
import http.server
import json
import socket
import threading
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from ida_pro_mcp import server


class _OutputBackend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.downloads.append(self.path)
        body = self.server.output_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="output.json"')
        if self.server.framing == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "keep-alive, X-Backend-Connection")
            self.send_header("Keep-Alive", "timeout=5")
            self.send_header("X-Backend-Connection", "backend-only")
            self.send_header("Trailer", "X-Checksum")
        elif self.server.framing == "close":
            self.send_header("Connection", "close")
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.server.framing == "chunked":
            self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
            self.wfile.write(b"0\r\nX-Checksum: complete\r\n\r\n")
        else:
            self.wfile.write(body)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "content": [{"type": "text", "text": "truncated output"}],
                    "_meta": {"ida_mcp": {"output_id": "aaaa-1111"}},
                },
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyHttpDownloadTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(server._session_proxy_targets, clear=True))
        self.stack.enter_context(patch.dict(server._session_proxy_last_seen, clear=True))
        self.stack.enter_context(patch.dict(server._output_proxy_targets, clear=True))

        proxy = server.McpServer("proxy-download-test")
        for tool in (server.list_instances, server.select_instance, server.instance_status):
            proxy.tool(tool)
        self.stack.enter_context(patch.object(server, "mcp", proxy))
        self.stack.enter_context(
            patch.object(server, "dispatch_original", proxy.registry.dispatch)
        )
        proxy.registry.dispatch = server.dispatch_proxy
        proxy.serve("127.0.0.1", 0, request_handler=server.ProxyHttpRequestHandler)
        self.stack.callback(proxy.stop)
        self.proxy_address = proxy._http_server.server_address

        self.backend = self._backend(b'{"source":"first"}')
        self.stack.enter_context(patch.object(server, "IDA_HOST", "127.0.0.1"))
        self.stack.enter_context(patch.object(server, "IDA_PORT", self.backend.server_port))

    def _backend(self, body):
        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OutputBackend)
        backend.output_body = body
        backend.framing = "length"
        backend.downloads = []
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        self.stack.callback(thread.join)
        self.stack.callback(backend.server_close)
        self.stack.callback(backend.shutdown)
        return backend

    def _connection(self):
        connection = http.client.HTTPConnection(*self.proxy_address, timeout=2)
        self.stack.callback(connection.close)
        return connection

    def _post(self, connection, method, params, session_id):
        connection.request(
            "POST",
            "/mcp",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            {"Content-Type": "application/json", "Mcp-Session-Id": session_id},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        payload = json.loads(response.read())
        self.assertNotIn("error", payload)
        return payload["result"]

    def test_output_get_rejects_request_bodies_and_closes_connection(self):
        cases = [
            (b"Content-Length: 1\r\n", b"x"),
            (b"Transfer-Encoding: chunked\r\n", b"1\r\nx\r\n0\r\n\r\n"),
            (b"Content-Length: invalid\r\n", b""),
            (b"Content-Length: 0\r\nContent-Length: 0\r\n", b""),
        ]
        for headers, body in cases:
            with self.subTest(headers=headers):
                with socket.create_connection(self.proxy_address, timeout=2) as connection:
                    connection.sendall(
                        b"GET /output/aaaa-1111.json HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n" + headers + b"\r\n" + body
                    )
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 400)
                    self.assertEqual(response.getheader("Connection"), "close")
                    self.assertIn(b"Request body is not allowed", response.read())
                    self.assertEqual(connection.recv(1), b"")
        self.assertEqual(self.backend.downloads, [])

    def test_output_download_frames_each_backend_body_for_keep_alive(self):
        for framing in ("length", "chunked", "close"):
            with self.subTest(framing=framing):
                self.backend.framing = framing
                connection = self._connection()
                connection.connect()
                original_socket = connection.sock
                for _ in range(2):
                    connection.request("GET", "/output/aaaa-1111.json")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.version, 11)
                    self.assertEqual(response.getheader("Content-Length"), "18")
                    for header in (
                        "Transfer-Encoding", "Connection", "Keep-Alive", "Trailer",
                        "X-Backend-Connection",
                    ):
                        self.assertIsNone(response.getheader(header), header)
                    self.assertEqual(response.getheader("Content-Type"), "application/json")
                    self.assertEqual(
                        response.getheader("Content-Disposition"),
                        'attachment; filename="output.json"',
                    )
                    self.assertEqual(response.read(), b'{"source":"first"}')
                    self.assertIs(connection.sock, original_socket)
                connection.close()

    def test_output_get_preserves_host_and_origin_guards(self):
        for headers in (
            {"Host": "evil.example"},
            {"Origin": "https://evil.example"},
        ):
            with self.subTest(headers=headers):
                connection = self._connection()
                connection.request("GET", "/output/aaaa-1111.json", headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                self.assertEqual(response.getheader("Connection"), "close")
                response.read()
        self.assertEqual(self.backend.downloads, [])

    def test_download_stays_with_owner_after_client_selects_another_instance(self):
        second = self._backend(b'{"source":"second"}')
        instances = [
            {
                "instance_id": name,
                "host": "127.0.0.1",
                "port": backend.server_port,
                "pid": index,
                "binary": f"{name}.dll",
                "binary_path": f"/{name}.dll",
                "idb_path": f"/{name}.i64",
            }
            for index, (name, backend) in enumerate(
                (("first", self.backend), ("second", second)), start=1
            )
        ]
        # Isolate filesystem discovery; instance probes and proxy requests use sockets.
        self.stack.enter_context(patch.object(server, "discover_instances", return_value=instances))
        # Make the default different from the owner, so fallback cannot hide lost routing.
        server.IDA_PORT = second.server_port
        connection = self._connection()
        first = self._post(
            connection, "tools/call",
            {"name": "select_instance", "arguments": {"target": "first"}}, "client-a",
        )
        self.assertTrue(first["structuredContent"]["success"])
        output = self._post(
            connection, "tools/call",
            {"name": "export_data", "arguments": {}}, "client-a",
        )
        self.assertEqual(output["_meta"]["ida_mcp"]["output_id"], "aaaa-1111")
        selected = self._post(
            connection, "tools/call",
            {"name": "select_instance", "arguments": {"target": "second"}}, "client-a",
        )
        self.assertTrue(selected["structuredContent"]["success"])
        connection.request("GET", "/output/aaaa-1111.json")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b'{"source":"first"}')
        self.assertEqual(self.backend.downloads, ["/output/aaaa-1111.json"])
        self.assertEqual(second.downloads, [])


if __name__ == "__main__":
    unittest.main()

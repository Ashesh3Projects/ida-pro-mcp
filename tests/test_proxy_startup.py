"""A stdio client can discover tools before its IDA backend starts."""

import http.server
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack


_ROOT = Path(__file__).resolve().parents[1]


class _StdioProxy:
    def __init__(self, target_url, profile_dir, stderr):
        env = os.environ.copy()
        env.update(
            {
                "PYTHONPATH": str(_ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
                # The error path also discovers instances. Keep both the current
                # and legacy registries away from the user's running IDA sessions.
                "APPDATA": profile_dir,
                "USERPROFILE": profile_dir,
                "HOME": profile_dir,
            }
        )
        self.stderr = stderr
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(_ROOT / "src" / "ida_pro_mcp" / "server.py"),
                "--ida-rpc",
                target_url,
            ],
            cwd=_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            encoding="utf-8",
        )
        self.responses = queue.Queue()
        self.next_id = 0
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.reader.start()

    def _read_stdout(self):
        try:
            for line in self.process.stdout:
                self.responses.put(line)
        finally:
            self.responses.put(None)

    def _send(self, request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

    def notify(self, method):
        self._send({"jsonrpc": "2.0", "method": method})

    def request(self, method, params=None):
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            request["params"] = params
        self._send(request)
        try:
            line = self.responses.get(timeout=15)
        except queue.Empty:
            line = None
        if line is None:
            self.stderr.seek(0)
            diagnostics = self.stderr.read().decode("utf-8", errors="replace")
            raise AssertionError(
                f"No stdio response to {method}; exit={self.process.poll()}\n{diagnostics}"
            )
        response = json.loads(line)
        if response.get("id") != self.next_id:
            raise AssertionError(f"Unexpected stdio response: {response!r}")
        return response

    def close(self):
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if self.reader.is_alive():
            raise AssertionError("The stdio reader did not stop with its child process")


class _LateIdaBackend(http.server.BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append((self.path, request))
        response = {"jsonrpc": "2.0", "id": request.get("id")}
        if request.get("method") == "tools/call" and request.get("params") == {
            "name": "server_health",
            "arguments": {},
        }:
            health = {"status": "ready", "module": "late-backend"}
            response["result"] = {
                "content": [{"type": "text", "text": json.dumps(health)}],
                "structuredContent": health,
                "isError": False,
            }
        else:
            response["error"] = {"code": -32601, "message": "Unexpected backend request"}
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _stop_backend(backend, thread):
    backend.shutdown()
    thread.join(timeout=5)
    if thread.is_alive():
        raise AssertionError("The test backend did not stop")


class ProxyStartupTests(unittest.TestCase):
    def test_tools_discovered_offline_work_when_ida_starts_without_reconnect(self):
        for extensions in ("", "?ext=dbg"):
            with self.subTest(extensions=extensions), ExitStack() as stack:
                profile = stack.enter_context(tempfile.TemporaryDirectory())
                stderr = stack.enter_context(tempfile.TemporaryFile())
                backend = http.server.HTTPServer(
                    ("127.0.0.1", 0), _LateIdaBackend, bind_and_activate=False
                )
                stack.callback(backend.server_close)
                # Reserve the endpoint without listening: startup and the first
                # call must work correctly while no backend accepts connections.
                backend.server_bind()
                backend.requests = []
                endpoint = f"127.0.0.1:{backend.server_port}"
                proxy = _StdioProxy(f"http://{endpoint}{extensions}", profile, stderr)
                stack.callback(proxy.close)

                initialized = proxy.request(
                    "initialize",
                    {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "startup-regression", "version": "1"},
                    },
                )
                self.assertEqual(initialized["result"]["serverInfo"]["name"], "ida-pro-mcp")
                proxy.notify("notifications/initialized")
                listed = proxy.request("tools/list")["result"]
                names = {tool["name"] for tool in listed["tools"]}
                self.assertTrue(
                    {
                        "server_health",
                        "survey_binary",
                        "decompile",
                        "py_eval",
                        "list_instances",
                        "select_instance",
                        "instance_status",
                    }.issubset(names),
                    f"Cold-start tools/list is missing normal tools: {sorted(names)}",
                )
                self.assertEqual("dbg_status" in names, bool(extensions))

                arguments = {"name": "server_health", "arguments": {}}
                offline = proxy.request("tools/call", arguments)
                self.assertEqual(offline["error"]["code"], -32000)
                self.assertIn("IDA Pro", offline["error"]["message"])
                self.assertIn(endpoint, offline["error"]["message"])
                self.assertIsNone(proxy.process.poll())
                self.assertEqual(proxy.request("tools/list")["result"], listed)

                backend.server_activate()
                thread = threading.Thread(
                    target=backend.serve_forever,
                    kwargs={"poll_interval": 0.02},
                    daemon=True,
                )
                thread.start()
                stack.callback(_stop_backend, backend, thread)

                # Reuse the original process and client tool cache. There is no
                # initialize or tools/list between backend startup and this call.
                online = proxy.request("tools/call", arguments)
                self.assertNotIn("error", online)
                self.assertFalse(online["result"]["isError"])
                self.assertEqual(
                    online["result"]["structuredContent"],
                    {"status": "ready", "module": "late-backend"},
                )
                self.assertEqual(len(backend.requests), 1)
                path, forwarded = backend.requests[0]
                self.assertEqual(path, f"/mcp{extensions}")
                self.assertEqual(forwarded["method"], "tools/call")
                self.assertEqual(forwarded["params"], arguments)
                self.assertIsNone(proxy.process.poll())


if __name__ == "__main__":
    unittest.main()

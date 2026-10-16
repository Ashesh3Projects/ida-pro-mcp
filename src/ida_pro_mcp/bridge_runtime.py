"""Authenticated in-process typed-tool bridge, bootstrapped briefly via Nexus.

ensure_bridge must return to Nexus before forwarding any tools/call over HTTP.
The listener dispatches the canonical fork registry without creating another
McpServer or starting a competing main-thread pump. Its bearer token is an
internal credential, never a model-visible result or part of a URL.
"""

import atexit
import hmac
import importlib
import json
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .runtime_identity import PACKAGE_FINGERPRINT
from .instance_contract import RoutingError, require_instance_id
from .instance_runtime import runtime_identity as database_identity, generation_context

_bridge = None
_start_lock = threading.Lock()
_CLIENT_META = "ida_pro_mcp_client"


def runtime_identity() -> str:
    """Identify the source loaded by this runtime, independent of install path."""
    return PACKAGE_FINGERPRINT


def _load_runtime():
    # Never import top-level ida_mcp: that name belongs to the official adapter.
    package = importlib.import_module("ida_pro_mcp.ida_mcp")
    context = importlib.import_module("ida_pro_mcp.ida_mcp.execution_context")
    hooks = importlib.import_module("ida_pro_mcp.ida_mcp.instance_hooks")
    hooks.install_instance_hooks()
    return package.rpc, context


def ensure_bridge() -> dict:
    """Start once per IDA process; return a private versioned connection handle."""
    global _bridge
    with _start_lock:
        if _bridge is None:
            rpc, context = _load_runtime()
            _bridge = _Bridge(rpc, context)
            atexit.register(_bridge.close)
        return _bridge.descriptor()


class _Bridge:
    def __init__(self, rpc, context):
        self.rpc = rpc
        self.context = context
        self.token = secrets.token_urlsafe(32)
        self.id_prefix = secrets.token_hex(16)
        self.lock = threading.RLock()
        self.drained = threading.Condition(self.lock)
        self.active: dict[str, threading.Event] = {}
        self.active_clients: dict[str, str | None] = {}
        self.released_clients: set[str] = set()
        self.early_cancellations: dict[str, float] = {}
        self.clients: set[str] = set()
        self.closed = False
        bridge = self
        base = rpc.McpHttpRequestHandler

        class Handler(base):
            def __init__(self, request, client_address, server):
                # Bypass the base's connection ownership: the actual MCP_SERVER
                # may independently serve a legacy endpoint or not be started.
                self.mcp_server = rpc.MCP_SERVER
                BaseHTTPRequestHandler.__init__(self, request, client_address, server)

            def send_cors_headers(self, **kwargs):
                pass  # Internal direct HTTP only; never grant browser access.

            def _check_api_request(self):
                authority = f"127.0.0.1:{self.server.server_port}"
                if self.headers.get_all("Host", []) != [authority]:
                    self.send_error(403, "Invalid Host")
                    return False
                if "Origin" in self.headers or "Sec-Fetch-Site" in self.headers:
                    self.send_error(403, "Invalid Origin")
                    return False
                values = self.headers.get_all("Authorization", [])
                expected = "Bearer " + bridge.token
                if len(values) != 1 or not hmac.compare_digest(
                    values[0].encode(), expected.encode()
                ):
                    self.send_error(401, "Authentication required")
                    return False
                return True

            def do_POST(self):
                if not self._check_api_request():
                    return
                if urlsplit(self.path).path != "/mcp":
                    self.send_error(404, "Not Found")
                    return
                body = self._read_body()
                if body is None:
                    return
                response = bridge.dispatch(body)
                data = json.dumps(response).encode() if response is not None else b""
                self.send_response(200 if response is not None else 202)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if not self._check_api_request():
                    return
                if self._has_unexpected_body():
                    self.send_error(400, "Request body is not allowed")
                    return
                try:
                    generation = require_instance_id(self.headers.get("X-IDA-MCP-Generation"))
                    database_identity().check(generation)
                except RoutingError as error:
                    self.send_error(409, str(error))
                    return
                match = re.fullmatch(
                    r"/output/([a-f0-9-]+)\.json", urlsplit(self.path).path
                )
                data = rpc.get_cached_output(match[1]) if match else None
                if data is None:
                    self.send_error(404, "Not Found")
                    return
                payload = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.http.serve_forever, name="ida-mcp-bridge", daemon=True
        )
        self.thread.start()

    def descriptor(self):
        identity = database_identity().snapshot()
        if not identity:
            raise RoutingError("INSTANCE_CLOSED", "No database is open for this bridge.")
        return {
            "host": "127.0.0.1",
            "port": self.http.server_port,
            "token": self.token,
            "version": 2,
            "generation": identity["generation"],
            "idb_path": identity["idb_path"],
            "binary_path": identity["binary_path"],
        }

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for event in self.active.values():
                event.set()
            for client in self.clients:
                self.context.release_bridge_client(client)
            self.clients.clear()
        self.http.shutdown()
        self.http.server_close()

    def _request_key(self, client, request_id):
        # Include type and JSON boundaries to prevent ambiguous concatenations
        # and keep this listener isolated from the legacy cancellation registry.
        return self.id_prefix + json.dumps(
            [client, type(request_id).__name__, request_id], separators=(",", ":")
        )

    def _cancel(self, key):
        with self.lock:
            now = time.monotonic()
            self.early_cancellations = {
                key: expiry
                for key, expiry in self.early_cancellations.items()
                if expiry > now
            }
            event = self.active.get(key)
            if event is not None:
                event.set()
            else:
                if len(self.early_cancellations) >= 1024:
                    self.early_cancellations.pop(next(iter(self.early_cancellations)))
                self.early_cancellations[key] = now + 300

    def dispatch(self, body):
        registry = self.rpc.MCP_SERVER.registry
        try:
            request = json.loads(body)
        except (ValueError, TypeError):
            return registry.dispatch(body)
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return registry.dispatch(request)
        request_id = request.get("id")

        def error(code, message):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }

        if request_id is not None and (type(request_id) not in (str, int, float)):
            return error(-32600, "Invalid request ID")
        method = request.get("method")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return error(-32602, "Bridge parameters must be an object")
        meta = params.get("_meta") or {}
        client = meta.get(_CLIENT_META) if isinstance(meta, dict) else None
        if not isinstance(meta, dict) or (
            _CLIENT_META in meta
            and (not isinstance(client, str) or not client or len(client) > 256)
        ):
            return error(-32602, "Invalid bridge client context")
        if method in (
            "tools/call",
            "notifications/cancelled",
            "bridge/release_session",
        ):
            if not isinstance(client, str) or not client or len(client) > 256:
                return error(-32602, "Missing or invalid bridge client context")
        generation = None
        if method in ("tools/call", "resources/read"):
            try:
                generation = require_instance_id(meta.get("ida_pro_mcp_generation"))
                database_identity().check(generation)
            except RoutingError as exc:
                response = error(-32602, str(exc))
                response["error"]["data"] = {"error_code": exc.code}
                return response
        if method == "bridge/release_session":
            if params.get("client_id") != client:
                return error(-32602, "Release must match the request client context")
            with self.drained:
                # Stop admission atomically with selecting the calls to drain.
                # A frontend MUST retain its Nexus lease if this ACK is lost.
                self.released_clients.add(client)
                for key, active_client in self.active_clients.items():
                    if active_client == client:
                        self.active[key].set()
                while client in self.active_clients.values():
                    self.drained.wait()
                self.context.release_bridge_client(client)
                self.clients.discard(client)
            return (
                {"jsonrpc": "2.0", "id": request_id, "result": {"released": True}}
                if "id" in request
                else None
            )
        if method == "notifications/cancelled":
            target_id = params.get("requestId")
            if type(target_id) not in (str, int):
                return error(-32602, "Invalid cancellation request ID")
            key = self._request_key(client, target_id)
            self._cancel(key)
            request = {
                **request,
                "params": {k: v for k, v in params.items() if k != "_meta"},
            }
            request["params"]["requestId"] = key
            return registry.dispatch(request)
        key = self._request_key(client, request_id)
        event = threading.Event()
        with self.lock:
            if client in self.released_clients:
                return error(
                    -32602, "Bridge session was released; use a new client context"
                )
            if key in self.active:
                return error(-32600, "Request ID already in flight for this client")
            if self.early_cancellations.pop(key, 0) > time.monotonic():
                event.set()
            self.active[key] = event
            self.active_clients[key] = client
        server = self.rpc.MCP_SERVER
        old_extensions = getattr(server._enabled_extensions, "data", set())
        old_session = getattr(server._transport_session_id, "data", None)
        server._enabled_extensions.data = {"dbg"}
        server._transport_session_id.data = f"bridge:{client}" if client else None
        try:
            internal = {**request, "id": key} if "id" in request else request
            if client:
                with self.context.bridge_context(client, event), generation_context(generation):
                    with self.lock:
                        self.clients.add(client)
                    response = registry.dispatch(internal)
            else:
                response = registry.dispatch(internal)
            if response is not None:
                response["id"] = request_id
            return response
        except BaseException as exc:
            # execute_sync cannot propagate BaseException to its caller. The
            # sync layer ferries it back; terminate this request, not the server.
            return (
                error(-32603, f"Bridge execution failed: {type(exc).__name__}")
                if "id" in request
                else None
            )
        finally:
            server._enabled_extensions.data = old_extensions
            server._transport_session_id.data = old_session
            with self.drained:
                self.active.pop(key, None)
                self.active_clients.pop(key, None)
                self.drained.notify_all()

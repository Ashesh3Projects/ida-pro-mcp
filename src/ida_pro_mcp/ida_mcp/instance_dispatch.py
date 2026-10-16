"""Explicit identity and scoped cancellation for the lightweight IDA endpoint."""

from copy import deepcopy
import json
import secrets
import threading
import time
from ida_pro_mcp.instance_contract import (
    RoutingError,
    require_instance_id,
    split_instance_uri,
)
from ida_pro_mcp.instance_runtime import (
    expected_generation,
    generation_context,
    runtime_identity,
)

from .execution_context import bridge_context

_GLOBAL_TOOLS = {"list_instances", "idb_open", "idb_list"}


def install_instance_dispatch(server) -> None:
    if getattr(server, "_instance_dispatch_installed", False):
        return
    server._instance_dispatch_installed = True
    original = server.registry.dispatch
    original_list = server.registry.methods["tools/list"]
    original_templates = server.registry.methods["resources/templates/list"]
    original_resources = server.registry.methods["resources/list"]
    pending = {}
    early = {}
    lock = threading.Lock()

    @server.tool
    def list_instances() -> dict:
        info = runtime_identity().snapshot()
        return {"instances": [info] if info else [], "count": int(bool(info))}

    def tools_list(_meta=None):
        result = deepcopy(original_list(_meta))
        for tool in result["tools"]:
            if tool["name"] in _GLOBAL_TOOLS:
                continue
            schema = tool["inputSchema"]
            schema.setdefault("properties", {})["instance_id"] = {
                "type": "string",
                "pattern": "^[0-9a-f]{16}$",
                "description": "Required instance ID returned by this endpoint's list_instances.",
            }
            required = schema.setdefault("required", [])
            if "instance_id" not in required:
                required.append("instance_id")
        return result

    def templates_list():
        templates = deepcopy(original_templates())["resourceTemplates"]
        for resource in original_resources()["resources"]:
            templates.append(
                {
                    "uriTemplate": resource["uri"],
                    "name": resource["name"],
                    "description": resource.get("description", ""),
                }
            )
        for resource in templates:
            resource["uriTemplate"] += "{?instance_id}"
        return {"resourceTemplates": templates}

    server.registry.methods["tools/list"] = tools_list
    server.registry.methods["resources/templates/list"] = templates_list
    server.registry.methods["resources/list"] = lambda: {"resources": []}

    def dispatch(raw):
        try:
            request = (
                json.loads(raw)
                if isinstance(raw, (str, bytes, bytearray))
                else deepcopy(raw)
            )
        except (TypeError, ValueError):
            return original(raw)
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return original(raw)
        method = request.get("method")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return original(request)
        # Only a trusted in-process bridge can set this ContextVar. Wire metadata
        # never grants permission to bypass the public instance argument.
        if expected_generation() is not None:
            runtime_identity().check(expected_generation())
            return original(request)
        session = server.get_current_transport_session_id() or "direct:default"
        original_id = request.get("id")
        if method == "notifications/cancelled":
            cancelled_id = params.get("requestId")
            if type(cancelled_id) not in (str, int):
                return None
            key = (session, type(cancelled_id), cancelled_id)
            with lock:
                event = pending.get(key)
                if event is not None:
                    event.set()
                else:
                    now = time.monotonic()
                    for old, expiry in list(early.items()):
                        if expiry < now:
                            early.pop(old, None)
                    if len(early) >= 1024:
                        early.pop(next(iter(early)))
                    early[key] = now + 30
            return None
        if method not in {"tools/call", "resources/read"}:
            return original(request)
        if method == "tools/call" and params.get("name") in _GLOBAL_TOOLS:
            return original(request)
        public_uri = None
        try:
            if method == "tools/call":
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    return original(request)
                generation = require_instance_id(arguments.pop("instance_id", None))
            else:
                public_uri = params.get("uri", "")
                params["uri"], generation = split_instance_uri(public_uri)
            runtime_identity().check(generation)
            # Replace rather than merge reserved caller context metadata.
            params.pop("_meta", None)
            request["params"] = params
            key = (session, type(original_id), original_id)
            if type(original_id) not in (str, int):
                raise RoutingError(
                    "INVALID_REQUEST",
                    "Database calls require an integer or string request ID.",
                )
            event = threading.Event()
            with lock:
                if key in pending:
                    raise RoutingError(
                        "INVALID_REQUEST",
                        "Request ID is already in flight for this client.",
                    )
                if early.pop(key, 0) > time.monotonic():
                    event.set()
                pending[key] = event
            request["id"] = secrets.token_hex(16)
            try:
                with (
                    generation_context(generation),
                    bridge_context(f"direct:{session}:{generation}", event),
                ):
                    response = original(request)
                if response is not None:
                    response["id"] = original_id
                    if public_uri and "result" in response:
                        for content in response["result"].get("contents", []):
                            content["uri"] = public_uri
                return response
            finally:
                with lock:
                    pending.pop(key, None)
        except RoutingError as error:
            if original_id is None:
                return None
            if method == "tools/call":
                return {
                    "jsonrpc": "2.0",
                    "id": original_id,
                    "result": error.tool_result(),
                }
            return {
                "jsonrpc": "2.0",
                "id": original_id,
                "error": {
                    "code": -32602,
                    "message": str(error),
                    "data": {"error_code": error.code},
                },
            }

    server.registry.dispatch = dispatch

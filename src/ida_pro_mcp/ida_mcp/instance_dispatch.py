"""Explicit identity and scoped cancellation for the lightweight IDA endpoint."""

from copy import deepcopy
import json
import secrets
import threading
import time
import weakref
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

from .execution_context import bridge_context, release_bridge_client

_GLOBAL_TOOLS = {"list_instances", "idb_open", "idb_list"}
_servers = weakref.WeakSet()


def retire_database_contexts(generation):
    """Fence old contexts without blocking IDA's database-close notification."""
    for server in list(_servers):
        server._retire_instance_generation(generation)


def install_instance_dispatch(server) -> None:
    if getattr(server, "_instance_dispatch_installed", False):
        return
    server._instance_dispatch_installed = True
    original = server.registry.dispatch
    original_list = server.registry.methods["tools/list"]
    original_templates = server.registry.methods["resources/templates/list"]
    original_resources = server.registry.methods["resources/list"]
    pending = {}
    pending_generations = {}
    early = {}
    lock = threading.Lock()
    drained = threading.Condition(lock)
    clients = set()
    released = set()
    completed_drains = set()

    def retire_generation(generation):
        with drained:
            for key, active_generation in pending_generations.items():
                if active_generation == generation:
                    pending[key].set()
            for client in list(clients):
                if client[1] == generation:
                    release_bridge_client(f"direct:{client[0]}:{generation}")
                    clients.discard(client)
            # The runtime generation guard permanently rejects this lifetime.
            released.difference_update({c for c in released if c[1] == generation})
            completed_drains.difference_update(
                {c for c in completed_drains if c[1] == generation}
            )

    server._retire_instance_generation = retire_generation
    _servers.add(server)

    def control(method, params, session):
        generation = require_instance_id(params.get("instance_id"))
        client = (session, generation)
        requested = params.get("request_ids", [])
        if method == "instance/drain" and (
            not isinstance(requested, list)
            or not requested
            or any(type(value) not in (str, int) for value in requested)
        ):
            raise RoutingError("INVALID_REQUEST", "Drain requires request_ids")
        keys = {(session, type(value), value) for value in requested}
        with drained:
            if method == "instance/release":
                # Fence admission before acknowledging: a request whose HTTP
                # response was lost must never outlive a successful release.
                released.add(client)
                keys = {
                    key
                    for key, value in pending_generations.items()
                    if key[0] == session and value == generation
                }
            else:
                # A lost request may arrive after its control connection. This
                # operation tombstone lasts until its binding is released.
                completed_drains.update((key, generation) for key in keys)
            for key in keys:
                event = pending.get(key)
                if event is not None and pending_generations[key] == generation:
                    event.set()
            while any(
                key in pending and pending_generations[key] == generation
                for key in keys
            ):
                drained.wait()
            if method == "instance/release":
                release_bridge_client(f"direct:{session}:{generation}")
                clients.discard(client)
                completed_drains.difference_update(
                    {
                        item
                        for item in completed_drains
                        if item[0][0] == session and item[1] == generation
                    }
                )
                for key in list(early):
                    if key[0] == session:
                        early.pop(key, None)
                return {"released": True}
            return {"drained": True}

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
        if method not in {
            "tools/call",
            "resources/read",
            "instance/release",
            "instance/drain",
        }:
            return original(request)
        if method == "tools/call" and params.get("name") in _GLOBAL_TOOLS:
            return original(request)
        public_uri = None
        try:
            if method in {"instance/release", "instance/drain"}:
                if type(original_id) not in (str, int):
                    raise RoutingError(
                        "INVALID_REQUEST", "Lifecycle controls require a request ID"
                    )
                return {
                    "jsonrpc": "2.0",
                    "id": original_id,
                    "result": control(method, params, session),
                }
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
                # Recheck under admission's lock against concurrent closebase.
                runtime_identity().check(generation)
                client = (session, generation)
                if client in released:
                    raise RoutingError(
                        "INSTANCE_CLOSED", "This client binding was released"
                    )
                if (key, generation) in completed_drains:
                    raise RoutingError(
                        "REQUEST_CANCELLED", "This operation was already drained"
                    )
                if key in pending:
                    raise RoutingError(
                        "INVALID_REQUEST",
                        "Request ID is already in flight for this client.",
                    )
                if early.pop(key, 0) > time.monotonic():
                    event.set()
                pending[key] = event
                pending_generations[key] = generation
                clients.add(client)
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
                with drained:
                    pending.pop(key, None)
                    pending_generations.pop(key, None)
                    if runtime_identity().snapshot().get("generation") != generation:
                        # closebase can win between admission and context entry.
                        release_bridge_client(f"direct:{session}:{generation}")
                        clients.discard(client)
                    drained.notify_all()
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

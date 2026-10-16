"""Schema-preserving asynchronous MCP frontend with explicit database routing."""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
from copy import deepcopy
from importlib.metadata import version
import json
import math
import re

from fastmcp import FastMCP
from fastmcp.tools import Tool, ToolResult
from fastmcp.resources import Resource, ResourceTemplate
from fastmcp.resources.base import ResourceContent, ResourceResult
from fastmcp.exceptions import ResourceError
from jsonschema import Draft202012Validator, ValidationError
from mcp_types import CallToolResult
from pydantic import PrivateAttr

from .instance_contract import RoutingError, require_instance_id, split_instance_uri
from .instance_router import InstanceRouter, finish_cleanup
from .tool_catalog import get_ida_tools, get_ida_resources, fork_schema_generator

_INSTANCE_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9a-f]{16}$",
    "description": "Required instance ID from this server's list_instances or open_database. Never omit or use a list index.",
}
_MANAGEMENT = {
    "list_instances",
    "list_databases",
    "instance_status",
    "open_database",
    "execute_python",
    "save_database",
    "close_database",
    "read_output",
    "reference",
}


def _native(result):
    return ToolResult.from_mcp_result(CallToolResult.model_validate(result))


def _data(value):
    return _native(
        {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "structuredContent": value,
            "isError": False,
        }
    )


class RoutedTool(Tool):
    _router: InstanceRouter = PrivateAttr()
    _validator: Draft202012Validator = PrivateAttr()
    _action: str = PrivateAttr(default="typed")

    async def run(self, arguments):
        instance_id = arguments.get("instance_id")
        try:
            if "instance_id" in self.parameters.get("required", []):
                instance_id = require_instance_id(instance_id)
            self._validator.validate(arguments)
            args = {
                key: value for key, value in arguments.items() if key != "instance_id"
            }
            action = self._action
            if action == "typed":
                return _native(
                    await self._router.request(
                        instance_id,
                        "tools/call",
                        {"name": self.name, "arguments": args},
                    )
                )
            if action == "list":
                return _data(await self._router.list_instances())
            if action == "status":
                return _data(await self._router.instance_status(instance_id))
            if action == "open":
                path = args.pop("path", None) or args.pop("input_path", None)
                return _data(await self._router.open_database(path, **args))
            if action == "close":
                return _data(
                    await self._router.close_database(
                        instance_id, save=args.get("save", self.name == "idb_close")
                    )
                )
            if action == "output":
                return _data(await self._router.read_output(instance_id, **args))
            if action == "reference":
                return ToolResult(
                    content=await self._router.provider.reference(args["query"])
                )
            if action == "execute_python":
                timeout = args.get("timeout", 360)
                if (
                    isinstance(timeout, bool)
                    or not isinstance(timeout, (float, int))
                    or not math.isfinite(timeout)
                    or timeout <= 0
                ):
                    raise ValueError("timeout must be a positive finite number")
            return _data(await self._router.request(instance_id, action, args))
        except RoutingError as error:
            return _native(
                error.tool_result(instance_id if isinstance(instance_id, str) else None)
            )
        except ValidationError as error:
            return _native(
                RoutingError("INVALID_ARGUMENTS", error.message).tool_result()
            )
        except Exception as error:
            return _native(
                RoutingError("BACKEND_ERROR", str(error)).tool_result(instance_id)
            )


class RoutedResource(Resource):
    _router: InstanceRouter = PrivateAttr()

    async def read(self):
        try:
            result = await self._router.read_resource(str(self.uri))
            content = [
                ResourceContent(
                    item["text"] if "text" in item else base64.b64decode(item["blob"]),
                    mime_type=item.get("mimeType"),
                    meta=item.get("_meta"),
                )
                for item in result["contents"]
            ]
            return ResourceResult(content, meta=result.get("_meta"))
        except RoutingError as error:
            raise ResourceError(str(error)) from error


class RoutedResourceTemplate(ResourceTemplate):
    _router: InstanceRouter = PrivateAttr()
    _backend_uri: str = PrivateAttr()

    def matches(self, uri):
        try:
            backend_uri, instance_id = split_instance_uri(uri)
        except (RoutingError, ValueError):
            return None
        pattern = re.escape(self._backend_uri)
        pattern = re.sub(r"\\\{[^}]+\\\}", "[^/]+", pattern)
        return (
            {"instance_id": instance_id} if re.fullmatch(pattern, backend_uri) else None
        )

    async def create_resource(self, uri, params):
        resource = RoutedResource(uri=uri, name=self.name, description=self.description)
        resource._router = self._router
        return resource


def create_server(
    router: InstanceRouter,
    *,
    extensions: set[str] | None = None,
    profile: set[str] | None = None,
    legacy_aliases: bool = False,
    database: str | None = None,
    trace=None,
):
    extensions = set(extensions or ())
    if extensions - {"dbg"}:
        raise ValueError("Unknown extension; supported extension: dbg")

    @asynccontextmanager
    async def lifespan(server):
        if trace is not None:
            trace.emit("mcp_started")
        opening = (
            asyncio.create_task(router.open_database(database)) if database else None
        )
        try:
            yield {"router": router}
        finally:
            await finish_cleanup(asyncio.create_task(router.shutdown()))
            if opening is not None:
                await asyncio.gather(opening, return_exceptions=True)
            if trace is not None:
                trace.emit("mcp_stopped")

    server = FastMCP(
        "ida-pro-mcp",
        version=version("ida-pro-mcp"),
        lifespan=lifespan,
        instructions="Call list_instances or open_database, then pass the exact instance_id on every database call. Calls to different instances may run concurrently. Closed IDs cannot be reused.",
    )
    if trace is not None:
        from .diagnostics import RoutingTraceMiddleware

        server.add_middleware(RoutingTraceMiddleware(trace))
    catalog = get_ida_tools(fork_schema_generator(), extensions)
    known = {item["name"] for item in catalog} | _MANAGEMENT
    if profile is not None and profile - known:
        raise ValueError(
            f"Unknown or disabled profile tools: {', '.join(sorted(profile - known))}"
        )

    def add(name, description, schema, output=None, action="typed"):
        tool = RoutedTool(
            name=name, description=description, parameters=schema, output_schema=output
        )
        tool._router = router
        tool._validator = Draft202012Validator(schema)
        tool._action = action
        server.add_tool(tool)

    for descriptor in catalog:
        if profile is not None and descriptor["name"] not in profile:
            continue
        schema = deepcopy(descriptor["inputSchema"])
        schema.setdefault("properties", {})["instance_id"] = deepcopy(_INSTANCE_SCHEMA)
        schema.setdefault("required", []).append("instance_id")
        add(
            descriptor["name"],
            descriptor["description"],
            schema,
            descriptor.get("outputSchema"),
        )

    def management(
        name, action, description, properties=None, required=(), targeted=False
    ):
        properties = dict(properties or {})
        required = list(required)
        if targeted:
            properties["instance_id"] = deepcopy(_INSTANCE_SCHEMA)
            required.append("instance_id")
        add(
            name,
            description,
            {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
            action=action,
        )

    management(
        "list_instances",
        "list",
        "List exact available IDA databases and their opaque instance IDs. Does not select or open a database.",
    )
    management(
        "list_databases",
        "list",
        "List IDA databases and their instance IDs; alias of list_instances.",
    )
    management(
        "instance_status",
        "status",
        "Show the state of this exact instance.",
        targeted=True,
    )
    management(
        "open_database",
        "open",
        "Open or attach to an explicit path and return its instance_id. Does not select a default.",
        {"path": {"type": "string"}},
        ["path"],
    )
    management(
        "execute_python",
        "execute_python",
        "Run persistent Nexus Python on this instance. Both db and ida_domain are available; trailing expressions and run(db) entrypoints are supported.",
        {
            "code": {"type": "string"},
            "timeout": {"type": "number", "exclusiveMinimum": 0, "default": 360},
        },
        ["code"],
        True,
    )
    management(
        "save_database", "save_database", "Save this exact IDA database.", targeted=True
    )
    management(
        "close_database",
        "close",
        "Drain this binding and release its owned lease without closing peer leases or adopted GUI databases.",
        targeted=True,
    )
    management(
        "read_output",
        "output",
        "Read a bounded page of cached output from its original instance.",
        {
            "output_id": {"type": "string"},
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 32000,
                "default": 32000,
            },
        },
        ["output_id"],
        True,
    )
    management(
        "reference",
        "reference",
        "Look up the installed IDA Domain API reference without opening a database.",
        {"query": {"type": "string"}},
        ["query"],
    )
    if legacy_aliases:
        management("idb_list", "list", "List database instances and their IDs.")
        management(
            "idb_close",
            "close",
            "Drain and close this binding, saving first by default.",
            {"save": {"type": "boolean", "default": True}},
            targeted=True,
        )
        management(
            "idb_open",
            "open",
            "Open a binary with explicit GUI/headless policy; returns an opaque instance_id.",
            {
                "input_path": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": [
                        "prefer_headless",
                        "force_headless",
                        "prefer_gui",
                        "force_gui",
                    ],
                    "default": "prefer_headless",
                },
                "run_auto_analysis": {"type": "boolean", "default": True},
                "build_caches": {"type": "boolean", "default": True},
                "init_hexrays": {"type": "boolean", "default": True},
                "idle_ttl_sec": {"type": "integer", "default": 600},
            },
            ["input_path"],
        )
    for descriptor in get_ida_resources():
        template = RoutedResourceTemplate(
            uri_template=descriptor["uri"] + "{?instance_id}",
            name=descriptor["name"],
            description=descriptor["description"],
            parameters={
                "type": "object",
                "properties": {"instance_id": _INSTANCE_SCHEMA},
                "required": ["instance_id"],
            },
        )
        template._router = router
        template._backend_uri = descriptor["uri"]
        server.add_template(template)
    return server

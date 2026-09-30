"""One official MCP frontend with the fork's schema-preserving typed tools."""

from __future__ import annotations

import inspect
import re
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs, urlsplit, urlunsplit

from .official_adapter import (
    NativeResourceResult,
    NativeToolResult,
    install_compatibility,
)
from .tool_catalog import (
    fork_schema_generator,
    get_ida_resources,
    get_ida_tool_signatures,
    get_ida_tools,
)
from .unified_bridge import bridge_manager_class


def manager_options(official, idle_timeout=None) -> dict:
    """Options accepted by the official public serve_stdio/serve_http APIs."""
    if idle_timeout is not None:
        raise ValueError(
            "Unified typed tools require indefinite leases; use close_database for explicit release"
        )
    return {
        "database_manager_class": bridge_manager_class(official.DatabaseManager),
        "database_manager_kwargs": {
            "open_timeout": official.OPEN_TIMEOUT_SECONDS,
            "execute_timeout": official.EXECUTE_TIMEOUT_SECONDS,
            "idle_timeout": None,
        },
    }


def _profile_names(profile):
    if profile is None or isinstance(profile, set):
        return profile
    return {
        name
        for line in Path(profile).read_text(encoding="utf-8").splitlines()
        if (name := line.split("#", 1)[0].strip())
    }


def configure_server(*, extensions: set[str] | None = None, profile=None):
    """Register once per process, while discovery stays independent of IDA."""
    from ida_mcp import mcp as official

    extensions = set(extensions or ())
    unknown_extensions = extensions - {"dbg"}
    if unknown_extensions:
        raise ValueError(f"Unknown extensions: {', '.join(sorted(unknown_extensions))}")
    profile = _profile_names(profile)
    configuration = (
        frozenset(extensions),
        None if profile is None else frozenset(profile),
    )
    previous = getattr(official, "_ida_pro_mcp_configuration", None)
    if previous is not None:
        if previous != configuration:
            raise ValueError(
                "Unified MCP is already configured with a different profile"
            )
        return official
    catalog = get_ida_tools(fork_schema_generator(), extensions)
    signatures = get_ida_tool_signatures(extensions)
    known = (
        {item["name"] for item in catalog}
        | set(official.mcp.tools.methods)
        | {"read_output"}
    )
    if profile is not None and profile - known:
        raise ValueError(
            f"Unknown or disabled profile tools: {', '.join(sorted(profile - known))}"
        )
    catalog = [item for item in catalog if profile is None or item["name"] in profile]
    schemas = {}
    for descriptor in catalog:
        name = descriptor["name"]
        if name in official.mcp.tools.methods:
            raise ValueError(f"Official and typed tool name conflict: {name}")
        descriptor = deepcopy(descriptor)
        descriptor["inputSchema"]["properties"]["instance_id"] = {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "default": None,
            "description": "Optional database instance id; otherwise use the current Nexus target.",
        }
        schemas[name] = descriptor
    NativeToolError = install_compatibility(official, schemas)

    def bridge():
        manager = official.DATABASE_MANAGER
        if not hasattr(manager, "unified_bridge"):
            raise RuntimeError(
                "Start unified MCP with manager_options() to preserve Nexus lease cleanup"
            )
        return manager.unified_bridge

    def register(descriptor):
        name = descriptor["name"]
        signature = signatures[name]
        if "instance_id" in signature.parameters:
            raise ValueError(
                f"Typed tool already owns reserved instance_id parameter: {name}"
            )
        parameter = inspect.Parameter(
            "instance_id",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=str | None,
        )
        signature = signature.replace(
            parameters=[*signature.parameters.values(), parameter]
        )

        async def forward(**arguments):
            instance_id = arguments.pop("instance_id", None)
            result = await bridge().call_tool(name, arguments, instance_id)
            if result.get("isError"):
                raise NativeToolError(result)
            return NativeToolResult(result)

        forward.__name__ = name
        forward.__doc__ = descriptor["description"]
        forward.__signature__ = signature
        forward.__annotations__ = {
            key: value.annotation for key, value in signature.parameters.items()
        }
        # Schema lookup uses the exact fork output schema; no annotation leakage
        # from temporary TypedDict namespaces into the official schema generator.
        forward.__annotations__["return"] = dict
        official.tool(forward)

    for descriptor in catalog:
        register(descriptor)

    @official.tool(read_only=True)
    async def read_output(
        output_id: Annotated[
            str, "Output id returned by a truncated typed tool result."
        ],
        offset: Annotated[
            int, "Character offset from the previous next_offset; starts at zero."
        ] = 0,
        limit: Annotated[
            int, "Maximum characters to return, between 1 and 32000."
        ] = 32000,
    ) -> dict:
        """Read a bounded page of cached output from its original database target."""
        return await bridge().read_output(output_id, offset, limit)

    # Keep resource discovery offline too. The public resource decorator still
    # owns URI matching, async dispatch, and MCP cancellation registration.
    resource_target = ContextVar("ida_pro_mcp_resource_target", default=None)
    for descriptor in get_ida_resources():

        def register_resource(descriptor):
            uri = descriptor["uri"]
            names = re.findall(r"\{([^}]+)\}", uri)

            async def read(**arguments):
                return NativeResourceResult(
                    await bridge().request(
                        "resources/read",
                        {"uri": uri.format(**arguments)},
                        resource_target.get(),
                    )
                )

            read.__name__ = descriptor["name"]
            read.__doc__ = descriptor["description"]
            read.__signature__ = inspect.Signature(
                [
                    inspect.Parameter(
                        name, inspect.Parameter.KEYWORD_ONLY, annotation=str
                    )
                    for name in names
                ]
            )
            read.__annotations__ = {name: str for name in names}
            official.mcp.resource(uri)(read)

        register_resource(descriptor)

    original_read = official.mcp.registry.methods["resources/read"]

    def read_target_resource(uri: str, _meta: dict | None = None):
        parts = urlsplit(uri)
        query = parse_qs(parts.query)
        if set(query) - {"instance_id"} or len(query.get("instance_id", [])) > 1:
            raise ValueError(
                "Resource URI accepts only one instance_id query parameter"
            )
        target = query.get("instance_id", [None])[0]
        token = resource_target.set(target)
        try:
            clean_uri = urlunsplit(parts._replace(query=""))
            result = original_read(clean_uri, _meta)
            if not inspect.isawaitable(result):
                return result

            async def read_in_context():
                async_token = resource_target.set(target)
                try:
                    return await result
                finally:
                    resource_target.reset(async_token)

            return read_in_context()
        finally:
            resource_target.reset(token)

    official.mcp.registry.method(read_target_resource, "resources/read")
    official._ida_pro_mcp_configuration = configuration
    return official

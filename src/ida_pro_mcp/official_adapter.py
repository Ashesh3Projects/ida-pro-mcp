"""Narrow compatibility contract for the pinned official MCP / ZeroMCP releases.

Public ``tool`` and ``resource`` registration retain official execution and
tracing. These two result formatters and schema lookup are the only adapted
ZeroMCP internals: the fork already returns complete MCP result envelopes.
"""

import json
import sys
from copy import deepcopy
from importlib.metadata import distributions, version
from pathlib import Path


def _canonical_gui_plugin_installed(plugins: Path) -> bool:
    """Recognize only a current canonical loader with its pinned Nexus runtime."""
    source = Path(__file__).resolve().parent
    try:
        document = json.loads(
            (plugins / "ida-pro-mcp-runtime.json").read_text(encoding="utf-8")
        )
        if not isinstance(document, dict):
            return False
        if document.get("python_version") != list(sys.version_info[:2]):
            return False
        if not Path(document["python"]).is_file():
            return False
        roots = document["site_packages"]
        if not isinstance(roots, list) or not all(
            isinstance(root, str) for root in roots
        ):
            return False
        for name in ("__init__.py", "bridge_runtime.py"):
            if (plugins / "ida_pro_mcp" / name).read_bytes() != (
                source / name
            ).read_bytes():
                return False
        if (plugins / "ida_mcp.py").read_bytes() != (
            source / "ida_mcp.py"
        ).read_bytes():
            return False
        if not (
            Path(document["package_root"]) / "ida_pro_mcp" / "__init__.py"
        ).is_file():
            return False
        return any(
            package.metadata.get("Name", "").replace("_", "-").lower() == "ida-nexus"
            and package.version == "0.13.0"
            and Path(package.locate_file("ida_nexus/plugin.py")).is_file()
            for package in distributions(path=roots)
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


class NativeToolResult(dict):
    pass


class NativeResourceResult(dict):
    pass


def install_compatibility(official, schemas):
    from zeromcp import McpToolError

    if official.PACKAGE_VERSION != "20260929.0.1" or version("zeromcp") != "1.10.3":
        raise RuntimeError(
            "Unified IDA MCP requires the pinned ida-mcp 20260929.0.1 / zeromcp 1.10.3 adapter"
        )
    server = official.mcp
    for name in (
        "_generate_tool_schema",
        "_format_tool_response",
        "_format_resource_response",
    ):
        if not callable(getattr(server, name, None)):
            raise RuntimeError(f"Unsupported official MCP adapter: missing {name}")
    server.name = "ida-pro-mcp"
    server.version = version("ida-pro-mcp")
    original_gui_installed = official._gui_plugin_installed
    official._gui_plugin_installed = lambda: (
        original_gui_installed()
        or _canonical_gui_plugin_installed(official._get_idausr_dir() / "plugins")
    )

    class NativeToolError(McpToolError):
        def __init__(self, result):
            self.result = result
            message = "\n".join(
                item.get("text", "")
                for item in result.get("content", [])
                if item.get("type") == "text"
            )
            super().__init__(message or "IDA tool failed")

    original_schema = server._generate_tool_schema
    original_tool = server._format_tool_response
    original_resource = server._format_resource_response
    original_error = server.tools.map_exception

    def schema(name, function):
        return (
            deepcopy(schemas[name])
            if name in schemas
            else original_schema(name, function)
        )

    def error(exception):
        if isinstance(exception, NativeToolError):
            return {
                "code": -32000,
                "message": str(exception),
                "data": {"ida_pro_mcp_result": exception.result},
            }
        return original_error(exception)

    def tool_result(name, response):
        if name in schemas:
            result = response.get("result")
            if isinstance(result, NativeToolResult):
                return dict(result)
            data = response.get("error", {}).get("data")
            if isinstance(data, dict) and "ida_pro_mcp_result" in data:
                return data["ida_pro_mcp_result"]
        return original_tool(name, response)

    def resource_result(uri, response):
        result = response.get("result")
        if isinstance(result, NativeResourceResult):
            return dict(result)
        return original_resource(uri, response)

    server._generate_tool_schema = schema
    server.tools.map_exception = error
    server._format_tool_response = tool_result
    server._format_resource_response = resource_result
    return NativeToolError

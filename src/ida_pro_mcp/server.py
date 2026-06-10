import argparse
import http.client
import json
import os
import re
import sys
import traceback
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )

try:
    from .instance_registry import (
        cleanup_stale_instances,
        find_instance_by_binary,
        find_instance_by_id,
        list_instances as registry_list_instances,
    )
except ImportError:
    from instance_registry import (
        cleanup_stale_instances,
        find_instance_by_binary,
        find_instance_by_id,
        list_instances as registry_list_instances,
    )

DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

# Currently selected target instance for custom multi-instance routing.
_target_instance_id: str | None = None

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

_OUTPUT_PATH_RE = re.compile(r"^/output/([a-f0-9-]+)\.(\w+)$")


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {"Content-Type": "application/json"}
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def _get_target_instance() -> tuple[str, int] | None:
    """Resolve the target IDA instance using the custom registry."""
    global _target_instance_id

    if _target_instance_id:
        info = find_instance_by_id(_target_instance_id)
        if info and info.is_alive():
            return (info.host, info.port)
        _target_instance_id = None

    instances = registry_list_instances()
    if len(instances) == 1:
        return (instances[0].host, instances[0].port)

    return None


def _proxy_to_ida(
    payload: bytes | str | dict, host: str | None = None, port: int | None = None
) -> dict:
    """Send a JSON-RPC request to the configured IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    target_host = host if host is not None else IDA_HOST
    target_port = port if port is not None else IDA_PORT
    conn = http.client.HTTPConnection(target_host, target_port, timeout=120)
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        return json.loads(raw_data)
    finally:
        conn.close()


def _proxy_output_download(path: str) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Proxy a raw output download from the configured IDA instance."""
    target = _get_target_instance()
    host = target[0] if target else IDA_HOST
    port = target[1] if target else IDA_PORT
    conn = http.client.HTTPConnection(host, port, timeout=120)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests, routing to the selected custom registry instance."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    if request_obj["method"] == "tools/call":
        params = request_obj.get("params", {})
        if isinstance(params, dict):
            tool_name = params.get("name", "")
            if tool_name in ("list_instances", "select_instance", "instance_status"):
                return dispatch_original(request)

    if request_obj["method"] == "tools/list":
        local_response = dispatch_original(request)
        target = _get_target_instance()
        host = target[0] if target else IDA_HOST
        port = target[1] if target else IDA_PORT
        try:
            remote_response = _proxy_to_ida(request, host, port)
            remote_result = remote_response.get("result") if remote_response else None
            local_result = local_response.get("result") if local_response else None
            if remote_result is not None and local_result is not None:
                remote_tools = remote_result.get("tools", [])
                local_tools = local_result.get("tools", [])
                remote_names = {tool["name"] for tool in remote_tools}
                for local_tool in local_tools:
                    if local_tool["name"] not in remote_names:
                        remote_tools.append(local_tool)
                remote_result["tools"] = remote_tools
            return remote_response
        except Exception:
            return local_response

    target = _get_target_instance()
    host = target[0] if target else IDA_HOST
    port = target[1] if target else IDA_PORT

    try:
        return _proxy_to_ida(request, host, port)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        instances = registry_list_instances()
        if instances:
            instance_list = "\n".join(
                f"  - {inst.binary_name} ({inst.host}:{inst.port}, id={inst.instance_id})"
                for inst in instances
            )
            instance_hint = (
                "\n\nRegistered instances:\n"
                f"{instance_list}\n\n"
                "Use 'select_instance' tool to choose a target instance."
            )
        else:
            instance_hint = ""
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}{instance_hint}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


@mcp.tool
def list_instances() -> dict:
    """List all active IDA Pro instances from the custom registry."""
    cleanup_stale_instances()
    instances = registry_list_instances()
    return {
        "instances": [inst.to_dict() for inst in instances],
        "count": len(instances),
        "selected_instance": _target_instance_id,
    }


@mcp.tool
def select_instance(target: str) -> dict:
    """Select which IDA Pro instance to send subsequent commands to."""
    global _target_instance_id

    info = find_instance_by_id(target)
    if info and info.is_alive():
        _target_instance_id = info.instance_id
        return {
            "selected": info.to_dict(),
            "message": f"Selected instance '{info.instance_id}' analyzing '{info.binary_name}'",
        }

    info = find_instance_by_binary(target)
    if info and info.is_alive():
        _target_instance_id = info.instance_id
        return {
            "selected": info.to_dict(),
            "message": f"Selected instance '{info.instance_id}' analyzing '{info.binary_name}'",
        }

    instances = registry_list_instances()
    available = [f"{inst.instance_id} ({inst.binary_name})" for inst in instances]
    return {
        "error": f"Instance not found: '{target}'",
        "available_instances": available,
    }


@mcp.tool
def instance_status() -> dict:
    """Get the current connection status and selected IDA Pro instance."""
    cleanup_stale_instances()
    instances = registry_list_instances()
    target = _get_target_instance()
    status = {
        "connected": target is not None,
        "target_host": target[0] if target else IDA_HOST,
        "target_port": target[1] if target else IDA_PORT,
        "selected_instance_id": _target_instance_id,
        "available_instances": [inst.to_dict() for inst in instances],
        "instance_count": len(instances),
    }
    if _target_instance_id:
        info = find_instance_by_id(_target_instance_id)
        if info:
            status["selected_binary"] = info.binary_name
    return status


class ProxyHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if _OUTPUT_PATH_RE.match(parsed.path):
            if not self._check_api_request():
                return
            try:
                status, _, response_headers, body = _proxy_output_download(parsed.path)
            except Exception as e:
                self.send_error(502, f"Failed to proxy output download: {e}")
                return

            self.send_response(status)
            for header, value in response_headers:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Resolve the IDA RPC target: explicit --ida-rpc, or auto-discovery."""
    global IDA_HOST, IDA_PORT

    if args.ida_rpc is not None:
        # Explicit --ida-rpc: use directly (backwards compatible)
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port

        # Preserve ?ext= query param so proxy requests include the extensions
        ext_value = parse_qs(ida_rpc.query).get("ext", [""])[0]
        if ext_value:
            mcp._enabled_extensions.data = set(ext_value.split(","))

        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances using the custom registry.
    cleanup_stale_instances()
    instances = registry_list_instances()
    if len(instances) == 0:
        print(
            f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst.host
        IDA_PORT = inst.port
        print(
            f"[MCP] Auto-connected to: {inst.binary_name} at {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(
                f"  [{i}] {inst.binary_name} at {inst.host}:{inst.port} (id={inst.instance_id})",
                file=sys.stderr,
            )
        inst = instances[0]
        IDA_HOST = inst.host
        IDA_PORT = inst.port
        print(
            f"[MCP] Auto-selected: {inst.binary_name}. "
            "Pass --ida-rpc http://host:port to override.",
            file=sys.stderr,
        )

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server (default: auto-discover, fallback: {DEFAULT_IDA_RPC})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port, request_handler=ProxyHttpRequestHandler)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()

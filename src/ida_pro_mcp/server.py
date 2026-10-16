"""Legacy GUI command compatibility with request-specific FastMCP routing."""

import argparse
from urllib.parse import parse_qs, urlparse

if __package__ in (None, ""):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    # Executing this file directly otherwise makes its sibling ida_mcp package
    # shadow the separate official distribution used by diagnostic helpers.
    script_dir = str(Path(__file__).resolve().parent)
    sys.path[:] = [entry for entry in sys.path if entry != script_dir]

from ida_pro_mcp.installer import (
    list_available_clients,
    print_mcp_config,
    run_install_command,
    set_ida_rpc,
)
from ida_pro_mcp.instance_router import InstanceRouter
from ida_pro_mcp.proxy_backend import ProxyProvider
from ida_pro_mcp.fastmcp_frontend import create_server

DEFAULT_IDA_RPC = "http://127.0.0.1:13337"


def create_proxy_server(*, endpoint=None, extensions=None, profile=None):
    provider = ProxyProvider(endpoint=endpoint, extensions=extensions)
    return create_server(
        InstanceRouter(provider), extensions=extensions, profile=profile
    )


def main():

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

    endpoint = None
    extensions = set()
    if args.ida_rpc:
        target = urlparse(args.ida_rpc)
        if target.hostname is None or target.port is None:
            parser.error("--ida-rpc requires a host and port")
        endpoint = (target.hostname, target.port)
        extensions = set(
            filter(None, parse_qs(target.query).get("ext", [""])[0].split(","))
        )
        set_ida_rpc(*endpoint)

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

    server = create_proxy_server(endpoint=endpoint, extensions=extensions)
    from ida_pro_mcp.diagnostics import TraceWriter, RoutingTraceMiddleware

    server.add_middleware(RoutingTraceMiddleware(TraceWriter()))
    transport = args.transport or "stdio"
    if transport == "stdio":
        server.run(transport="stdio", show_banner=False)
    else:
        url = urlparse(transport)
        if url.hostname is None or url.port is None:
            parser.error("Invalid transport URL")
        server.run(
            transport="http",
            host=url.hostname,
            port=url.port,
            path="/mcp",
            json_response=False,
            stateless_http=False,
            host_origin_protection=True,
            allowed_hosts=[url.hostname, "localhost", "127.0.0.1", "::1"],
            show_banner=False,
        )


if __name__ == "__main__":
    main()

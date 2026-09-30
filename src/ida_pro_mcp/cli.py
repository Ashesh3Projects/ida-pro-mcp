"""Single-package entry point for unified and legacy IDA workflows.

Imports stay lazy so help, diagnostics and configuration work without IDA.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence
from pathlib import Path


def _python_executable() -> str:
    return sys.executable


def unified_config(agent: str | None = None) -> dict:
    arguments = ["-m", "ida_pro_mcp", "stdio"]
    if agent:
        arguments.extend(["--agent", agent])
    return {"command": _python_executable(), "args": arguments}


def _legacy(arguments: list[str]) -> int:
    from ida_pro_mcp.server import main as legacy_main

    previous = sys.argv
    try:
        sys.argv = ["ida-pro-mcp legacy", *arguments]
        return legacy_main() or 0
    finally:
        sys.argv = previous


def _diagnostic(command: str, arguments: list[str]) -> int:
    from ida_mcp.cli import main as official_main

    return official_main([command, *arguments]) or 0


def _configure_unified(*, extensions: set[str], profile: str | None):
    from ida_pro_mcp.unified_server import configure_server, manager_options

    adapter = configure_server(extensions=extensions, profile=profile)
    return adapter, manager_options(adapter)


def _idle_timeout(value: str) -> float | None:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("idle timeout must be a number") from error
    if not math.isfinite(timeout) or timeout < 0:
        raise argparse.ArgumentTypeError("idle timeout must be finite and nonnegative")
    return timeout or None


def _server_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"ida-pro-mcp {command}")
    parser.add_argument("--database", help="Executable or IDB to open on startup")
    parser.add_argument("--agent", help="Agent label in session diagnostics")
    parser.add_argument(
        "--ext",
        action="append",
        choices=["dbg"],
        default=[],
        help="Enable optional tools (dbg enables debugger tools)",
    )
    parser.add_argument("--profile", help="Allowlist of typed tool names, one per line")
    parser.add_argument(
        "--idle-timeout",
        type=_idle_timeout,
        default=None,
        help="Only zero is supported; close_database or client exit releases leases",
    )
    if command == "http":
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8737)
        parser.add_argument("--path-prefix", default="")
    return parser


def _help() -> None:
    parser = argparse.ArgumentParser(
        prog="ida-pro-mcp",
        description="Typed IDA tools with Hex-Rays database coordination and diagnostics.",
        epilog="Existing --install/--uninstall/--ida-rpc flags remain available through legacy.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "stdio",
            "http",
            "dashboard",
            "logs",
            "hook",
            "config",
            "install",
            "legacy",
        ],
        help="Default: stdio. Unified execution requires IDA 9.4+.",
    )
    parser.print_help()


def _install(arguments: list[str]) -> int:
    from ida_pro_mcp import installer

    parser = argparse.ArgumentParser(prog="ida-pro-mcp install")
    parser.add_argument(
        "clients", nargs="?", default="", help="Comma-separated client names"
    )
    parser.add_argument("--scope", choices=["global", "project"], default="global")
    parser.add_argument("--allow-ida-free", action="store_true")
    args = parser.parse_args(arguments)
    installer.install_ida_plugin(allow_ida_free=args.allow_ida_free)
    if not args.clients:
        print("GUI plugin installed. Configure your client with:")
        print(json.dumps({"mcpServers": {"ida-pro-mcp": unified_config()}}, indent=2))
        return 0

    # Reuse the supported-client config writer while selecting this CLI's
    # unified stdio command. No existing legacy config generation is changed.
    previous = installer.generate_mcp_config

    def config_for_client(*, client_name: str, transport: str = "stdio"):
        config = unified_config(client_name.lower().replace(" ", "-"))
        if client_name == "Opencode":
            return {"type": "local", "command": [config["command"], *config["args"]]}
        return config

    try:
        installer.generate_mcp_config = config_for_client
        installer.install_mcp_servers(
            transport="stdio",
            only=args.clients.split(","),
            project=args.scope == "project",
        )
    finally:
        installer.generate_mcp_config = previous
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"-h", "--help"}:
        _help()
        return 0
    if arguments and arguments[0] == "--version":
        from importlib.metadata import version

        print(version("ida-pro-mcp"))
        return 0
    if arguments and arguments[0].startswith("-"):
        return _legacy(arguments)
    command = arguments.pop(0) if arguments else "stdio"
    if command == "legacy":
        return _legacy(arguments)
    if command in {"dashboard", "logs", "hook"}:
        return _diagnostic(command, arguments)
    if command == "install":
        return _install(arguments)
    if command == "config":
        parser = argparse.ArgumentParser(prog="ida-pro-mcp config")
        parser.add_argument("--agent")
        parsed = parser.parse_args(arguments)
        print(
            json.dumps(
                {"mcpServers": {"ida-pro-mcp": unified_config(parsed.agent)}}, indent=2
            )
        )
        return 0
    if command not in {"stdio", "http"}:
        raise SystemExit(f"Unknown command: {command}. Run ida-pro-mcp --help.")
    parser = _server_parser(command)
    args = parser.parse_args(arguments)
    if args.idle_timeout is not None:
        parser.error(
            "unified mode keeps leases until close_database or client exit; use --idle-timeout 0"
        )
    if args.profile and not Path(args.profile).is_file():
        parser.error(f"profile does not exist: {args.profile}")
    adapter, options = _configure_unified(
        extensions=set(args.ext), profile=args.profile
    )
    server_options = {
        "database": args.database,
        "agent": args.agent,
        "idle_timeout": args.idle_timeout,
        **options,
    }
    if command == "stdio":
        adapter.serve_stdio(**server_options)
    else:
        adapter.serve_http(
            args.host,
            args.port,
            path_prefix=args.path_prefix,
            background=False,
            **server_options,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

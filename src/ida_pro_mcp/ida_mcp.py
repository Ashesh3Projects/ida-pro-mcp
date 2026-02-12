"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Supports:
- Dynamic port allocation to avoid conflicts between multiple IDA instances
- Instance registration for multi-instance discovery and routing
- Start/Stop/Status server control via plugin hotkey (toggle)
"""

import os
import sys
import uuid
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp
    from .instance_registry import HeartbeatThread, InstanceInfo


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def _get_binary_name() -> str:
    """Get the name of the binary being analyzed in IDA."""
    try:
        import ida_nalt
        return ida_nalt.get_root_filename() or "unknown"
    except Exception:
        return "unknown"


def _get_binary_path() -> str:
    """Get the full path of the binary being analyzed in IDA."""
    try:
        import ida_nalt
        return ida_nalt.get_input_file_path() or ""
    except Exception:
        return ""


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    HOST = "127.0.0.1"

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start/stop the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.port: int = 0
        self.instance_id: str = uuid.uuid4().hex[:8]
        self.heartbeat: "HeartbeatThread | None" = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Toggle: if running, stop; if stopped, start
        if self.mcp:
            self._stop_server()
            print("[MCP] Server stopped")
            return

        self._start_server()

    def _start_server(self):
        """Start the MCP server with dynamic port allocation and instance registration."""
        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Determine port: use IDA_MCP_PORT env var, or find an available port
        env_port = os.environ.get("IDA_MCP_PORT")
        if env_port:
            self.port = int(env_port)
        else:
            try:
                from ida_pro_mcp.instance_registry import find_available_port
                self.port = find_available_port(self.HOST)
            except Exception:
                # Fallback: try importing from relative path for plugin context
                try:
                    script_dir = os.path.dirname(os.path.realpath(__file__))
                    parent_dir = os.path.dirname(script_dir) if os.path.basename(script_dir) == "ida_mcp" else script_dir
                    if parent_dir not in sys.path:
                        sys.path.insert(0, parent_dir)
                    from instance_registry import find_available_port
                    self.port = find_available_port(self.HOST)
                except Exception:
                    self.port = 13337  # Fallback to default

        try:
            MCP_SERVER.serve(
                self.HOST, self.port, request_handler=IdaMcpHttpRequestHandler
            )
            print(f"  Config: http://{self.HOST}:{self.port}/config.html")
            self.mcp = MCP_SERVER

            # Register instance for multi-instance discovery
            self._register_instance()

        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: Port {self.port} is already in use")
                # Try next available port
                if not env_port:
                    self.port += 1
                    try:
                        MCP_SERVER.serve(
                            self.HOST, self.port, request_handler=IdaMcpHttpRequestHandler
                        )
                        print(f"  Config: http://{self.HOST}:{self.port}/config.html")
                        self.mcp = MCP_SERVER
                        self._register_instance()
                    except OSError:
                        print(f"[MCP] Error: Could not find available port")
            else:
                raise

    def _register_instance(self):
        """Register this instance in the multi-instance registry."""
        try:
            from ida_pro_mcp.instance_registry import register_instance, HeartbeatThread
        except ImportError:
            try:
                script_dir = os.path.dirname(os.path.realpath(__file__))
                parent_dir = os.path.dirname(script_dir) if os.path.basename(script_dir) == "ida_mcp" else script_dir
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                from instance_registry import register_instance, HeartbeatThread
            except ImportError:
                print("[MCP] Warning: Instance registry not available, multi-instance features disabled")
                return

        binary_name = _get_binary_name()
        binary_path = _get_binary_path()

        register_instance(
            instance_id=self.instance_id,
            host=self.HOST,
            port=self.port,
            binary_name=binary_name,
            binary_path=binary_path,
        )

        # Start heartbeat to keep registration alive
        self.heartbeat = HeartbeatThread(self.instance_id)
        self.heartbeat.start()

        print(f"  Instance: {self.instance_id} ({binary_name})")
        print(f"  Port: {self.port}")

    def _unregister_instance(self):
        """Unregister this instance from the multi-instance registry."""
        # Stop heartbeat
        if self.heartbeat:
            self.heartbeat.stop()
            self.heartbeat = None

        try:
            from ida_pro_mcp.instance_registry import unregister_instance
        except ImportError:
            try:
                from instance_registry import unregister_instance
            except ImportError:
                return

        unregister_instance(self.instance_id)

    def _stop_server(self):
        """Stop the MCP server and unregister the instance."""
        self._unregister_instance()

        if self.mcp:
            self.mcp.stop()
            self.mcp = None

    def term(self):
        self._stop_server()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX

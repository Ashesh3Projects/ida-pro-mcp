"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import json
import sys
import uuid
from importlib.metadata import distribution
from pathlib import Path
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


NETNODE_AUTOSTART = "$ ida_mcp.autostart"
NETNODE_CONFIG = "$ ida_mcp.config"
_ALT_PORT = 0  # altval index for the persisted port (0 = not set)
_ALT_PERSIST = 1  # altval index for the "save host/port" preference
_SUP_HOST = 0  # supval index for the persisted host


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_autostart(enabled: bool):
    """Persist the autostart preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def _get_port(default: int) -> int:
    """Read the persisted server port from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PORT)  # 0 = not set
    return val if val != 0 else default


def _set_port(port: int):
    """Persist the server port into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PORT, port)


def _get_host(default: str) -> str:
    """Read the persisted server host from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.supstr(_SUP_HOST)
    return val if val else default


def _set_host(host: str):
    """Persist the server host into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.supset(_SUP_HOST, host)


def _get_persist() -> bool:
    """Read the 'save host/port' preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PERSIST)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_persist(enabled: bool):
    """Persist the 'save host/port' preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PERSIST, 2 if enabled else 1)


def _clear_endpoint():
    """Forget any persisted host/port so the next load uses the defaults."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altdel(_ALT_PORT)
    node.supdel(_SUP_HOST)


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


def _configure_runtime_paths() -> None:
    """Find the canonical fork and optional Nexus runtime from its installer."""
    plugin_dir = Path(__file__).absolute().parent
    manifest_path = plugin_dir / "ida-pro-mcp-runtime.json"
    candidates = [plugin_dir, Path(__file__).resolve().parent.parent]
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("runtime manifest must be a JSON object")
            package_root = manifest.get("package_root")
            if isinstance(package_root, str):
                candidates.append(Path(package_root))
            # Do not mix binary modules built for another embedded Python ABI.
            if manifest.get("python_version") == list(sys.version_info[:2]):
                candidates.extend(Path(p) for p in manifest.get("site_packages", [])
                                  if isinstance(p, str))
        except (OSError, ValueError, TypeError) as error:
            print(f"[MCP] Runtime manifest could not be read: {error}")
    for candidate in reversed(candidates):
        path = str(candidate)
        if candidate.is_dir():
            if path in sys.path:
                sys.path.remove(path)
            sys.path.insert(0, path)


def _start_nexus():
    """Share this GUI's database through the official Nexus runtime when available."""
    _configure_runtime_paths()
    try:
        from ida_nexus import plugin
    except ImportError:
        return None
    try:
        package = distribution("ida-nexus")
        expected_plugin = Path(package.locate_file("ida_nexus/plugin.py")).resolve()
        if package.version != "0.13.0" or Path(plugin.__file__).resolve() != expected_plugin:
            raise RuntimeError("IDA Nexus 0.13.0 from this installation is required; restart IDA after updating")
        return plugin if plugin.init(owner="ida-pro-mcp") else None
    except Exception as error:
        print(f"[MCP] Nexus startup failed; legacy server remains available: {error}")
        return None


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int, autostart: bool, persist: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
<Autostart server when IDA opens:{autostart}>
<Save host and port to this database:{save_endpoint}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "checks": idaapi.Form.ChkGroupControl(
                    ("autostart", "save_endpoint"),
                    value=(1 if autostart else 0) | (2 if persist else 0),
                ),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port
        old_autostart = self.plugin.autostart
        old_persist = self.plugin.persist_endpoint

        form = MCPConfigForm(
            self.plugin.host,
            self.plugin.port,
            self.plugin.autostart,
            self.plugin.persist_endpoint,
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        autostart = bool(form.checks.value & 1)
        persist = bool(form.checks.value & 2)
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if persist != old_persist:
            self.plugin.persist_endpoint = persist
            _set_persist(persist)
            print(f"[MCP] Save host/port {'enabled' if persist else 'disabled'}")

        endpoint_changed = host != old_host or port != old_port
        self.plugin.host = host
        self.plugin.port = port

        # Save or forget the endpoint based on the preference.
        if persist:
            _set_host(host)
            _set_port(port)
            if endpoint_changed or persist != old_persist:
                print(f"[MCP] Configuration updated: {host}:{port} (saved to IDB)")
        else:
            if persist != old_persist:
                _clear_endpoint()  # next load falls back to defaults
            if endpoint_changed:
                print(f"[MCP] Configuration updated: {host}:{port} (not saved)")

        if not endpoint_changed and autostart == old_autostart and persist == old_persist:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        # Apply new endpoint immediately if the server is running.
        if endpoint_changed and self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin._restart_server()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment and autostart until the UI is fully ready."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        # Skip autostart when running under idalib – the idalib_server manages
        # the MCP server lifecycle itself and would otherwise hit a port conflict
        # because unload_package creates a separate MCP_SERVER instance.
        if self.plugin.autostart and ida_kernwin.is_idaq():
            print("[MCP] Autostarting server...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        self._nexus_plugin = _start_nexus()
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.instance_id = uuid.uuid4().hex[:8]
        self.autostart = _get_autostart()
        self.persist_endpoint = _get_persist()
        if self.persist_endpoint:
            self.host = _get_host(self.DEFAULT_HOST)
            self.port = _get_port(self.DEFAULT_PORT)
        else:
            self.host = self.DEFAULT_HOST
            self.port = self.DEFAULT_PORT

        if self.autostart and ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded, server will start automatically")
        elif not ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded (idalib mode, server managed externally)")
        else:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start/stop the server"
            )

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment and autostart until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                from ida_pro_mcp.ida_mcp.discovery import unregister_instance
                unregister_instance(port, getattr(self, "_registered_generation", ""))
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    def run(self, arg):
        if self.mcp:
            self._stop_server()
            print("[MCP] Server stopped")
            return

        self._start_server()

    def _start_server(self):
        """Start the server and register this IDA instance."""

        _configure_runtime_paths()
        # Keep module identity stable while a Nexus bridge owns its registries.
        # The official distribution also uses the top-level name ida_mcp.
        from ida_pro_mcp.ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
        from ida_pro_mcp.ida_mcp.instance_hooks import install_instance_hooks, activate_database
        from ida_pro_mcp.ida_mcp.instance_dispatch import install_instance_dispatch
        install_instance_hooks(self._database_identity_changed)
        activate_database()
        install_instance_dispatch(MCP_SERVER)

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                self._register_instance(port)
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def _register_instance(self, port: int):
        try:
            from ida_pro_mcp.ida_mcp.discovery import register_instance
            import os
            import idc
            import ida_nalt
            from ida_pro_mcp.instance_runtime import runtime_identity
            identity = runtime_identity().snapshot()
            if not identity:
                return
            binary = ida_nalt.get_root_filename() or ""
            binary_path = ida_nalt.get_input_file_path() or ""
            idb_path = idc.get_idb_path() or ""
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                binary_path=binary_path,
                idb_path=idb_path,
                instance_id=identity["instance_id"],
                generation=identity["generation"],
            )
            self._registered_port = port
            self._registered_generation = identity["generation"]
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance registration failed: {e}")
            traceback.print_exc()

    def _database_identity_changed(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            self._unregister_instance()
            self._register_instance(port)

    def _stop_server(self):
        """Stop the server and remove its discovery registration."""
        self._unregister_instance()
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

    def _restart_server(self):
        """Apply configuration changes without changing toggle semantics."""
        self._stop_server()
        self._start_server()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._stop_server()
        nexus = getattr(self, "_nexus_plugin", None)
        if nexus is not None:
            nexus.term()


def PLUGIN_ENTRY():
    return MCP()

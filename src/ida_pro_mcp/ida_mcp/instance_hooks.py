"""Persistent database-lifetime hooks; separate from GUI autostart hooks."""

import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt

from ida_pro_mcp.instance_runtime import runtime_identity
from ida_pro_mcp.nexus_gui_lifecycle import refresh_gui_service

_hooks = None
_on_change = None


def activate_database():
    path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    binary = ida_nalt.get_input_file_path() or ""
    if path or binary:
        runtime_identity().activate(binary, path)
    if _on_change is not None:
        _on_change()
    refresh_gui_service()


def invalidate_database():
    runtime_identity().invalidate()
    if _on_change is not None:
        _on_change()
    refresh_gui_service()


def install_instance_hooks(on_change=None):
    global _hooks, _on_change
    if on_change is not None:
        _on_change = on_change
    if _hooks is not None:
        return

    class UI(ida_kernwin.UI_Hooks):
        def ready_to_run(self):
            refresh_gui_service()

        def initing_database(self):
            invalidate_database()

        def database_inited(self, is_new_database, idc_script):
            activate_database()

    class IDB(ida_idp.IDB_Hooks):
        def closebase(self):
            invalidate_database()

    _hooks = (UI(), IDB())
    for hook in _hooks:
        hook.hook()
    if not runtime_identity().snapshot():
        activate_database()
    refresh_gui_service()

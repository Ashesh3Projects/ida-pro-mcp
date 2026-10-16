"""Generation guard inside the pinned Nexus main-thread execution unit."""

import inspect
from importlib.metadata import version
import os

from .instance_contract import RoutingError
from .instance_runtime import runtime_identity


def _idb_path():
    import ida_loader
    return ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""


def _check(generation, idb_path):
    runtime_identity().check(generation)
    if os.path.normcase(os.path.abspath(_idb_path())) != os.path.normcase(os.path.abspath(idb_path)):
        raise RoutingError("INSTANCE_CHANGED", "IDA now has a different database path.")


def _load_evaluator():
    if version("ida-nexus") != "0.13.0":
        raise RuntimeError("Generation-safe Python requires the pinned Nexus 0.13.0 runtime.")
    from ida_nexus._runtime import _execute_user_code
    if list(inspect.signature(_execute_user_code).parameters) != ["code", "namespace", "runtime", "filename"]:
        raise RuntimeError("Unsupported Nexus Python evaluator signature")
    return _execute_user_code


def execute(code: str, expected_generation: str, expected_idb_path: str,
            namespace: dict, filename: str = "<ida-mcp>"):
    _check(expected_generation, expected_idb_path)
    return _load_evaluator()(code, namespace, {"db": namespace.get("db"), "ida_domain": namespace.get("ida_domain")}, filename)


def save(expected_generation: str, expected_idb_path: str, backend: str) -> dict:
    _check(expected_generation, expected_idb_path)
    import ida_loader
    import ida_kernwin
    path = _idb_path()
    if backend == "gui":
        if ida_loader.is_database_flag(ida_loader.DBFL_TEMP):
            raise RuntimeError("Use Save As in IDA before saving this temporary database remotely.")
        saved = ida_kernwin.process_ui_action("SaveBase")
    else:
        saved = ida_loader.save_database(path, 0)
    if not saved:
        raise RuntimeError("IDA failed to save the database")
    return {"path": os.path.abspath(path)}


def analyze(expected_generation: str, expected_idb_path: str) -> bool:
    _check(expected_generation, expected_idb_path)
    import ida_auto
    return bool(ida_auto.auto_wait())

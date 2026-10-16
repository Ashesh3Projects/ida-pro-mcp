import builtins
import sys
from types import SimpleNamespace

import pytest

from ida_pro_mcp import nexus_guard
from ida_pro_mcp.instance_runtime import RuntimeIdentity
from ida_pro_mcp.instance_contract import RoutingError


@pytest.fixture
def namespace(monkeypatch):
    state = RuntimeIdentity()
    generation = state.activate("a.exe", "a.i64")
    monkeypatch.setattr(nexus_guard, "runtime_identity", lambda: state)
    monkeypatch.setattr(nexus_guard, "_idb_path", lambda: "a.i64")
    values = {"__builtins__": builtins.__dict__, "db": SimpleNamespace(value=42), "ida_domain": object()}
    return state, generation, values


def test_replacement_is_rejected_before_user_mutation(namespace):
    state, old, values = namespace
    state.invalidate()
    state.activate("a.exe", "a.i64")
    with pytest.raises(RoutingError) as error:
        nexus_guard.execute("changed=True", old, "a.i64", values)
    assert error.value.code == "INSTANCE_CHANGED"
    assert "changed" not in values


def test_preserves_globals_callbacks_and_entrypoint_semantics(namespace):
    _, generation, values = namespace
    assert nexus_guard.execute("value=1\ndef callback(): return value\ncallback()", generation, "a.i64", values) == 1
    assert nexus_guard.execute("value=2\ncallback()", generation, "a.i64", values) == 2
    for name in ("run", "execute", "main"):
        assert nexus_guard.execute(f"def {name}(db): return db.value", generation, "a.i64", values) == 42
    assert nexus_guard.execute("globals=1\n__import__=2\n3", generation, "a.i64", values) == 3


def test_future_imports_and_source_line_numbers_survive(namespace):
    _, generation, values = namespace
    code = '"module docstring"\nfrom __future__ import annotations\nanswer: Missing = 42\nanswer'
    assert nexus_guard.execute(code, generation, "a.i64", values) == 42
    with pytest.raises(SyntaxError) as error:
        nexus_guard.execute("x=1\ny=2\nif", generation, "a.i64", values)
    assert error.value.lineno == 3


def test_interrupt_cannot_be_swallowed_by_user_except(namespace):
    from ida_nexus._runtime import _OperationInterrupt
    _, generation, values = namespace
    values["interrupt"] = _OperationInterrupt
    with pytest.raises(_OperationInterrupt):
        nexus_guard.execute("try:\n raise interrupt()\nexcept BaseException:\n pass", generation, "a.i64", values)


def test_wrong_idb_path_rejected_with_same_generation(namespace, monkeypatch):
    _, generation, values = namespace
    monkeypatch.setattr(nexus_guard, "_idb_path", lambda: "b.i64")
    with pytest.raises(RoutingError):
        nexus_guard.execute("changed=True", generation, "a.i64", values)
    assert "changed" not in values

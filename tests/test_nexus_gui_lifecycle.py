from types import SimpleNamespace

import pytest

from ida_pro_mcp.instance_runtime import RuntimeIdentity
from ida_pro_mcp.instance_contract import RoutingError
from ida_pro_mcp import nexus_gui_lifecycle


def test_nexus_unit_is_guarded_after_dispatch_before_execution(monkeypatch):
    state = RuntimeIdentity()
    generation = state.activate("a.exe", "a.i64")
    monkeypatch.setattr(nexus_gui_lifecycle, "runtime_identity", lambda: state)
    callbacks = []
    runtime = SimpleNamespace(_run_sync=lambda fn, **kwargs: callbacks.append(fn))
    nexus_gui_lifecycle.guard_runtime(runtime, generation)
    mutations = []
    runtime._run_sync(lambda: mutations.append(True))
    state.invalidate()
    state.activate("a.exe", "a.i64")
    with pytest.raises(RoutingError):
        callbacks[0]()
    assert mutations == []


def test_runtime_guard_cannot_rebind_existing_service(monkeypatch):
    state = RuntimeIdentity()
    old = state.activate("a.exe", "a.i64")
    monkeypatch.setattr(nexus_gui_lifecycle, "runtime_identity", lambda: state)
    runtime = SimpleNamespace(_run_sync=lambda fn, **kw: fn())
    nexus_gui_lifecycle.guard_runtime(runtime, old)
    new = state.activate("a.exe", "a.i64")
    nexus_gui_lifecycle.guard_runtime(runtime, new)
    with pytest.raises(RoutingError):
        runtime._run_sync(lambda: "must not execute")

from contextvars import copy_context

import pytest

from ida_pro_mcp.instance_contract import RoutingError
from ida_pro_mcp import instance_runtime
from ida_pro_mcp.instance_runtime import (
    RuntimeIdentity,
    generation_context,
    check_request_generation,
)


def test_same_path_reopen_rejects_queued_generation(monkeypatch):
    state = RuntimeIdentity()
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    old = state.activate("a.exe", "a.i64")
    with generation_context(old):
        queued = copy_context()
    state.invalidate()
    new = state.activate("a.exe", "a.i64")
    assert new != old
    with pytest.raises(RoutingError) as error:
        queued.run(check_request_generation)
    assert error.value.code == "INSTANCE_CHANGED"
    check_request_generation()  # Local SDK callers have no remote identity.


def test_closed_runtime_rejects_old_generation():
    state = RuntimeIdentity()
    old = state.activate("a.exe", "a.i64")
    state.invalidate()
    with pytest.raises(RoutingError) as error:
        state.check(old)
    assert error.value.code == "INSTANCE_CLOSED"


def test_runtime_snapshot_has_no_selected_state():
    state = RuntimeIdentity()
    generation = state.activate("a.exe", "a.i64")
    result = state.snapshot()
    assert result["instance_id"] == generation
    assert result["generation"] == generation
    assert result["idb_path"] == "a.i64"
    assert result["identity_version"] == 1
    assert "current" not in result


def test_nested_request_context_is_restored(monkeypatch):
    state = RuntimeIdentity()
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    live = state.activate("a.exe", "a.i64")
    with generation_context(live):
        with generation_context("0" * 16):
            with pytest.raises(RoutingError):
                check_request_generation()
        check_request_generation()

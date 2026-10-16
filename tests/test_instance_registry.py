"""Public IDs must never become aliases for another database incarnation."""

from dataclasses import replace
import re
from concurrent.futures import ThreadPoolExecutor

import pytest

from ida_pro_mcp.instance_contract import BackendIdentity, RoutingError, require_instance_id
from ida_pro_mcp.instance_registry import InstanceRegistry


def identity(key="runtime-a", **changes):
    return BackendIdentity(
        provider="fake", key=key, backend="gui", binary_name="sample.exe",
        binary_path="/samples/sample.exe", idb_path="/samples/sample.i64",
        pid=42, started_at="2026-10-16T00:00:00Z", **changes,
    )


@pytest.mark.parametrize("value", ["", " ", True, 1, [], {}, "123", "A" * 16, " a" * 8])
def test_invalid_ids_are_not_coerced(value):
    with pytest.raises(RoutingError) as error:
        require_instance_id(value)
    assert error.value.code == "INVALID_INSTANCE_ID"


def test_missing_id_is_required_even_with_one_instance():
    registry = InstanceRegistry()
    registry.publish(identity())
    with pytest.raises(RoutingError) as error:
        registry.resolve(None)
    assert error.value.code == "INSTANCE_ID_REQUIRED"


def test_public_id_is_random_and_registry_owned():
    first, second = InstanceRegistry(), InstanceRegistry()
    a, b = first.publish(identity()), second.publish(identity())
    assert re.fullmatch("[0-9a-f]{16}", a.instance_id)
    assert a.instance_id != b.instance_id
    assert first.resolve(a.instance_id) is a
    with pytest.raises(RoutingError) as error:
        second.resolve(a.instance_id)
    assert error.value.code == "INSTANCE_NOT_FOUND"


def test_retired_id_cannot_be_rebound():
    generated = iter(["a" * 16, "a" * 16, "b" * 16])
    registry = InstanceRegistry(id_factory=lambda: next(generated))
    first = registry.publish(identity())
    registry.retire(first)
    second = registry.publish(identity("runtime-b"))
    assert second.instance_id == "b" * 16
    with pytest.raises(RoutingError) as error:
        registry.resolve(first.instance_id)
    assert error.value.code == "INSTANCE_CLOSED"


def test_rediscovery_reuses_live_binding_but_not_closed_binding():
    registry = InstanceRegistry()
    record = identity()
    first = registry.publish(record)
    assert registry.publish(replace(record, binary_path="/alias/sample.exe")) is first
    registry.retire(first)
    reopened = registry.publish(record)
    assert reopened.instance_id != first.instance_id


def test_same_filename_and_endpoint_metadata_do_not_merge_incarnations():
    registry = InstanceRegistry()
    first = registry.publish(identity("generation-a"))
    second = registry.publish(identity("generation-b"))
    assert first.instance_id != second.instance_id


def test_failed_close_cannot_be_bypassed_by_discovery():
    registry = InstanceRegistry()
    record = identity()
    binding = registry.publish(record)
    registry.set_state(binding, "closing")
    assert registry.publish(record) is binding
    with pytest.raises(RoutingError) as error:
        registry.resolve(binding.instance_id)
    assert error.value.code == "INSTANCE_CLOSED"
    assert registry.resolve(binding.instance_id, allow_closing=True) is binding


def test_unavailable_binding_does_not_revive():
    registry = InstanceRegistry()
    first = registry.publish(identity())
    registry.retire(first, state="unavailable")
    assert registry.publish(identity()).instance_id != first.instance_id
    with pytest.raises(RoutingError) as error:
        registry.resolve(first.instance_id)
    assert error.value.code == "INSTANCE_UNAVAILABLE"


def test_incompatible_registration_never_acquires_usable_id():
    registry = InstanceRegistry()
    with pytest.raises(RoutingError) as error:
        registry.publish(identity(compatible=False))
    assert error.value.code == "INSTANCE_INCOMPATIBLE"
    assert registry.bindings() == []


def test_parallel_discovery_publishes_one_binding():
    registry = InstanceRegistry()
    with ThreadPoolExecutor(max_workers=8) as pool:
        bindings = list(pool.map(lambda _: registry.publish(identity()), range(64)))
    assert len({binding.instance_id for binding in bindings}) == 1


def test_status_exposes_metadata_without_selection_or_internal_key():
    registry = InstanceRegistry()
    binding = registry.publish(identity("private-record"))
    result = registry.describe(binding)
    assert result["instance_id"] == binding.instance_id
    assert result["binary_name"] == "sample.exe"
    assert result["status"] == "available"
    assert not {"key", "selected", "current", "active", "token"} & result.keys()


def test_foreign_binding_cannot_mutate_registry_state():
    a, b = InstanceRegistry(), InstanceRegistry()
    foreign = b.publish(identity())
    with pytest.raises(RoutingError):
        a.set_state(foreign, "ready")

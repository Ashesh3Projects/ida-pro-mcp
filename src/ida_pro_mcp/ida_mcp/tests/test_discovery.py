"""Tests for the instance discovery module (discovery.py).

Exercises registration/unregistration round-trips, the multi-stage staleness
pipeline in discover_instances, and sort-order guarantees that server.py
relies on for auto-selection.
"""

import contextlib
import json
import os
import tempfile

from ..framework import test
from .. import discovery


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _tmp_instances_dir():
    """Redirect every discovery registry to one temp directory."""
    with tempfile.TemporaryDirectory() as tmp:
        original_current = discovery.get_instances_dir
        original_legacy = discovery.get_legacy_instances_dir
        discovery.get_instances_dir = lambda: tmp
        discovery.get_legacy_instances_dir = lambda: tmp
        try:
            yield tmp
        finally:
            discovery.get_instances_dir = original_current
            discovery.get_legacy_instances_dir = original_legacy


@contextlib.contextmanager
def _patched_instances_dir(path):
    """Redirect every discovery registry to an arbitrary path."""
    original_current = discovery.get_instances_dir
    original_legacy = discovery.get_legacy_instances_dir
    discovery.get_instances_dir = lambda: path
    discovery.get_legacy_instances_dir = lambda: path
    try:
        yield
    finally:
        discovery.get_instances_dir = original_current
        discovery.get_legacy_instances_dir = original_legacy


# ---------------------------------------------------------------------------
# Registration / unregistration round-trips
# ---------------------------------------------------------------------------


@test()
def test_register_unregister_roundtrip():
    """register_instance creates a file that unregister_instance removes."""
    with _tmp_instances_dir():
        path = discovery.register_instance("127.0.0.1", 55000, os.getpid(), "test.exe", "/tmp/test.idb")
        assert os.path.isfile(path)
        assert discovery.unregister_instance(55000) is True
        assert not os.path.isfile(path)


@test()
def test_register_persists_instance_id_and_binary_path():
    """Discovery metadata includes the fork-compatible identity and input path."""
    with _tmp_instances_dir() as tmp:
        discovery.register_instance(
            "127.0.0.1",
            55001,
            os.getpid(),
            "test.exe",
            "/tmp/test.i64",
            instance_id="abc12345",
            binary_path="/tmp/test.exe",
        )
        with open(os.path.join(tmp, "instance_55001.json"), encoding="utf-8") as f:
            data = json.load(f)
        assert data["instance_id"] == "abc12345"
        assert data["binary_path"] == "/tmp/test.exe"


@test()
def test_unregister_nonexistent_returns_false():
    """unregister_instance returns False when no registration exists."""
    with _tmp_instances_dir():
        assert discovery.unregister_instance(99999) is False


@test()
def test_register_overwrites_existing():
    """Re-registering the same port atomically replaces the previous entry."""
    with _tmp_instances_dir() as tmp:
        discovery.register_instance("127.0.0.1", 55005, os.getpid(), "first.bin", "first.idb")
        discovery.register_instance("127.0.0.1", 55005, os.getpid(), "second.bin", "second.idb")
        with open(os.path.join(tmp, "instance_55005.json"), "r") as f:
            data = json.load(f)
        assert data["binary"] == "second.bin"


# ---------------------------------------------------------------------------
# PID liveness
# ---------------------------------------------------------------------------


@test()
def test_is_pid_alive_current_process():
    """is_pid_alive returns True for the current (known-alive) process."""
    assert discovery.is_pid_alive(os.getpid()) is True


@test()
def test_is_pid_alive_bogus_pid():
    """is_pid_alive returns False for a PID that cannot exist."""
    assert discovery.is_pid_alive(4_000_000) is False


# ---------------------------------------------------------------------------
# TCP probe
# ---------------------------------------------------------------------------


@test()
def test_probe_instance_unreachable():
    """probe_instance returns False for a port nothing listens on."""
    assert discovery.probe_instance("127.0.0.1", 1, timeout=0.5) is False


# ---------------------------------------------------------------------------
# discover_instances staleness pipeline
# ---------------------------------------------------------------------------


@test()
def test_discover_cleans_up_dead_pid():
    """discover_instances removes registrations whose PID is dead."""
    with _tmp_instances_dir() as tmp:
        discovery.register_instance("127.0.0.1", 55002, 4_000_000, "dead.bin", "dead.idb")
        assert discovery.discover_instances() == []
        assert not os.path.isfile(os.path.join(tmp, "instance_55002.json"))


@test()
def test_discover_cleans_up_corrupt_json():
    """discover_instances removes files with invalid JSON."""
    with _tmp_instances_dir() as tmp:
        corrupt_path = os.path.join(tmp, "instance_55003.json")
        with open(corrupt_path, "w") as f:
            f.write("not json{{{")
        assert discovery.discover_instances() == []
        assert not os.path.isfile(corrupt_path)


@test()
def test_discover_ignores_atomic_temp_files():
    """Discovery never consumes or deletes an in-progress registration write."""
    with _tmp_instances_dir() as tmp:
        temp_path = os.path.join(tmp, ".tmp_in_progress.json")
        with open(temp_path, "w") as f:
            f.write("{")
        assert discovery.discover_instances() == []
        assert os.path.isfile(temp_path)


@test()
def test_discover_cleans_up_missing_required_keys():
    """discover_instances removes registrations missing host/port/pid."""
    with _tmp_instances_dir() as tmp:
        path = os.path.join(tmp, "instance_55004.json")
        with open(path, "w") as f:
            json.dump({"host": "127.0.0.1"}, f)
        assert discovery.discover_instances() == []
        assert not os.path.isfile(path)


@test()
def test_discover_skips_alive_pid_unreachable_port():
    """discover_instances removes entries with alive PID but no listening server."""
    with _tmp_instances_dir():
        discovery.register_instance("127.0.0.1", 1, os.getpid(), "no_server.bin", "no.idb")
        assert discovery.discover_instances() == []


@test()
def test_discover_returns_empty_when_dir_missing():
    """discover_instances returns [] when the instances directory doesn't exist."""
    with _patched_instances_dir("/nonexistent/path/that/does/not/exist"):
        assert discovery.discover_instances() == []


# ---------------------------------------------------------------------------
# Sort order — server.py picks instances[0], so order matters
# ---------------------------------------------------------------------------


@test()
def test_discover_sorts_by_started_at():
    """discover_instances returns results sorted by started_at (oldest first).

    server.py auto-selects instances[0], so this order determines which
    instance gets auto-connected when multiple are running.
    """
    with _tmp_instances_dir() as tmp:
        for port, ts in [(55010, "2025-01-01T00:00:02+00:00"),
                         (55011, "2025-01-01T00:00:01+00:00")]:
            info = {
                "host": "127.0.0.1", "port": port,
                "pid": os.getpid(), "binary": f"bin_{port}",
                "idb_path": f"/tmp/{port}.idb", "started_at": ts,
            }
            path = os.path.join(tmp, f"instance_{port}.json")
            with open(path, "w") as f:
                json.dump(info, f)

        orig_pid = discovery.is_pid_alive
        orig_probe = discovery.probe_instance
        discovery.is_pid_alive = lambda pid: True
        discovery.probe_instance = lambda h, p, timeout=2.0: True
        try:
            results = discovery.discover_instances()
            assert len(results) == 2
            assert results[0]["port"] == 55011
            assert results[1]["port"] == 55010
        finally:
            discovery.is_pid_alive = orig_pid
            discovery.probe_instance = orig_probe


@test()
def test_discover_normalizes_and_deduplicates_legacy_entries():
    """Legacy fork registrations remain selectable during an in-place upgrade."""
    with tempfile.TemporaryDirectory() as current, tempfile.TemporaryDirectory() as legacy:
        current_info = {
            "instance_id": "current1",
            "host": "127.0.0.1",
            "port": 55020,
            "pid": os.getpid(),
            "binary": "current.dll",
            "binary_path": "/tmp/current.dll",
            "idb_path": "/tmp/current.i64",
            "started_at": "2026-01-01T00:00:00+00:00",
        }
        legacy_info = {
            "instance_id": "legacy1",
            "host": "127.0.0.1",
            "port": 55021,
            "pid": os.getpid(),
            "binary_name": "legacy.dll",
            "binary_path": "/tmp/legacy.dll",
            "timestamp": 1_767_225_600,
        }
        duplicate = {**legacy_info, "instance_id": "duplicate", "port": 55020}

        with open(os.path.join(current, "instance_55020.json"), "w") as f:
            json.dump(current_info, f)
        with open(os.path.join(legacy, "legacy1.json"), "w") as f:
            json.dump(legacy_info, f)
        with open(os.path.join(legacy, "duplicate.json"), "w") as f:
            json.dump(duplicate, f)

        original_dirs = discovery.get_instance_dirs
        original_pid = discovery.is_pid_alive
        original_probe = discovery.probe_instance
        discovery.get_instance_dirs = lambda: [current, legacy]
        discovery.is_pid_alive = lambda pid: True
        discovery.probe_instance = lambda host, port, timeout=2.0: True
        try:
            results = discovery.discover_instances()
        finally:
            discovery.get_instance_dirs = original_dirs
            discovery.is_pid_alive = original_pid
            discovery.probe_instance = original_probe

        assert len(results) == 2
        by_port = {item["port"]: item for item in results}
        assert by_port[55020]["instance_id"] == "current1"
        assert by_port[55021]["binary"] == "legacy.dll"
        assert by_port[55021]["idb_path"] == "/tmp/legacy.dll"
        assert results[0]["port"] == 55021

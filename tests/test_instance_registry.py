"""Tests for the instance registry module.

These tests validate the file-based instance registry used for
multi-instance MCP support. They run without IDA Pro.
"""

import json
import os
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_pro_mcp.instance_registry import (
    InstanceInfo,
    register_instance,
    unregister_instance,
    refresh_instance,
    list_instances,
    find_instance_by_binary,
    find_instance_by_id,
    cleanup_stale_instances,
    find_available_port,
    HeartbeatThread,
    REGISTRY_DIR,
    STALE_TIMEOUT,
)


class TestInstanceInfo(unittest.TestCase):
    """Tests for the InstanceInfo data class."""

    def test_to_dict(self):
        info = InstanceInfo(
            instance_id="test123",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="/path/to/test.exe",
            pid=12345,
            timestamp=1000.0,
        )
        d = info.to_dict()
        self.assertEqual(d["instance_id"], "test123")
        self.assertEqual(d["host"], "127.0.0.1")
        self.assertEqual(d["port"], 13337)
        self.assertEqual(d["binary_name"], "test.exe")
        self.assertEqual(d["binary_path"], "/path/to/test.exe")
        self.assertEqual(d["pid"], 12345)
        self.assertEqual(d["timestamp"], 1000.0)

    def test_from_dict(self):
        d = {
            "instance_id": "test123",
            "host": "127.0.0.1",
            "port": 13337,
            "binary_name": "test.exe",
            "binary_path": "/path/to/test.exe",
            "pid": 12345,
            "timestamp": 1000.0,
        }
        info = InstanceInfo.from_dict(d)
        self.assertEqual(info.instance_id, "test123")
        self.assertEqual(info.binary_name, "test.exe")

    def test_roundtrip(self):
        info = InstanceInfo(
            instance_id="abc",
            host="127.0.0.1",
            port=13338,
            binary_name="hello.elf",
            binary_path="/tmp/hello.elf",
            pid=999,
            timestamp=time.time(),
        )
        d = info.to_dict()
        info2 = InstanceInfo.from_dict(d)
        self.assertEqual(info.instance_id, info2.instance_id)
        self.assertEqual(info.port, info2.port)
        self.assertEqual(info.binary_name, info2.binary_name)

    def test_is_stale_fresh(self):
        info = InstanceInfo(
            instance_id="fresh",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="",
            pid=os.getpid(),
            timestamp=time.time(),
        )
        self.assertFalse(info.is_stale())

    def test_is_stale_old(self):
        info = InstanceInfo(
            instance_id="old",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="",
            pid=os.getpid(),
            timestamp=time.time() - STALE_TIMEOUT - 10,
        )
        self.assertTrue(info.is_stale())

    def test_is_alive_current_process(self):
        info = InstanceInfo(
            instance_id="alive",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="",
            pid=os.getpid(),
            timestamp=time.time(),
        )
        self.assertTrue(info.is_alive())

    def test_is_alive_dead_process(self):
        info = InstanceInfo(
            instance_id="dead",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="",
            pid=999999999,  # Very unlikely to be a real PID
            timestamp=time.time(),
        )
        self.assertFalse(info.is_alive())


class TestRegistryOperations(unittest.TestCase):
    """Tests for registry CRUD operations using a temporary directory."""

    def setUp(self):
        """Use a temporary directory for the registry."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_registry_dir = REGISTRY_DIR
        # Patch the module-level REGISTRY_DIR
        import ida_pro_mcp.instance_registry as reg_module
        reg_module.REGISTRY_DIR = Path(self.temp_dir)

    def tearDown(self):
        """Restore original registry dir and clean up."""
        import ida_pro_mcp.instance_registry as reg_module
        reg_module.REGISTRY_DIR = self.original_registry_dir
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_register_and_find_by_id(self):
        info = register_instance(
            instance_id="inst1",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
            binary_path="/path/to/test.exe",
        )
        self.assertEqual(info.instance_id, "inst1")
        self.assertEqual(info.port, 13337)

        found = find_instance_by_id("inst1")
        self.assertIsNotNone(found)
        self.assertEqual(found.instance_id, "inst1")
        self.assertEqual(found.binary_name, "test.exe")

    def test_register_and_find_by_binary(self):
        register_instance(
            instance_id="inst2",
            host="127.0.0.1",
            port=13338,
            binary_name="malware.dll",
        )

        found = find_instance_by_binary("malware.dll")
        self.assertIsNotNone(found)
        self.assertEqual(found.port, 13338)

    def test_find_by_binary_case_insensitive(self):
        register_instance(
            instance_id="inst3",
            host="127.0.0.1",
            port=13339,
            binary_name="MyBinary.EXE",
        )

        found = find_instance_by_binary("mybinary.exe")
        self.assertIsNotNone(found)
        self.assertEqual(found.instance_id, "inst3")

    def test_unregister_instance(self):
        register_instance(
            instance_id="inst4",
            host="127.0.0.1",
            port=13340,
            binary_name="test.exe",
        )

        result = unregister_instance("inst4")
        self.assertTrue(result)

        found = find_instance_by_id("inst4")
        self.assertIsNone(found)

    def test_unregister_nonexistent(self):
        result = unregister_instance("nonexistent")
        self.assertTrue(result)  # unlink with missing_ok=True

    def test_list_instances(self):
        register_instance(
            instance_id="list1",
            host="127.0.0.1",
            port=13341,
            binary_name="binary1.exe",
        )
        register_instance(
            instance_id="list2",
            host="127.0.0.1",
            port=13342,
            binary_name="binary2.dll",
        )

        instances = list_instances()
        self.assertEqual(len(instances), 2)
        names = {i.binary_name for i in instances}
        self.assertIn("binary1.exe", names)
        self.assertIn("binary2.dll", names)

    def test_list_instances_empty(self):
        instances = list_instances()
        self.assertEqual(len(instances), 0)

    def test_refresh_instance(self):
        register_instance(
            instance_id="refresh1",
            host="127.0.0.1",
            port=13343,
            binary_name="test.exe",
        )

        # Wait a moment and refresh
        time.sleep(0.1)
        result = refresh_instance("refresh1")
        self.assertTrue(result)

        found = find_instance_by_id("refresh1")
        self.assertIsNotNone(found)
        # Timestamp should be updated
        self.assertGreater(found.timestamp, time.time() - 1)

    def test_refresh_nonexistent(self):
        result = refresh_instance("nonexistent")
        self.assertFalse(result)

    def test_cleanup_stale_instances(self):
        import ida_pro_mcp.instance_registry as reg_module

        # Create a stale instance with a dead PID
        stale_info = InstanceInfo(
            instance_id="stale1",
            host="127.0.0.1",
            port=13344,
            binary_name="old.exe",
            binary_path="",
            pid=999999999,  # Very unlikely to exist
            timestamp=time.time() - STALE_TIMEOUT - 100,
        )
        filepath = Path(self.temp_dir) / "stale1.json"
        with open(filepath, "w") as f:
            json.dump(stale_info.to_dict(), f)

        # Create a fresh instance
        register_instance(
            instance_id="fresh1",
            host="127.0.0.1",
            port=13345,
            binary_name="new.exe",
        )

        removed = cleanup_stale_instances()
        self.assertEqual(removed, 1)

        # Fresh instance should still be there
        instances = list_instances()
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].instance_id, "fresh1")

    def test_multiple_instances_different_ports(self):
        """Test that multiple instances can coexist with different ports."""
        for i in range(5):
            register_instance(
                instance_id=f"multi{i}",
                host="127.0.0.1",
                port=13350 + i,
                binary_name=f"binary{i}.exe",
            )

        instances = list_instances()
        self.assertEqual(len(instances), 5)
        ports = {i.port for i in instances}
        self.assertEqual(len(ports), 5)  # All unique ports


class TestFindAvailablePort(unittest.TestCase):
    """Tests for port discovery."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        import ida_pro_mcp.instance_registry as reg_module
        self.original_registry_dir = REGISTRY_DIR
        reg_module.REGISTRY_DIR = Path(self.temp_dir)

    def tearDown(self):
        import ida_pro_mcp.instance_registry as reg_module
        reg_module.REGISTRY_DIR = self.original_registry_dir
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_find_available_port(self):
        """Should find a port in the configured range."""
        port = find_available_port("127.0.0.1")
        self.assertGreaterEqual(port, 13337)
        self.assertLess(port, 13437)

    def test_find_port_avoids_registered(self):
        """Should not return a port that's already registered."""
        # Register a fake instance on the first port
        register_instance(
            instance_id="blocker",
            host="127.0.0.1",
            port=13337,
            binary_name="blocker.exe",
        )

        port = find_available_port("127.0.0.1")
        self.assertNotEqual(port, 13337)


class TestHeartbeatThread(unittest.TestCase):
    """Tests for the heartbeat mechanism."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        import ida_pro_mcp.instance_registry as reg_module
        self.original_registry_dir = REGISTRY_DIR
        reg_module.REGISTRY_DIR = Path(self.temp_dir)

    def tearDown(self):
        import ida_pro_mcp.instance_registry as reg_module
        reg_module.REGISTRY_DIR = self.original_registry_dir
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_heartbeat_start_stop(self):
        register_instance(
            instance_id="hb1",
            host="127.0.0.1",
            port=13337,
            binary_name="test.exe",
        )

        hb = HeartbeatThread("hb1")
        hb.start()
        self.assertIsNotNone(hb._thread)
        hb.stop()
        self.assertIsNone(hb._thread)


if __name__ == "__main__":
    unittest.main()

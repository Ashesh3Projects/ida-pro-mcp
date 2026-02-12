"""Instance Registry for Multi-Instance MCP Support

Provides a file-based registry for IDA instances to register themselves
and for the MCP server to discover and route requests to the correct instance.

Architecture (Centralized Host Model):
- Each IDA instance runs its own MCP server on a dynamically assigned port
- Each instance writes a registration file to a shared directory
- The MCP server (host) discovers instances by reading registration files
- Requests are routed based on binary/executable name

Registry files are stored in ~/.ida-mcp/instances/ as JSON files.
Each file contains instance metadata: port, binary name, PID, timestamp.
"""

import json
import os
import time
import socket
import threading
from pathlib import Path
from typing import Optional

# Registry directory
REGISTRY_DIR = Path.home() / ".ida-mcp" / "instances"

# Port range for dynamic allocation
PORT_RANGE_START = 13337
PORT_RANGE_END = 13437  # 100 ports available

# Stale instance timeout (seconds) - instances not refreshed within this time are removed
STALE_TIMEOUT = 60

# Heartbeat interval (seconds)
HEARTBEAT_INTERVAL = 30


class InstanceInfo:
    """Information about a registered IDA instance."""

    def __init__(
        self,
        instance_id: str,
        host: str,
        port: int,
        binary_name: str,
        binary_path: str,
        pid: int,
        timestamp: float,
    ):
        self.instance_id = instance_id
        self.host = host
        self.port = port
        self.binary_name = binary_name
        self.binary_path = binary_path
        self.pid = pid
        self.timestamp = timestamp

    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "host": self.host,
            "port": self.port,
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "pid": self.pid,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def from_dict(data: dict) -> "InstanceInfo":
        return InstanceInfo(
            instance_id=data["instance_id"],
            host=data["host"],
            port=data["port"],
            binary_name=data["binary_name"],
            binary_path=data.get("binary_path", ""),
            pid=data["pid"],
            timestamp=data["timestamp"],
        )

    def is_stale(self) -> bool:
        """Check if this instance registration is stale."""
        return (time.time() - self.timestamp) > STALE_TIMEOUT

    def is_alive(self) -> bool:
        """Check if the process is still running."""
        try:
            os.kill(self.pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def __repr__(self) -> str:
        return f"InstanceInfo({self.instance_id}, {self.binary_name}, {self.host}:{self.port})"


def _ensure_registry_dir() -> Path:
    """Ensure the registry directory exists."""
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
    return REGISTRY_DIR


def _instance_file(instance_id: str) -> Path:
    """Get the path to an instance registration file."""
    return REGISTRY_DIR / f"{instance_id}.json"


def find_available_port(host: str = "127.0.0.1") -> int:
    """Find an available port in the configured range.

    Checks both the OS-level port availability and the registry to avoid
    conflicts with other IDA instances.
    """
    registered_ports = {inst.port for inst in list_instances()}

    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port in registered_ports:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                return port
        except OSError:
            continue

    raise RuntimeError(
        f"No available ports in range {PORT_RANGE_START}-{PORT_RANGE_END}"
    )


def register_instance(
    instance_id: str,
    host: str,
    port: int,
    binary_name: str,
    binary_path: str = "",
) -> InstanceInfo:
    """Register an IDA instance in the registry.

    Args:
        instance_id: Unique identifier for this instance
        host: Host the instance is listening on
        port: Port the instance is listening on
        binary_name: Name of the binary being analyzed
        binary_path: Full path to the binary being analyzed

    Returns:
        The registered InstanceInfo
    """
    _ensure_registry_dir()

    info = InstanceInfo(
        instance_id=instance_id,
        host=host,
        port=port,
        binary_name=binary_name,
        binary_path=binary_path,
        pid=os.getpid(),
        timestamp=time.time(),
    )

    filepath = _instance_file(instance_id)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(info.to_dict(), f, indent=2)

    return info


def unregister_instance(instance_id: str) -> bool:
    """Remove an instance from the registry.

    Returns:
        True if the instance was found and removed, False otherwise
    """
    filepath = _instance_file(instance_id)
    try:
        filepath.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def refresh_instance(instance_id: str) -> bool:
    """Update the timestamp of an instance registration (heartbeat).

    Returns:
        True if the instance was found and refreshed, False otherwise
    """
    filepath = _instance_file(instance_id)
    if not filepath.exists():
        return False

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["timestamp"] = time.time()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except (json.JSONDecodeError, OSError, KeyError):
        return False


def list_instances(*, include_stale: bool = False) -> list[InstanceInfo]:
    """List all registered instances.

    Args:
        include_stale: If True, include stale instances in the results

    Returns:
        List of InstanceInfo objects for active instances
    """
    _ensure_registry_dir()
    instances = []

    for filepath in REGISTRY_DIR.glob("*.json"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            info = InstanceInfo.from_dict(data)

            # Skip stale instances unless requested
            if not include_stale and info.is_stale() and not info.is_alive():
                # Clean up stale registration
                filepath.unlink(missing_ok=True)
                continue

            instances.append(info)
        except (json.JSONDecodeError, KeyError, OSError):
            # Invalid registration file, clean up
            try:
                filepath.unlink(missing_ok=True)
            except OSError:
                pass

    return instances


def find_instance_by_binary(binary_name: str) -> Optional[InstanceInfo]:
    """Find an instance by the binary name it's analyzing.

    Args:
        binary_name: Name of the binary to search for (case-insensitive)

    Returns:
        InstanceInfo if found, None otherwise
    """
    binary_name_lower = binary_name.lower()
    for info in list_instances():
        if info.binary_name.lower() == binary_name_lower:
            return info
    return None


def find_instance_by_id(instance_id: str) -> Optional[InstanceInfo]:
    """Find an instance by its ID.

    Args:
        instance_id: The instance ID to search for

    Returns:
        InstanceInfo if found, None otherwise
    """
    filepath = _instance_file(instance_id)
    if not filepath.exists():
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return InstanceInfo.from_dict(data)
    except (json.JSONDecodeError, KeyError, OSError):
        return None


def cleanup_stale_instances() -> int:
    """Remove stale instance registrations.

    Returns:
        Number of stale instances removed
    """
    removed = 0
    _ensure_registry_dir()
    for filepath in REGISTRY_DIR.glob("*.json"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            info = InstanceInfo.from_dict(data)
            if info.is_stale() and not info.is_alive():
                filepath.unlink(missing_ok=True)
                removed += 1
        except (json.JSONDecodeError, KeyError, OSError):
            try:
                filepath.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
    return removed


class HeartbeatThread:
    """Background thread that periodically refreshes instance registration."""

    def __init__(self, instance_id: str):
        self.instance_id = instance_id
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the heartbeat thread."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the heartbeat thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self):
        while not self._stop_event.is_set():
            refresh_instance(self.instance_id)
            self._stop_event.wait(timeout=HEARTBEAT_INTERVAL)

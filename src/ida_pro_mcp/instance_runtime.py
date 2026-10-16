"""Database lifetime identity and request context, without importing IDAPython."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import os
import secrets
import threading

from .instance_contract import RoutingError, require_instance_id

_expected = ContextVar("ida_mcp_expected_generation", default=None)


class RuntimeIdentity:
    def __init__(self):
        self._lock = threading.RLock()
        self._info: dict = {}

    def activate(self, binary_path: str, idb_path: str) -> str:
        with self._lock:
            generation = secrets.token_hex(8)
            self._info = {
                "instance_id": generation, "generation": generation,
                "identity_version": 1, "pid": os.getpid(),
                "binary_path": binary_path, "idb_path": idb_path,
                "binary_name": os.path.basename(binary_path or idb_path),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "ready",
            }
            return generation

    def invalidate(self) -> None:
        with self._lock:
            self._info = {}

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._info)

    def check(self, expected: str) -> None:
        require_instance_id(expected)
        with self._lock:
            actual = self._info.get("generation")
            if actual is None:
                raise RoutingError("INSTANCE_CLOSED", "No database is open in this IDA runtime.")
            if actual != expected:
                raise RoutingError("INSTANCE_CHANGED", "The database or listener was replaced; rediscover its new instance_id.")


_runtime = RuntimeIdentity()


def runtime_identity() -> RuntimeIdentity:
    return _runtime


def expected_generation() -> str | None:
    return _expected.get()


@contextmanager
def generation_context(expected: str):
    token = _expected.set(expected)
    try:
        yield
    finally:
        _expected.reset(token)


def check_request_generation() -> None:
    expected = _expected.get()
    if expected is not None:
        _runtime.check(expected)

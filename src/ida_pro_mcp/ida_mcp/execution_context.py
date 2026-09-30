"""IDA-free request context and bounded, explicitly released Python namespaces.

Context variables are copied by idasync before crossing into IDA's main thread.
These namespaces separate clients' convenience state; they are not a sandbox.
"""

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

MAX_BRIDGE_CLIENTS = 256
_client = ContextVar("ida_mcp_bridge_client", default=None)
_cancel = ContextVar("ida_mcp_bridge_cancel", default=None)
_lock = threading.RLock()


@dataclass
class _Session:
    namespace: dict = field(default_factory=dict)
    active: int = 0
    released: bool = False


_sessions: dict[str, _Session] = {}


def get_bridge_client() -> str | None:
    return _client.get()


def get_bridge_cancel_event() -> threading.Event | None:
    return _cancel.get()


@contextmanager
def bridge_context(client_id: str, cancel_event: threading.Event | None = None):
    with _lock:
        session = _sessions.get(client_id)
        if session is None:
            if len(_sessions) >= MAX_BRIDGE_CLIENTS:
                raise RuntimeError(
                    "Bridge session capacity reached; release unused sessions"
                )
            session = _sessions[client_id] = _Session()
        if session.released:
            raise RuntimeError("Bridge session is being released")
        session.active += 1
    client_token = _client.set(client_id)
    cancel_token = _cancel.set(cancel_event)
    try:
        yield
    finally:
        _cancel.reset(cancel_token)
        _client.reset(client_token)
        with _lock:
            session.active -= 1
            if session.released and session.active == 0:
                session.namespace.clear()
                _sessions.pop(client_id, None)


def get_python_namespace(legacy: dict) -> dict:
    client_id = get_bridge_client()
    if client_id is None:
        return legacy
    with _lock:
        return _sessions[client_id].namespace


def release_bridge_client(client_id: str) -> bool:
    """Clear only this client's state once its already running calls unwind."""
    with _lock:
        session = _sessions.get(client_id)
        if session is None:
            return False
        session.released = True
        if session.active == 0:
            session.namespace.clear()
            del _sessions[client_id]
        return True

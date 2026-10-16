"""Transport-independent identities and explicit routing contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import secrets
import threading
from typing import Protocol
from urllib.parse import parse_qs, urlsplit, urlunsplit


class RoutingError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def tool_result(self, instance_id: str | None = None) -> dict:
        metadata = {"error_code": self.code}
        if instance_id is not None:
            metadata["instance_id"] = instance_id
        return {
            "content": [{"type": "text", "text": str(self)}],
            "isError": True,
            "_meta": {"ida_mcp": metadata},
        }


def require_instance_id(value: object) -> str:
    if value is None:
        raise RoutingError(
            "INSTANCE_ID_REQUIRED",
            "Pass instance_id from list_instances or open_database with every database operation.",
        )
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value):
        raise RoutingError(
            "INVALID_INSTANCE_ID",
            "instance_id must be the exact 16-character ID returned by this server.",
        )
    return value


def split_instance_uri(uri: str) -> tuple[str, str]:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    if set(query) != {"instance_id"} or len(query["instance_id"]) != 1:
        raise RoutingError(
            "INSTANCE_ID_REQUIRED",
            "Resource URI requires exactly one instance_id query parameter.",
        )
    return urlunsplit(parts._replace(query="")), require_instance_id(
        query["instance_id"][0]
    )


@dataclass(frozen=True)
class BackendIdentity:
    provider: str
    key: str
    backend: str
    binary_name: str
    binary_path: str
    idb_path: str
    pid: int
    started_at: str
    compatible: bool = True


@dataclass(frozen=True)
class InstanceBinding:
    instance_id: str
    identity: BackendIdentity


@dataclass(eq=False)
class Invocation:
    binding: InstanceBinding
    operation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    cancelled: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)


class BackendSession(Protocol):
    identity: BackendIdentity
    runtime_generation: str

    async def request(
        self, invocation: Invocation, method: str, params: dict
    ) -> dict: ...
    async def cancel(self, invocation: Invocation) -> None: ...
    async def close(self) -> None: ...


class BackendProvider(Protocol):
    name: str

    async def discover(self) -> list[BackendIdentity]: ...
    async def attach(
        self, identity: BackendIdentity, invocation: Invocation
    ) -> BackendSession: ...
    async def open_path(self, path: str, options: dict) -> BackendSession: ...
    async def reference(self, query: str) -> str: ...

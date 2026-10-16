"""Authenticated typed calls on the same Nexus target and lease as official tools.

All blocking Nexus/HTTP work runs in worker threads. A typed operation never
waits inside a Nexus Python execution, and mutations are never replayed.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import threading
import uuid
from collections import OrderedDict
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .runtime_identity import PACKAGE_FINGERPRINT
from .instance_contract import RoutingError, require_instance_id
from .instance_router import finish_cleanup

MAX_OUTPUT_CHARS = 32_000
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_OUTPUTS = 128
HTTP_TIMEOUT = 150


def bootstrap_expression() -> str:
    """Accept identical copied installs and reject a cached different runtime."""
    return (
        "(lambda bridge: bridge.ensure_bridge() if "
        f"getattr(bridge, 'runtime_identity', lambda: None)() == {PACKAGE_FINGERPRINT!r} else "
        "(_ for _ in ()).throw(RuntimeError('IDA bridge installation differs from this client; restart IDA with the current plugin')))"
        "(__import__('ida_pro_mcp.bridge_runtime', fromlist=['ensure_bridge']))"
    )


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    token: str = field(repr=False)
    generation: str

    @classmethod
    def parse(cls, value: Any) -> Endpoint:
        if not isinstance(value, dict) or value.get("version") != 2:
            raise ValueError("unsupported IDA bridge protocol")
        if value.get("host") != "127.0.0.1":
            raise ValueError("IDA bridge must bind IPv4 loopback")
        port, token = value.get("port"), value.get("token")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("invalid IDA bridge port")
        if not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
            raise ValueError("invalid IDA bridge credential")
        return cls("127.0.0.1", port, token, require_instance_id(value.get("generation")))


@dataclass(eq=False)
class Invocation:
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    target: str | None = None
    client_id: str | None = None
    endpoint: Endpoint | None = None
    bootstrapping: bool = False
    transport_failed: bool = False
    cancelled: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)


class UnifiedBridge:
    def __init__(self, manager: Any, *, endpoints=None, raw_outputs=False):
        self.manager = manager
        self.client_id = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._endpoints: dict[str, Endpoint] = dict(endpoints or {})
        self._raw_outputs = raw_outputs
        self._clients: dict[str, str] = {}
        self._bootstrap_locks: dict[str, threading.Lock] = {}
        self._active: set[Invocation] = set()
        self._closed: set[str] = set()
        self._shutdown = False
        self._shutdown_pending: set[str] = set()
        self._outputs: OrderedDict[str, tuple[str, Endpoint, str]] = OrderedDict()

    def _http(
        self, endpoint: Endpoint, method: str, path: str, body: dict | None = None
    ) -> bytes:
        connection = http.client.HTTPConnection(
            endpoint.host, endpoint.port, timeout=HTTP_TIMEOUT
        )
        try:
            encoded = None if body is None else json.dumps(body).encode("utf-8")
            connection.request(
                method,
                path,
                body=encoded,
                headers={
                    "Authorization": f"Bearer {endpoint.token}",
                    "Content-Type": "application/json",
                    "X-IDA-MCP-Generation": endpoint.generation,
                },
            )
            response = connection.getresponse()
            if response.status not in (200, 202, 204):
                raise RuntimeError(
                    f"IDA bridge HTTP {response.status}; request was not retried"
                )
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError("IDA bridge output exceeds the 64 MiB download limit")
            return data
        finally:
            connection.close()

    def _rpc(
        self,
        endpoint: Endpoint,
        method: str,
        params: dict,
        request_id: str | None,
        client_id: str,
    ) -> Any:
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": {**params, "_meta": {"ida_pro_mcp_client": client_id, "ida_pro_mcp_generation": endpoint.generation}},
        }
        if request_id is not None:
            request["id"] = request_id
        data = self._http(endpoint, "POST", "/mcp", request)
        if request_id is None:
            return None
        response = json.loads(data)
        if not isinstance(response, dict) or response.get("id") != request_id:
            raise ValueError("IDA bridge returned a mismatched response id")
        if "error" in response:
            code = response["error"].get("data", {}).get("error_code")
            if code:
                raise RoutingError(code, response["error"].get("message", code))
            raise RuntimeError(
                str(response["error"].get("message", "IDA bridge RPC failed"))
            )
        if "result" not in response:
            raise ValueError("IDA bridge returned no result")
        return response["result"]

    def _endpoint(self, invocation: Invocation) -> Endpoint:
        target = invocation.target
        with self._lock:
            bootstrap_lock = self._bootstrap_locks.setdefault(target, threading.Lock())
        with bootstrap_lock:
            with self._lock:
                if target in self._endpoints:
                    return self._endpoints[target]
            if invocation.cancelled.is_set():
                raise asyncio.CancelledError()
            invocation.bootstrapping = True
            try:
                result = self.manager.execute_python(
                    bootstrap_expression(),
                    target,
                    timeout=120,
                    operation_id=invocation.request_id,
                    operation_label="ida-pro-mcp bridge bootstrap",
                    persist_globals=True,
                )
            finally:
                invocation.bootstrapping = False
            endpoint = Endpoint.parse(result.get("result"))
            with self._lock:
                self._endpoints[target] = endpoint
            return endpoint

    def _run(
        self, invocation: Invocation, method: str, params: dict, instance_id: str | None
    ) -> Any:
        try:
            # Startup resolution can join the asynchronous open thread, which
            # needs our lock to mark its target ready. Never hold it while joining.
            target = self.manager.resolve_instance_id(instance_id)
            with self._lock:
                invocation.target = target
                invocation.client_id = self._clients.setdefault(target, self.client_id)
                if self._shutdown or target in self._closed:
                    raise ValueError("IDA bridge target is closed")
            invocation.endpoint = self._endpoint(invocation)
            if invocation.cancelled.is_set():
                raise asyncio.CancelledError()
            try:
                result = self._rpc(
                    invocation.endpoint,
                    method,
                    params,
                    invocation.request_id,
                    invocation.client_id,
                )
            except Exception:
                invocation.transport_failed = True
                raise
            if method == "tools/call":
                if not isinstance(result, dict) or not isinstance(
                    result.get("content"), list
                ):
                    raise ValueError("IDA bridge returned an invalid tool result")
                if not self._raw_outputs:
                    result = self._own_output(result, target, invocation.endpoint)
            return result
        finally:
            with self._lock:
                self._active.discard(invocation)
            invocation.done.set()

    def _cancel(self, invocation: Invocation) -> None:
        invocation.cancelled.set()
        if invocation.done.is_set():
            return
        with suppress(Exception):
            if invocation.endpoint is not None:
                self._rpc(
                    invocation.endpoint,
                    "notifications/cancelled",
                    {
                        "requestId": invocation.request_id,
                        "reason": "MCP client cancelled request",
                    },
                    None,
                    invocation.client_id,
                )
            elif invocation.bootstrapping and invocation.target is not None:
                self.manager.cancel_operation(invocation.target, invocation.request_id)

    def _wait_cancelled(self, invocation: Invocation) -> None:
        self._cancel(invocation)
        while not invocation.done.wait(0.05):
            # Nexus may not have registered the bootstrap operation when the
            # first cancellation arrived. Repeat only this invocation's ID.
            if invocation.bootstrapping:
                self._cancel(invocation)

    def _cancel_and_wait(self, invocation: Invocation) -> None:
        self._wait_cancelled(invocation)
        if invocation.transport_failed and invocation.target is not None:
            # A broken request connection cannot prove IDA finished. Retire this
            # target's bridge context and wait for the runtime drain ACK, keeping
            # its Nexus lease alive. Explicit reopen starts a fresh namespace.
            self.release_target(invocation.target)

    async def request(
        self, method: str, params: dict, instance_id: str
    ) -> Any:
        if not isinstance(instance_id, str) or not instance_id:
            raise RoutingError("INSTANCE_ID_REQUIRED", "Explicit bridge target is required")
        invocation = Invocation(target=instance_id)
        with self._lock:
            if self._shutdown:
                raise ValueError("IDA bridge is closed")
            self._active.add(invocation)
        worker = asyncio.create_task(
            asyncio.to_thread(self._run, invocation, method, params, instance_id)
        )
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cleanup = asyncio.create_task(
                asyncio.to_thread(self._cancel_and_wait, invocation)
            )
            await finish_cleanup(cleanup)
            with suppress(BaseException):
                await worker
            raise

    async def call_tool(
        self, name: str, arguments: dict, instance_id: str
    ) -> dict:
        return await self.request(
            "tools/call", {"name": name, "arguments": arguments}, instance_id
        )

    def _own_output(self, result: dict, target: str, endpoint: Endpoint) -> dict:
        metadata = result.get("_meta", {}).get("ida_mcp", {})
        backend_id = metadata.get("output_id")
        if not isinstance(backend_id, str):
            return result
        result = deepcopy(result)
        output_id = uuid.uuid4().hex
        with self._lock:
            self._outputs[output_id] = (target, endpoint, backend_id)
            while len(self._outputs) > MAX_OUTPUTS:
                self._outputs.popitem(last=False)
        metadata = result["_meta"]["ida_mcp"]
        metadata.pop("download_url", None)
        metadata["output_id"] = output_id
        hint = f'Output truncated. Use read_output(output_id="{output_id}", offset=0, limit=32000).'
        metadata["download_hint"] = hint
        # The fork appends a raw unauthenticated download command after preview.
        result["content"] = result["content"][:1] + [{"type": "text", "text": hint}]
        return result

    async def read_output(
        self, output_id: str, offset: int = 0, limit: int = MAX_OUTPUT_CHARS
    ) -> dict:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_OUTPUT_CHARS
        ):
            raise ValueError("limit must be between 1 and 32000 characters")
        with self._lock:
            output = self._outputs.get(output_id)
            if output is None:
                raise ValueError("unknown or expired output_id for this client")
            target, endpoint, backend_id = output
            if self._shutdown or target in self._closed:
                raise ValueError("output belongs to a closed database target")
        data = await asyncio.to_thread(
            self._http, endpoint, "GET", f"/output/{quote(backend_id, safe='')}.json"
        )
        text = data.decode("utf-8")
        end = min(offset + limit, len(text))
        return {
            "output_id": output_id,
            "instance_id": target,
            "offset": offset,
            "text": text[offset:end],
            "total_chars": len(text),
            "next_offset": end if end < len(text) else None,
        }

    def release_target(self, target: str) -> None:
        with self._lock:
            self._closed.add(target)
            active = [call for call in self._active if call.target == target]
        for call in active:
            self._cancel(call)
        for call in active:
            self._wait_cancelled(call)
        with self._lock:
            endpoint = self._endpoints.get(target)
            client_id = self._clients.get(target, self.client_id)
        if endpoint is not None:
            # The ACK proves all backend calls have unwound, including a call
            # whose HTTP connection failed locally before execution finished.
            # Preserve endpoint and Nexus lease if this fails, so close can be
            # retried without replaying any typed tool or losing its context.
            self._rpc(
                endpoint,
                "bridge/release_session",
                {"client_id": client_id},
                uuid.uuid4().hex,
                client_id,
            )
        with self._lock:
            self._endpoints.pop(target, None)
            self._outputs = OrderedDict(
                (key, value)
                for key, value in self._outputs.items()
                if value[0] != target
            )

    def shutdown(self, on_released=None, targets=()) -> None:
        with self._lock:
            self._shutdown = True
            active = list(self._active)
        for call in active:
            self._cancel(call)
        for call in active:
            self._wait_cancelled(call)
        with self._lock:
            self._shutdown_pending.update(self._endpoints)
            self._shutdown_pending.update(targets)
            targets = sorted(self._shutdown_pending)
        errors = []
        for target in targets:
            try:
                self.release_target(target)
                if on_released is not None:
                    on_released(target)
                self._shutdown_pending.discard(target)
            except Exception as error:
                error.add_note(f"IDA database target: {target}")
                errors.append(error)
        if errors:
            raise ExceptionGroup("IDA bridge shutdown did not release every target", errors)

    def reopen_target(self, target: str) -> None:
        with self._lock:
            if target in self._closed:
                if target in self._endpoints:
                    raise ValueError(
                        "Previous bridge close did not finish; retry close_database first"
                    )
                self._clients[target] = uuid.uuid4().hex
            self._closed.discard(target)

    async def download_output(self, output_id: str, instance_id: str) -> str:
        target = self.manager.resolve_instance_id(instance_id)
        with self._lock:
            if self._shutdown or target in self._closed:
                raise RoutingError("INSTANCE_CLOSED", "Output belongs to a closed database")
            endpoint = self._endpoints.get(target)
        if endpoint is None:
            raise RoutingError("OUTPUT_EXPIRED", "Output endpoint is no longer available")
        data = await asyncio.to_thread(self._http, endpoint, "GET", f"/output/{quote(output_id, safe='')}.json")
        return data.decode("utf-8")

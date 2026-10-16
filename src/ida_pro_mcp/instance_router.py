"""Concurrent explicit routing with independent database admission and cleanup."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass, field
import os
import threading
import weakref

import anyio

from .instance_contract import (
    BackendProvider,
    BackendSession,
    InstanceBinding,
    Invocation,
    RoutingError,
    split_instance_uri,
)
from .instance_registry import InstanceRegistry
from .output_store import OutputStore


@dataclass
class _Slot:
    binding: InstanceBinding
    gate: asyncio.Lock = field(default_factory=asyncio.Lock)
    session: BackendSession | None = None
    calls: dict[Invocation, asyncio.Task] = field(default_factory=dict)
    phases: dict[Invocation, str] = field(default_factory=dict)
    closing: asyncio.Task | None = None


async def finish_cleanup(task: asyncio.Task):
    """Keep cleanup owned even under repeated asyncio/AnyIO cancellation."""
    with anyio.CancelScope(shield=True):
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
        return task.result()


class InstanceRouter:
    def __init__(
        self, provider: BackendProvider, *, registry: InstanceRegistry | None = None
    ):
        self.provider = provider
        self.registry = registry or InstanceRegistry()
        self._slots: dict[str, _Slot] = {}
        self._opens: dict[str, asyncio.Task] = {}
        self._session_bindings = weakref.WeakKeyDictionary()
        self._shutdown = False
        self._output_store = OutputStore()
        self.trace = None
        self._trace_lock = threading.RLock()
        self._disconnected = set()

    def _emit(self, event, binding):
        if self.trace is not None:
            identity = binding.identity
            self.trace.emit(
                event,
                instance_id=binding.instance_id,
                target={
                    "idb_path": identity.idb_path,
                    "exe_path": identity.binary_path,
                    "backend": identity.backend,
                },
            )

    def _disconnected_event(self, binding):
        with self._trace_lock:
            if binding.instance_id not in self._disconnected:
                self._disconnected.add(binding.instance_id)
                self._emit("database_disconnected", binding)

    def _adopt(self, slot, session):
        slot.session = session
        self._session_bindings[session] = slot.binding
        # Nexus signals disconnect independently of the next tool request.
        callback = getattr(session, "set_disconnect_callback", None)
        if callback is not None:
            callback(lambda: self._disconnected_event(slot.binding))
        self._emit("database_opened", slot.binding)

    def _check_running(self):
        if self._shutdown:
            raise RoutingError("INSTANCE_CLOSED", "MCP server is shutting down.")

    def _slot(self, binding):
        return self._slots.setdefault(binding.instance_id, _Slot(binding))

    async def list_instances(self) -> dict:
        records = await self.provider.discover()
        seen = {(r.provider, r.key) for r in records if r.compatible}
        result = []
        for binding in self.registry.bindings():
            slot = self._slots.get(binding.instance_id)
            if (binding.identity.provider, binding.identity.key) not in seen and not (
                slot and slot.session
            ):
                if self.registry.state(binding) not in {"closing", "attaching"}:
                    self.registry.retire(binding, state="unavailable")
                    self._disconnected_event(binding)
        for record in records:
            if not record.compatible:
                result.append(
                    {
                        "instance_id": None,
                        "binary_name": record.binary_name,
                        "idb_path": record.idb_path,
                        "backend": record.backend,
                        "status": "incompatible",
                        "error_code": "INSTANCE_INCOMPATIBLE",
                    }
                )
                continue
            binding = self.registry.publish(record)
            result.append(self.registry.describe(binding))
        listed = {row["instance_id"] for row in result}
        for binding in self.registry.bindings():
            if binding.instance_id not in listed:
                result.append(self.registry.describe(binding))
        return {"instances": result, "count": len(result)}

    async def instance_status(self, instance_id: str) -> dict:
        binding = self.registry.resolve(instance_id, allow_closing=True)
        return self.registry.describe(binding)

    async def _attach(self, slot: _Slot, invocation: Invocation):
        if slot.session is not None:
            return slot.session
        self.registry.set_state(slot.binding, "attaching")
        slot.phases[invocation] = "attaching"
        session = await self.provider.attach(slot.binding.identity, invocation)
        self._adopt(slot, session)
        if (
            session.identity.key != slot.binding.identity.key
            or session.identity.provider != slot.binding.identity.provider
        ):
            self.registry.set_state(slot.binding, "closing")
            raise RoutingError(
                "INSTANCE_CHANGED",
                "Attachment returned a different database incarnation.",
            )
        if self.registry.state(slot.binding) != "closing":
            self.registry.set_state(slot.binding, "ready")
        return session

    async def _run(self, slot: _Slot, invocation: Invocation, method, params):
        try:
            async with slot.gate:
                self.registry.resolve(slot.binding.instance_id)
                if invocation.cancelled.is_set():
                    raise asyncio.CancelledError()
                session = await self._attach(slot, invocation)
                self.registry.resolve(slot.binding.instance_id)
                if invocation.cancelled.is_set():
                    raise asyncio.CancelledError()
                slot.phases[invocation] = "executing"
                if method == "output/read":
                    expected = params.pop("expected_generation", None)
                    if expected != session.runtime_generation:
                        raise RoutingError(
                            "INSTANCE_CHANGED",
                            "Cached output's backend generation changed",
                        )
                result = await session.request(invocation, method, params)
                if method == "save_database":
                    self._emit("database_saved", slot.binding)
                if method == "tools/call":
                    result = self._own_output(result, slot)
                return result
        finally:
            slot.calls.pop(invocation, None)
            slot.phases.pop(invocation, None)
            invocation.done.set()

    async def _cancel(self, slot, invocation, worker):
        invocation.cancelled.set()
        phase = slot.phases.get(invocation)
        if phase == "queued":
            worker.cancel()
        elif phase == "executing" and slot.session is not None:
            await slot.session.cancel(invocation)
        # Attachment must finish so an acquired lease is never abandoned.
        with suppress(asyncio.CancelledError, RoutingError):
            await worker

    async def request(self, instance_id: str, method: str, params: dict) -> dict:
        self._check_running()
        binding = self.registry.resolve(instance_id)
        slot = self._slot(binding)
        invocation = Invocation(binding)
        worker = asyncio.create_task(
            self._run(slot, invocation, method, deepcopy(params))
        )
        slot.calls[invocation] = worker
        slot.phases[invocation] = "queued"
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            await finish_cleanup(
                asyncio.create_task(self._cancel(slot, invocation, worker))
            )
            raise

    def _own_output(self, result, slot):
        result = deepcopy(result)
        metadata = result.setdefault("_meta", {}).setdefault("ida_mcp", {})
        metadata["instance_id"] = slot.binding.instance_id
        backend_id = metadata.get("output_id")
        if isinstance(backend_id, str):
            output_id = self._output_store.remember(
                slot.binding,
                slot.session.runtime_generation,
                backend_id,
                slot.binding.instance_id,
            )
            metadata["output_id"] = output_id
            metadata.pop("download_url", None)
            hint = f'Output truncated. Use read_output(instance_id="{slot.binding.instance_id}", output_id="{output_id}", offset=0, limit=32000).'
            metadata["download_hint"] = hint
            result["content"] = result.get("content", [])[:1] + [
                {"type": "text", "text": hint}
            ]
        return result

    async def read_output(
        self, instance_id: str, output_id: str, offset: int = 0, limit: int = 32000
    ):
        if (
            type(offset) is not int
            or offset < 0
            or type(limit) is not int
            or not 1 <= limit <= 32000
        ):
            raise ValueError(
                "offset must be nonnegative and limit must be between 1 and 32000"
            )
        output = self._output_store.lookup(instance_id, output_id)
        result = await self.request(
            instance_id,
            "output/read",
            {
                "output_id": output.backend_output_id,
                "expected_generation": output.runtime_generation,
            },
        )
        text = result["text"]
        end = min(offset + limit, len(text))
        return {
            "instance_id": instance_id,
            "output_id": output_id,
            "offset": offset,
            "text": text[offset:end],
            "total_chars": len(text),
            "next_offset": end if end < len(text) else None,
        }

    async def read_resource(self, uri: str):
        backend_uri, instance_id = split_instance_uri(uri)
        result = deepcopy(
            await self.request(instance_id, "resources/read", {"uri": backend_uri})
        )
        for content in result.get("contents", []):
            content["uri"] = uri
        return result

    async def _open(self, path, options):
        session = await self.provider.open_path(path, options)
        try:
            owner = self._session_bindings.get(session)
            binding = (
                self.registry.resolve(owner.instance_id)
                if owner is not None
                else self.registry.publish(session.identity)
            )
            slot = self._slot(binding)
            reused = False
            async with slot.gate:
                self.registry.resolve(binding.instance_id)
                if slot.session is None:
                    self._adopt(slot, session)
                    session = None
                    if not self._shutdown:
                        self.registry.set_state(binding, "ready")
                else:
                    reused = True
                    if slot.session is session:
                        session = None
                if self._shutdown:
                    # Shutdown's final sweep owns a newly acquired session,
                    # including a failed release; never strand it in this task.
                    self.registry.set_state(binding, "closing")
                    raise RoutingError(
                        "INSTANCE_CLOSED", "Server closed while database was opening."
                    )
            if reused:
                self._emit("database_reused", binding)
            return self.registry.describe(binding)
        finally:
            if session is not None and session not in self._session_bindings:
                # Some providers return an already-owned session for an alias.
                # Rejecting a closing binding must not release that same lease.
                await session.close()

    async def open_database(self, path: str, **options) -> dict:
        self._check_running()
        if not isinstance(path, str) or not path.strip():
            raise ValueError("A nonempty database path is required")
        key = os.path.normcase(os.path.abspath(os.path.expanduser(path)))
        task = self._opens.get(key)
        if task is None or task.done():
            task = asyncio.create_task(self._open(path, options))
            self._opens[key] = task

            def finished(done):
                if self._opens.get(key) is done:
                    self._opens.pop(key, None)
                if not done.cancelled():
                    done.exception()  # Observe failures if all callers cancelled.

            task.add_done_callback(finished)
        return await asyncio.shield(task)

    async def _close(self, slot, save):
        try:
            return await self._drain_and_close(slot, save)
        except BaseException:
            self._emit("database_release_error", slot.binding)
            raise

    async def _drain_and_close(self, slot, save):
        calls = list(slot.calls.items())
        outcomes = await asyncio.gather(
            *(self._cancel(slot, invocation, task) for invocation, task in calls),
            return_exceptions=True,
        )
        failures = [
            r
            for r in outcomes
            if isinstance(r, Exception) and not isinstance(r, RoutingError)
        ]
        if failures:
            raise ExceptionGroup("Database operations did not drain", failures)
        async with slot.gate:
            if slot.session is not None:
                if save:
                    await slot.session.request(
                        Invocation(slot.binding), "save_database", {}
                    )
                    self._emit("database_saved", slot.binding)
                await slot.session.close()
                slot.session = None
            if self._output_store is not None:
                self._output_store.expire(slot.binding.instance_id)
            self.registry.retire(slot.binding)
        self._emit("database_released", slot.binding)
        return {"closed": True, "instance_id": slot.binding.instance_id}

    async def close_database(self, instance_id: str, *, save: bool = False) -> dict:
        binding = self.registry.resolve(instance_id, allow_closing=True)
        slot = self._slot(binding)
        if slot.closing is None or slot.closing.done():
            self.registry.set_state(binding, "closing")
            slot.closing = asyncio.create_task(self._close(slot, save))
        return await asyncio.shield(slot.closing)

    async def shutdown(self) -> None:
        self._shutdown = True
        opens = list(self._opens.values())
        targets = [
            b
            for b in self.registry.bindings()
            if self.registry.state(b) not in {"closed", "unavailable", "incompatible"}
        ]
        # An alias open may be waiting on an active call's admission gate.
        # Start cancellation now, rather than waiting for the dependent open.
        closing = [
            asyncio.create_task(self.close_database(b.instance_id)) for b in targets
        ]
        outcomes = await asyncio.gather(
            *closing,
            *opens,
            return_exceptions=True,
        )
        results = outcomes[: len(closing)]
        initial = {b.instance_id for b in targets}
        late = [
            b
            for b in self.registry.bindings()
            if b.instance_id not in initial
            and self.registry.state(b) not in {"closed", "unavailable", "incompatible"}
        ]
        results.extend(
            await asyncio.gather(
                *(self.close_database(b.instance_id) for b in late),
                return_exceptions=True,
            )
        )
        errors = [result for result in results if isinstance(result, Exception)]
        if errors:
            raise ExceptionGroup(
                "Some IDA database leases could not be released", errors
            )

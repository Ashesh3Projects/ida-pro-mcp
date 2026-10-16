"""Exact Nexus instances and owned leases behind the explicit router."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import os
from pathlib import Path

from ida_nexus import DatabaseHandle, DatabaseOpenOptions, InstanceState, discover_databases, reference

from .instance_contract import BackendIdentity, Invocation, RoutingError
from .instance_router import finish_cleanup
from .unified_bridge import UnifiedBridge, Endpoint, bootstrap_expression


def _identity(record) -> BackendIdentity:
    return BackendIdentity(
        provider="nexus", key=record.record_id, backend=record.backend,
        binary_name=Path(record.exe_path or record.idb_path).name,
        binary_path=record.exe_path, idb_path=record.idb_path, pid=record.pid,
        started_at=datetime.fromtimestamp(record.started_at, timezone.utc).isoformat(),
    )


def guarded_expression(code: str, generation: str, idb_path: str) -> str:
    return (
        '__builtins__["__import__"]("ida_pro_mcp.nexus_guard", fromlist=["execute"]).execute('
        f'{code!r}, {generation!r}, {idb_path!r}, __builtins__["globals"](), filename="<ida-mcp>")'
    )


class NexusProvider:
    name = "nexus"

    def __init__(self):
        self._records = {}

    async def discover(self):
        entries = await asyncio.to_thread(discover_databases)
        records = {row.instance.record_id: row.instance for row in entries if row.state == InstanceState.READY}
        self._records = records
        return [_identity(record) for record in records.values()]

    async def _session(self, handle, invocation=None):
        session = NexusSession(handle)
        try:
            await session.initialize(invocation)
            return session
        except BaseException:
            await finish_cleanup(asyncio.create_task(asyncio.to_thread(handle.close, wait_for_database=True)))
            raise

    async def attach(self, identity, invocation):
        record = self._records.get(identity.key)
        if record is None:
            raise RoutingError("INSTANCE_UNAVAILABLE", "The discovered Nexus instance is no longer available.")
        handle = await asyncio.to_thread(DatabaseHandle.attach, record, idle_timeout=None)
        return await self._session(handle, invocation)

    async def open_path(self, path, options):
        if options:
            raise ValueError(f"Unsupported Nexus open options: {', '.join(options)}")
        handle = await asyncio.to_thread(DatabaseHandle.open, path, options=DatabaseOpenOptions(startup_timeout=300, idle_timeout=None))
        self._records[handle.instance.record_id] = handle.instance
        return await self._session(handle)

    async def reference(self, query):
        return await asyncio.to_thread(reference, query)


class NexusSession:
    def __init__(self, handle):
        self.handle = handle
        self.identity = _identity(handle.instance)
        self.runtime_generation = ""
        self._descriptor = None
        self._bridge = None
        self._active = {}
        self._analysis_complete = False

    async def initialize(self, invocation=None):
        operation_id = invocation.operation_id if invocation else None
        result = await asyncio.to_thread(
            self.handle.execute_python, bootstrap_expression(), timeout=120,
            operation_id=operation_id, persist_globals=True,
            operation_label="ida-pro-mcp bridge bootstrap",
        )
        descriptor = result.get("result")
        endpoint = Endpoint.parse(descriptor)
        path = descriptor.get("idb_path", "")
        if not path or os.path.normcase(os.path.abspath(path)) != os.path.normcase(os.path.abspath(self.identity.idb_path)):
            raise RoutingError("INSTANCE_CHANGED", "Nexus record does not match the loaded IDA database.")
        self.runtime_generation = endpoint.generation
        self._descriptor = descriptor
        self._bridge = UnifiedBridge(self, endpoints={self.identity.key: endpoint}, raw_outputs=True)

    def resolve_instance_id(self, value):
        if value != self.identity.key or not self.handle.connected:
            raise RoutingError("INSTANCE_UNAVAILABLE", "This exact Nexus handle is no longer connected.")
        return value

    def execute_python(self, code, target, **kwargs):
        self.resolve_instance_id(target)
        return {"result": self._descriptor}

    def cancel_operation(self, target, operation_id):
        self.resolve_instance_id(target)
        return self.handle.cancel_operation(operation_id)

    async def _execute(self, invocation, code, timeout):
        worker = asyncio.create_task(asyncio.to_thread(
            self.handle.execute_python, code, timeout=timeout,
            operation_id=invocation.operation_id, persist_globals=True,
            filename="<ida-mcp>", operation_label="ida-pro-mcp",
        ))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            invocation.cancelled.set()
            async def drain():
                while not worker.done():
                    with suppress(Exception):
                        await asyncio.to_thread(self.handle.cancel_operation, invocation.operation_id)
                    await asyncio.sleep(0.01)
                with suppress(BaseException):
                    await worker
            await finish_cleanup(asyncio.create_task(drain()))
            raise

    async def request(self, invocation: Invocation, method: str, params: dict):
        self.resolve_instance_id(self.identity.key)
        self._active[invocation.operation_id] = asyncio.current_task()
        try:
            if method in {"tools/call", "resources/read"}:
                return await self._bridge.request(method, params, self.identity.key)
            if method == "output/read":
                return {"text": await self._bridge.download_output(params["output_id"], self.identity.key)}
            if method == "execute_python":
                if not self._analysis_complete:
                    expr = f'__import__("ida_pro_mcp.nexus_guard", fromlist=["analyze"]).analyze({self.runtime_generation!r}, {self.identity.idb_path!r})'
                    result = await self._execute(invocation, expr, 300)
                    if result.get("result") is not True:
                        raise RuntimeError("Initial IDA analysis did not complete")
                    self._analysis_complete = True
                if invocation.cancelled.is_set():
                    raise asyncio.CancelledError()
                return await self._execute(invocation, guarded_expression(params["code"], self.runtime_generation, self.identity.idb_path), params.get("timeout", 360))
            if method == "save_database":
                expr = f'__builtins__["__import__"]("ida_pro_mcp.nexus_guard", fromlist=["save"]).save({self.runtime_generation!r}, {self.identity.idb_path!r}, {self.identity.backend!r})'
                response = await self._execute(invocation, expr, 300)
                if not isinstance(response.get("result"), dict) or "path" not in response["result"]:
                    raise RuntimeError(response.get("stderr") or "IDA save failed")
                return response["result"]
            raise ValueError(f"Unsupported Nexus operation: {method}")
        finally:
            self._active.pop(invocation.operation_id, None)

    async def cancel(self, invocation):
        invocation.cancelled.set()
        task = self._active.get(invocation.operation_id)
        if task:
            task.cancel()

    async def close(self):
        if self._bridge is not None:
            await asyncio.to_thread(self._bridge.shutdown)
        await asyncio.to_thread(self.handle.close, wait_for_database=True)

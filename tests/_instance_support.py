"""Event-controlled backend doubles; all routing stays in production code."""

import asyncio
from copy import deepcopy
from dataclasses import replace
import json

from ida_pro_mcp.instance_contract import BackendIdentity, RoutingError


def identity(key: str, **changes) -> BackendIdentity:
    return replace(BackendIdentity(
        provider="fake", key=key, backend="gui", binary_name=f"{key}.exe",
        binary_path=f"/samples/{key}.exe", idb_path=f"/samples/{key}.i64",
        pid=42, started_at="2026-10-16T00:00:00Z",
    ), **changes)


class FakeSession:
    def __init__(self, provider, record):
        self.provider = provider
        self.identity = record
        self.runtime_generation = record.key
        self.close_count = 0
        self.closed = False
        self.active = {}

    async def request(self, invocation, method, params):
        if self.closed:
            raise RoutingError("INSTANCE_CLOSED", "backend closed")
        self.provider.calls.append((self.identity.key, method, deepcopy(params), invocation.operation_id))
        self.active[invocation.operation_id] = asyncio.current_task()
        try:
            await self.provider.pause(self.identity.key, "request")
            if invocation.cancelled.is_set():
                raise asyncio.CancelledError()
            if method == "output/read":
                return {"text": self.provider.outputs.get(params["output_id"], '{"result":"complete"}')}
            if method == "resources/read":
                return {"contents": [{"uri": params["uri"], "mimeType": "application/json", "text": json.dumps({"backend": self.identity.key})}]}
            if self.provider.result is not None:
                return deepcopy(self.provider.result)
            value = {"backend": self.identity.key}
            return {"content": [{"type": "text", "text": json.dumps(value)}], "structuredContent": value, "isError": False}
        finally:
            self.active.pop(invocation.operation_id, None)

    async def cancel(self, invocation):
        self.provider.cancelled.append((self.identity.key, invocation.operation_id))
        invocation.cancelled.set()
        task = self.active.get(invocation.operation_id)
        if task is not None:
            task.cancel()

    async def close(self):
        await self.provider.pause(self.identity.key, "close")
        if self.identity.key in self.provider.fail_close:
            raise RuntimeError("drain failed")
        self.close_count += 1
        self.closed = True


class FakeProvider:
    name = "fake"

    def __init__(self, records):
        self.records = list(records)
        self.calls = []
        self.sessions = []
        self.cancelled = []
        self.opens = []
        self.outputs = {}
        self.result = None
        self.fail_close = set()
        self.gates = {}
        self.entered = {}

    def block_request(self, key):
        self.block(key, "request")

    def release_request(self, key):
        self.release(key, "request")

    def block(self, key, stage):
        self.gates[(key, stage)] = asyncio.Event()

    def release(self, key, stage):
        self.gates[(key, stage)].set()

    async def wait_entered(self, key, stage):
        event = self.entered.setdefault((key, stage), asyncio.Event())
        await asyncio.wait_for(event.wait(), 3)

    async def pause(self, key, stage):
        self.entered.setdefault((key, stage), asyncio.Event()).set()
        gate = self.gates.get((key, stage))
        if gate is not None:
            await gate.wait()

    async def discover(self):
        return list(self.records)

    async def attach(self, record, invocation):
        await self.pause(record.key, "attach")
        if record not in self.records:
            raise RoutingError("INSTANCE_UNAVAILABLE", "instance vanished")
        session = FakeSession(self, record)
        self.sessions.append(session)
        return session

    async def open_path(self, path, options):
        record = next((r for r in self.records if path in {r.binary_path, r.idb_path}), None)
        if record is None:
            raise FileNotFoundError(path)
        self.opens.append(path)
        await self.pause(record.key, "open")
        session = FakeSession(self, record)
        self.sessions.append(session)
        return session

    async def reference(self, query):
        return f"Reference: {query}"

"""Exact legacy IDA HTTP endpoints behind the common asynchronous router."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
from urllib.parse import quote

from .instance_contract import BackendIdentity, RoutingError, require_instance_id
from .instance_router import finish_cleanup


def load_discovery():
    spec = importlib.util.spec_from_file_location("ida_pro_mcp_discovery", Path(__file__).parent / "ida_mcp/discovery.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProxyProvider:
    name = "proxy"

    def __init__(self, *, endpoint=None, discover=None, extensions=None, timeout=130):
        self.endpoint = endpoint
        self._discover = discover or load_discovery().discover_instances
        self.extensions = set(extensions or ())
        self.timeout = timeout
        self._records = {}

    def _identity(self, record):
        generation = record.get("generation")
        compatible = record.get("identity_version") == 1
        try:
            require_instance_id(generation)
        except RoutingError:
            compatible = False
        key = f"{record['host']}:{record['port']}:{generation}" if compatible else ""
        return BackendIdentity(self.name, key, record.get("backend", "gui"),
                               record.get("binary_name", record.get("binary", "")),
                               record.get("binary_path", ""), record.get("idb_path", ""),
                               int(record.get("pid", 0)), record.get("started_at", ""), compatible)

    async def discover(self):
        records = await asyncio.to_thread(self._discover)
        if self.endpoint:
            host, port = self.endpoint
            records = [r for r in records if (r.get("host"), r.get("port")) == (host, port)]
            if not records:
                try:
                    session = ProxySession({"host": host, "port": port}, self, None)
                    reply = await asyncio.to_thread(session.rpc, "tools/call", {"name": "list_instances", "arguments": {}}, secrets.token_hex(8))
                    records = [{**item, "host": host, "port": port} for item in reply.get("structuredContent", {}).get("instances", [])]
                except (OSError, ValueError, RuntimeError):
                    records = []
        result = []
        for record in records:
            identity = self._identity(record)
            if identity.compatible:
                self._records[identity.key] = dict(record)
            result.append(identity)
        live = {r.key for r in result if r.compatible}
        self._records = {key: record for key, record in self._records.items() if key in live}
        return result

    async def attach(self, identity, invocation):
        record = self._records.get(identity.key)
        if record is None:
            raise RoutingError("INSTANCE_UNAVAILABLE", "The discovered IDA instance disappeared.")
        session = ProxySession(record, self, identity)
        await session.verify_identity()
        return session

    async def open_path(self, path, options):
        if options:
            raise ValueError("GUI proxy open supports a path only")
        normalized = os.path.normcase(os.path.abspath(path))
        matches = [item for item in await self.discover() if item.compatible and normalized in {
            os.path.normcase(os.path.abspath(item.binary_path)), os.path.normcase(os.path.abspath(item.idb_path))}]
        if len(matches) != 1:
            raise RoutingError("INSTANCE_NOT_FOUND", "Open the file in IDA first, then use list_instances; path must match exactly one instance.")
        return await self.attach(matches[0], None)

    async def reference(self, query):
        from ida_nexus import reference
        return await asyncio.to_thread(reference, query)


class ProxySession:
    def __init__(self, record, provider, identity):
        self.record = dict(record)
        self.provider = provider
        self.identity = identity
        self.runtime_generation = record.get("generation", "")
        self.client_id = secrets.token_hex(16)
        self._active = {}
        self._closed = False

    def rpc(self, method, params, request_id):
        connection = http.client.HTTPConnection(self.record["host"], self.record["port"], timeout=self.provider.timeout)
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            request["id"] = request_id
        path = "/mcp"
        if self.provider.extensions:
            path += "?ext=" + ",".join(sorted(self.provider.extensions))
        try:
            connection.request("POST", path, json.dumps(request).encode(), {
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                "Mcp-Session-Id": self.client_id,
            })
            response = connection.getresponse()
            data = response.read(64 * 1024 * 1024 + 1)
            if response.status not in (200, 202, 204):
                raise RuntimeError(f"IDA HTTP {response.status}; request was not retried")
            if request_id is None:
                return None
            if len(data) > 64 * 1024 * 1024:
                raise ValueError("IDA result exceeds 64 MiB")
            reply = json.loads(data)
            if reply.get("id") != request_id:
                raise ValueError("IDA returned a mismatched response ID")
            if "error" in reply:
                error = reply["error"]
                raise RoutingError(error.get("data", {}).get("error_code", "BACKEND_ERROR"), error.get("message", "IDA RPC failed"))
            return reply["result"]
        finally:
            connection.close()

    async def verify_identity(self):
        result = await asyncio.to_thread(self.rpc, "tools/call", {"name": "list_instances", "arguments": {}}, secrets.token_hex(16))
        instances = result.get("structuredContent", {}).get("instances", [])
        if not any(i.get("generation") == self.runtime_generation and i.get("identity_version") == 1 for i in instances):
            raise RoutingError("INSTANCE_CHANGED", "The endpoint now hosts a different IDA database.")

    def _download(self, output_id):
        connection = http.client.HTTPConnection(self.record["host"], self.record["port"], timeout=self.provider.timeout)
        try:
            path = f"/output/{quote(output_id, safe='')}.json?instance_id={self.runtime_generation}"
            connection.request("GET", path)
            response = connection.getresponse()
            data = response.read(64 * 1024 * 1024 + 1)
            if response.status != 200:
                raise RoutingError("OUTPUT_EXPIRED", f"Output unavailable (HTTP {response.status})")
            if len(data) > 64 * 1024 * 1024:
                raise ValueError("Output exceeds 64 MiB")
            return {"text": data.decode("utf-8")}
        finally:
            connection.close()

    async def request(self, invocation, method, params):
        if self._closed:
            raise RoutingError("INSTANCE_CLOSED", "IDA binding has closed")
        if method == "output/read":
            worker = asyncio.create_task(asyncio.to_thread(self._download, params["output_id"]))
        else:
            if method == "save_database":
                method, params = "tools/call", {"name": "idb_save", "arguments": {}}
            if method == "tools/call":
                params = {**params, "arguments": {**params.get("arguments", {}), "instance_id": self.runtime_generation}}
            elif method == "resources/read":
                params = {"uri": params["uri"] + "?instance_id=" + self.runtime_generation}
            else:
                raise RoutingError("UNSUPPORTED_OPERATION", "This legacy backend supports typed tools; use py_eval for Python.")
            worker = asyncio.create_task(asyncio.to_thread(self.rpc, method, params, invocation.operation_id))
        self._active[invocation.operation_id] = worker
        try:
            result = await asyncio.shield(worker)
            if params.get("name") == "idb_save" and (result.get("isError") or not result.get("structuredContent", {}).get("ok")):
                raise RuntimeError("IDA save failed; binding kept open")
            return result
        except asyncio.CancelledError:
            async def drain():
                await self.cancel(invocation)
                with suppress(asyncio.CancelledError):
                    await worker
            await finish_cleanup(asyncio.create_task(drain()))
            raise
        finally:
            self._active.pop(invocation.operation_id, None)

    async def cancel(self, invocation):
        invocation.cancelled.set()
        if invocation.operation_id in self._active:
            with suppress(Exception):
                await asyncio.to_thread(self.rpc, "notifications/cancelled", {"requestId": invocation.operation_id}, None)

    async def close(self):
        if self._active:
            await asyncio.gather(*self._active.values(), return_exceptions=True)
        self._closed = True

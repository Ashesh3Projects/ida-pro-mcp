"""Expose existing supervisor workers through exact public instance bindings."""

import asyncio
from dataclasses import replace
import secrets

from .instance_contract import RoutingError
from .proxy_backend import ProxyProvider, ProxySession


class SupervisorProvider(ProxyProvider):
    name = "supervisor"

    def __init__(self, supervisor, *, extensions=None):
        super().__init__(discover=supervisor.discovery_instances, extensions=extensions,
                         timeout=supervisor.call_timeout)
        self.supervisor = supervisor
        self._owned = {}

    async def discover(self):
        records = await super().discover()
        known = {record.key for record in records}
        for key, session in list(self._owned.items()):
            if session.worker.is_alive() and key not in known:
                records.append(session.identity)
                self._records[key] = session.record
        return records

    async def attach(self, identity, invocation):
        owned = self._owned.get(identity.key)
        if owned is not None and not owned._closed:
            return owned
        return await super().attach(identity, invocation)

    async def open_path(self, path, options):
        worker = await asyncio.to_thread(self.supervisor.open_session, path, **options)
        # Identity comes from the listener, never from the supervisor's private
        # session name or an inferred PID/port combination.
        probe = ProxySession({"host": worker.host, "port": worker.port}, self, None)
        reply = await asyncio.to_thread(probe.rpc, "tools/call", {"name": "list_instances", "arguments": {}}, secrets.token_hex(16))
        rows = reply.get("structuredContent", {}).get("instances", [])
        if len(rows) != 1:
            raise RoutingError("INSTANCE_INCOMPATIBLE", "Worker must expose one database generation; update its plugin.")
        record = {**rows[0], "host": worker.host, "port": worker.port, "backend": worker.backend}
        identity = self._identity(record)
        if not identity.compatible:
            raise RoutingError("INSTANCE_INCOMPATIBLE", "Worker lacks an exact database identity")
        existing = self._owned.get(identity.key)
        if existing is not None and not existing._closed:
            return existing
        session = SupervisorSession(record, self, identity, worker)
        self._records[identity.key] = record
        self._owned[identity.key] = session
        return session


class SupervisorSession(ProxySession):
    def __init__(self, record, provider, identity, worker):
        super().__init__(record, provider, identity)
        self.worker = worker

    async def close(self):
        await super().close()
        supervisor = self.provider.supervisor
        with supervisor._lock:
            if supervisor.sessions.get(self.worker.session_id) is self.worker:
                supervisor._unregister_session_locked(self.worker.session_id)
        if self.worker.owned:
            await asyncio.to_thread(supervisor._terminate_worker, self.worker)
        self.provider._owned.pop(self.identity.key, None)

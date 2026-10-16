"""Opaque, non-reassignable public handles for exact backend incarnations."""

from __future__ import annotations

import secrets
import threading
from typing import Callable

from .instance_contract import (
    BackendIdentity,
    InstanceBinding,
    RoutingError,
    require_instance_id,
)

_STATES = {
    "available",
    "attaching",
    "ready",
    "closing",
    "closed",
    "unavailable",
    "incompatible",
}


class InstanceRegistry:
    def __init__(self, *, id_factory: Callable[[], str] | None = None):
        self._id_factory = id_factory or (lambda: secrets.token_hex(8))
        self._lock = threading.RLock()
        self._bindings: dict[str, InstanceBinding] = {}
        self._incarnations: dict[tuple[str, str], InstanceBinding] = {}
        self._states: dict[str, str] = {}

    def publish(self, identity: BackendIdentity) -> InstanceBinding:
        if not identity.compatible or not identity.key:
            raise RoutingError(
                "INSTANCE_INCOMPATIBLE",
                "Update the IDA plugin: this instance has no verifiable database generation.",
            )
        key = (identity.provider, identity.key)
        with self._lock:
            existing = self._incarnations.get(key)
            if existing is not None:
                return existing
            while True:
                instance_id = require_instance_id(self._id_factory())
                if instance_id not in self._bindings:
                    break
            binding = InstanceBinding(instance_id, identity)
            self._bindings[instance_id] = binding
            self._incarnations[key] = binding
            self._states[instance_id] = "available"
            return binding

    def resolve(self, value: object, *, allow_closing: bool = False) -> InstanceBinding:
        instance_id = require_instance_id(value)
        with self._lock:
            binding = self._bindings.get(instance_id)
            if binding is None:
                raise RoutingError(
                    "INSTANCE_NOT_FOUND",
                    f"Unknown instance_id {instance_id}; call list_instances on this server.",
                )
            state = self._states[instance_id]
            if state in {"closed", "closing"} and not (
                allow_closing and state == "closing"
            ):
                raise RoutingError(
                    "INSTANCE_CLOSED",
                    f"Instance {instance_id} is {state}; rediscover after close completes.",
                )
            if state == "unavailable":
                raise RoutingError(
                    "INSTANCE_UNAVAILABLE",
                    f"Instance {instance_id} is unavailable; explicitly reopen or rediscover.",
                )
            if state == "incompatible":
                raise RoutingError(
                    "INSTANCE_INCOMPATIBLE",
                    f"Instance {instance_id} requires an updated IDA plugin.",
                )
            return binding

    def _owned(self, binding: InstanceBinding) -> None:
        if self._bindings.get(binding.instance_id) is not binding:
            raise RoutingError(
                "INSTANCE_NOT_FOUND", "Binding does not belong to this server."
            )

    def state(self, binding: InstanceBinding) -> str:
        with self._lock:
            self._owned(binding)
            return self._states[binding.instance_id]

    def set_state(self, binding: InstanceBinding, state: str) -> None:
        if state not in _STATES:
            raise ValueError(f"Invalid instance state: {state}")
        with self._lock:
            self._owned(binding)
            previous = self._states[binding.instance_id]
            if previous in {"closed", "unavailable"} and state != previous:
                raise RoutingError(
                    "INSTANCE_CLOSED", "A retired binding cannot be revived."
                )
            if previous == "closing" and state not in {
                "closing",
                "closed",
                "unavailable",
            }:
                raise RoutingError(
                    "INSTANCE_CLOSED", "A closing binding cannot accept work."
                )
            self._states[binding.instance_id] = state

    def retire(self, binding: InstanceBinding, *, state: str = "closed") -> None:
        if state not in {"closed", "unavailable"}:
            raise ValueError("Retirement requires closed or unavailable state")
        with self._lock:
            self._owned(binding)
            self._states[binding.instance_id] = state
            key = (binding.identity.provider, binding.identity.key)
            if self._incarnations.get(key) is binding:
                self._incarnations.pop(key)

    def bindings(self) -> list[InstanceBinding]:
        with self._lock:
            return list(self._incarnations.values())

    def describe(self, binding: InstanceBinding) -> dict:
        with self._lock:
            self._owned(binding)
            identity = binding.identity
            return {
                "instance_id": binding.instance_id,
                "binary_name": identity.binary_name,
                "binary_path": identity.binary_path,
                "idb_path": identity.idb_path,
                "backend": identity.backend,
                "pid": identity.pid,
                "started_at": identity.started_at,
                "status": self._states[binding.instance_id],
            }

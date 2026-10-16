"""Bounded output ownership; no discovery or default-target fallback."""

from collections import OrderedDict
from dataclasses import dataclass
import secrets
import threading

from .instance_contract import InstanceBinding, RoutingError, require_instance_id


@dataclass(frozen=True)
class OutputReference:
    output_id: str
    binding: InstanceBinding
    runtime_generation: str
    backend_output_id: str
    context_id: str


class OutputStore:
    def __init__(self, max_outputs=128):
        self._outputs = OrderedDict()
        self._max = max_outputs
        self._lock = threading.Lock()

    def remember(self, binding, runtime_generation, backend_output_id, context_id):
        output_id = secrets.token_hex(16)
        with self._lock:
            self._outputs[output_id] = OutputReference(
                output_id, binding, runtime_generation, backend_output_id, context_id
            )
            while len(self._outputs) > self._max:
                self._outputs.popitem(last=False)
        return output_id

    def lookup(self, instance_id, output_id):
        require_instance_id(instance_id)
        if not isinstance(output_id, str):
            raise RoutingError("OUTPUT_EXPIRED", "Unknown output_id")
        with self._lock:
            output = self._outputs.get(output_id)
            if output is None:
                raise RoutingError(
                    "OUTPUT_EXPIRED",
                    "Output is unknown or expired; request it again from its instance.",
                )
            if output.binding.instance_id != instance_id:
                raise RoutingError(
                    "OUTPUT_INSTANCE_MISMATCH",
                    "This output belongs to a different instance_id.",
                )
            return output

    def expire(self, instance_id):
        with self._lock:
            self._outputs = OrderedDict(
                (key, value)
                for key, value in self._outputs.items()
                if value.binding.instance_id != instance_id
            )

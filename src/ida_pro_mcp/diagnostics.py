"""Schema-1 diagnostic traces compatible with the existing dashboard and logs."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import threading
import time

from fastmcp.server.middleware import Middleware


class TraceWriter:
    def __init__(self, state_dir: Path | None = None, *, agent=None):
        if state_dir is None:
            from ida_mcp.paths import get_mcp_state_dir

            state_dir = get_mcp_state_dir()
        self.server_id = secrets.token_hex(6)
        self.path = Path(state_dir) / "sessions" / f"{self.server_id}.jsonl"
        self.agent = agent
        self._lock = threading.Lock()

    def emit(self, event: str, **fields):
        record = {
            "schema": 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp_server_id": self.server_id,
            "pid": os.getpid(),
            "event": event,
            "agent": self.agent,
            "session": {"mcp_id": os.environ.get("IDA_MCP_ID")},
            **fields,
        }
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


class RoutingTraceMiddleware(Middleware):
    def __init__(self, writer):
        self.writer = writer

    async def on_call_tool(self, context, call_next):
        call_id = secrets.token_hex(16)
        message = context.message
        name = message.name
        arguments = message.arguments or {}
        fields = {
            "tool": name,
            "call_id": call_id,
            "instance_id": arguments.get("instance_id"),
        }
        meta = getattr(message, "meta", None) or {}
        if self.writer.agent and isinstance(meta, dict):
            field = self.writer.agent + "_session_path"
            value = meta.get(field)
            if isinstance(value, str):
                fields["session"] = {
                    "mcp_id": os.environ.get("IDA_MCP_ID"),
                    field: value,
                }
        self.writer.emit("tool_call", **fields)
        start = time.monotonic()
        try:
            result = await call_next(context)
        except BaseException as error:
            self.writer.emit(
                "tool_error",
                **fields,
                error={"type": type(error).__name__},
                elapsed_ms=(time.monotonic() - start) * 1000,
            )
            raise
        self.writer.emit(
            "tool_error" if result.is_error else "tool_result",
            **fields,
            elapsed_ms=(time.monotonic() - start) * 1000,
        )
        # Resource lifecycle events come from the router, not tool names:
        # attachment, alias reuse and shutdown can happen without management
        # tool calls, and failed close must be reported at the ownership layer.
        return result

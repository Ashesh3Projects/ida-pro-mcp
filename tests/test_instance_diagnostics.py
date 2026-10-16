import asyncio
import json

from fastmcp import Client

from _instance_support import FakeProvider, identity
from ida_pro_mcp.diagnostics import TraceWriter, RoutingTraceMiddleware
from ida_pro_mcp.fastmcp_frontend import create_server
from ida_pro_mcp.instance_router import InstanceRouter


def test_new_trace_is_readable_by_existing_dashboard(tmp_path):
    from ida_mcp.dashboard import _summarize_session

    writer = TraceWriter(tmp_path, agent="test")
    writer.emit("mcp_started", transport="stdio")
    writer.emit(
        "database_opened",
        instance_id="a" * 16,
        target={"idb_path": "a.i64", "backend": "gui"},
    )
    writer.emit("tool_call", tool="decompile", call_id="one")
    writer.emit("tool_result", tool="decompile", call_id="one")
    writer.emit("mcp_stopped")
    summary = _summarize_session(writer.path)
    assert summary.tool_calls == 1 and summary.stopped
    assert summary.agent == "test"
    assert summary.targets[0]["idb_path"] == "a.i64"


def test_middleware_preserves_routing_and_hides_backend_credentials(tmp_path):
    async def scenario():
        provider = FakeProvider([identity("A")])
        provider.credential = "never-log-this-secret"
        writer = TraceWriter(tmp_path, agent="test")
        server = create_server(InstanceRouter(provider), profile={"decompile"})
        server.add_middleware(RoutingTraceMiddleware(writer))
        async with Client(server) as client:
            target = (await client.call_tool("list_instances", {})).data["instances"][
                0
            ]["instance_id"]
            provider.result = {
                "content": [{"type": "text", "text": "failure"}],
                "isError": True,
            }
            await client.call_tool_mcp(
                "decompile", {"addr": "0x1000", "instance_id": target}
            )
        content = writer.path.read_text()
        assert provider.credential not in content
        events = [json.loads(line) for line in content.splitlines()]
        failed = [e for e in events if e["event"] == "tool_error"]
        assert failed[0]["instance_id"] == target
        assert failed[0]["tool"] == "decompile"

    asyncio.run(scenario())

import asyncio

import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.utilities.asgi_transport import StreamingASGITransport

from _instance_support import FakeProvider, identity
from ida_pro_mcp.instance_router import InstanceRouter
from ida_pro_mcp.fastmcp_frontend import create_server


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_shared_connection_runs_and_cancels_instances_independently(mode):
    async def scenario():
        p = FakeProvider([identity("A"), identity("B")])
        server = create_server(
            InstanceRouter(p), extensions=set(), profile={"decompile"}
        )
        app = server.http_app(json_response=False, stateless_http=False)
        headers = []

        async def capture(scope, receive, send):
            if scope["type"] == "http":
                headers.append(dict(scope["headers"]))
            await app(scope, receive, send)

        def factory(**kwargs):
            return httpx2.AsyncClient(
                transport=StreamingASGITransport(capture), **kwargs
            )

        transport = StreamableHttpTransport(
            "http://probe.local/mcp", httpx_client_factory=factory
        )
        async with app.router.lifespan_context(app):
            async with Client(transport, mode=mode) as client:
                result = await client.call_tool("list_instances", {})
                a, b = [r["instance_id"] for r in result.data["instances"]]
                p.result = {
                    "content": [{"type": "text", "text": "fixture"}],
                    "structuredContent": {"addr": "0x1000", "code": "fixture"},
                    "isError": False,
                }
                p.block_request("A")
                slow = asyncio.create_task(
                    client.call_tool_mcp(
                        "decompile", {"instance_id": a, "addr": "0x1000"}
                    )
                )
                await p.wait_entered("A", "request")
                fast = await asyncio.wait_for(
                    client.call_tool("decompile", {"instance_id": b, "addr": "0x1000"}),
                    2,
                )
                assert fast.meta["ida_mcp"]["instance_id"] == b and not slow.done()
                slow.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await slow
                for _ in range(100):
                    if p.cancelled:
                        break
                    await asyncio.sleep(0.01)
                assert [key for key, _ in p.cancelled] == ["A"]
                assert (
                    await client.call_tool(
                        "decompile", {"instance_id": b, "addr": "0x1000"}
                    )
                ).meta["ida_mcp"]["instance_id"] == b
                if mode == "auto":
                    assert client.protocol_version == "2026-07-28"
                    assert not any(b"mcp-session-id" in h for h in headers)

    asyncio.run(scenario())

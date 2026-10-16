"""Legacy proxy advertises its installed explicit catalog without a backend."""
import asyncio
from copy import deepcopy
from fastmcp import Client
from ida_pro_mcp.server import create_proxy_server
from ida_pro_mcp.tool_catalog import get_ida_tools, fork_schema_generator


def test_offline_proxy_catalog_requires_ids_and_preserves_schemas():
    async def scenario():
        async with Client(create_proxy_server(extensions={"dbg"})) as client:
            listed = {tool.name: tool for tool in await client.list_tools()}
            for expected in get_ida_tools(fork_schema_generator(), {"dbg"}):
                actual = listed[expected["name"]]
                schema = deepcopy(actual.input_schema)
                schema["properties"].pop("instance_id")
                schema["required"].remove("instance_id")
                assert schema == expected["inputSchema"]
                assert actual.output_schema == expected["outputSchema"]
            assert "select_instance" not in listed
            assert "instance_status" in listed
    asyncio.run(scenario())


def test_offline_proxy_ping_and_repeated_catalog_do_not_contact_ida(monkeypatch):
    from ida_pro_mcp import proxy_backend
    monkeypatch.setattr(proxy_backend.http.client, "HTTPConnection", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("network used")))
    async def scenario():
        async with Client(create_proxy_server(), mode="legacy") as client:
            first = await client.list_tools()
            assert await client.ping()
            second = await client.list_tools()
            assert [t.model_dump() for t in first] == [t.model_dump() for t in second]
            error = await client.call_tool_mcp("decompile", {"addr":"0x1000"})
            assert error.is_error
    asyncio.run(scenario())

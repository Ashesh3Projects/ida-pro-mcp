import asyncio
from copy import deepcopy

from fastmcp import Client

from _instance_support import FakeProvider, identity
from ida_pro_mcp.instance_router import InstanceRouter
from ida_pro_mcp.fastmcp_frontend import create_server
from ida_pro_mcp.tool_catalog import get_ida_tools, fork_schema_generator


def test_catalog_preserves_typed_schemas_and_requires_identity():
    async def scenario():
        provider = FakeProvider([identity("A")])
        server = create_server(InstanceRouter(provider), extensions={"dbg"}, profile=None)
        async with Client(server) as client:
            listed = {tool.name: tool for tool in await client.list_tools()}
            catalog = get_ida_tools(fork_schema_generator(), {"dbg"})
            for expected in catalog:
                actual = listed[expected["name"]]
                schema = deepcopy(actual.input_schema)
                assert schema["properties"].pop("instance_id")["type"] == "string"
                schema["required"].remove("instance_id")
                assert schema == expected["inputSchema"]
                assert actual.output_schema == expected["outputSchema"]
            assert len(catalog) == 88
            assert "select_instance" not in listed
            assert "set_current" not in listed["open_database"].input_schema["properties"]
            result = await client.call_tool_mcp("decompile", {"addr": "0x1000"})
            assert result.is_error
            assert result.meta["ida_mcp"]["error_code"] == "INSTANCE_ID_REQUIRED"
            assert provider.calls == [] and provider.sessions == []
    asyncio.run(scenario())


def test_profile_disabled_calls_fail_and_global_discovery_stays_available():
    async def scenario():
        p = FakeProvider([identity("A")])
        server = create_server(InstanceRouter(p), extensions=set(), profile={"decompile"})
        async with Client(server) as client:
            listed = {t.name for t in await client.list_tools()}
            assert "decompile" in listed and "py_eval" not in listed
            result = await client.call_tool_mcp("list_instances", {})
            target = result.structured_content["instances"][0]["instance_id"]
            error = await client.call_tool_mcp("py_eval", {"instance_id": target, "code": "1"})
            assert error.is_error and p.calls == []
    asyncio.run(scenario())

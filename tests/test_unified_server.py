"""The composed frontend stays IDA-free and preserves native contracts."""
import asyncio
import json
import os
import subprocess
import sys
import pytest
from fastmcp import Client
from _instance_support import FakeProvider, identity
from ida_pro_mcp.unified_server import configure_server


def test_offline_catalog_never_imports_ida_or_official_server(tmp_path):
    code = """
import asyncio, importlib.abc, json, sys
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, *args):
        if fullname in {'idapro','idaapi','idc','ida_kernwin','ida_pro_mcp.ida_mcp','ida_mcp.mcp'}:
            raise AssertionError('forbidden import: ' + fullname)
sys.meta_path.insert(0, Guard())
from ida_pro_mcp.unified_server import configure_server
from fastmcp import Client
async def main():
    async with Client(configure_server(extensions={'dbg'})) as client:
        tools = await client.list_tools()
        assert len(tools) == 97, len(tools)
        assert 'select_instance' not in {t.name for t in tools}
        print(json.dumps({'tools':len(tools)}))
asyncio.run(main())
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                            env={**os.environ, "IDA_NEXUS_STATE_DIR": str(tmp_path / "nexus")},
                            text=True, capture_output=True, timeout=25)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["tools"] == 97


def test_native_envelope_and_errors_are_not_double_wrapped():
    async def scenario():
        p = FakeProvider([identity("A")])
        async with Client(configure_server(provider=p)) as client:
            target = (await client.call_tool("list_instances", {})).data["instances"][0]["instance_id"]
            p.result = {"content": [{"type":"text", "text":"backend error"}], "isError":True, "_meta":{"test":1}}
            result = await client.call_tool_mcp("decompile", {"addr":"0x1000", "instance_id":target})
            assert result.is_error and result.content[0].text == "backend error"
            assert result.meta["test"] == 1
            assert result.meta["ida_mcp"]["instance_id"] == target
    asyncio.run(scenario())


def test_resource_routing_preserves_identity_uri():
    async def scenario():
        p = FakeProvider([identity("A")])
        async with Client(configure_server(provider=p)) as client:
            target = (await client.call_tool("list_instances", {})).data["instances"][0]["instance_id"]
            uri = f"ida://idb/metadata?instance_id={target}"
            result = await client.read_resource(uri)
            assert str(result[0].uri) == uri
            assert json.loads(result[0].text)["backend"] == "A"
            with pytest.raises(Exception):
                await client.read_resource("ida://idb/metadata")
    asyncio.run(scenario())


def test_unknown_extensions_and_profile_fail():
    with pytest.raises(ValueError):
        configure_server(extensions={"missing"})
    with pytest.raises(ValueError):
        configure_server(profile={"dbg_start"})

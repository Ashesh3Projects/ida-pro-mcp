"""Subprocess acceptance helper; caller must provide an owned fixture copy."""

import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

root = Path(__file__).resolve().parents[1]
fixture = Path(sys.argv[1]).resolve()


async def start(stack, agent):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_pro_mcp", "stdio", "--agent", agent],
        env=dict(os.environ),
        cwd=str(root),
    )
    streams = await stack.enter_async_context(stdio_client(params))
    session = await stack.enter_async_context(ClientSession(*streams))
    await session.initialize()
    return session


async def call(session, name, args):
    result = await session.call_tool(name, args)
    if result.isError:
        raise RuntimeError((name, result))
    return result


def data(result):
    if result.structuredContent is not None:
        return result.structuredContent
    return json.loads(result.content[0].text)


async def main():
    async with AsyncExitStack() as stack:
        a = await start(stack, "acceptance-a")
        b = await start(stack, "acceptance-b")
        listing = await a.list_tools()
        names = {t.name for t in listing.tools}
        assert len(names) == 73, names
        assert {
            "decompile",
            "execute_python",
            "open_database",
            "reference",
            "read_output",
        } <= names
        print("offline_catalog", len(names), flush=True)
        refs = await call(a, "reference", {"query": "decompile function"})
        assert "IDA Domain API reference" in refs.content[0].text
        print("offline_reference", True, flush=True)
        targets = [
            data(await call(s, "open_database", {"path": str(fixture)}))["instance_id"]
            for s in (a, b)
        ]
        health = data(await call(a, "server_health", {"instance_id": targets[0]}))
        assert health["status"] == "ok", health
        print("unified_typed_health", True, flush=True)
        value = data(
            await call(
                a,
                "py_eval",
                {"code": "value=123\ndef callback(): return value\ncallback()"},
            )
        )
        assert value["result"] == "123", value
        assert (
            data(await call(a, "py_eval", {"code": "value=124;callback()"}))["result"]
            == "124"
        )
        assert (
            data(
                await call(b, "py_eval", {"code": "globals().get('value','isolated')"})
            )["result"]
            == "isolated"
        )
        print("typed_clients_isolated", True, flush=True)
        result = data(await call(a, "execute_python", {"code": "[1,2,3]"}))
        assert result["result"] == [1, 2, 3], result
        functions = data(await call(a, "list_funcs", {"queries": {"count": 3}}))
        addr = functions["result"][0]["data"][0]["addr"]
        decomp = data(await call(a, "decompile", {"addr": addr, "max_lines": 2}))
        assert "cursor" in decomp, decomp
        print("paginated_decompile", decomp.get("line_count"), flush=True)
        large = await call(a, "py_eval", {"code": "'x'*120000"})
        payload = large.model_dump(by_alias=True)
        output_id = payload["_meta"]["ida_mcp"]["output_id"]
        assert "download_url" not in payload["_meta"]["ida_mcp"]
        full = []
        offset = 0
        while True:
            chunk = data(
                await call(
                    a,
                    "read_output",
                    {"output_id": output_id, "offset": offset, "limit": 32000},
                )
            )
            full.append(chunk["text"])
            if chunk["next_offset"] is None:
                break
            offset = chunk["next_offset"]
        assert json.loads("".join(full))["result"] == "x" * 120000
        print("complete_output", 120000, flush=True)
        resource = await a.read_resource("ida://idb/metadata")
        assert resource.contents
        print("resources", True, flush=True)
        cancel_id = a._request_id
        pending = asyncio.create_task(
            a.call_tool(
                "execute_python", {"code": "import time\nwhile True: time.sleep(0.02)"}
            )
        )
        await asyncio.sleep(1)
        await a.send_notification(
            types.ClientNotification(
                types.CancelledNotification(
                    params=types.CancelledNotificationParams(requestId=cancel_id)
                )
            )
        )
        pending.cancel()
        try:
            await pending
        except asyncio.CancelledError:
            pass
        assert data(await call(a, "py_eval", {"code": "40+2"}))["result"] == "42"
        print("official_cancel_then_typed", True, flush=True)
        cancel_id = a._request_id
        pending = asyncio.create_task(
            a.call_tool(
                "py_eval", {"code": "import time\nwhile True: time.sleep(0.02)"}
            )
        )
        await asyncio.sleep(1)
        await a.send_notification(
            types.ClientNotification(
                types.CancelledNotification(
                    params=types.CancelledNotificationParams(requestId=cancel_id)
                )
            )
        )
        pending.cancel()
        try:
            await pending
        except asyncio.CancelledError:
            pass
        assert data(await call(a, "execute_python", {"code": "40+2"}))["result"] == 42
        print("typed_cancel_then_official", True, flush=True)
        await call(a, "close_database", {"instance_id": targets[0]})
        assert data(await call(b, "py_eval", {"code": "21*2"}))["result"] == "42"
        print("peer_after_close", True, flush=True)
        await call(b, "close_database", {"instance_id": targets[1]})
    print("PASS", flush=True)


asyncio.run(asyncio.wait_for(main(), 120))

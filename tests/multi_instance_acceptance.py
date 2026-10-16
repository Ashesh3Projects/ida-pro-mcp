"""Live acceptance against two explicitly owned fixture copies."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=["headless", "gui", "supervisor"], default="headless"
    )
    parser.add_argument("--fixture-a", required=True)
    parser.add_argument("--fixture-b", required=True)
    args = parser.parse_args()
    paths = [str(Path(args.fixture_a).resolve()), str(Path(args.fixture_b).resolve())]
    assert paths[0] != paths[1]
    assert all(Path(path).is_file() for path in paths)
    command = (
        ["-m", "ida_pro_mcp.idalib_supervisor", "--stdio"]
        if args.mode == "supervisor"
        else ["-m", "ida_pro_mcp", "stdio", "--ext", "dbg"]
    )
    transport = StdioTransport(sys.executable, command, env=dict(os.environ))
    async with Client(transport, timeout=420) as client:

        async def call(name, **arguments):
            result = await client.call_tool_mcp(name, arguments)
            if result.is_error:
                raise RuntimeError(f"{name}: {result.content}")
            return result.structured_content or json.loads(result.content[0].text)

        names = {tool.name for tool in await client.list_tools()}
        assert "select_instance" not in names
        print(
            json.dumps(
                {
                    "phase": "catalog",
                    "tools": len(names),
                    "protocol": client.protocol_version,
                }
            ),
            flush=True,
        )
        missing = await client.call_tool_mcp("decompile", {"addr": "0x1000"})
        assert missing.is_error
        targets = []
        for path in paths:
            opened = await call("open_database", path=path)
            targets.append(opened["instance_id"])
            print(
                json.dumps(
                    {
                        "phase": "opened",
                        "instance_id": opened["instance_id"],
                        "backend": opened["backend"],
                        "path": opened["idb_path"],
                    }
                ),
                flush=True,
            )
        a, b = targets
        assert a != b
        health = await asyncio.gather(
            *(call("server_health", instance_id=t) for t in targets)
        )
        assert health[0]["idb_path"] != health[1]["idb_path"], health
        for index, target in enumerate(targets):
            result = await call(
                "py_eval",
                instance_id=target,
                code=f"marker={index + 100}\ndef callback(): return marker\ncallback()",
            )
            assert result["result"] == str(index + 100)
        values = await asyncio.gather(
            *(call("py_eval", instance_id=t, code="callback()") for t in targets)
        )
        assert [r["result"] for r in values] == ["100", "101"]
        functions = await call("list_funcs", instance_id=a, queries={"count": 2})
        addr = functions["result"][0]["data"][0]["addr"]
        decompiled = await call("decompile", instance_id=a, addr=addr)
        assert decompiled.get("code"), decompiled
        old_comments = []
        for index, target in enumerate(targets):
            result = await call("py_eval", instance_id=target, code=f"import ida_bytes, ida_ida\ne=ida_ida.inf_get_min_ea()\nold_comment=ida_bytes.get_cmt(e, False)\nida_bytes.set_cmt(e, 'instance-test-{index}', False)\nold_comment")
            old_comments.append(result["result"])
        for index, target in enumerate(targets):
            result = await call("py_eval", instance_id=target, code="ida_bytes.get_cmt(e, False)")
            assert result["result"] == f"instance-test-{index}"
            await call("py_eval", instance_id=target, code="ida_bytes.set_cmt(e, old_comment or '', False)")
        if args.mode != "supervisor":
            result = await call("execute_python", instance_id=a, code="[1,2,3]")
            assert result["result"] == [1, 2, 3], result
        marker_file = Path(paths[0]).parent / "call-entered.txt"
        marker_file.unlink(missing_ok=True)
        slow = asyncio.create_task(
            call(
                "py_eval",
                instance_id=a,
                code=f"from pathlib import Path\nimport time\nPath({str(marker_file)!r}).write_text('ready')\ntime.sleep(4)\n42",
            )
        )
        async with asyncio.timeout(30):
            while not marker_file.exists():
                await asyncio.sleep(0.05)
        peer = await asyncio.wait_for(
            call("py_eval", instance_id=b, code="callback()"), 3
        )
        assert peer["result"] == "101" and not slow.done()
        assert (await slow)["result"] == "42"
        print(
            json.dumps({"phase": "parallel", "separate_python_state": True}), flush=True
        )
        for tool in ("py_eval", "execute_python") if args.mode != "supervisor" else ("py_eval",):
            cancel_marker = Path(paths[0]).parent / f"cancel-{tool}.txt"
            cancel_marker.unlink(missing_ok=True)
            pending = asyncio.create_task(call(tool, instance_id=a, code=f"from pathlib import Path\nimport time\nPath({str(cancel_marker)!r}).write_text('ready')\nwhile True: time.sleep(0.02)"))
            async with asyncio.timeout(30):
                while not cancel_marker.exists():
                    await asyncio.sleep(0.05)
            pending.cancel()
            try:
                await pending
            except asyncio.CancelledError:
                pass
            peer = await asyncio.wait_for(call("py_eval", instance_id=b, code="callback()"), 5)
            assert peer["result"] == "101"
            recovered = await asyncio.wait_for(call("py_eval", instance_id=a, code="40+2"), 15)
            assert recovered["result"] == "42"
        print(json.dumps({"phase":"cancelled", "backend_usable_after_cancel":True, "reversible_edits_isolated":True}), flush=True)
        large = await client.call_tool_mcp(
            "py_eval", {"instance_id": a, "code": "'x'*120000"}
        )
        output_id = large.meta["ida_mcp"]["output_id"]
        wrong = await client.call_tool_mcp(
            "read_output", {"instance_id": b, "output_id": output_id}
        )
        assert wrong.is_error
        chunk = await call(
            "read_output", instance_id=a, output_id=output_id, limit=32000
        )
        assert len(chunk["text"]) == 32000 and chunk["next_offset"] == 32000
        resource = await client.read_resource(f"ida://idb/metadata?instance_id={a}")
        assert resource
        await call("save_database", instance_id=a)
        await call("close_database", instance_id=a)
        stale = await client.call_tool_mcp("py_eval", {"instance_id": a, "code": "1"})
        assert stale.is_error
        assert (await call("py_eval", instance_id=b, code="callback()"))[
            "result"
        ] == "101"
        reopened = await call("open_database", path=paths[0])
        assert reopened["instance_id"] != a
        await call("close_database", instance_id=reopened["instance_id"])
        await call("close_database", instance_id=b)
        print(
            json.dumps(
                {
                    "phase": "PASS",
                    "mode": args.mode,
                    "instances": targets,
                    "output_ownership": True,
                    "stale_ids": True,
                    "peer_close": True,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    asyncio.run(main())

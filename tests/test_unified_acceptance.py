"""Opt-in live acceptance; always copy fixtures and isolate all worker state."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("IDA_MCP_RUN_INTEGRATION") != "1",
    reason="Set IDA_MCP_RUN_INTEGRATION=1 with a licensed IDA 9.4 runtime",
)
def test_unified_stdio_fixture(tmp_path):
    """Typed and official APIs share a database, cancel cleanly, and preserve peers."""
    root = Path(__file__).resolve().parents[1]
    fixture = tmp_path / "typed_fixture.elf"
    shutil.copy2(root / "tests/typed_fixture.elf", fixture)
    env = dict(os.environ)
    env.update(
        IDA_NEXUS_STATE_DIR=str(tmp_path / "nexus"),
        IDA_MCP_STATE_DIR=str(tmp_path / "mcp"),
        IDAUSR=str(tmp_path / "ida-user"),
        PYTHONPATH=str(root / "src"),
        PYTHONUTF8="1",
    )
    Path(env["IDAUSR"]).mkdir()
    # Only license files are copied; existing plugins, databases and registries
    # are never read or used by the worker. No license contents are logged.
    original_idausr = os.environ.get("IDAUSR", "").split(os.pathsep)[0]
    license_root = (
        Path(original_idausr)
        if original_idausr
        else (
            Path(os.environ["APPDATA"]) / "Hex-Rays/IDA Pro"
            if os.name == "nt"
            else Path.home() / ".idapro"
        )
    )
    for license_file in license_root.glob("*.hexlic"):
        shutil.copy2(license_file, Path(env["IDAUSR"]) / license_file.name)
    result = subprocess.run(
        [sys.executable, str(root / "tests/unified_acceptance.py"), str(fixture)],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_unified_http_discovery_without_ida(tmp_path):
    """A real HTTP session sees the combined catalog before any database opens."""
    import socket
    import time

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = dict(
        os.environ,
        IDA_NEXUS_STATE_DIR=str(tmp_path / "nexus"),
        IDA_MCP_STATE_DIR=str(tmp_path / "mcp"),
    )
    log_path = tmp_path / "server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "ida_pro_mcp", "http", "--port", str(port)],
            env=env,
            cwd=tmp_path,
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert process.poll() is None, log_path.read_text()
                    if time.monotonic() >= deadline:
                        raise AssertionError("HTTP server did not start")
                    time.sleep(0.05)

            async def check():
                async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (
                    read,
                    write,
                    _,
                ):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        names = {tool.name for tool in tools.tools}
                        assert len(names) == 73
                        assert {
                            "reference",
                            "decompile",
                            "execute_python",
                            "read_output",
                        } <= names
                        result = await session.call_tool(
                            "reference", {"query": "decompile"}
                        )
                        assert not result.isError

            asyncio.run(check())
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

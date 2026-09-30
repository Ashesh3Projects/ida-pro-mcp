"""Unified command routing and installed plugin bootstrap regressions."""

from __future__ import annotations

import importlib
import subprocess
import sys
from types import SimpleNamespace

import pytest


def cli_module():
    try:
        return importlib.import_module("ida_pro_mcp.cli")
    except ModuleNotFoundError:
        pytest.fail("Unified CLI has not been implemented")


def test_default_cli_starts_unified_stdio(monkeypatch):
    cli = cli_module()
    received = []
    adapter = SimpleNamespace(serve_stdio=lambda **kw: received.append(kw))
    monkeypatch.setattr(cli, "_configure_unified", lambda **kw: (adapter, {}))
    assert cli.main([]) == 0
    assert received == [{"database": None, "agent": None, "idle_timeout": None}]


def test_stdio_propagates_database_agent_and_extension(monkeypatch):
    cli = cli_module()
    calls = []
    configuration = []

    def configure(**kwargs):
        configuration.append(kwargs)
        return SimpleNamespace(serve_stdio=lambda **kw: calls.append(kw)), {}

    monkeypatch.setattr(cli, "_configure_unified", configure)
    assert (
        cli.main(
            ["stdio", "--database", "sample.i64", "--agent", "codex", "--ext", "dbg"]
        )
        == 0
    )
    assert configuration[0]["extensions"] == {"dbg"}
    assert calls[0]["database"] == "sample.i64"
    assert calls[0]["agent"] == "codex"
    assert calls[0]["idle_timeout"] is None


def test_idle_release_cannot_expire_during_typed_calls(monkeypatch):
    cli = cli_module()
    monkeypatch.setattr(
        cli,
        "_configure_unified",
        lambda **kw: pytest.fail("unsupported lease policy initialized"),
    )
    with pytest.raises(SystemExit) as error:
        cli.main(["stdio", "--idle-timeout", "30"])
    assert error.value.code == 2


def test_legacy_flags_keep_original_route(monkeypatch):
    cli = cli_module()
    received = []
    monkeypatch.setattr(cli, "_legacy", lambda args: received.append(args) or 0)
    assert cli.main(["--ida-rpc", "http://127.0.0.1:13338"]) == 0
    assert received == [["--ida-rpc", "http://127.0.0.1:13338"]]


def test_diagnostics_routes_without_loading_unified_server(monkeypatch):
    cli = cli_module()
    received = []
    monkeypatch.setattr(
        cli, "_diagnostic", lambda command, args: received.append((command, args)) or 0
    )
    monkeypatch.setattr(
        cli, "_configure_unified", lambda **kw: pytest.fail("server initialized")
    )
    assert cli.main(["logs", "--output", "support.zip"]) == 0
    assert received == [("logs", ["--output", "support.zip"])]


def test_cli_help_does_not_import_ida(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-m", "ida_pro_mcp", "--help"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    assert "dashboard" in completed.stdout
    assert "legacy" in completed.stdout
    assert "stdio" in completed.stdout


def test_unified_config_uses_this_package_entry(monkeypatch):
    cli = cli_module()
    monkeypatch.setattr(cli, "_python_executable", lambda: "python-for-fork")
    config = cli.unified_config("codex")
    assert config["command"] == "python-for-fork"
    assert config["args"] == ["-m", "ida_pro_mcp", "stdio", "--agent", "codex"]
    assert "ida_mcp" not in config["args"]


def test_unknown_extensions_and_invalid_timeout_rejected():
    cli = cli_module()
    for args in (
        ["stdio", "--ext", "bad"],
        ["stdio", "--idle-timeout", "-2"],
        ["stdio", "--idle-timeout", "nan"],
    ):
        with pytest.raises(SystemExit) as error:
            cli.main(args)
        assert error.value.code == 2

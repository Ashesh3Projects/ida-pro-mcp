"""The installed GUI loader must use the canonical fork package."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from ida_pro_mcp import installer


def test_installer_provides_canonical_package_and_runtime_manifest(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(installer, "_get_ida_user_dir", lambda: str(tmp_path))
    installer.install_ida_plugin(quiet=True)
    plugins = tmp_path / "plugins"
    assert (plugins / "ida_pro_mcp" / "__init__.py").is_file()
    assert (plugins / "ida_pro_mcp" / "bridge_runtime.py").is_file()
    manifest = json.loads((plugins / "ida-pro-mcp-runtime.json").read_text())
    assert Path(manifest["python"]).resolve() == Path(sys.executable).resolve()
    assert (
        Path(manifest["package_root"]).resolve()
        == Path(installer.SCRIPT_DIR).parent.resolve()
    )
    assert "token" not in manifest


def test_uninstall_removes_canonical_package_but_preserves_other_plugin(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(installer, "_get_ida_user_dir", lambda: str(tmp_path))
    installer.install_ida_plugin(quiet=True)
    other = tmp_path / "plugins" / "other_plugin.py"
    other.write_text("# unrelated")
    installer.install_ida_plugin(uninstall=True, quiet=True)
    assert not (tmp_path / "plugins" / "ida_pro_mcp").exists()
    assert not (tmp_path / "plugins" / "ida-pro-mcp-runtime.json").exists()
    assert other.read_text() == "# unrelated"


def test_package_loader_keeps_official_namespace_intact(monkeypatch):
    loader_path = Path(installer.IDA_PLUGIN_LOADER)
    fake_idaapi = ModuleType("idaapi")
    fake_idaapi.Form = SimpleNamespace
    fake_idaapi.action_handler_t = object
    fake_idaapi.plugin_t = object
    fake_idaapi.PLUGIN_KEEP = 0
    fake_kernwin = ModuleType("ida_kernwin")
    fake_kernwin.UI_Hooks = object
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", fake_kernwin)
    monkeypatch.setitem(sys.modules, "ida_netnode", ModuleType("ida_netnode"))
    official = ModuleType("ida_mcp")
    monkeypatch.setitem(sys.modules, "ida_mcp", official)
    spec = importlib.util.spec_from_file_location("_gui_loader_test", loader_path)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    seen = []
    fake_server = SimpleNamespace(serve=lambda *a, **kw: seen.append((a, kw)))
    fork_package = ModuleType("ida_pro_mcp.ida_mcp")
    fork_package.MCP_SERVER = fake_server
    fork_package.IdaMcpHttpRequestHandler = object
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp", fork_package)
    hooks = ModuleType("ida_pro_mcp.ida_mcp.instance_hooks")
    hooks.install_instance_hooks = lambda callback=None: None
    hooks.activate_database = lambda: None
    dispatch = ModuleType("ida_pro_mcp.ida_mcp.instance_dispatch")
    dispatch.install_instance_dispatch = lambda server: None
    monkeypatch.setitem(sys.modules, hooks.__name__, hooks)
    monkeypatch.setitem(sys.modules, dispatch.__name__, dispatch)
    monkeypatch.setattr(loader, "unload_package", lambda name: seen.append(name))
    instance = loader.MCP()
    instance.host = "127.0.0.1"
    instance.port = 13337
    instance.mcp = None
    monkeypatch.setattr(instance, "_register_instance", lambda port: None)
    instance._start_server()
    assert instance.mcp is fake_server
    assert sys.modules["ida_mcp"] is official
    assert "ida_mcp" not in seen


def test_runtime_paths_prefer_pinned_matching_abi(tmp_path, monkeypatch):
    import importlib.util
    import sys
    from types import ModuleType, SimpleNamespace

    fake_idaapi = ModuleType("idaapi")
    fake_idaapi.Form = SimpleNamespace
    fake_idaapi.action_handler_t = object
    fake_idaapi.plugin_t = object
    fake_idaapi.PLUGIN_KEEP = 0
    fake_kernwin = ModuleType("ida_kernwin")
    fake_kernwin.UI_Hooks = object
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", fake_kernwin)
    monkeypatch.setitem(sys.modules, "ida_netnode", ModuleType("ida_netnode"))
    spec = importlib.util.spec_from_file_location(
        "_loader_paths_test", installer.IDA_PLUGIN_LOADER
    )
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    pinned = tmp_path / "pinned"
    pinned.mkdir()
    old = tmp_path / "old"
    old.mkdir()
    (tmp_path / "ida-pro-mcp-runtime.json").write_text(
        json.dumps(
            {
                "package_root": str(Path(installer.SCRIPT_DIR).parent),
                "python_version": list(sys.version_info[:2]),
                "site_packages": [str(pinned)],
            }
        )
    )
    monkeypatch.setattr(loader, "__file__", str(tmp_path / "ida_mcp.py"))
    monkeypatch.setattr(sys, "path", [str(old), *sys.path])
    loader._configure_runtime_paths()
    assert sys.path.index(str(pinned)) < sys.path.index(str(old))


def test_non_object_plugin_manifest_does_not_break_discovery(tmp_path):
    from ida_pro_mcp.official_adapter import _canonical_gui_plugin_installed
    for document in ("[]", "null", '"invalid"'):
        (tmp_path / "ida-pro-mcp-runtime.json").write_text(document)
        assert _canonical_gui_plugin_installed(tmp_path) is False


def test_installer_honors_explicit_idausr(tmp_path, monkeypatch):
    from ida_pro_mcp import installer
    primary=tmp_path/"custom-user"
    secondary=tmp_path/"fallback"
    monkeypatch.setenv("IDAUSR",str(primary)+os.pathsep+str(secondary))
    assert Path(installer._get_ida_user_dir()) == primary


def test_mismatched_abi_manifest_does_not_load_external_binary_packages(tmp_path, monkeypatch):
    """A GUI on Python 3.11 must not import a client's Python 3.12 site-packages."""
    fake_idaapi = ModuleType("idaapi")
    fake_idaapi.Form = SimpleNamespace
    fake_idaapi.action_handler_t = object
    fake_idaapi.plugin_t = object
    fake_idaapi.PLUGIN_KEEP = 0
    fake_kernwin = ModuleType("ida_kernwin")
    fake_kernwin.UI_Hooks = object
    monkeypatch.setitem(sys.modules,"idaapi",fake_idaapi)
    monkeypatch.setitem(sys.modules,"ida_kernwin",fake_kernwin)
    monkeypatch.setitem(sys.modules,"ida_netnode",ModuleType("ida_netnode"))
    spec=importlib.util.spec_from_file_location("_loader_abi_test",installer.IDA_PLUGIN_LOADER)
    loader=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    external=tmp_path/"other-python-site-packages"
    external.mkdir()
    (tmp_path/"ida-pro-mcp-runtime.json").write_text(json.dumps({
        "python_version":[3,99],"site_packages":[str(external)]
    }))
    monkeypatch.setattr(loader,"__file__",str(tmp_path/"ida_mcp.py"))
    monkeypatch.setattr(sys,"path",list(sys.path))
    loader._configure_runtime_paths()
    assert str(external) not in sys.path

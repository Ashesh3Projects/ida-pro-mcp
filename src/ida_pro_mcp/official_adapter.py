"""Narrow compatibility contract for the pinned official MCP / ZeroMCP releases.

Public ``tool`` and ``resource`` registration retain official execution and
tracing. These two result formatters and schema lookup are the only adapted
ZeroMCP internals: the fork already returns complete MCP result envelopes.
"""

import json
import sys
from copy import deepcopy
from importlib.metadata import distributions, version
from pathlib import Path


def _canonical_gui_plugin_installed(plugins: Path) -> bool:
    """Recognize only a current canonical loader with its pinned Nexus runtime."""
    source = Path(__file__).resolve().parent
    try:
        document = json.loads(
            (plugins / "ida-pro-mcp-runtime.json").read_text(encoding="utf-8")
        )
        if not isinstance(document, dict):
            return False
        if document.get("python_version") != list(sys.version_info[:2]):
            return False
        if not Path(document["python"]).is_file():
            return False
        roots = document["site_packages"]
        if not isinstance(roots, list) or not all(
            isinstance(root, str) for root in roots
        ):
            return False
        for name in ("__init__.py", "bridge_runtime.py"):
            if (plugins / "ida_pro_mcp" / name).read_bytes() != (
                source / name
            ).read_bytes():
                return False
        if (plugins / "ida_mcp.py").read_bytes() != (
            source / "ida_mcp.py"
        ).read_bytes():
            return False
        if not (
            Path(document["package_root"]) / "ida_pro_mcp" / "__init__.py"
        ).is_file():
            return False
        return any(
            package.metadata.get("Name", "").replace("_", "-").lower() == "ida-nexus"
            and package.version == "0.13.0"
            and Path(package.locate_file("ida_nexus/plugin.py")).is_file()
            for package in distributions(path=roots)
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False

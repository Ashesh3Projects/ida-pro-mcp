"""The proxy must advertise usable schemas before any IDA process starts."""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from ida_pro_mcp import server


class OfflineToolCatalogTests(unittest.TestCase):
    def setUp(self):
        self.previous_extensions = getattr(server.mcp._enabled_extensions, "data", set())
        server.mcp._enabled_extensions.data = set()

    def tearDown(self):
        server.mcp._enabled_extensions.data = self.previous_extensions

    def list_tools(self):
        response = server.dispatch_proxy(
            {"jsonrpc": "2.0", "id": "offline-catalog", "method": "tools/list"}
        )
        self.assertEqual(response["id"], "offline-catalog")
        self.assertNotIn("error", response)
        return response["result"]["tools"]

    def test_cold_listing_has_analysis_tools_without_contacting_ida(self):
        with patch.object(
            server.http.client, "HTTPConnection", side_effect=AssertionError("network used")
        ) as connection:
            tools = self.list_tools()

        names = {tool["name"] for tool in tools}
        self.assertTrue(
            {"decompile", "disasm", "survey_binary", "py_eval", "server_health"} <= names
        )
        self.assertTrue(server.LOCAL_TOOLS <= names)
        self.assertEqual(len(names), len(tools))
        self.assertNotIn("dbg_start", names)
        connection.assert_not_called()

    def test_ping_succeeds_without_ida(self):
        with patch.object(
            server.http.client, "HTTPConnection", side_effect=ConnectionRefusedError("offline")
        ) as connection:
            response = server.dispatch_proxy(
                {"jsonrpc": "2.0", "id": 42, "method": "ping"}
            )
        self.assertEqual(response, {"jsonrpc": "2.0", "id": 42, "result": {}})
        connection.assert_not_called()

    def test_catalog_error_returns_protocol_error_instead_of_partial_listing(self):
        with patch.object(server, "get_ida_tools", side_effect=ValueError("invalid signature")):
            response = server.dispatch_proxy(
                {"jsonrpc": "2.0", "id": 43, "method": "tools/list"}
            )
        self.assertEqual(response["id"], 43)
        self.assertEqual(response["error"]["code"], -32603)
        self.assertNotIn("result", response)
        self.assertIn("decompile", {tool["name"] for tool in self.list_tools()})

    def test_extension_selection_and_returned_schemas_are_isolated(self):
        with patch.object(server, "_proxy_to_ida", side_effect=ConnectionRefusedError("offline")):
            standard = self.list_tools()
            server.mcp._enabled_extensions.data = {"dbg"}
            extended = self.list_tools()
            self.assertIn("dbg_start", {tool["name"] for tool in extended})
            server.mcp._enabled_extensions.data = set()
            self.assertEqual(self.list_tools(), standard)

            decompile = next(tool for tool in extended if tool["name"] == "decompile")
            decompile["inputSchema"]["properties"].clear()
            self.assertEqual(self.list_tools(), standard)

    def test_schemas_preserve_named_defaults_nested_types_and_output_unions(self):
        with patch.object(server, "_proxy_to_ida", side_effect=ConnectionRefusedError("offline")):
            tools = {tool["name"]: tool for tool in self.list_tools()}

        self.assertEqual(
            tools["add_bookmark"]["inputSchema"]["properties"]["prefix"]["default"],
            "idaMCP: ",
        )
        decompile = tools["decompile"]
        self.assertEqual(decompile["inputSchema"]["required"], ["addr"])
        self.assertEqual(decompile["inputSchema"]["properties"]["addr"]["type"], "string")
        self.assertIn("addr", decompile["outputSchema"]["required"])
        self.assertNotIn("refs", decompile["outputSchema"]["required"])
        export = tools["export_funcs"]["outputSchema"]
        self.assertEqual(export["type"], "object")
        self.assertEqual(len(export["anyOf"]), 3)
        self.assertEqual(
            [item["required"] for item in export["anyOf"]],
            [["format", "functions"], ["format", "content"], ["format", "functions"]],
        )
        for tool in tools.values():
            self.assertTrue(tool["description"].strip(), tool["name"])
            self.assertEqual(tool["inputSchema"]["type"], "object", tool["name"])
            if "outputSchema" in tool:
                self.assertEqual(tool["outputSchema"]["type"], "object", tool["name"])

    def test_fresh_process_does_not_import_ida_or_connect_for_discovery(self):
        script = '''
import importlib.abc
import json
import sys

class NoIda(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".", 1)[0]
        if root in {"idaapi", "idautils", "idc", "idapro", "ida_mcp"} or (
            root.startswith("ida_") and root != "ida_pro_mcp"
        ):
            raise RuntimeError("Attempted IDA import: " + fullname)

sys.meta_path.insert(0, NoIda())
from ida_pro_mcp import server
from unittest.mock import patch
with patch.object(server.http.client, "HTTPConnection", side_effect=RuntimeError("network used")) as conn:
    response = server.dispatch_proxy({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert not conn.called, "Discovery used the network"
print(json.dumps([tool["name"] for tool in response["result"]["tools"]]))
'''
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("decompile", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()

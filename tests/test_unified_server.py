"""Exercise registration against the pinned official adapter, with no IDA imports."""

import json
import os
from pathlib import Path
import subprocess
import sys


def run_script(script, tmp_path):
    env = dict(
        os.environ,
        IDA_MCP_STATE_DIR=str(tmp_path / "mcp"),
        IDA_NEXUS_STATE_DIR=str(tmp_path / "nexus"),
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(result.stdout)


def test_offline_catalog_exact_parity_and_no_ida_imports(tmp_path):
    result = run_script(
        """
import importlib.abc, json, sys
class NoIda(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'idaapi','idc','idautils','idapro','ida_kernwin'}:
            raise AssertionError('IDA imported: ' + fullname)
sys.meta_path.insert(0, NoIda())
from ida_pro_mcp.unified_server import configure_server
from ida_pro_mcp.tool_catalog import get_ida_tools, fork_schema_generator
official = configure_server()
result = official.mcp.registry.dispatch({'jsonrpc':'2.0','id':1,'method':'tools/list'})
tools = {t['name']:t for t in result['result']['tools']}
catalog = get_ida_tools(fork_schema_generator(), set())
for expected in catalog:
    actual = dict(tools[expected['name']])
    actual['inputSchema']['properties'].pop('instance_id')
    assert actual == expected, expected['name']
assert len(catalog) == 66
assert set(tools) == {t['name'] for t in catalog} | {'open_database','list_databases','save_database','close_database','execute_python','reference','read_output'}
assert 'dbg_start' not in tools
assert sys.modules['zeromcp'].__file__.endswith('zeromcp\\\\__init__.py') or sys.modules['zeromcp'].__file__.endswith('zeromcp/__init__.py')
assert 'ida_pro_mcp.ida_mcp' not in sys.modules
print(json.dumps({'count':len(tools)}))
""",
        tmp_path,
    )
    assert result == {"count": 73}


def test_debugger_extension_and_profile_reject_disabled_calls(tmp_path):
    result = run_script(
        """
import json
from ida_pro_mcp.unified_server import configure_server
official = configure_server(extensions={'dbg'}, profile={'dbg_start','decompile'})
tools = official.mcp.registry.dispatch({'jsonrpc':'2.0','id':1,'method':'tools/list'})['result']['tools']
names = {tool['name'] for tool in tools}
assert 'dbg_start' in names and 'decompile' in names and 'py_eval' not in names
assert len(names) == 9
reply = official.mcp.registry.dispatch({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'py_eval','arguments':{'code':'1'}}})
assert 'error' in reply or reply['result']['isError']
print(json.dumps({'names':sorted(names)}))
""",
        tmp_path,
    )
    assert "close_database" in result["names"]


def test_native_result_and_backend_error_are_not_double_wrapped_and_are_traced(
    tmp_path,
):
    run_script(
        """
import json
from ida_pro_mcp.unified_server import configure_server
official = configure_server()
class Bridge:
    async def call_tool(self, name, arguments, instance_id=None):
        assert instance_id == 'A'
        if name == 'decompile':
            return {'content':[{'type':'text','text':'backend error'}], 'isError':True, '_meta':{'test':1}}
        return {'content':[{'type':'text','text':'[1,2]'}], 'structuredContent':{'result':[1,2]}, 'isError':False}
class Manager:
    unified_bridge = Bridge()
    def shutdown(self): pass
old = official.DATABASE_MANAGER
official.DATABASE_MANAGER = Manager()
old.shutdown()
def call(name, arguments):
    return official.mcp.registry.dispatch({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':dict(arguments,instance_id='A')}})['result']
result = call('lookup_funcs', {'queries':'main'})
assert result == {'content':[{'type':'text','text':'[1,2]'}], 'structuredContent':{'result':[1,2]}, 'isError':False}, result
error = call('decompile', {'addr':'0x1000'})
assert error == {'content':[{'type':'text','text':'backend error'}], 'isError':True, '_meta':{'test':1}}, error
events = [json.loads(line) for line in official.TRACE.path.read_text().splitlines()]
assert any(e['event'] == 'tool_error' and e['tool'] == 'decompile' for e in events)
assert any(e['event'] == 'tool_result' and e['tool'] == 'lookup_funcs' for e in events)
print('{}')
""",
        tmp_path,
    )


def test_resources_available_offline_and_forward_native_envelope(tmp_path):
    run_script(
        """
import json
from ida_pro_mcp.unified_server import configure_server
official = configure_server()
def rpc(method, params={}):
    result = official.mcp.registry.dispatch({'jsonrpc':'2.0','id':1,'method':method,'params':params})
    assert 'error' not in result, result
    return result['result']
resources = rpc('resources/list')['resources']
assert any(r['uri']=='ida://idb/metadata' for r in resources)
templates = rpc('resources/templates/list')['resourceTemplates']
assert any(r['uriTemplate']=='ida://struct/{name}' for r in templates)
class Bridge:
    async def request(self, method, params, instance_id=None):
        assert method == 'resources/read' and params == {'uri':'ida://idb/metadata'}
        assert instance_id == 'A'
        return {'contents':[{'uri':'ida://idb/metadata','mimeType':'application/json','text':'{"module":"fixture"}'}]}
class Manager:
    unified_bridge = Bridge()
    def shutdown(self): pass
old = official.DATABASE_MANAGER
official.DATABASE_MANAGER = Manager()
old.shutdown()
result = rpc('resources/read', {'uri':'ida://idb/metadata?instance_id=A'})
assert result['contents'][0]['text'] == '{"module":"fixture"}'
print('{}')
""",
        tmp_path,
    )


def test_canonical_gui_install_suppresses_only_false_missing_plugin_hint(tmp_path):
    run_script(
        """
import json, os, shutil, sys
from pathlib import Path
from importlib.metadata import version
import ida_pro_mcp
from ida_pro_mcp.unified_server import configure_server
official = configure_server()
root = Path(os.environ['IDA_MCP_STATE_DIR']).parent / 'ida-user'
os.environ['IDAUSR'] = str(root)
plugins = root / 'plugins'
plugins.mkdir(parents=True)
source = Path(ida_pro_mcp.__file__).parent
assert not official._gui_plugin_installed()
shutil.copytree(source, plugins / 'ida_pro_mcp', ignore=shutil.ignore_patterns('__pycache__'))
shutil.copyfile(source / 'ida_mcp.py', plugins / 'ida_mcp.py')
site = root / 'site'
(site / 'ida_nexus').mkdir(parents=True)
(site / 'ida_nexus' / 'plugin.py').write_text('# fixture')
metadata = site / 'ida_nexus-0.13.0.dist-info'
metadata.mkdir()
(metadata / 'METADATA').write_text('Metadata-Version: 2.1\\nName: ida-nexus\\nVersion: 0.13.0\\n')
manifest = plugins / 'ida-pro-mcp-runtime.json'
manifest.write_text(json.dumps({'python':sys.executable, 'python_version':list(sys.version_info[:2]),'package_root':str(source.parent),'site_packages':[str(site)]}))
assert official._gui_plugin_installed()
(metadata / 'METADATA').write_text('Metadata-Version: 2.1\\nName: ida-nexus\\nVersion: 0.12.0\\n')
assert not official._gui_plugin_installed(), 'incompatible Nexus must not suppress hint'
init = official.mcp.registry.dispatch({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'test','version':'1'}}})
assert init['result']['serverInfo'] == {'name':'ida-pro-mcp','version':version('ida-pro-mcp')}
print('{}')
""",
        tmp_path,
    )

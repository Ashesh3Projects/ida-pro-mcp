# IDA Pro MCP

This fork combines the community project's typed analysis tools with a FastMCP frontend and IDA Nexus database services. Use one MCP entry point for decompilation, disassembly, xrefs, signatures, debugging, persistent Python, shared database sessions, API reference lookup, and session diagnostics.

**Quick start**

Unified mode requires IDA 9.4+ with activated idalib and Python 3.11+. Keep the MCP client and IDA plugin on the same installation. Existing GUI/proxy and headless commands remain available with the same required-ID contract.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\ida-pro-mcp install
.venv\Scripts\ida-pro-mcp config --agent codex
```

If your package mirror has not published the pinned official dependencies, build the exact reviewed sources without changing your configured package index:

```powershell
.venv\Scripts\python scripts/bootstrap_unified.py --wheel-dir wheels --install
```

The bootstrap verifies Git revisions, builds dependency wheels, and writes a SHA-256 receipt. ZeroMCP's tagged source retains version 0.0.0; the helper applies the same metadata-only version step as its release workflow. The installed code remains the reviewed 1.10.3 revision.

Add the JSON returned by `ida-pro-mcp config` to your MCP client. Or install a supported client directly with `ida-pro-mcp install codex --scope global`. The plugin installer exposes the current GUI database through Nexus and retains the existing legacy endpoint. Restart IDA after installing or upgrading the plugin.

```console
ida-pro-mcp stdio --agent codex
ida-pro-mcp stdio --ext dbg
ida-pro-mcp http --host 127.0.0.1 --port 8737
ida-pro-mcp dashboard --open
ida-pro-mcp logs --output support.zip
```

**Unified tools**

The default catalog has 75 tools: 66 typed analysis tools plus discovery, lifecycle, Python, reference and output tools. Use `--ext dbg` for all 22 debugger tools, yielding 97 tools. Discovery and reference lookup work before a database is open.

Call `list_instances()` for running databases or `open_database(path)` to open a file. Every database operation requires the exact `instance_id` returned by this MCP server, including both Python tools, debugger tools, save/close, status and `read_output`. IDs are random 16-character handles. There is no selected database and no `select_instance` tool.

```python
# Keep these returned values; do not invent IDs.
a = open_database(path="C:/samples/file-a.exe")["instance_id"]
b = open_database(path="C:/samples/file-b.exe")["instance_id"]
decompile(instance_id=a, addr="main")
xrefs_to(instance_id=b, addrs="ImportantExport")
```

Agents sharing one stdio or HTTP connection may submit these calls concurrently. Each database has its own queue; different IDA processes can progress independently. Closing/replacing a database retires the old ID. A stale ID fails and never follows a new file at the same path, PID, port or list position. Restarting the frontend creates a new ID namespace, so rediscover after reconnecting.

Database resources require an identity-bearing URI such as `ida://idb/metadata?instance_id=<returned-id>`. Large results return a continuation: `read_output(instance_id=<returned-id>, output_id=<returned-output-id>, offset=0)`. Both IDs are required, and a closed binding expires its outputs.

FastMCP 4.1 and MCP SDK 2.3 support the modern `2026-07-28` sessionless protocol and older clients through automatic negotiation. Modern HTTP uses per-request streams without a session ID; older HTTP clients retain transport sessions for cancellation. Neither stores database selection. Keep `json_response=False` and normal legacy session handling; forcing legacy `stateless_http=True` loses cancellation. Use one frontend process per configured service; multiple ASGI workers need separate shared lease coordination.

Separate MCP processes retain separate leases. Within one server, agents using the same instance ID share that database's edits and persistent Python namespace; IDs isolate routing, not transactions or private copies of the same IDB.

`py_eval` retains its string result/stdout/stderr contract and callback persistence, with an isolated namespace per bridge client. `execute_python` uses its own Nexus namespace and returns JSON-compatible results. These two namespaces are separate. Unified leases remain active until `close_database` or client shutdown; timed idle release is disabled because typed bridge activity is outside Nexus's idle accounting.

`--profile PATH` restricts advertised typed tools, while official lifecycle tools, `execute_python`, `reference`, and `read_output` remain available. Profiles are convenience filters, not read-only or security policies. Internal database and bridge services authenticate local requests; the outer MCP HTTP server does not add authentication. Keep it on loopback unless you supply an authenticated network boundary.

**Compatibility and verification**

- Legacy GUI proxy: `ida-pro-mcp legacy` or `ida-pro-mcp-legacy`. Existing flag-style commands such as `--ida-rpc`, `--install`, and `--config` retain their original routes.
- Legacy headless supervisor: `idalib-mcp --stdio`, including explicit GUI/headless modes.
- Legacy mode retains the advertised IDA 8.3+ floor; the new unified runtime requires 9.4+.
- Run offline tests with `python -m pytest`. Run IDA tests separately with `ida-mcp-test <copied-fixture>`.
- Runtime pins: FastMCP 4.1.0, MCP SDK 2.3.0, ida-mcp 20260929.0.1, ida-nexus 0.13.0, ida-domain 0.5.1, ZeroMCP 1.10.3. See [CHANGELOG](CHANGELOG.md), [implementation design](docs/superpowers/specs/2026-10-16-explicit-instance-routing-design.md), and [local validation results and limits](docs/explicit-instance-validation.md).

Version 4.0 is a breaking tool-contract upgrade: restart IDA after installing the new plugin, reconnect the MCP client to refresh schemas, then obtain fresh instance IDs. Backends without generation support are reported as incompatible. The remaining documentation describes the legacy launch workflows and typed APIs; every database-specific example requires `instance_id`.



https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://claude.com/product/claude-code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://kilo.ai/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Kimi Code](https://moonshotai.github.io/kimi-code/en/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

**Note**: This requires having idalib activated globally and [uv](https://astral.sh/uv) installed:

```bash
# windows
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
# macos
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
# linux
uv run "/path/to/idapro-9.3/idalib/python/py-activate-idalib.py"
```

## Installation (Claude Code)

To install the latest IDA Pro MCP in Claude Code:

```bash
claude plugin marketplace add mrexodia/claude-marketplace
claude plugin uninstall ida-pro-mcp@mrexodia
claude plugin install ida-pro-mcp@mrexodia
```

## Installation (Codex)

To install the latest IDA Pro MCP in Codex:

```bash
codex plugin marketplace add mrexodia/codex-marketplace
codex plugin remove ida-pro-mcp@mrexodia
codex plugin add ida-pro-mcp@mrexodia
```

## Installation (Kimi Code)

To install the latest IDA Pro MCP in Kimi Code, run this slash command in the chat:

```
/plugins install https://github.com/mrexodia/ida-pro-mcp/tree/main
/reload
```

This installs the `idalib` MCP server and the `idapython` skill. Plugins are copied to
`$KIMI_CODE_HOME/plugins/managed/`, so `uv` must be on your `PATH`. The first session after
installing is slower, because `uv` resolves the dependencies before the server responds.

## Installation (GUI)

**Note**: the MCP plugin is no longer recommended and will eventually be deprecated. Use `idalib-mcp` instead.

If you want to configure the MCP server manually from the IDA GUI:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
```

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

**Important**: Make sure you completely restart IDA and your MCP client for the installation to take effect. Some clients (like Claude) run in the background and need to be quit from the tray icon.

### Start your MCP client before IDA

For the GUI workflow, configure your client to launch the `ida-pro-mcp` proxy
over **stdio**:

```sh
ida-pro-mcp --install codex,claude-code --transport stdio --scope global
```

The proxy advertises the installed tool catalog even when no IDA instance is
running. Start IDA and its MCP plugin when you need to use a tool; the existing
client connection can then make calls without refreshing its tool list. The
`list_instances` and `instance_status(instance_id)` tools remain available.
Pass the returned `instance_id` with every operation. MCP pings also work while IDA is closed.

This requires a proxy process independent of IDA. A client configured directly
with `http://127.0.0.1:13337/mcp` connects to the GUI plugin, which is unavailable
while IDA is closed. If you prefer HTTP, run the proxy separately on another port
with `ida-pro-mcp --transport http://127.0.0.1:8744/mcp` and configure the client to
use that URL.

The catalog is generated from the installed Python tool signatures and cached
for the proxy's lifetime. It preserves extension filtering (`?ext=dbg`), and IDA
still enforces each database's enabled-tool settings when a tool is called.
Restart the client or its MCP connection once after updating the package or
switching its configuration; opening IDA later does not require another reload.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## Transports & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/core/idalib/getting-started) you can also run a headless MCP server. You can start with an initial binary:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

Or start without a binary and open arbitrary files later with `idb_open(...)`:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

For stdio-based clients, use:

```sh
uv run idalib-mcp --stdio
```

The legacy headless supervisor (`idalib-mcp`) and direct worker
(`python -m ida_pro_mcp.idalib_server`) enable unsafe tools, including `py_eval`
and `py_exec_file`, by default. Pass `--no-unsafe` to either command to disable
them; explicit `--unsafe` is still accepted. The supervisor forwards this choice
to workers it starts. Already running or adopted instances keep their original
settings, and tool profiles and debugger extension filtering still apply.

Database workers are persistent: each one runs as a detached process that
outlives the supervisor that spawned it. When a new supervisor (over stdio
or HTTP) calls `idb_open` for a binary that is already open under a worker
on this host, the supervisor adopts that worker transparently — there is
no separate "shared" mode to enable. Workers self-exit when no request has
hit them for an idle interval.

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## Headless idalib Session Model

`idalib-mcp` is a supervisor that keeps each open database in its own idalib worker process. Workers register themselves in a host-local discovery directory and outlive the supervisor that spawned them; any subsequent supervisor that wants the same path adopts the running worker. A worker self-exits when no request has hit it for its idle TTL (default 1 hour). Call `idb_close` to release a worker eagerly (freeing a slot toward `--max-workers`), adopted GUI/worker instances are detached rather than killed.

`idb_open` picks the backend via its `mode` parameter:

- `prefer_headless` (default): spawn an idalib worker (or adopt one that already has the file open).
- `force_headless`: same, but never adopt a running GUI even if one has the file.
- `prefer_gui`: adopt a running GUI for the file; otherwise spawn an idalib worker.
- `force_gui`: adopt a running GUI for the file; otherwise launch a new IDA GUI process.

Every tool call must carry an explicit `database` argument. There is no implicit "current database" — callers name the session they want to operate on.

```sh
uv run idalib-mcp --stdio --max-workers 4
```

Typical flow:

```python
a = idb_open(input_path="/path/to/binary_a.exe")["instance_id"]
b = idb_open(input_path="/path/to/library.dll")["instance_id"]
decompile(addr="main", instance_id=a)
xrefs_to(addrs="ImportantExport", instance_id=b)
```

`instance_id` is generated by this server. The old `database` argument and caller-chosen `preferred_session_id` are removed. A disappeared GUI is never silently reopened headlessly under its old ID; explicitly open the file again to obtain a new ID.

### Management tools

- `idb_open(input_path, mode="prefer_headless", run_auto_analysis=True, build_caches=True, init_hexrays=True)`: open and warm up a binary with the requested GUI/headless policy, returning its instance ID.
- `idb_list()` / `list_instances()`: list exact databases with identity, path, backend and status.
- `idb_close(instance_id, save=True)`: drain, optionally save, and release the binding. Owned workers are closed; adopted GUI/workers remain running. A failed save/drain retains the binding in closing state for an explicit close retry; unrelated instances continue.
- `idb_save(instance_id, path="")` / `save_database(instance_id)`: save the addressed database.
- `server_health(instance_id)` / `instance_status(instance_id)`: inspect the addressed database/binding.

Worker controls:

- `--max-workers N`: maximum simultaneous database workers (`0` = unlimited, default `4`).
- `IDA_MCP_MAX_WORKERS`: environment default for `--max-workers`.

The bundled Codex plugin forwards the runtime's `IDA_MCP_*` configuration variables from the Codex host environment:

- Capacity and lifecycle: `IDA_MCP_MAX_WORKERS`, `IDA_MCP_OPEN_TIMEOUT`, `IDA_MCP_WEDGED_GRACE_SEC`, `IDA_MCP_WORKER_CALL_TIMEOUT`.
- Health probes: `IDA_MCP_HEALTH_TCP_TIMEOUT`, `IDA_MCP_HEALTH_RPC_TIMEOUT`, `IDA_MCP_HEALTH_RETRIES`, `IDA_MCP_HEALTH_RETRY_BACKOFF`.
- Worker behavior: `IDA_MCP_TOOL_TIMEOUT_SEC`, `IDA_MCP_ANALYSIS_PROMPT`, `IDA_MCP_URL`.
- Request logging: `IDA_MCP_LOG_REQUESTS`, `IDA_MCP_LOG_SKIP_METHODS`.


## MCP Resources

**Resources** represent browsable state (read-only data) following MCP's philosophy.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (path, arch, base, size, hashes)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Lookups:**
- `ida://import/{name}` - Import details by name
- `ida://export/{name}` - Export details by name
- `ida://xrefs/from/{addr}` - Cross-references from address

## Core Functions

- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `decompile(addr)`: Decompile function at the given address.
- `disasm(addr)`: Disassemble function with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).

## Modification Operations

- `add_bookmark(addr, name, prefix)`: Add or replace the IDA bookmark at an address; set `prefix=""` for no prefix.
- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.
- `define_func(items)`: Define function(s) at address(es). Optionally specify `end` for explicit bounds.
- `define_code(items)`: Convert bytes to code instruction(s) at address(es).
- `undefine(items)`: Undefine item(s) at address(es), converting back to raw bytes. Optionally specify `end` or `size`.

## Memory Reading Operations

- `get_bytes(addrs)`: Read raw bytes at address(es).
- `get_int(queries)`: Read integer values using ty (i8/u64/i16le/i16be/etc).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Extension)

Debugger tools are hidden by default. Enable with `?ext=dbg` query parameter:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

**Control:**
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue execution.
- `dbg_run_to(addr)`: Run to address.
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.

**Breakpoints:**
- `dbg_bps()`: List all breakpoints.
- `dbg_add_bp(addrs)`: Add breakpoint(s).
- `dbg_delete_bp(addrs)`: Delete breakpoint(s).
- `dbg_toggle_bp(items)`: Enable/disable breakpoint(s).

**Registers:**
- `dbg_regs()`: All registers, current thread.
- `dbg_regs_all()`: All registers, all threads.
- `dbg_regs_remote(tids)`: All registers, specific thread(s).
- `dbg_gpregs()`: GP registers, current thread.
- `dbg_gpregs_remote(tids)`: GP registers, specific thread(s).
- `dbg_regs_named(names)`: Named registers, current thread.
- `dbg_regs_named_remote(tid, names)`: Named registers, specific thread.

**Stack & Memory:**
- `dbg_stacktrace()`: Call stack with module/symbol info.
- `dbg_read(regions)`: Read memory from debugged process.
- `dbg_write(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).
- `analyze_funcs(addrs)`: Comprehensive function analysis (decompilation, assembly, xrefs, callees, callers, strings, constants, basic blocks).

## Pattern Matching & Search

- `find_regex(queries)`: Search strings with case-insensitive regex (paginated).
- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000.
- `find_insns(sequences, limit=1000, offset=0)`: Find instruction sequence(s) in code. Max limit: 10000.
- `find(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.

## Type Operations

- `set_type(edits)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.
- `put_int(items)`: Write integer values using ty (i8/u64/i16le/i16be/etc).

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```

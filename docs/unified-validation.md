# Unified IDA MCP validation

Validated locally on Windows, 30 September 2026. The implementation merges community upstream c133c385 into the fork and composes official MCP 20260929.0.1, Nexus 0.13.0, IDA Domain 0.5.1 and ZeroMCP 1.10.3.

| Check | Result |
| --- | --- |
| Full non-IDA suite | 343 passed, 1 opt-in integration skipped, 128 subtests |
| Registered stdio/HTTP + live IDA acceptance | 2 passed |
| Existing IDA 9.4 typed fixture suite | 342 passed, 2 fixture-dependent skips |
| Wheel-only install, no source path | 95 debugger-enabled tools; package/version correct; dependency check clean |
| Offline standard catalog | 73 tools, without IDAPython import |
| Real IDA GUI | IDA 9.4 / Python 3.11.9; Nexus GUI discovery, py_eval, execute_python, debugger breakpoint listing |
| Shared-worker behavior | Two MCP processes retain isolated Python names; peer works after other closes |
| Cancellation | Explicit MCP cancellation for official and typed execution, then successful call through the other API |
| Large output | Complete 120,000-character value retrieved through bounded read_output pages |
| Diagnostics | Session log ZIP exported; dashboard and hook commands available |
| Packaging | Pinned-source bootstrap builds exact revisions; hashes in build receipt; uv lock check passes |

The GUI was a separately launched fixture instance with isolated plugins/state. The existing user databases were not modified. Tests required a Python 3.11 runtime matching the GUI; the headless test environment used Python 3.12. Older IDA versions, remote GUI hosts, and a live debugger target session were not exercised. The existing debugger helper tests and live breakpoint listing passed.

Official components retain their upstream semantics: one manager per MCP server process; multiple HTTP sessions in that process share it. Unified typed calls keep leases until explicit close or client exit. Namespace isolation does not isolate database edits or imported modules. Tool profiles are convenience allowlists and leave arbitrary Python available.

Raw logs and wheel/source receipts are retained in the ignored plan workspace under .superpowers/sdd/2026-09-30-unified-ida-mcp. No internal bridge tokens or user transcript contents are included in this document.

# Unified IDA MCP Implementation Plan

> For agentic workers: use superpowers:subagent-driven-development with test-first feature work and independent final review.

**Goal:** combine all audited upstream fixes and official MCP benefits with the fork's existing typed APIs in one installable tool.

**Architecture:** revision-pinned official MCP/Nexus provide lifecycle and diagnostics. Authenticated loopback bridge forwards fork tools against the same selected IDB after Nexus bootstrap returns. Existing legacy workflows remain available.

**Tech stack:** Python 3.11+, vendored fork ZeroMCP plus official ZeroMCP dependency, IDA 9.4/idalib for unified mode, pytest and MCP SDK.

**Spec:** docs/superpowers/specs/2026-09-30-unified-ida-mcp-design.md

**Global constraints**

- Preserve fork history with normal upstream merge; no reset/rebase replacement.
- Use managed worktree codex/ida-mcp-unified; root coordinates Git commits.
- Preserve existing tool signatures, callback state, profiles and explicit instance routing.
- Keep offline tool discovery independent of IDAPython.
- All mutation failures stay non-retried; cancellation targets exact original request.
- Tests isolate actual user registries and IDBs; use copied fixture binaries.
- Never log bridge secrets or return them in model-visible output.

**Review focus**

- Same numeric request ID from two clients must not cancel another client's operation.
- Switching target before cancellation or output retrieval must retain original IDB ownership.
- Two supervisors/leases closing in either order must leave the peer working.
- Top-level ida_mcp/zeromcp import collisions must not switch implementations or start IDA.
- A long-running typed call must leave the Nexus control path available for cancellation and release.

**Task 1: preserve fork while merging current upstream**

Files: api_analysis.py, discovery.py, idalib_server.py plus upstream changes/tests.
- [ ] Run baseline non-IDA tests with isolated registries.
- [ ] Merge upstream/main with --no-commit; resolve three conflicts preserving fork behavior.
- [ ] Isolate legacy registry in incoming wildcard tests.
- [ ] Run upstream regression tests, fork proxy tests and full non-IDA suite.
- [ ] Review ancestry/diff and commit normal merge.

**Task 2: authenticated IDA bridge runtime and isolated Python contexts**

Files: new bridge_runtime.py and context helper; ida_mcp/api_python.py, tests/test_bridge_runtime.py.
Interface: ensure_bridge() -> {host, port, token}; authenticated tools/call supports _meta bridge_client; release_bridge_client(client_id) clears only that namespace; no outer Nexus wait on forwarded execution.
- [ ] Tests for authentication, reentrant startup, context separation/reset, callback globals, BaseException unwind and release.
- [ ] Implement runtime startup without initializing a database or altering current IDB.
- [ ] Validate namespace lifetime boundedness and loopback-only listener.
- [ ] Run focused tests and report changed files/interfaces.

**Task 3: client bridge and schema registration**

Files: new unified_bridge.py, unified_server.py, tests/test_unified_bridge.py, tests/test_unified_server.py.
Interfaces: UnifiedBridge wraps a supplied DatabaseManager; call_tool(name, arguments, instance_id=None) returns native result; read_output(output_id,offset,limit) returns bounded original output; cleanup releases owned bridge context.
- [ ] Tests for pinned targets, unique request IDs, backend cancellation, no retries, output ownership/continuation, disabled tools.
- [ ] Register typed wrappers from AST catalog plus official six tools; add optional instance_id and correct output envelope without IDA imports.
- [ ] Preserve official tracing by using its tool decorator; explicit supported-version compatibility shim.
- [ ] Test stdio schema listing, list and union results, separate clients and graceful shutdown.

**Task 4: one-package CLI, GUI integration and documentation**

Files: cli.py, __main__.py, pyproject.toml, uv.lock, ida_mcp.py loader, installer.py, manifests, README, CHANGELOG, offline CI.
- [ ] Default unified stdio; stdio/http/dashboard/logs/hook subcommands; legacy command preserves existing flags.
- [ ] Pin official/Nexus revisions available from authoritative Git source if internal index lags.
- [ ] GUI loader cohosts Nexus with one install, retains compatibility when Nexus is unavailable.
- [ ] Update all plugin manifests to invoke unified entry point; package metadata fork identity/version.
- [ ] Installer/package/CLI tests and clean wheel-only smoke run.

**Task 5: acceptance, independent review and handoff**

- [ ] Verify whole non-IDA suite and build wheel.
- [ ] Run copied-fixture IDA tests and combined official+typed integration on IDA9.4.
- [ ] Verify per-client state, cancellation, cached output, reference, diagnostic commands and last-lease closure.
- [ ] Review the whole diff independently, fix findings and rerun affected checks.
- [ ] Commit tested changes; report exact branch, usage, evidence and any unverified boundaries.


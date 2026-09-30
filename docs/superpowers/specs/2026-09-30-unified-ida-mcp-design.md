# Unified IDA Pro MCP design

Date: 2026-09-30

The user authorized improving the fork with the latest upstream fixes and official MCP benefits, retaining one usable tool. This is the implementation brief derived from the completed comparison; proceed autonomously within that scope. Preserve the working project until validation, use normal Git merge ancestry, and retain a complete reviewable change.

**Outcome and compatibility**

- Integrate upstream c133c3853faa111a9b00ee615c013b720d0c4acd with fork customizations preserved.
- Offer one new default unified entry point, using the official MCP adapter and Nexus as maintained, revision-pinned components. The legacy GUI/proxy and idalib commands remain supported for old integrations and IDA before 9.4.
- Preserve all 66 analysis tools and 22 optional debugger tools, tool schemas, IDAPython callbacks, 120-second defaults, profiles, multi-instance selection and output ownership.
- Unified mode adds official open/list/save/close, execute_python, installed API reference, peer-aware leases, crash recovery, authenticated internal database services, cancellation, dashboard, transcript hooks and support archives.
- Python >=3.11; unified mode IDA >=9.4; no live user database modifications during validation. Tests use copied fixtures and isolated profile/state directories.
- Never silently retry mutation requests. A disconnected target remains explicit and cannot fall through to another IDB.

**Architecture choice**

Porting and maintaining all official code independently duplicates lifecycle and diagnostic machinery. Replacing the fork discards its typed APIs and compatibility. Compose the official adapter through its documented tool/serve APIs and a narrow tested compatibility module, pin its version, and add our typed tools. The user runs only ida-pro-mcp.

The official adapter owns MCP transport, tracing, official six tools and Nexus DatabaseManager. A bridge targets the same selected DatabaseManager instance and holds the same Nexus lease. It initializes a loopback authenticated fork listener inside that selected IDA process by a short Nexus execution, then ends that execution before forwarding a typed call over HTTP. This avoids nesting IDA main-thread synchronization and preserves debugger deferred batch behavior. The listener starts once per IDA runtime and remains tied to database lifetime.

All typed requests carry an opaque per-manager/per-target lease context and unique backend request ID. py_eval uses persistent state isolated by bridge client, clears only the requested context, and retains dictionary identity. The modern execute_python namespace is Nexus-owned; its semantics are separate and documented. Namespace isolation is not a sandbox. Bridge session release is best effort before releasing the Nexus handle.

Cancellation pins the target and backend request ID before execution; it sends backend notifications through a separate connection and waits for the request to unwind. IDs must never collide across clients. No Nexus operation may wait for a legacy HTTP request inside the IDA main thread. Output IDs are registered with their original producing target and exposed through a bounded read_output tool, available over stdio and HTTP without exposing unauthenticated raw backend URLs.

Catalog metadata comes from inert AST signatures without importing IDAPython. The adapter registers each existing tool with its real schema plus optional database target. It must handle conflicting official/fork names deterministically, preserve list-return result envelopes, and reject disabled tools. Debugger tools stay opt-in through --ext dbg. Existing three GUI management tools and four backend modes remain available through the legacy entry point; unified lifecycle uses official semantics and explicit target IDs.

The GUI loader starts Nexus when supported/installed without requiring a second GUI plugin, and continues serving the legacy API. Resolve the top-level ida_mcp name collision: official adapter only imports outside IDA; fork runtime loads through a unique/fully qualified package and never shadows official ida_mcp in the client process. Bootstrap requires the same local installed package path; heterogeneous hosts are outside the local bridge contract.

**Modules and responsibilities**

- Existing analysis/rpc/discovery/installer files: upstream merge and regressions.
- bridge_runtime.py: IDA-side authenticated listener startup, session namespaces, release and tool dispatch.
- unified_bridge.py: client target pinning, bootstrap, typed forwarding, cancellation, output ownership/cache.
- unified_server.py: schema-preserving typed tool registration on official MCP, profiles/extensions and official adapter compatibility.
- cli.py: unified entry points, legacy dispatch, dashboard/log/hook delegation.
- GUI loader and installer: one plugin dependency discovery; unified client configuration.
- Tests: pure unit/transport, schema parity, fake-backend cancellation, package install, and live copied-fixture IDA integration.

**Validation and completion**

Run the existing non-IDA suite, added regression tests, wheel validation, stdio/HTTP smoke tests, and available IDA 9.4 fixture tests. Verify offline discovery, typed and official tool interoperability on the same fixture, separate clients' state, shared-worker close behavior, cancellation, preserved callback globals, debugger registration, output continuation, reference and diagnostics commands. A test failure is investigated, never reported green or hidden by weaker assertions.

Finish with independent review, fixes, commits and a usable local installation path. User did not explicitly request publication or changing main in this turn; prepare the tested branch and report its exact readiness. Further authorization is only needed for consequential external publication not already implied.


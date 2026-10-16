# Explicit Instance Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user has approved the written specification; implementation starts after plan review and execution-method selection.

**Goal:** Let agents sharing an MCP connection operate concurrently on different IDA databases using mandatory immutable instance IDs, without selection races or stale-target execution.

**Architecture:** FastMCP owns the external protocol, tool registration, and asynchronous transports. A framework-independent registry/router owns explicit database bindings, queues, operations, and cleanup; backend adapters retain Nexus leases or existing GUI/headless transports. The IDA runtime validates database generation immediately before executing work, while output and cancellation ownership follow the admitted invocation.

**Tech Stack:** Python 3.11+, FastMCP 4.1.0, MCP SDK 2.3.0, Nexus 0.13.0, IDA Domain 0.5.1, existing typed IDA APIs and lightweight in-IDA ZeroMCP, pytest, JSON Schema, Windows and Linux.

**Spec:** [Approved design](../specs/2026-10-16-explicit-instance-routing-design.md). Read the entire spec before implementation. Baseline product commit: `7245a50a92ef914cbb64d9be6d000785cbbcb41e`; design commit: `2ea1a5a`.

## Execution status (2026-10-16)

Implementation is committed locally through `d343b85028b9b2e0dd9986fc3fe1188efb5f57e1`.
All local checks are complete; the two unchecked native/client gates below are
partially verified, with their exact limits in [validation](../../explicit-instance-validation.md).
See [execution rulings](2026-10-16-explicit-instance-routing-rulings.md) for task
ordering/environment decisions and their costs. Tests ran with the worktree
Python and pinned dependencies; the configured mirror replaced failed default
TLS downloads rather than changing versions. The proposed aggregate
`tests/test_instance_acceptance.py` was not added: its checks live in the focused
router/transport/bridge tests and `tests/multi_instance_acceptance.py`.

## Global Constraints

- Every existing typed IDA tool receives a required nonempty string `instance_id`.
- The public ID is a random 16-character hexadecimal handle.
- The user explicitly chose required `instance_id` arguments and removal of shared selection, with no legacy selection mode.
- Use FastMCP 4.1.0 for the external MCP frontend, with MCP Python SDK 2.3.0.
- Keep Python 3.11 support; unified execution retains IDA 9.4+, legacy execution retains its supported pre-9.4 behavior.
- Use `json_response=False` and `stateless_http=False` with automatic protocol-era detection. Modern HTTP remains sessionless; older sessions never store database selection.
- No operation retries on another database. A transport failure after dispatch reports execution uncertainty and does not automatically replay a mutation.
- All IDA SDK work executes on its owning main thread. Do not nest typed `@idasync` calls inside Nexus Python execution.
- Discovery and reference lookup work without opening IDA or acquiring every discovered lease.
- Preserve the 66 standard typed tools and 22 optional debugger tools, original argument semantics and output schemas, profiles, timeouts, Python callbacks, and diagnostics.
- Registry locks protect bookkeeping only. No global lock is held while waiting for IDA, network I/O, database startup, or drain.
- Keep backend credentials out of public IDs, responses, URLs, and logs; retain loopback and Host/Origin restrictions.
- Test against copied fixtures and isolated registries. The temp FastMCP research environment is evidence, not the product environment.
- Reuse the current managed worktree. Do not publish, merge, or change the user's installed plugin/configuration as part of this plan.
- The release contract is breaking: prepare version `4.0.0` metadata and migration documentation, without publishing a release.

## Review Focus

These additional input classes receive explicit tests in the indicated task.

1. **File and IDB aliases, duplicate filenames, and concurrent opens:** aliases to one incarnation share an ID/queue; different processes remain distinct; cancellation of one open waiter does not close the winner. Tasks 1, 3, 4.
2. **Database replacement between bootstrap/queueing and execution:** both typed work and Nexus Python/save must fail before touching the replacement, including a reopen of the same path in the same process. Tasks 2, 4.
3. **Close failure followed by rediscovery:** an incomplete drain cannot be bypassed by minting another binding; other instances must still progress. Tasks 1, 3, 5.
4. **Many requests queued for one instance:** asynchronous waiting cannot exhaust worker threads or block a second instance, and duplicate request numbers from separate clients cannot share cancellation. Tasks 3, 6, 9.
5. **Copied installations, old clients, and stale registrations:** new schemas remain discoverable offline, missing generation support reports incompatibility, and old protocol clients retain cancellation without recovering implicit routing. Tasks 2, 6, 7, 8, 9.

## File Structure and Boundaries

Paths below are relative to this worktree. Existing files are adapted in place; do not split the analysis API modules.

| File | Responsibility |
| --- | --- |
| `src/ida_pro_mcp/instance_contract.py` (new) | ID validation, public errors, immutable identity/binding records and backend interfaces; no framework or IDA imports |
| `src/ida_pro_mcp/instance_registry.py` (new) | Publish, resolve, retire, deduplicate and describe bindings; retain tombstones |
| `src/ida_pro_mcp/instance_router.py` (new) | Per-binding asynchronous queues, attachment, operations, cancellation and close/shutdown |
| `src/ida_pro_mcp/instance_runtime.py` (new) | Lightweight database-generation state and request-generation context; importable without IDA |
| `src/ida_pro_mcp/ida_mcp/instance_dispatch.py` (new) | Apply required target validation and operation-ID mapping to direct/plugin RPC |
| `src/ida_pro_mcp/ida_mcp/instance_hooks.py` (new) | Persistent IDA database-load/close hooks and runtime-generation rotation |
| `src/ida_pro_mcp/ida_mcp.py`, `idalib_server.py`, `idalib_session_manager.py`, `ida_mcp/discovery.py`, `ida_mcp/sync.py`, `bridge_runtime.py` | Attach runtime guards to existing GUI/worker lifecycle and execution |
| `src/ida_pro_mcp/nexus_backend.py` (new) | Exact Nexus discovery/attach/open, owned handles, Python/reference/save and closure |
| `src/ida_pro_mcp/nexus_guard.py` (new) | Small pinned-runtime adapter enforcing the generation check inside Nexus's execution namespace/main-thread boundary |
| `src/ida_pro_mcp/unified_bridge.py` | Keep authenticated typed HTTP execution, cancellation and drain; remove optional-target/lifecycle-manager coupling |
| `src/ida_pro_mcp/output_store.py` (new) | Bound output continuations, expiration and original-target ownership |
| `src/ida_pro_mcp/fastmcp_frontend.py` (new) | Reusable FastMCP tool registration, explicit schemas/native results and resource routing |
| `src/ida_pro_mcp/unified_server.py` | Compose the FastMCP frontend with the Nexus provider, replacing the official server singleton |
| `src/ida_pro_mcp/proxy_backend.py`, `supervisor_backend.py` (new) | Adapt exact legacy GUI endpoints and supervisor worker ownership to the common router |
| `src/ida_pro_mcp/server.py`, `idalib_supervisor.py`, `cli.py` | Preserve command entry points while using the new frontend/router |
| `src/ida_pro_mcp/diagnostics.py` (new), `official_adapter.py` | Write compatible diagnostic events; remove obsolete official schema/result monkeypatching |
| `tests/_instance_support.py` (new) | Event-controlled fake providers/backends shared by routing tests |
| `tests/test_instance_*.py`, `test_fastmcp_*.py`, `test_nexus_backend.py`, `test_nexus_guard.py`, `test_output_store.py` (new) | Contract, lifecycle, generation, SDK and integration regressions |
| `tests/unified_acceptance.py`, `test_unified_acceptance.py`, existing transport/bridge/supervisor tests | Migrate old assumptions and verify the complete feature |
| `pyproject.toml`, `uv.lock`, `scripts/bootstrap_unified.py`, plugin manifests, README, CHANGELOG, CI | Reproducible runtime, major-version migration and release verification |

The legacy direct/plugin endpoint stays lightweight. FastMCP is imported by the external frontend, never by `instance_runtime.py`, IDA hooks, or the typed API modules.

## Shared Interfaces

Define these in Tasks 1 and 3. Later tasks use these names instead of introducing competing registries or adapters.

```python
from dataclasses import dataclass, field
import secrets
import threading

@dataclass(frozen=True)
class BackendIdentity:
    provider: str
    key: str
    backend: str
    binary_name: str
    binary_path: str
    idb_path: str
    pid: int
    started_at: str
    compatible: bool = True

@dataclass(frozen=True)
class InstanceBinding:
    instance_id: str
    identity: BackendIdentity

@dataclass(eq=False)
class Invocation:
    binding: InstanceBinding
    operation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    cancelled: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
```

`BackendIdentity.key` is provider-owned immutable incarnation identity: the exact Nexus registry record, or the legacy runtime generation plus listener identity. It is not a path lookup. The provider privately retains credentials and exact discovery objects, excluded from these records and their representation.

Backend interface (type these as Protocols in `instance_contract.py`):

- `BackendProvider.name: str`
- `await BackendProvider.discover() -> list[BackendIdentity]`
- `await BackendProvider.attach(identity: BackendIdentity, invocation: Invocation) -> BackendSession`
- `await BackendProvider.open_path(path: str, options: dict) -> BackendSession`
- `await BackendProvider.reference(query: str) -> str`
- `BackendSession.identity: BackendIdentity`
- `BackendSession.runtime_generation: str`
- `await BackendSession.request(invocation: Invocation, method: str, params: dict) -> dict`
- `await BackendSession.cancel(invocation: Invocation) -> None`
- `await BackendSession.close() -> None`

Internal `method` values are `tools/call`, `resources/read`, `execute_python`, `save_database`, and `output/read`. `tools/call` uses `{name, arguments}`; resource reads use `{uri}`; Python uses `{code, timeout}`; save uses `{}`; output reads use `{output_id}` and return `{text}` containing the backend's full serialized output. The adapter raises a clear unsupported-operation error for capabilities its backend does not provide. These method values are adapter calls, not extra public MCP methods.

Router interface:

- `InstanceRouter(provider: BackendProvider, *, registry: InstanceRegistry | None = None)`
- `await router.list_instances() -> dict`
- `await router.open_database(path: str, **options) -> dict`
- `await router.request(instance_id: str, method: str, params: dict) -> dict`
- `await router.instance_status(instance_id: str) -> dict`
- `await router.close_database(instance_id: str, *, save: bool = False) -> dict`
- `await router.shutdown() -> None`

Registry interface:

- `InstanceRegistry(*, id_factory: Callable[[], str] | None = None)`
- `registry.publish(identity: BackendIdentity) -> InstanceBinding`
- `registry.resolve(value: object, *, allow_closing: bool = False) -> InstanceBinding`
- `registry.describe(binding: InstanceBinding) -> dict`
- `registry.set_state(binding: InstanceBinding, state: str) -> None`
- `registry.retire(binding: InstanceBinding, *, state: str = "closed") -> None`

State is stored separately from immutable bindings. Allowed states are `available`, `attaching`, `ready`, `closing`, `closed`, `unavailable`, and `incompatible`. A failed close stays `closing` with error metadata and the owned lease. Its incarnation index remains occupied until successful close.

## Execution Setup

Setup is part of Task 1's baseline, not a separately reviewed deliverable. Read applicable repository instructions and the execution skill, inspect the current worktree/HEAD, and reuse this checkout. Create a `codex/explicit-instance-routing` branch using managed app controls or ordinary Git if needed and allowed; preserve the design/plan commits. Do not reset files.

Use an existing `uv` installation if available. If absent, install it into a workspace-only bootstrap environment, then resolve the reviewed dependencies through the configured package index:

```powershell
python -m venv .venv-routing-bootstrap
$routingBootstrapPython = Join-Path (Get-Location) '.venv-routing-bootstrap/Scripts/python.exe'
& $routingBootstrapPython -m pip install uv
$routingUv = Join-Path (Get-Location) '.venv-routing-bootstrap/Scripts/uv.exe'
& $routingBootstrapPython scripts/bootstrap_unified.py --wheel-dir wheels
& $routingUv sync --python 3.11 --find-links wheels
& $routingUv run --frozen python -m pytest -q --basetemp .pytest-tmp-routing-baseline
```

On Linux use the equivalent environment's `bin/python` and `bin/uv`. Subsequent command blocks abbreviate the selected executable as `uv`. Do not reinstall dependencies before each task. Save baseline failures and distinguish pre-existing failures from introduced failures; do not weaken a test to conceal either.

## Task 1: Establish immutable IDs and a reusable routing test harness

**Files:** Create `instance_contract.py`, `instance_registry.py`, `tests/_instance_support.py`, and `tests/test_instance_registry.py`.

**Interfaces:** Produces the identity/binding records, `RoutingError(code: str, message: str)`, `require_instance_id(value: object) -> str`, and registry API above. Test support exports `identity(key: str, **changes) -> BackendIdentity` and `FakeProvider(records: list[BackendIdentity])`; the fake implements the backend protocol and exposes `calls`, `sessions`, event gates, and close/cancel records.

- [x] **1. Write deterministic validation, collision, and retirement tests.** Cover `None`, empty/blank strings, bool/int/list values, malformed IDs, exact case, duplicate publication, aliases sharing a key, and two same-named files with distinct keys. Supply an `id_factory` with a deliberate active/retired collision; assert regeneration rather than overwrite. An incompatible registration gets an error/status record but no usable target ID; never treat PID/port alone as its incarnation key.

```python
def test_retired_id_cannot_be_rebound():
    generated = iter(["a" * 16, "a" * 16, "b" * 16])
    registry = InstanceRegistry(id_factory=lambda: next(generated))
    first = registry.publish(identity("runtime-a"))
    registry.retire(first)
    second = registry.publish(identity("runtime-b"))
    assert second.instance_id == "b" * 16
    with pytest.raises(RoutingError) as error:
        registry.resolve(first.instance_id)
    assert error.value.code == "INSTANCE_CLOSED"

def test_failed_close_cannot_be_bypassed_by_discovery():
    registry = InstanceRegistry()
    record = identity("runtime-a")
    binding = registry.publish(record)
    registry.set_state(binding, "closing")
    assert registry.publish(record) is binding
    with pytest.raises(RoutingError) as error:
        registry.resolve(binding.instance_id)
    assert error.value.code == "INSTANCE_CLOSED"
```

- [x] **2. Run the new tests and record the expected missing-contract failure.** `uv run python -m pytest tests/test_instance_registry.py -q` must initially fail for the missing implementation, not unrelated imports.
- [x] **3. Implement validation and registry behavior.** Generate IDs with `secrets.token_hex(8)`, resolve by exact key only, retain retired entries, deduplicate by `(provider, key)`, and explicitly project safe metadata. Accept different path aliases only after the provider establishes the same incarnation; never deduplicate by basename.

```python
def require_instance_id(value: object) -> str:
    if value is None:
        raise RoutingError("INSTANCE_ID_REQUIRED", "Pass instance_id from list_instances or open_database")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value):
        raise RoutingError("INVALID_INSTANCE_ID", "instance_id must be the exact 16-character ID returned by this server")
    return value
```

- [x] **4. Build event-controlled fake sessions.** Fake `request` records `(identity.key, method, params, operation_id)`, waits on an optional per-key gate, returns a valid native result, and records cancellation. Fake `attach` has a separate gate and allocates a close-counted session. Fake `close` can fail once and succeed on retry. Teardown releases every gate so failing tests cannot hang.
- [x] **5. Run the focused tests green and commit.** `uv run python -m pytest tests/test_instance_registry.py -q`; `git diff --check`; commit `feat: add immutable instance bindings and exact ID validation`.

## Task 2: Enforce database generations at the IDA execution boundary

**Files:** Create `instance_runtime.py`, `ida_mcp/instance_dispatch.py`, `ida_mcp/instance_hooks.py`, `tests/test_instance_runtime.py`, `tests/test_instance_dispatch.py`. Modify `ida_mcp.py`, `idalib_server.py`, `idalib_session_manager.py`, `ida_mcp/discovery.py`, `ida_mcp/sync.py`, `ida_mcp/rpc.py`, `ida_mcp/http.py`, `bridge_runtime.py`; extend existing bridge, namespace, discovery and loader tests.

**Interfaces:** `RuntimeIdentity.activate(binary_path: str, idb_path: str) -> str`, `invalidate() -> None`, `snapshot() -> dict`, `check(expected: str) -> None`; `runtime_identity() -> RuntimeIdentity` is the singleton accessor. `generation_context(expected: str)` is a context manager and `check_request_generation() -> None` validates its context when present. `install_instance_dispatch(server) -> None` adds the public argument/URI guard and unique operation mapping. Authenticated bridge protocol becomes version 2 and includes `generation` in its private descriptor.

- [x] **1. Add generation tests that model same-path reopen and queued execution.** Activate A, capture its generation, invalidate, reactivate the same paths, and assert the old generation fails. Simulate a main-thread callback queued before replacement and verify its mutation body never runs.

```python
def test_queued_body_rejects_reopened_same_path():
    state = RuntimeIdentity()
    old = state.activate("sample.exe", "sample.i64")
    touched = []
    def queued():
        state.check(old)
        touched.append("mutation")
    state.invalidate()
    new = state.activate("sample.exe", "sample.i64")
    assert new != old
    with pytest.raises(RoutingError) as error:
        queued()
    assert error.value.code == "INSTANCE_CHANGED"
    assert touched == []
```

- [x] **2. Add RPC-boundary tests before implementing the wrapper.** Missing `instance_id` fails even with one open database; correct direct ID is consumed before calling the original typed method; wrong private generation fails on the authenticated bridge; direct caller metadata cannot impersonate a trusted bridge context. Exercise resources, output GETs, and two transport clients using request number `1` with independent cancellation. Include the `server_health` busy fast path: it must report only cached bookkeeping after boundary validation, with its IDA-reading path still checked on the main thread.
- [x] **3. Run red.** `uv run python -m pytest tests/test_instance_runtime.py tests/test_instance_dispatch.py -q`.
- [x] **4. Implement lifecycle state and hooks.** Use persistent `UI_Hooks.database_inited` and early `IDB_Hooks.closebase`; keep them separate from the existing one-shot autostart hook. Invalidate before database close/replacement, create a fresh generation on open/listener restart, publish it atomically, and only remove a registration if its generation still matches. Headless open/close explicitly drives the same state. Stop accepting old work immediately; avoid waiting for a main-thread-dependent request inside a main-thread lifecycle callback.
- [x] **5. Insert the second check inside the captured main-thread body.** The existing `idasync` closure copies ContextVars; place the generation check inside that captured context immediately before the actual function call. Preserve local Python tests/calls without an RPC context and retain cancellation/deadline/batch restoration.

```python
def guarded_call():
    check_request_generation()
    return f(*args, **kwargs)

context = copy_context()
ff = functools.partial(context.run, guarded_call)
ff.__name__ = f.__name__
```

- [x] **6. Guard internal and direct transports separately.** The bridge verifies authentication before installing its expected-generation context. Public direct calls resolve their own advertised `instance_id`; strip untrusted reserved context fields. Generate private request IDs and retain original response IDs; map cancellation using the transport identity and original ID, including early-cancellation registration races. Backend generation checks are identity checks, not a new authentication mechanism.
- [x] **7. Preserve worker single-database semantics.** An owned worker hosts one live database at a time; a request must not activate an old session. Update direct worker open/list results to generated IDs, remove caller-controlled public IDs, and ensure reopening retires prior identity. Internal supervisor bookkeeping can keep private names until Task 7 replaces its public API.
- [x] **8. Run green and commit.** `uv run python -m pytest tests/test_instance_runtime.py tests/test_instance_dispatch.py tests/test_bridge_runtime.py tests/test_bridge_namespaces.py tests/test_unified_install.py tests/test_idalib_session_manager.py tests/test_discovery_wildcard_host.py -q`; commit `fix: reject stale database generations before IDA execution`.

## Task 3: Implement independent queues, attachment, and close/drain

**Files:** Create `instance_router.py` and `tests/test_instance_router.py`; extend `_instance_support.py` and `test_instance_registry.py`; add direct `anyio>=4.9` runtime dependency in `pyproject.toml` and regenerate `uv.lock` for cancellation shielding.

**Interfaces:** Produces the complete router interface. Each runtime slot owns one binding, async gate, backend session, active invocation set, and shared close task. Invocations already contain a binding before they become visible to close/cancellation.

- [x] **1. Add a barrier-based concurrency regression.** The fake emits a valid `{content, structuredContent, isError}` result containing its key. Hold A, queue at least 64 additional calls for A, and prove B completes before releasing A. This verifies worker-pool independence, not elapsed-time speed alone.

```python
def test_busy_instance_does_not_block_peer():
    async def scenario():
        provider = FakeProvider([identity("A"), identity("B")])
        router = InstanceRouter(provider)
        rows = (await router.list_instances())["instances"]
        a, b = [row["instance_id"] for row in rows]
        provider.block_request("A")
        pending = asyncio.create_task(router.request(a, "tools/call", {"name": "server_health", "arguments": {}}))
        await provider.wait_entered("A", "request")
        peer = await asyncio.wait_for(router.request(b, "tools/call", {"name": "server_health", "arguments": {}}), 2)
        assert peer["structuredContent"]["backend"] == "B"
        assert not pending.done()
        provider.release_request("A")
        await pending
        await router.shutdown()
    asyncio.run(scenario())
```

The fake helper methods used here are implemented in `_instance_support.py`: `block_request(key)`, `wait_entered(key, stage)`, and `release_request(key)`; `wait_entered` has a bounded timeout and accepts `attach`, `request`, or `close`.

- [x] **2. Add attachment/close races.** Close A while B's attach is paused; close A while A's own attach finishes; close before queued work enters; cancel a waiter without cancelling a shared open; retry a failed close; verify rediscovery cannot bypass it. Snapshot request dictionaries to ensure forwarding never mutates another caller's arguments.
- [x] **3. Run red.** `uv run python -m pytest tests/test_instance_router.py -q`.
- [x] **4. Implement asynchronous admission and attachment.** Resolve synchronously, register `Invocation(binding=...)`, then await the binding's gate. Recheck state after acquiring the gate and after attachment. Use one attachment per live binding, and never hold the registry lock across an await. Work queued on A awaits its gate without consuming a blocking worker thread. Coalesce explicit open by canonical path, then deduplicate its resulting incarnation; close any redundant owned lease, not the retained winner.
- [x] **5. Implement cancellation/drain before releasing leases.** Cancellation signals only the admitted invocation. If attach completes after cancellation, retain or close the exact acquired handle before finishing cleanup. Use an AnyIO-shielded cleanup region under asyncio and wait for actual backend unwind. A close task is shared by concurrent close callers; cancelling one waiter cannot abandon it.

```python
async def run_attached(session, invocation, method, params):
    worker = asyncio.create_task(session.request(invocation, method, params))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        invocation.cancelled.set()
        async def drain():
            await session.cancel(invocation)
            with suppress(asyncio.CancelledError):
                await worker
        cleanup = asyncio.create_task(drain())
        with anyio.CancelScope(shield=True):
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    pass
            cleanup.result()
        raise
```

Apply this pattern only after a backend session exists; attachment and queued-state cancellation use their corresponding tracked tasks. Do not reference `session` or `worker` before assignment. Backend exceptions during cleanup remain reported and retain the lease for retry.

- [x] **6. Implement close and shutdown.** Atomically mark closing, cancel queued/running operations on that binding, drain, optionally perform legacy `idb_close(save=True)` save against the same generation, expire outputs, then close the owned session. A failed drain or requested save leaves the binding closing with a retriable error; document the save-failure behavior. Successful close retires the ID. Shutdown attempts all bindings and aggregates errors; it cannot silently stop at the first failed peer.
- [x] **7. Run green and commit.** `uv run python -m pytest tests/test_instance_registry.py tests/test_instance_router.py -q`; commit `feat: route concurrent operations through per-instance queues`.

## Task 4: Adapt Nexus and the typed bridge without implicit manager state

**Files:** Create `nexus_backend.py`, `nexus_guard.py`, `tests/test_nexus_backend.py`, `tests/test_nexus_guard.py`. Modify `unified_bridge.py`, `bridge_runtime.py`, `ida_mcp/instance_hooks.py`, and `tests/test_unified_bridge.py`.

**Interfaces:** `NexusProvider` implements `BackendProvider`; `NexusSession` implements `BackendSession`. `UnifiedBridge` receives an explicit session adapter, requires `instance_id` for every target-specific method, and no longer exports `bridge_manager_class`. The adapter method `resolve_instance_id(value: str) -> str` validates only its exact attached binding; it never chooses a current target. `nexus_guard.execute(code: str, expected_generation: str, expected_idb_path: str, namespace: dict, filename: str = "<ida-mcp>") -> object` checks identity before evaluating user code in that same namespace. Its private `_load_evaluator() -> Callable` validates the Nexus version and returns the pinned `_execute_user_code` helper. `nexus_guard.save(expected_generation: str, expected_idb_path: str, backend: str) -> dict` performs the guarded save inside an existing Nexus main-thread operation.

- [x] **1. Add exact-attachment tests.** Supply two fake Nexus `DatabaseInstance` records, reuse a path with a different record, and assert `DatabaseHandle.attach(exact_record)` is used for discovered IDs. Discovery calls no `open` or Python operation. Explicit `open_path` may call `DatabaseHandle.open`, but a failed ordinary tool call may not. Duplicate path opens must return one binding and retain only one lease.
- [x] **2. Add generation tests for the Nexus family.** A successful preflight followed by generation replacement must reject Python and save before their effects. Test callback globals, a trailing expression, newly defined `run(db)`/`execute(db)`/`main(db)`, future imports, a module docstring, syntax-error line numbers, and cancellation raised as `BaseException`. A guard must not wrap user code in a local function and break persistent globals.

```python
def test_guard_runs_before_user_evaluation(monkeypatch):
    state = RuntimeIdentity()
    old = state.activate("a.exe", "a.i64")
    touched = []
    monkeypatch.setattr(nexus_guard, "runtime_identity", lambda: state)
    monkeypatch.setattr(nexus_guard, "_load_evaluator",
                        lambda: lambda *args: touched.append("evaluated"))
    namespace = {"__builtins__": __builtins__}
    state.invalidate()
    state.activate("a.exe", "a.i64")
    with pytest.raises(RoutingError):
        nexus_guard.execute("changed = True", old, "a.i64", namespace)
    assert touched == []
    assert "changed" not in namespace
```

Integration tests invoke this guard through the pinned Nexus execution adapter, including snippets that rebind `globals` or `__import__` in their persistent namespace.

- [x] **3. Run red.** `uv run python -m pytest tests/test_nexus_backend.py tests/test_nexus_guard.py tests/test_unified_bridge.py -q`.
- [x] **4. Implement exact handle ownership.** Use the pinned public Nexus APIs and private provider storage for discovered records. Bootstrap the typed bridge briefly through the same lease; verify protocol version 2, runtime fingerprint, generation and expected IDB identity. Retain one lease and typed client context per binding. Close a failed or redundant attachment without touching a peer's handle. Remove current-target lookup and process-wide lifecycle locking.
- [x] **5. Put the Nexus generation check inside the execution unit.** Submit one expression through public `handle.execute_python` that calls `nexus_guard.execute` with the original code string and the actual Nexus namespace. The helper checks generation/path first, then invokes Nexus 0.13.0's pinned `_execute_user_code` with that same namespace and `{db, ida_domain}` runtime mapping. This preserves future imports, traceback line numbers, top-level state, entrypoint detection and Nexus interrupt protection without AST/source rewriting or nested IDA synchronization.

```python
def guarded_expression(code: str, generation: str, idb_path: str) -> str:
    return (
        '__builtins__["__import__"]("ida_pro_mcp.nexus_guard", '
        'fromlist=["execute"]).execute('
        f'{code!r}, {generation!r}, {idb_path!r}, '
        '__builtins__["globals"](), filename="<ida-mcp>")'
    )
```

Implement `guarded_expression` in `nexus_backend.py`. Nexus restores its builtins mapping on each call, so prior user variables named `globals` or `__import__` cannot redirect the wrapper. The one private evaluator import is isolated in `_load_evaluator`, rejects an incompatible dependency version/signature, and gets dedicated parity tests; lifecycle and transport continue through public Nexus APIs. Evaluate user code in its original namespace, not helper locals. This protects against lifecycle races, not intentionally hostile Python code.

- [x] **6. Make save and initial analysis part of guarded main-thread units.** Route the public save operation through the same guard and a small runtime save helper preserving the pinned behavior: reject a temporary GUI database requiring Save As, use GUI `SaveBase` for GUI, `ida_loader.save_database(path, 0)` for headless, validate success, and return the original `{path}` public result. Do not perform a separate unguarded `handle.save_database()` after a guard-only request. Any initial autoanalysis wait must check generation in its own main-thread execution unit too; a separate preflight check before an unguarded analysis call is insufficient. Preserve cancellation and never nest typed synchronization inside Nexus execution.
- [x] **7. Update GUI Nexus lifecycle on database replacement.** Rotate/retire the old registration and lease-bound runtime using the package's public lifecycle hooks. Schedule teardown so it cannot join a request waiting on the same IDA main thread; re-register the new database only after old registration cleanup. Add a test that an old handle cannot bootstrap against a reopened same-path database.
- [x] **8. Run green and commit.** `uv run python -m pytest tests/test_nexus_backend.py tests/test_nexus_guard.py tests/test_unified_bridge.py tests/test_bridge_runtime.py tests/test_bridge_namespaces.py -q`; commit `refactor: bind Nexus and typed execution to exact instances`.

## Task 5: Bind output continuations and resource reads to their owners

**Files:** Create `output_store.py`, `tests/test_output_store.py`; modify `instance_router.py`, `unified_bridge.py`, `bridge_runtime.py`, `ida_mcp/rpc.py`, `ida_mcp/http.py`; add `tests/test_instance_resources.py`.

**Interfaces:** `OutputStore.remember(binding: InstanceBinding, runtime_generation: str, backend_output_id: str, context_id: str) -> str`; `lookup(instance_id: str, output_id: str) -> OutputReference`; `expire(instance_id: str) -> None`. `OutputReference` is immutable and contains those four ownership fields plus `output_id`. Router adds `await read_output(instance_id: str, output_id: str, offset: int = 0, limit: int = 32000) -> dict` and `await read_resource(uri: str) -> dict`.

- [x] **1. Test ownership before I/O.** Use the same backend output ID from A and B, verify different public handles, reject a mismatching supplied instance, reject unknown/expired output, and assert no HTTP request occurred on failures. Close A while an output read is blocked; it must participate in drain. Keep `MAX_OUTPUTS=128`, 32,000-character pages, and the current 64 MiB transfer limit.

```python
def test_output_handle_cannot_cross_instances():
    registry = InstanceRegistry()
    a = registry.publish(identity("A"))
    b = registry.publish(identity("B"))
    outputs = OutputStore()
    handle = outputs.remember(a, "generation-a", "same-backend-id", "context-a")
    with pytest.raises(RoutingError) as error:
        outputs.lookup(b.instance_id, handle)
    assert error.value.code == "OUTPUT_INSTANCE_MISMATCH"
    outputs.expire(a.instance_id)
    with pytest.raises(RoutingError) as error:
        outputs.lookup(a.instance_id, handle)
    assert error.value.code == "OUTPUT_EXPIRED"
```

- [x] **2. Test resource parsing.** Cover `ida://idb/metadata?instance_id=...`, named struct templates, absent/blank/duplicate selectors, percent-encoded names, unknown query parameters and differing IDs for otherwise equal resources. Returned `contents[].uri` must retain the public identity-bearing URI.
- [x] **3. Run red.** `uv run python -m pytest tests/test_output_store.py tests/test_instance_resources.py -q`.
- [x] **4. Implement ownership and rewrite hints.** Public output metadata contains `instance_id` and the public output handle. Strip backend URLs and generate an executable hint containing both IDs. Output lookup resolves its pinned binding, then uses the router's normal admission/close tracking. Verify the backend generation on output GET as well as POST. Raw compatibility downloads return an error for unowned IDs and never use a default endpoint.

```python
hint = (
    f'Output truncated. Use read_output(instance_id="{binding.instance_id}", '
    f'output_id="{output_id}", offset=0, limit=32000).'
)
```

- [x] **5. Implement URI stripping/restoration.** Parse with blank values retained; require exactly one selector; forward the original backend URI after removing only that selector. Rebuild response URIs with the same public binding. Preserve MIME types, text/blob contents, native errors, and truncation envelopes.
- [x] **6. Run green and commit.** `uv run python -m pytest tests/test_output_store.py tests/test_instance_resources.py tests/test_mcp_spec_truncation.py tests/test_unified_bridge.py -q`; commit `fix: pin outputs and resources to their originating instance`.

## Task 6: Replace the unified public frontend with FastMCP

**Files:** Create `fastmcp_frontend.py`, `tests/test_fastmcp_catalog.py`, `tests/test_fastmcp_transport.py`; modify `unified_server.py`, `official_adapter.py`, `tool_catalog.py`, `cli.py`, `pyproject.toml`, `uv.lock`, `.github/workflows/offline-tests.yml`, and unified server/CLI/acceptance tests.

**Interfaces:** `create_server(router: InstanceRouter, *, extensions: set[str], profile: set[str] | None, legacy_aliases: bool = False) -> FastMCP`; `RoutedTool(Tool)` stores the router privately and forwards validated arguments. `configure_server` composes a Nexus provider and this frontend without importing `ida_mcp.mcp` or creating its `DATABASE_MANAGER`.

- [x] **1. Add catalog and dependency contracts.** Compare all standard/debugger descriptors against `get_ida_tools(fork_schema_generator(), extensions)`, allowing only required routing metadata changes. Missing IDs must fail before provider calls; profile-disabled tools remain unavailable; no `select_instance` or `set_current` parameter is present. Run fresh subprocess import guards proving IDAPython and the official frontend singleton are not imported by discovery.
- [x] **2. Pin the new runtime as part of the frontend deliverable.** Add `fastmcp==4.1.0`, `mcp==2.3.0`, and runtime `jsonschema>=4.20.0` because custom tools use its validator. Remove the contradictory SDK 1 development pin. Retain the pinned Nexus/Domain and official diagnostic dependency until Task 8 verifies its consumers. Resolve and record the new lockfile and update offline CI's dependency installation in the same commit.

```toml
"fastmcp==4.1.0",
"mcp==2.3.0",
"jsonschema>=4.20.0",
```

- [x] **3. Run the new frontend tests red.** `uv run python -m pytest tests/test_fastmcp_catalog.py tests/test_fastmcp_transport.py -q`.
- [x] **4. Implement explicit-schema tools through public FastMCP APIs.** Validate required identity before any backend operation; validate remaining arguments against the preserved JSON Schema and retain original defaults/coercion at the backend. Convert native results without stringifying or double-wrapping `structuredContent` and `_meta`.

```python
async def run(self, arguments: dict) -> ToolResult:
    instance_id = require_instance_id(arguments.get("instance_id"))
    self._validator.validate(arguments)
    backend_arguments = {key: value for key, value in arguments.items() if key != "instance_id"}
    result = await self._router.request(instance_id, "tools/call", {
        "name": self.name, "arguments": backend_arguments})
    return ToolResult.from_mcp_result(CallToolResult.model_validate(result))
```

`self._validator` is a precompiled `Draft202012Validator` for `self.parameters`. Catch `RoutingError` and `jsonschema.ValidationError` at the adapter boundary and return an error result with `_meta.ida_mcp.error_code`; do not log full sensitive argument dumps. Keep application error metadata outside strict tool output schemas.

- [x] **5. Register lifecycle and resource adapters.** Expose `list_instances`, `list_databases`, `instance_status(instance_id)`, `open_database(path)`, `execute_python(code, instance_id, timeout)`, `save_database(instance_id)`, `close_database(instance_id)`, `read_output(instance_id, output_id, offset, limit)`, and global `reference(query)`. Register identity-bearing resource templates. `open_database` has no selection side effect. Preserve backend-specific unsupported-capability reporting.
- [x] **6. Wire transport and lifetime.** Use one router per frontend process and FastMCP's lifespan to await shutdown. Keep stdio concurrent. For HTTP use streaming-capable responses, automatic modern/legacy negotiation, `stateless_http=False`, explicit Host/Origin protections, and the existing path-prefix/default-port CLI contract. Do not add auto-retry middleware or a cache for database-dependent tool results.

```python
app = server.http_app(
    path=mcp_path,
    json_response=False,
    stateless_http=False,
    host_origin_protection=True,
    allowed_hosts=allowed_hosts,
)
```

Compute `mcp_path` from the existing CLI path prefix and `allowed_hosts` from the configured bind/public host using the current accepted-loopback behavior; keep CORS as a separate configured policy.

- [x] **7. Verify supported protocol modes.** Run event-controlled fake backends through in-memory, subprocess stdio, and real loopback HTTP, with modern and legacy clients. Assert modern HTTP sends no session ID; legacy cancellation is retained. Keep a regression documenting why forcing legacy stateless mode is excluded, without requiring an unsupported mode to pass. Duplicate original request IDs on two HTTP clients must not collide in backend IDs or cancellation maps.
- [x] **8. Run green and commit.** `uv run python -m pytest tests/test_fastmcp_catalog.py tests/test_fastmcp_transport.py tests/test_unified_server.py tests/test_unified_cli.py tests/test_unified_acceptance.py -q`; commit `feat: serve explicit instance tools through FastMCP`.

## Task 7: Migrate legacy GUI and headless entry points to the same contract

**Files:** Create `proxy_backend.py`, `supervisor_backend.py`, `tests/test_instance_legacy.py`. Modify `server.py`, `idalib_supervisor.py`, `idalib_server.py`, `cli.py`, `tests/test_server_transport.py`, `test_proxy_startup.py`, `test_proxy_http_downloads.py`, `test_offline_tool_catalog.py`, `test_idalib_supervisor.py`.

**Interfaces:** `ProxyProvider` and `SupervisorProvider` implement the shared provider/session protocols. `server.py` and `idalib_supervisor.py` retain command parsing but compose `create_server`. Supervisor internal session IDs stay private and cannot be chosen by an agent.

- [x] **1. Replace old-selection tests with contract regressions.** Prove the legacy commands advertise mandatory `instance_id`, no `select_instance`, and no `database` argument. Simulate registry reorder and port reuse; an old ID must error. A `--ida-rpc` constraint filters discovery but cannot supply the target of an ID-less tool call.

```python
def test_disappeared_gui_is_not_reopened_implicitly(monkeypatch):
    provider = make_supervisor_provider_with_gui()
    monkeypatch.setattr(provider.supervisor, "_allocate_worker_locked",
                        lambda: pytest.fail("ordinary calls must not spawn a replacement"))
    provider.mark_gui_unavailable()
    with pytest.raises(RoutingError) as error:
        asyncio.run(provider.call_discovered_gui())
    assert error.value.code in {"INSTANCE_UNAVAILABLE", "INSTANCE_CHANGED"}
```

Implement `make_supervisor_provider_with_gui`, `mark_gui_unavailable`, and `call_discovered_gui` as test-fixture helpers in `test_instance_legacy.py`: they create one registry record, hold its returned ID, mark the exact endpoint unreachable, and call `router.request` with that ID. They must not use the user's registry.

- [x] **2. Run red.** `uv run python -m pytest tests/test_instance_legacy.py tests/test_proxy_startup.py -q`.
- [x] **3. Remove shared selection.** Delete `_session_proxy_targets`, active/default target helpers, fuzzy name/port selection, auto-selection at startup, and output fallback. Keep configured endpoints only for discovery/install constraints. Runtime forwarding obtains the backend generation from the binding and sends it to the guarded endpoint, preserving extensions and allowed headers.
- [x] **4. Adapt headless ownership without weakening stale-ID handling.** Retain worker allocation/capacity, busy-worker handling, warmup, explicit GUI/headless open modes and adopted-vs-owned closure. Remove `_reopen_gui_session_headless` from normal resolution. `idb_open` is the only operation allowed to intentionally open a replacement. Public `idb_list` returns generated IDs; `idb_close(instance_id, save=True)` delegates to the router's drain/save/close policy. Existing explicit warmup/mode options remain supported.
- [x] **5. Keep offline discovery independent of workers.** Use `tool_catalog` for typed descriptors rather than spawning a schema worker on `tools/list`. Add only the backend's management aliases and supported operations. `list_instances` can list an incompatible old registration, but it must not call it or synthesize an identity from PID/port.
- [x] **6. Run concurrency and output checks on both legacy entry points.** Two calls sharing stdio must overlap across two workers; cancellation maps to one operation; raw output GET framing remains correct with no fallback; schema listing before backend startup continues to work after a later registration appears.
- [x] **7. Run green and commit.** `uv run python -m pytest tests/test_instance_legacy.py tests/test_server_transport.py tests/test_proxy_startup.py tests/test_proxy_http_downloads.py tests/test_offline_tool_catalog.py tests/test_idalib_supervisor.py -q`; commit `refactor: unify legacy routing on explicit instance bindings`.

## Task 8: Preserve diagnostics, packaging, and documented migration

**Files:** Create `diagnostics.py`, `tests/test_instance_diagnostics.py`, `docs/explicit-instance-validation.md`. Modify `official_adapter.py`, `cli.py`, `installer.py`, `scripts/bootstrap_unified.py`, `pyproject.toml`, `uv.lock`, `ida-plugin.json`, `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, `.kimi-plugin/plugin.json`, README, CHANGELOG, existing bootstrap/install tests, and `.github/workflows/offline-tests.yml`.

**Interfaces:** `TraceWriter(state_dir: Path, *, agent: str | None = None)` exposes `path: Path` and `emit(event: str, **fields) -> None`, writing compatible schema-1 JSONL under the existing MCP state path. `RoutingTraceMiddleware(writer: TraceWriter)` records unique call IDs, public instance IDs, tool/result/error and lifecycle events; it never initializes the official `DATABASE_MANAGER`.

- [x] **1. Add diagnostics and dependency tests.** Feed a trace produced by the new writer to the retained official dashboard/log readers. Assert start/stop, tool calls/results/errors, database open/reuse/disconnect/save/release and release errors remain visible. Cross-check manifest versions, configured command generation and Python ABI without reading or changing live user configuration.

```python
def test_trace_does_not_expose_transport_credentials(tmp_path):
    writer = TraceWriter(tmp_path, agent="test")
    writer.emit("database_opened", instance_id="a" * 16,
                target={"backend": "gui", "idb_path": "a.i64"})
    records = [json.loads(line) for line in writer.path.read_text().splitlines()]
    assert records[0]["schema"] == 1
    assert records[0]["instance_id"] == "a" * 16
    assert "token" not in records[0]["target"]
```

Add a separate integration test with a provider holding a sentinel credential and assert the sentinel never appears anywhere in captured trace or tool output. The writer test alone is not evidence of credential redaction across layers.

- [x] **2. Run red.** `uv run python -m pytest tests/test_instance_diagnostics.py tests/test_unified_install.py tests/test_bootstrap_unified.py -q`.
- [x] **3. Implement trace compatibility through explicit events.** Use the existing `ida_mcp.paths` state-path helper and schema-1 event names consumed by the dashboard. Keep configured agent transcript handling and environment-owned MCP identity; caller metadata cannot override them. Retain `dashboard`, `logs`, and `hook` commands. Delete obsolete result/schema monkeypatching and any imports used solely for the old public server.
- [x] **4. Update release metadata to 4.0.0 and dependency receipts.** Pin FastMCP/SDK at the approved versions; retain exact reviewed Nexus/Domain versions. Extend the bootstrap's receipt to record installed FastMCP/SDK versions and wheel hashes while retaining exact Git-source validation for unpublished official dependencies. A wheel built here must work without the temp probe environment or source checkout.
- [x] **5. Rewrite migration instructions with working examples.** Show `list_instances`, concurrent calls with two different IDs, explicit open, stale errors, resource URIs and `read_output` with both IDs. Remove all advice about selected/current targets and optional identity. Explain per-server ID lifetime, protocol-era compatibility, one frontend process, same-ID shared edits/Python state, and the legacy close save-failure behavior. Keep older design documents historical rather than rewriting their evidence.
- [x] **6. Validate copied plugin installs and imports.** Extend fingerprint/copy tests, verify the plugin imports without FastMCP's web stack inside IDA, and ensure pre-9.4 legacy use does not accidentally require a running Nexus service. Test startup with mismatched/old runtime generation capability and return an actionable incompatible-instance error.
- [x] **7. Run green and commit.** `uv run python -m pytest tests/test_instance_diagnostics.py tests/test_unified_install.py tests/test_unified_cli.py tests/test_bootstrap_unified.py tests/test_installer_scope_messages.py -q`; commit `docs: publish explicit instance API migration and 4.0 metadata` (a local commit only).

## Task 9: Verify the complete multi-instance behavior and review the branch

**Files:** Extend `tests/test_fastmcp_transport.py`, `tests/test_unified_acceptance.py`, `tests/unified_acceptance.py`, `docs/explicit-instance-validation.md`; add `tests/multi_instance_acceptance.py` and `tests/test_instance_acceptance.py`.

**Interfaces:** `tests/multi_instance_acceptance.py --mode {headless,gui} --fixture-a PATH --fixture-b PATH` exercises one MCP connection and explicitly owned fixture copies. The harness validates file hashes, IDs and paths before edits and reports JSON results for each gate. GUI mode starts only its own fixture processes and installs the test plugin into an isolated IDA user directory.

- [x] **1. Add the full acceptance harness before running it.** Migrate the old SDK 1 camelCase accessors to SDK 2 snake_case, use explicit IDs on every target operation and `client.protocol_version`, and stop guessing private client request counters. Include missing/stale ID checks, more than two fake targets, real transport cancellation, alias opens, output ownership, peer-close isolation and clean shutdown.

```python
async def assert_parallel_identity(client, a: str, b: str):
    first, second = await asyncio.gather(
        client.call_tool("server_health", {"instance_id": a}),
        client.call_tool("server_health", {"instance_id": b}),
    )
    assert first.data["idb_path"] != second.data["idb_path"]
```

This identity assertion supplements the event-gated blocking proof from Task 3 and transport tests; two fast successful responses alone do not prove parallel dispatch.

- [x] **2. Run focused transport/lifecycle checks once.** `uv run python -m pytest tests/test_instance_acceptance.py tests/test_fastmcp_transport.py tests/test_instance_router.py tests/test_unified_bridge.py -q`. On failure, fix the responsible layer and rerun affected checks; do not mask native cancellation or weaken stale-generation tests.
- [x] **3. Run full offline verification and build.** `uv run --frozen python -m pytest -q --basetemp .pytest-tmp-routing-final`; `uv build --wheel`; `git diff --check`. In a separate clean venv install only the built wheel plus declared dependencies, then verify version 4.0.0, offline catalog/schema parity, and startup without IDAPython. Use the wheel for a fake-backend protocol smoke test rather than importing the workspace through `PYTHONPATH`.
- [ ] **4. Verify IDA fixtures under the configured runtime.** Detect the actual licensed IDA installation and Python ABI before execution. Copy both fixtures into distinct directories under the test temp root; preserve licenses without logging their contents; isolate `IDAUSR`, `IDA_NEXUS_STATE_DIR`, and `IDA_MCP_STATE_DIR` in child environments. Run the retained fixture tests and the two-file harness in headless mode, then GUI mode against its own processes. Confirm the actual external client protocol and reconnect behavior.

```powershell
uv run python -m ida_pro_mcp.test .pytest-tmp-routing-live/a/typed_fixture.elf -q
uv run python -m ida_pro_mcp.test .pytest-tmp-routing-live/b/typed_fixture.elf -q
uv run python tests/multi_instance_acceptance.py --mode headless --fixture-a .pytest-tmp-routing-live/a/typed_fixture.elf --fixture-b .pytest-tmp-routing-live/b/typed_fixture.elf
uv run python tests/multi_instance_acceptance.py --mode gui --fixture-a .pytest-tmp-routing-live/a/typed_fixture.elf --fixture-b .pytest-tmp-routing-live/b/typed_fixture.elf
```

Create those copies before these commands; the two paths must resolve to different IDBs. Set `IDADIR` and IDA's Python bindings in the child environment if required. Do not reinterpret the sample paths as permission to analyze or edit a user's unrelated live database.

- [ ] **5. Exercise reversible edits and replacement.** Give the copied databases distinct marker comments; alternate typed and Nexus queries and verify each result matches its ID, path, and marker. Restore comments. Hold A's operation, prove B progresses, cancel A, and verify B/Python state remain usable. Close/reopen A and restart its owned backend with a reused port; the old ID and output handle must fail. Verify the final owned worker lease closes cleanly while an adopted GUI stays open until harness cleanup.
- [x] **6. Request the final independent review required by the selected execution workflow.** Provide the approved spec, this plan, baseline commit, changed files and actual verification results. Review all public entry points, cancellation/drain ordering, plugin generation checks, error/result schemas and migration docs. Fix actionable findings and rerun only affected checks plus any required final gate.
- [x] **7. Record evidence and commit.** Fill `docs/explicit-instance-validation.md` with exact local commit, dependency versions, test counts, actual protocol modes, GUI/headless identities, and any unavailable checks. Report a missing IDA/license/client check as unverified; do not mark it passed from the mock probes. Commit `test: verify concurrent instance routing across supported transports`.

## Completion and Coverage Map

| Approved spec requirement | Owning tasks |
| --- | --- |
| Mandatory opaque IDs, tombstones, aliases, missing/unknown/closed errors | 1, 3, 6 |
| No current target, no select/switch, no caller IDs, no same-ID GUI fallback | 4, 6, 7 |
| Exact backend incarnation, dispatch-to-main-thread race, direct plugin guard | 2, 4 |
| Parallel files on one connection, bounded worker usage, independent opens | 3, 6, 7, 9 |
| Cancellation, close, drain ACK, peer preservation, failed-close retry | 2, 3, 4, 5, 9 |
| Both Python APIs, debugger/profile/timeout/callback contracts | 2, 4, 6, 9 |
| Explicit resources, output ownership and expiration | 5, 6, 7 |
| Offline discovery, exact tool schemas and native results | 6, 7, 9 |
| Modern sessionless and older protocol clients, browser transport guards | 6, 9 |
| Nexus leases, legacy worker adoption/ownership, IDA version floors | 4, 7, 8, 9 |
| Diagnostic commands, copied installs, wheel-only use, version migration | 8, 9 |

- [x] Confirm every implementation/test step is complete or explicitly report its remaining blocker.
- [x] Confirm no uncommitted temporary probe code, credentials, licenses, IDBs, or generated environments are staged.
- [x] Report the implementation commit, verification evidence, required client/plugin restart, and any live-validation limitation.

Recommended execution method: inline implementation in this chat, followed by an independent whole-branch review. The tasks share the same registry, runtime identity, and close/cancel interfaces, so sequential ownership reduces coordination churn. Per-task subagent implementation and review remains available if the user prefers it.

# Explicit instance routing validation

Date: 2026-10-16. Branch: `codex/explicit-instance-routing`.
Implementation through `d343b85028b9b2e0dd9986fc3fe1188efb5f57e1`;
product baseline `7245a50a92ef914cbb64d9be6d000785cbbcb41e`.

Runtime: Python 3.11.9, FastMCP 4.1.0, MCP SDK 2.3.0, Nexus 0.13.0,
IDA Domain 0.5.1, licensed IDA 9.4 on Windows. All live checks used copied
fixtures and isolated IDA user, Nexus, and MCP state. The normal installed
plugin, configured MCP client, and user databases were not changed.

## Verified results

| Check | Result |
| --- | --- |
| Original offline baseline | 346 passed, 1 skipped, 128 subtests |
| Final offline suite | **401 passed, 1 opt-in skip, 119 subtests**, 71.28 s |
| Opt-in stdio / real HTTP acceptance | **2 passed**, 30.93 s |
| Typed IDA fixture, independent copy A | **337 passed, 2 skipped**, 30.00 s |
| Typed IDA fixture, independent copy B | **337 passed, 2 skipped**, 29.98 s |
| Changed Python files | Ruff `F` checks and `git diff --check` passed |
| Wheel build and isolated install | Passed; imported from wheel-only `site-packages` under Python `-I` |
| Wheel-only fake-backend protocol smoke | 97 tools, missing-ID rejection, two-instance parallel dispatch passed |

The fixture suite emits existing IDA API deprecation warnings. The modern
protocol negotiated by live clients was `2026-07-28`. Event-gated FastMCP HTTP
tests also exercised legacy negotiation and targeted cancellation; modern HTTP
requests were checked to omit the session header. A separate loopback HTTP
startup test validated catalog discovery before IDA opens.

Catalog checks preserve all 66 standard and 22 debugger tool descriptors, apart
from required routing metadata. Unified catalogs contain 75 default / 97 debug
tools; the legacy supervisor default includes 78 with its management aliases.

## Live two-database runs after review fixes

`tests/multi_instance_acceptance.py` used one subprocess MCP connection per run.

| Backend | Result | Public IDs |
| --- | --- | --- |
| Nexus headless | Passed | `a2d971b9a57da705`, `0fb53b720b3d9024` |
| Nexus GUI | Passed | `38de5622142d4498`, `0b7d8d522f47a6f8` |
| Legacy supervisor | Passed | `8cb10758b488ea68`, `2adcf1e3ac58d357` |

These runs verified distinct paths and IDs, real decompilation, isolated Python
variables/callbacks, reversible comments, a blocked A call while B completed,
targeted cancellation followed by successful calls on both files, 120,000-character
output continuation, wrong-instance output rejection, explicit resource URIs,
save, close, stale-ID rejection, unaffected peer state, and explicit reopen with
a fresh ID. Nexus runs exercised both Python APIs; the legacy supervisor uses
typed `py_eval`, not the intentionally unsupported Nexus Python capability.

Additional real GUI checks:

- A 0.2-second frontend timeout during a 3-second backend operation did not
  acknowledge close or issue a replacement ID. The binding remained `closing`,
  B answered successfully, and retry succeeded only after backend drain ACK.
- Invoking the production lifetime hooks in the existing GUI process rotated
  its generation on the **same PID and port**, republished discovery, rejected
  the old ID, and re-registered a usable Nexus service. Its peer stayed usable.
  This is a live hook-injection check, **not** a physical close/open of another
  GUI database in the same process.

One earlier headless probe was invalidated by editing source during the run;
the new worker correctly rejected an older frontend fingerprint. Fixed-source
reruns passed. No product source changed during the reported complete runs.

## Independent review and regressions

A read-only independent reviewer inspected `7245a50..4ec267e`, ran 22 focused
tests, and reported six Important lifecycle defects. All entered one fix pass:

| Finding | Regression and resolution |
| --- | --- |
| Proxy close acknowledged after a lost response while mutation still ran | Event-blocked HTTP timeout test failed, then passed with client-scoped drain/release ACKs; also verified against real GUI |
| Alias open closed a retained session after failed save | Failed-save and late-alias tests failed, then passed with session-to-binding ownership tracking |
| Shutdown waited on alias open before cancelling the call holding its gate | Dependency-deadlock test failed, then passed with concurrent initial drain and a late-open sweep |
| Direct Python contexts leaked after close | Repeated close/reopen past the 256-context capacity failed, then passed; GUI and headless teardown also retire old contexts |
| GUI invalidation lost the running listener's registration | Loader test failed, then passed after separating listener and registration lifetime; live rotation also passed |
| Nexus bootstrap ignored cancellation during attachment | Blocking bootstrap test failed, then passed after cancelling/draining its exact operation before releasing the handle |

Related RED/GREEN tests cover late requests arriving after drain ACK, teardown
between admission and context entry, and old shared sessions returning after
successful close. The complete suite was rerun after the fix pass. There were no
deferred minor review findings; the reviewer was not asked to re-review the fixes.

The completion checklist then caught missing diagnostic lifecycle events. Two
additional RED/GREEN tests verify alias reuse, disconnect, save, failed release,
shutdown release, and safe native Nexus disconnect callbacks. The final suite
and live headless acceptance were rerun after this correction.

## Wheel

Artifact: `dist/ida_pro_mcp-4.0.0-py3-none-any.whl`.

SHA-256:
`9a333136a3b41feeb263f831d16bb9d3f36cf81f776b8fbbee5e2517d77cadc7`.

The final wheel was installed into a separate non-editable environment with the
declared dependencies. A protocol smoke test ran from an unrelated scratch
directory with Python `-I`, asserted the package came from `site-packages`,
checked version 4.0.0, and ran two-instance calls without importing IDAPython.
Dependency installs/build isolation used the configured package mirror after
the default locked download host failed TLS; product dependency pins were kept.

## Validation limits and cleanup

- Same-process **physical GUI database replacement** was not exercised. There
  is deterministic queued-execution protection plus the live hook rotation
  described above; that is not substituted for a physical replacement result.
- GUI `qexit` hung after buffer flush/processor unload. A separately copied
  fixture with **no MCP plugin installed** reproduced the same behavior, and
  faulthandler showed only the main Python thread inside `ida_pro.qexit` in both
  cases. This does not establish a Nexus deadlock. Native clean GUI exit remains
  unverified in this environment. All six owned GUI test/baseline processes were
  stopped after verifying executable and fixture paths; no user process was
  stopped. No owned test process remains.
- Linux, Python 3.12, pre-9.4 legacy IDA, actual debugger execution, and the user's
  configured external MCP client were not run locally. Their schema/offline
  coverage must not be read as live runtime coverage. CI was not run remotely.
- Real backend restart on an explicitly reused port was not forced. Exact port
  reuse is covered by deterministic direct-endpoint generation tests; live
  supervisor reopen created a new worker and a new public ID.
- Diagnostic schema/dashboard compatibility, tool errors, open/reuse/disconnect,
  save/release/release-error events, and shutdown release are covered. Lifecycle
  records originate at binding ownership, not merely management tool names;
  the Nexus disconnect callback projects safe metadata without transport text.

This is a local prepared implementation, not a release: no push, PR, merge,
publish, or normal installation was performed. When installing 4.0 later,
restart IDA and reconnect the MCP client to reload schemas, then discover fresh
IDs. The managed worktree and branch are preserved.

Selected logs are preserved locally under `.pytest-tmp-routing-evidence/`.
Removal of this plan's ignored `.superpowers/sdd/` scratch directory was blocked
by execution policy, so it was retained; no cleanup bypass was attempted.

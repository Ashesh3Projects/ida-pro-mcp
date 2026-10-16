# Explicit instance routing validation

Date: 2026-10-16. Worktree: `codex/explicit-instance-routing`.

Implementation uses FastMCP 4.1.0, MCP SDK 2.3.0, Nexus 0.13.0 and IDA Domain
0.5.1. Python 3.11.9 and licensed IDA 9.4 were used for local live validation.
Validation used copied fixture files and isolated IDA user, Nexus and MCP state
directories; the user's normal plugin configuration was not changed.

## Completed validation before independent review

- Initial non-IDA baseline: 346 passed, 1 skipped, 128 subtests passed.
- Integrated non-IDA suite after routing/frontend migration: 384 passed,
  1 skipped, 119 subtests passed. Later final checks are recorded below.
- Typed IDA fixture suite after migrating old selection-specific tests:
  337 passed, 2 skipped. Deprecation warnings from existing IDA frame APIs remain.
- Modern and legacy HTTP: asynchronous calls and targeted cancellation through
  the real FastMCP ASGI protocol; modern requests do not send a session header.
- Real CLI HTTP startup and stdio proxy startup before a backend exists.
- Catalog parity for 66 standard and 22 optional debugger tool schemas. The
  public unified catalog contains 75 default tools or 97 with `--ext dbg`.
- Built `dist/ida_pro_mcp-4.0.0-py3-none-any.whl` and installed it into a separate
  environment for wheel-only discovery/validation.

## Live two-database runs

`tests/multi_instance_acceptance.py` ran through one subprocess MCP connection
with protocol `2026-07-28`. Both files were copies of `tests/typed_fixture.elf`
stored in separate directories, with distinct IDBs and public IDs.

| Mode | Result | Evidence |
| --- | --- | --- |
| Nexus headless | Passed | IDA instances `b6d8026e0a2d8e0c`, `7e52e93e838492d2` |
| Nexus GUI | Passed | IDA instances `fead59a58f9257d1`, `df58bb90a0174cdf`; owned GUI PIDs 20884 and 15956 |
| Legacy supervisor | Passed core two-file flow | IDA instances `270d1467244b312a`, `fffb5a8f7c573cea` |

Headless and GUI runs verified real decompilation, isolated persistent Python
variables/callbacks, reversible comments, a blocked A call while B completed,
both Python APIs, cancellation followed by successful calls on both databases,
120,000-character output continuation, wrong-instance output rejection,
identity-bearing resources, save, close, stale-ID rejection, unaffected peer
state, and explicit reopen with a fresh ID.

The supervisor run verified separate worker databases, parallel calls, typed
Python state, output ownership, resources, save, close, stale IDs and reopen.
Its Nexus-only Python API is deliberately unsupported; typed `py_eval` remains
available.

One initial headless probe was invalidated by a source edit during its run: a
new worker correctly rejected the frontend's older package fingerprint. The
complete run was repeated against fixed source and passed.

## Remaining gates at this checkpoint

Independent whole-branch review, final post-review regression results, final
wheel fingerprint, and cleanup of the owned GUI fixtures are recorded when
completed. Same-process GUI database replacement is covered by execution-guard
tests; the live GUI test above closes/reopens a binding while retaining the
GUI database. Linux and older IDA version validation rely on CI/other runtimes
and were not executed locally.

The package is prepared locally. It has not been published, merged to main,
installed into the user's normal plugin directory, or applied to the configured
MCP client.

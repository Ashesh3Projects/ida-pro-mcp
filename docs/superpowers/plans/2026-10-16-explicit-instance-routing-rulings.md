# Execution rulings and remaining validation limits

Approved plan: `2026-10-16-explicit-instance-routing.md`.
These decisions are listed in execution order; the final validation report
contains the test and live evidence. No minor review findings were deferred.

| Ruling | Reason | Cost if wrong / remaining risk |
| --- | --- | --- |
| Keep baseline in the worktree venv on SDK 1, migrate at the frontend task | Separate pre-existing behavior from the SDK migration | Baseline environment differences could obscure a regression |
| Use the configured package mirror after default-host TLS failures, retaining pins | Bootstrap and build had to be executable locally | Mirror availability and artifact provenance remain deployment inputs |
| Finish direct outputs and legacy public shape in Tasks 5/7 | Those tasks owned the corresponding boundaries | Intermediate commits were not complete deployable migrations; final suite covers the combination |
| Batch lock regeneration with the SDK migration | Avoid contradictory temporary runtime pins | Intermediate dependency state could mislead a checkout before that commit |
| Retain the old bridge-manager wrapper only until its last consumer was replaced | Keep task ordering runnable | Temporary obsolete code was removed in the final tree |
| Use a pinned private Nexus lifecycle adapter | Nexus 0.13 has no public nonblocking GUI retirement hook | Nexus upgrades require reviewing admission, main-thread and teardown seams |
| Replace tests of removed selection internals with lifetime and transport contract tests | The old public API is intentionally removed | Some historical internal assertions no longer run; contract tests are the replacement |
| Classify GUI qexit hang as an environment validation limit, not a proved Nexus regression | No-MCP fixture reproduced the same main-thread qexit hang | Native clean GUI exit remains unverified; only owned test processes were force-stopped |
| Leave Linux / pre-9.4 live claims unverified | Only licensed Windows IDA 9.4 was available locally | CI and older-runtime regressions cannot be ruled out by this run |
| Split acceptance coverage among focused transport/router/bridge tests and the live harness | Avoid a redundant aggregate test wrapper | The planned test_instance_acceptance.py filename is not present; equivalent checks are listed in the report |
| Do not substitute hook injection or mock port reuse for physical replacement / configured-client proof | Report only the boundary actually tested | Physical same-process replacement, forced port reuse and the user's real MCP client remain unverified |
| Preserve the local branch and managed worktree; do not push, merge, publish or install normally | This was explicitly required by the approved plan | Installation, restart, client schema refresh and release integration remain manual |

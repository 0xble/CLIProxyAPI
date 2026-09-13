# Maintenance

## Background

Maintained fork: `0xble/CLIProxyAPI` of `router-for-me/CLIProxyAPI`.
Both default branches are `main`. Canonical checkout: `~/Repos/CLIProxyAPI`.
Initial local, `origin/main`, and `upstream/main` baseline on 2026-09-13:
`44e62bc8acc2f224bff9c62d222717d3f6723dea` (upstream v7.3.1), with exact parity.
`origin` publishes to the owned fork. `upstream` is fetch-only.
This fork supplies the local gateway build. Initial fork setup introduced no routing behavior changes.

## Preserve

- Preserve upstream routing, credential refresh ownership, and protocol compatibility unless a separately accepted feature changes them.
- Keep credentials, account identities, quota snapshots, and live configuration outside this public repository.
- The dedicated `maintain-cliproxyapi-fork` Hermes job owns synchronization and the authorized local installation. Other maintenance agents must not race that job.
- Install only published fork revisions using `cliproxyapi-install <full-sha>`. The installer verifies the active process, binary checksum, and provider inference and restores the previous release on failed activation.

## Active patches

No behavioral patches at initialization. This maintenance contract is fork-only governance.
Reserve enforcement and quota-aware weighting are not implemented or approved by fork setup.
Use stable IDs `CPA-001`, `CPA-002`, and onward for future logical patches.
For each patch record required behavior, source surfaces, rationale, upstream issue/PR/source links and checked date, upstream disposition, fork delivery, focused regressions, source rollback, and retirement condition.
Upstream maintenance-contract issue/PR associations: none found when checked 2026-09-13.
Retain this contract while maintaining the fork. Retire behavioral patches only after a released upstream implementation passes their complete regression contract.

## Update

Fetch `origin` and `upstream` separately and record exact SHAs. Reconcile with the latest upstream `main`, retaining justified fork changes and checking current upstream feedback for every active patch.
Deliver changes through task branches and PRs targeting `0xble/CLIProxyAPI:main`, never the upstream repository by default.
Use targeted tests and inspect the fork-only diff. Before declaring synchronization current, fetch upstream again and require zero upstream-only commits.
Keep patch records current when behavior or upstream disposition changes. Do not create recurring jobs from this contract.
For source rollback, revert the identified fork change through a new reviewed PR. Preserve source recovery refs before history changes. Runtime rollback is a separate deployment operation.

## Verify

Follow `AGENTS.md`. For Go changes run `gofmt`, relevant regressions, `go test ./...`, and `go build -o /tmp/cliproxyapi-fork-check ./cmd/server`.
For routing changes include weighted selection, session affinity, and quota failover fixtures under `sdk/cliproxy/auth` and `test`.
Documentation-only changes require diff inspection and a compile check. Runtime changes require real Codex Responses/tool-result and Claude Messages canaries in addition to source tests.
After publication verify local `main` equals `origin/main`, and `git rev-list --left-right --count upstream/main...main` reports zero upstream-only commits.
Report source, publication, installation, and active runtime state separately. A maintenance run succeeds only after the published fork revision is active and verified. Preserve the prior release for rollback.

Known baseline on 2026-09-13: `TestOpenAICompatExecutorToolResultContentByInputModalities` fails identically on untouched upstream v7.3.1 and the fork because its image/tool-result expectations differ from the translator output. The initial installation changes no Go source. This inherited failure may be reported separately only while unchanged-source proof, routing/quota tests, build, and live Codex/Claude canaries pass. New failures or changes affecting that path block promotion.

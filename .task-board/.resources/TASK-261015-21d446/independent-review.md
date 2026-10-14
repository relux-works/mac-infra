# Independent security review — TASK-261015-21d446

Status: ACCEPTED within bounded review scope after fixes. Initial findings below
are historical and resolved; the final recheck records the current verdict.

## Scope and constraints

Read-only review of `internal/security` and `cmd/mac-security` including their tests in the task worktree. No product files, commits, board state, hosted systems, live audit commands, sudo, private projects, or real user SSH files were changed/read. Review scratch fixtures are under `.temp/security-review`. mac-infra skill read for read-only and secret handling constraints. Tool readiness recorded in `tool-readiness-01.log` (Go 1.25.5 darwin/arm64, rg 15.1.0, git 2.53.0).

## Findings communicated to owner

1. **High — SSH Include can read private key files.** Original `ssh.go:52-79` permits any glob beneath `.ssh` or system SSH config directory and opens each match through `scan`/`readFile` at line 33. `Include id_ed25519` and `Include *` open private-key artifacts, contrary to the explicit never-read-private-key contract. No actual key files were read during review. Existing SSH test also reads actual system ssh_config/root authorized_keys metadata; it was excluded from test execution. Owner proposes fixed config/config.d scope and injected system fixtures.
2. **High — unbounded directory materialization precedes limits.** Original `persistence.go:86` uses `filepath.WalkDir`, which reads/sorts a complete directory before callback `maxEntries` enforcement. Original `ssh.go:73` uses `filepath.Glob`, checking result count only after full expansion. These violate bounded memory/cancellation promises. Owner replacing both paths.
3. **High — unsafe ancestry becomes false deletion.** Original `persistence.go:76-84` treats ENOENT as complete absence after safeParents has already failed, including failure due to a symlink ancestor. Isolated synthetic overlay repro (`review_probe_test.go`, `overlay.json`) returned coverage=ok, removed=1, unknown=0 for a symlink-parent missing leaf. Expected unavailable/unknown with no removed entries. `unsafe-missing-source-01.log` records the intended failing assertion. Source-parent safety must be established independently from leaf absence.
4. **Medium — baseline JSON ambiguity/missing fields accepted.** Original `persistence.go:216-225` uses DisallowUnknownFields without recursive duplicate/member-presence validation. Synthetic `baseline-probe.go` confirms duplicate schema, escape-spelled duplicate schema, null entry mode, and absent entry mode accepted, alongside a valid control. See `baseline-probe-01.log`. Owner implementing strict recursive JSON and required fields; same decoder concern applies to IOC rules.
5. **Medium — baseline/rules parent symlink not rejected.** Original `files.go:19-47` protects only the leaf with O_NOFOLLOW. LoadBaseline and LoadRules do not check ancestry, so a static symlink ancestor is accepted. Path-based prechecks also cannot guarantee refusal of concurrent parent replacement. Owner notified; review requires static symlink regression plus precise limitation if traversal remains non-atomic.
6. **Contract question — metadata coverage.** Baseline Snapshot originally has schema but no capture timestamp; Drift originally has neither schema nor timestamp. Baseline/diff CLI discard observed check evidence. Owner asked to align with versioned/timed JSON acceptance scope.

## Evidence and validation

`tests-01.log`: scoped fixture/command validation passed in both packages. Exact command:

```
go test ./internal/security ./cmd/mac-security -run 'Test(Runner|Observe|Persistence|Baseline|IOC|Command|Posture|Exposure|Listener|Firewall|Stealth|Packet|Sharing|Software|XProtect)' -count=1
```

SSH test deliberately skipped because it accesses live system SSH configuration/root presence. Parser tests include real adjacent known/unknown controls and assert no raw backend secrets. Baseline duplicate and unsafe-source plants demonstrate actual negative contract failures rather than unrelated setup errors. No huge-directory or racing attacker experiment run: enumeration findings follow directly from standard-library algorithm semantics and source.

## Initial positive observations

Runner uses a fixed read-only command vocabulary, no shell/sudo, finite per-command and aggregate deadlines, bounded retained stdout, discarded stderr, and no persisted args/environment. Collector failures generally discard data and preserve unknown status. Listener/Posture parsing is strict and unknown outputs do not claim protection. Baseline uses private O_EXCL creation and preserves existing destinations. Initial volatile inventory digests were removed from stable drift by the owner during review; unprojected inventory is explicitly partial. Final verdict pending recheck of owner fixes.

## Final recheck — ACCEPTED within bounded review scope

All initial blocking findings above are resolved in the reviewed files. No remaining material security blocker found in `internal/security` or `cmd/mac-security`. This verdict concerns the explicitly limited collector implementation and does not assert complete original product coverage, a malware-free host, or live macOS command-output compatibility.

- SSH arbitrary Include expansion is removed. Only fixed config/config.d sources are inspected; Includes explicitly make coverage partial. Tests inject system paths and no longer read actual system SSH configuration. Synthetic private-key-shaped Include test preserves a nearby direct ForwardAgent control. Unsafe config.d parents now make coverage partial.
- Persistence uses incremental ReadDir(128), maximum entries and recursion depth; SSH uses bounded ReadDir and no Glob. Existing cancellation and oversized-directory fixture tests pass.
- Unsafe ancestry with a missing source now produces unavailable coverage and unknown drift, with zero removals. Static symlink parents are rejected by the shared file reader. Concurrent parent rename is explicitly a documented limitation, not claimed atomic protection.
- Baseline JSON rejects recursive exact/escape-spelled duplicate members, required null/missing entry fields, and case aliases in the closed Snapshot/Entry/Coverage objects. IOC rules similarly enforce exact closed members. The reviewer case-alias probes now reject both schema and coverage overwrites while retaining the valid control.
- Default and additional IOC rules are validated together before CLI collection; duplicate IDs cannot silently disable the default sweep.
- Snapshot emits captured_at and schema; Drift emits compared_at and schema. Baseline capture retains observed command evidence. Unprojected volatile inventory sources are explicitly partial and are not fingerprinted into stable drift.

Final passing evidence:

```
go test -race ./internal/security ./cmd/mac-security -count=1
```

`tests-02.log`: both packages pass, including fixture-only SSH tests and the 10,002-entry filesystem bound fixture. `recheck-probes-02.log`: both independent overlay regression plants now pass (unsafe source -> unavailable/removed0/unknown1; symlinked SSH config.d -> partial). `json-case-probe-03.log`: valid control accepted, schema/status alias overwrites rejected. `git diff --check` passes. Scope/base and exact reviewed untracked file object hashes are recorded in `reviewed-base.txt` and `reviewed-files.txt`; parent owns subsequent integration, hosted exact-head review, and delivery.

Intentional remaining limitations were checked against source/explicit contract: login-item/profile/system-extension identity projection remains unsupported/partial; root authorized_keys is presence-only and root-key-content IOC scanning is intentionally absent to preserve the no-key-content-read boundary; no sudoers/process argv/environment/private key collection; no UDP/router/WAN evidence; no atomic defense against concurrent directory rename. The skill reference exposes these limits. No live audit collection, installation, privilege change, key read, or host mutation was used as review evidence.

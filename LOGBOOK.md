# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-08-03

### 1114 — Privacy-Safe Document Intake Installed
- MILESTONE: `TASK-260803-22l53w` added and installed `mac-document-sanitize` plus reusable `internal/docsanitize` for TXT/Markdown/JSON/CSV/TSV/HTML/RTF/DOC/DOCX/PDF/XLSX intake.
- DECISION: Originals stay read-only; raw extracted text stays in memory; default `0600` artifacts use content hashes instead of source filenames; reports store categories/counts but never matched values.
- FIX: Main `agents/skills/mac-infra/SKILL.md` shrank from 620 to 486 lines by moving Safari and audio-sweep details to lazy references.
- STATUS: Full tests, targeted race tests, vet, setup/install, skill validation, synthetic multi-format smokes, and three local Word-document smokes passed.

### 1114 — Phone Redaction Must Precede SNILS
- ROOT CAUSE: An unlabelled Russian `+7` phone also matched the generic 11-digit SNILS shape when SNILS ran first, hiding the value but misreporting its category.
- FIX: Phone detection now precedes SNILS detection in `internal/docsanitize/sanitize.go`; regression coverage verifies `[PHONE_n]` classification.

## 2026-08-02

### 1815 — Idle Lock Prevention Split Into Independent Policies
- DECISION: `TASK-260802-19m3qg` keeps system sleep, display sleep, and idle-lock prevention as separate commands; there is no combined all-policy mutation.
- SAFETY: Idle-lock prevention does not call `sysadminctl -screenLock off`; manual Lock Screen and the immediate password policy remain unchanged.
- FIX: Display prevention uses a persistent current-user `/usr/bin/caffeinate -d` LaunchAgent without rewriting `pmset`; `idle-lock-prevention` captures and restores the current user's ByHost `idleTime` preference to control the automatic screen-saver lock trigger.
- SCOPE: `internal/maccore`, `cmd/mac-infra-core`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `scripts/setup.sh`, and installed-command verification.

## 2026-07-19

### 1742 — System-Wide Sleep Prevention Contract Resolved
- DECISION: `TASK-260719-cigkb7` uses one global `SleepDisabled` state with `applies_to: AC,battery`; no per-profile `disablesleep` values are invented.
- FIX: Added fixed root-daemon actions for `/usr/bin/pmset -a disablesleep 1|0`, strict `/usr/bin/pmset -g` parsing, and `mac-infra-core sleep-prevention enable|disable|status`.
- SCOPE: `internal/maccore`, `cmd/mac-infra-core`, `README.md`, `agents/skills/mac-infra/SKILL.md`, and `scripts/setup.sh`.
- STATUS: The provisional 1725 blocker is superseded by the revised system-wide contract. Tests, vet, build, setup, installed read-only status, and installed-skill match passed; reinstall the privileged daemon before live mutations.

### 1725 — SleepDisabled Is System-Wide
- FINDING: `/usr/bin/pmset -g` exposes one system-wide `SleepDisabled`; `/usr/bin/pmset -g custom` exposes AC/battery profiles without that key.
- FINDING: Apple `PowerManagement` source writes `disablesleep` through `IOPMSetSystemPowerSetting`, outside per-source preferences (`pmset/pmset.m:5813`, `pmset/pmset.m:802`).
- BLOCKED: `TASK-260719-cigkb7` requires per-source and inconsistent `disablesleep` states that the platform cannot represent.
- DECISION: Recommend one system-wide `enabled`/`disabled`/`unavailable` status; do not infer it from unrelated `sleep` timers.

## 2026-06-15

### 1632 - Safari Browser Session Harvest
- DECISION: Authenticated browser harvest uses Safari Apple Events and page-context `fetch(..., { credentials: "include" })`; cookies and browser storage stay inside Safari.
- FIX: Added `mac-safari-session` CLI plus reusable `internal/safarictl` package for background open, JS permission check, DOM snapshot, guarded JS, and chunked authenticated file fetch.
- FIX: Guard rejects obvious secret reads: `document.cookie`, `cookieStore`, `localStorage`, and `sessionStorage`; response metadata drops sensitive headers.
- SCOPE: `cmd/mac-safari-session`, `internal/safarictl`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `scripts/setup.sh`, `scripts/deinit.sh`.
- STATUS: Verified with `go test ./...`, `./scripts/setup.sh`, installed CLI help, cookie guard smoke, live `mac-safari-session check-js`, and `task-board validate`.

## 2026-06-12

### 1337 - AnyConnect Socket Filter Cleanup
- FINDING: Cisco AnyConnect can report `Disconnected` while `com.cisco.anyconnect.macos.acsockext` remains activated/enabled and resident around `869MB`.
- FIX: Added `mac-load-profile anyconnect` for read-only VPN state, system extension, `acsockext`, and `vpnagentd` diagnostics.
- FIX: Added `mac-infra-core anyconnect-cleanup` dry-run plus allowlisted `cleanup_anyconnect` apply action guarded by `vpn status == Disconnected`.
- SCOPE: `internal/anyconnect`, `cmd/mac-load-profile`, `cmd/mac-infra-core`, `internal/maccore`, `README.md`, `agents/skills/mac-infra/SKILL.md`.
- STATUS: User-level setup installed updated CLI/skill; root daemon reinstall is pending interactive sudo before `--apply` can run live.

## 2026-05-21

### 1121 - CoreSimulator Runtime Cleanup
- ROOT CAUSE: Xcode stale simulator entries came from unsupported legacy `.simruntime` bundles under `/Library/Developer/CoreSimulator/Profiles/Runtimes`, not from unavailable device records.
- FIX: Removed iOS 13.5, 14.2, 14.5, and 15.0 runtimes with `xcrun simctl runtime delete`; `simctl list runtimes` now shows only supported installed runtimes.
- FIX: Added `mac-cleanup xcode-runtimes` to detect `unavailable` + `deletable` runtimes and delete them only with explicit `--delete`.
- SCOPE: `cmd/mac-cleanup/main.go`, `internal/simcleanup/runtime.go`, `agents/skills/mac-infra/SKILL.md`, `README.md`.
- STATUS: Verified with `go test ./...`, `scripts/setup.sh`, and installed `mac-cleanup xcode-runtimes`.

## 2026-05-19

### 1600 - Cleanup Planner Test Roots
- FINDING: macOS `t.TempDir()` resolves under `/var/folders`, and cleanup root policy intentionally refuses `/var` descendants.
- DECISION: Cleanup planner/CLI tests use repo-local temporary directories under the checkout so fixtures exercise allowed user-owned child roots without weakening production safety rules.
- SCOPE: `internal/cleanup/planner_test.go`, `cmd/mac-cleanup/main_test.go`.

### 1557 - Disk Profile CLI Text Contract
- FIX: `internal/diskprofile/render.go` owns concise tabular text rendering for scan/top/explain output.
- FIX: `cmd/mac-disk-profile top` treats `--files` and `--dirs` as selectors; absent selectors renders both tables.
- ANOMALY: Sandboxed Go commands need task-scoped `GOCACHE/GOPATH`; default `~/Library/Caches/go-build` is not writable.
- STATUS: Verified with `go test ./...`, `go vet ./...`, `go build ./...`, and `gofmt -l cmd internal`.

### 1547 - Cleanup Plan Apply Contract
- DECISION: `internal/cleanup.Plan` schema v1 includes `categoryPolicyVersion`, `hashInputs`, `generatedAt`, `staleAfterSeconds`, root realpath, candidate identity, risk/default flags, sizes, apply contract, and `planHash`.
- DECISION: `clean --apply` v1 requires `--plan PATH`; direct category apply is explicitly unsupported until a future rescan-and-confirm flow exists.
- DECISION: Apply preflight refuses stale plans after 24h, hash mismatch, selected out-of-scope candidates, changed candidate identity, symlink swaps, out-of-root realpaths, and ownership mismatches before any deletion code can run.
- SCOPE: Contract and revalidation helpers only; no Trash/permanent deletion implementation.

### 1547 - Disk Scan Resource Controls
- DECISION: `internal/diskprofile` applies default generated-tree excludes by default; `--exclude` adds patterns; `--no-default-excludes` opts back into generated trees.
- DECISION: Top dirs/files are retained with bounded lists; JSON hierarchy retention is capped by `MaxRetainedEntries` without stopping byte accounting.
- FIX: Context cancellation now records `canceled` scan errors and returns a partial result with the context error.
- SCOPE: `internal/diskprofile` resource controls and `cmd/mac-disk-profile` flags.

### 1528 - Disk Profile Scan Model Contract
- DECISION: `internal/diskprofile` uses `os.Lstat` only, never follows symlinks, and records symlink skips as non-fatal `ScanError` entries.
- DECISION: Logical bytes are lstat apparent size; disk bytes are best-effort `st_blocks * 512`; hard links are de-duped by `(device,inode)`.
- DECISION: Scan JSON is schema-versioned and written with restrictive artifact permissions: created dirs `0700`, JSON files `0600`.
- SCOPE: Read-only disk profiler model and `cmd/mac-disk-profile`; cleanup executor/apply semantics unchanged.

### 1528 - Cleanup Category Policy Boundary
- DECISION: `internal/cleanup/policy.go` separates default-selected safe generated data from review-only user/risky data and v1 out-of-scope categories.
- DECISION: External volume roots are refused; child paths under `/Volumes/<name>/...` require explicit target selection plus ownership, symlink, and realpath containment checks.
- SCOPE: Category policy only; no deletion executor, scanner traversal, docs, setup, or disk profile changes.

### 1527 - Cleanup and Disk Work Package Decomposition
- FINDING: Board already captured architect-review blockers for plan/apply, Trash semantics, disk accounting, and resource controls.
- FINDING: Two implementation gaps remained: disk extension/type summaries and a non-mutating cleanup apply revalidation guard layer.
- DECISION: Added `TASK-260519-2lvhmz` for disk extension/type summaries before JSON artifacts.
- DECISION: Added `TASK-260519-3m5108` to split TOCTOU/revalidation guards from destructive Trash execution.
- DECISION: Linked docs/integration after category story so README/skill describe final category behavior, not just core CLIs.

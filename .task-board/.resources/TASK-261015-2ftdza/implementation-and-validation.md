# Root-owned core installation source fix

Task: TASK-261015-2ftdza (root-owned-core-installation).
Worktree: /Users/alexis/src/mac-infra/.temp/TASK-261015-2ftdza/worktree.
Baseline: 809e03381351219fe2c95b4a33ed9f61727ff2a3 (0 commits behind origin/main and main when checked).
Source-only work; no commits or publication by this worker.

## Problem and final behavior

The old installer wrote a root LaunchDaemon plist whose executable remained in the user's writable checkout. Root execution therefore inherited the user's control over the checkout, binary and ancestors.

The installer now snapshots the reviewed executable before elevation and sends the bounded bytes on stdin to fixed absolute-path OS commands. No privileged command reopens the user source pathname. It installs the executable as root:wheel 0755 at `/Library/PrivilegedHelperTools/works.relux.mac-infra/mac-infra-core`; the dedicated directory is root:wheel 0755 and the plist is root:wheel 0644 at the existing LaunchDaemons path. All ancestors must be root-owned, without group/world write authority or ACL modification grants. ACL deny-only/read-only entries remain supported; modification grants are conservatively rejected regardless of principal or inheritance flags.

Startup uses descriptor-relative openat/O_NOFOLLOW traversal, verifies owner/mode/ACL and single-link regular files, verifies the binary digest and inode/creation-time pins, and compares every byte of the plist against the fixed expected configuration. Inode+creation-time pins avoid using device numbers that can change on remount. Device numbers are compared only during publication to ensure same-filesystem renames.

The socket moves to the protected helper directory (`core.sock`) because the observed `/private/var/run` ancestor is root:daemon 0775. The socket remains 0600 and owned by the intended normal user. Kernel LOCAL_PEERCRED checks admit only the configured user or root; production clients require a root peer. The action allowlist and hardcoded action command paths are unchanged. Existing tests of daemon protocol/action behavior now call the internal fixture server; the public RunDaemon always applies installation checks.

Staging is root-private. Original executable/plist inodes are moved to backups before publication and retained through file verification and launchd activation/readiness. Publication/activation failures restore the previous files where feasible. Failed rollback retains its original backup in the private stage and reports the recovery path. Uninstall uses fixed absolute paths, validates protected ancestors, removes the installed binary/plist/socket and retains nonempty recovery directories.

## Changed scope

- `internal/maccore/config.go`: fixed protected executable/directory/socket paths.
- `internal/maccore/service.go`: snapshot installation, lifecycle callback with rollback, startup admission, peer admission, fixed privileged command paths and protected uninstall scope.
- `internal/maccore/service_files.go`: bounded snapshot, root-private staging, same-filesystem publication, rollback/recovery and stale socket guard.
- `internal/maccore/service_trust.go`: descriptor traversal, file identity/digest/config verification.
- `internal/maccore/trust_acl_darwin.go`, `trust_acl_unsupported.go`: native descriptor ACL checks, fail-closed unsupported builds.
- `internal/maccore/service_peer_darwin.go`, `service_peer_unsupported.go`: kernel peer identity.
- `cmd/mac-infra-core/main.go`: pinned startup arguments and positional argument rejection.
- Existing service tests plus new service_files/service_trust/no-cgo tests.
- README and authoring mac-infra skill: installation/migration/security boundaries and cgo build dependency.

## Verification and evidence

All commands run on macOS darwin/arm64, Go 1.25.5, Apple clang 21.0.0, at the baseline plus this working diff. Logs are under this worktree's `.temp/core-trust/`.

- `tool-readiness-01.log`: git 2.53.0, Go 1.25.5, rg 15.1.0.
- `clang-readiness-01.log`: Apple clang 21.0.0 / macOS toolchain.
- `stat-readiness-01.log`: native `%i:%B` format availability.
- `test-05.log`: PASS `go test ./internal/maccore ./cmd/mac-infra-core` (maccore 24.579s, CLI 1.486s).
- `trust-tests-04.log`: PASS focused positive/negative trust, real ACL, fixture installation, rollback and socket tests.
- `nocgo-test-06.log`: PASS `CGO_ENABLED=0 go test ./internal/maccore -run TestTrustUnavailable -count=1`; no privileged command is allowed by this control.
- `vet-07.log`: PASS `go vet ./internal/maccore ./cmd/mac-infra-core`.
- `race-test-08.log`: `go test -race ./internal/maccore ./cmd/mac-infra-core` (completion recorded below).
- `build-09.log`: `go build -o .temp/core-trust/mac-infra-core ./cmd/mac-infra-core` plus harmless `version` smoke (completion recorded below).
- `git diff --check`: PASS.

Early `test-01.log` records a missing exported x/sys constant; fixed using version 0 verified in the installed Apple SDK `sys/ucred.h`. Early `test-02.log` records Darwin's no-ACL ENOENT semantics; fixed and validated against real fixture ACL write grants. These are resolved development failures, not passing evidence.

Tests establish required controls: safe trees/install/reinstall are accepted; writable binary/config/ancestors, symlinks, hardlinks, changed bytes/config, same-byte inode replacements, wrong owner, invalid scope, invalid source types/sizes, cross-filesystem publication and wrong peer UID are refused for the intended reason. Real extended write ACL grants are detected; harmless deny/read ACLs are accepted before a write-grant control is planted in the same isolated tree. Rollback tests assert previous bytes and identities, and retained backup identity on rollback failure. Existing action tests continue to prove only fixed pmset and other allowlisted actions execute.

## Limits and deployment boundary

- No sudo, actual root install, launchctl operation, service restart, user/runtime skill setup, live chmod/chown, network/VPN/audio mutation or key access occurred. ACL/mode modifications were confined to isolated Go t.TempDir fixtures. A read-only `ls -lde` probe observed standard root/Library/helper/plist ancestors and the group-writable old /private/var/run directory.
- Root ownership is required by production; fixtures use the current user's private test root and explicitly state that they do not prove live root ownership or sudo/launchd integration.
- Initial reviewed build authentication remains the administrator's boundary. A same-user attacker controlling the initial installer/artifact is outside what a byte snapshot can authenticate.
- Self-checking userspace cannot attest already mapped malicious root code, or prevent root from rewriting config, executable, checks, ACLs or ancestors. Root concurrency is outside the protected unprivileged race boundary.
- Descriptor traversal prevents symlink substitution; root-controlled non-writable ancestors prevent unprivileged renames after checks. Installation uses separate privileged OS command invocations, not an atomic root-directory transaction against a root adversary.
- Binary/plist/launchd update is not crash-atomic. Crash or failed rollback may require recovery from the reported root-private directory and explicit reinstall. File rollback does not restore a stopped launchd service.
- Native ACL checks require cgo on macOS and fail closed without it. Unsupported platforms fail peer checks; this task targets macOS only.
- Rebuild clients and perform a separately authorized reviewed reinstall to migrate from /var/run to the protected socket. scripts/setup.sh alone does not migrate/restart. The existing live daemon remains untouched and unremediated by this source change.
- No changes to the analogous external vpn-core issue or excluded projects.

Source frozen for independent review after this handoff; only verification log/status append operations will follow unless the reviewer requests fixes.

## Final validation status

- PASS `build-09.log`: actual macOS executable builds and `version` prints `mac-infra-core dev unknown unknown` without service/config changes. Worktree remains 0 commits behind main.
- `race-test-08.log`: initial full race run FAILS existing helper-process timing expectations (no race reports): fsevents slow inspection elapsed 8.064s, launchctl disappearance exceeded 1s. The race runtime's default one-second process-exit sleep applies to each spawned fake command. This is recorded as a failed check, not passing race evidence.
- Full race rerun uses `GORACE=atexit_sleep_ms=0` to remove only the race diagnostic exit delay while retaining race instrumentation; result/log `race-test-11.log` pending. No source was modified for this rerun.
- PASS `race-test-11.log`: `GORACE=atexit_sleep_ms=0 go test -race ./internal/maccore ./cmd/mac-infra-core` (maccore 26.329s, CLI cached); no race reports. Apple's linker emits LC_DYSYMTAB warnings in race builds; the instrumented binaries run and pass. No product code or timing expectations were modified to obtain this result.

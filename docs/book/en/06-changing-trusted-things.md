# 6. Changing trusted things safely

Replacing a privileged executable changes the code that will judge later requests.
Replacing the vault executable can interrupt signing that depends on its existing trust.
How does mac-infra bind these changes to reviewed bytes, and what can recovery restore?
This chapter follows helper installation, owner authorization, build provenance and the vault rebuild freeze.
Chapter 3 explains the Keychain ACL reason for that freeze.
(*source*: `internal/maccore/service.go`, `InstallService`; `scripts/keyvault-build-guard.sh`, rebuild policy.)

## Install the reviewed snapshot

The operator first reviews the SHA-256 printed by `mac-infra-core install-digest`, then supplies it to `install --expect-sha256`.
Installation snapshots the executable before elevation and announces that snapshot's digest.
A mismatch refuses before sudo; the digest-gate test asserts zero sudo calls and a matching-digest control reaches the sudo seam.
The flag is optional, so omitting it removes the comparison with the earlier review.
A digest binds bytes, not their safety or origin.
Commands belong in the [installation runbook](../../../agents/skills/mac-infra/SKILL.md#privileged-daemon-installation-trust).
(*source*: `cmd/mac-infra-core/main.go`, `runInstall`; `internal/maccore/service.go`, `installServiceWithPreflight`; *tested*: `TestInstallDigestGateRunsBeforeSudo`.)

Installation requires the intended non-root client and fixed service paths.
It checks `/Library` before reading the snapshot, then requests sudo credentials.
The single authentication step can use cached credentials or one interactive `sudo -v`; subsequent privileged commands use `sudo -n`.
Those commands receive snapshot bytes through stdin rather than reopening a user-controlled executable path.
Root-private staging creates a root-owned executable with mode `0755` and plist with mode `0644`.
The plist points to the fixed privileged helper path, never the checkout.
The repeat-install fixture checks bytes, modes and pinned arguments, but simulates ownership changes.
(*source*: `internal/maccore/service.go`, `ensureSudoCredentials`; `internal/maccore/service_files.go`, `runInstallationCommand`, `installReviewedSnapshotWithOwnerKey`; *tested*: `TestInstallReviewedSnapshotSafeAndRepeatable`.)

An existing unsafe installation is refused rather than repaired by relaxing shared permissions.
The trust walker opens every ancestor relative to its checked parent without following symlinks.
It requires root ownership and rejects group/world writes, set-ID bits and multiply linked files.
Native ACL inspection rejects modification grants while permitting deny-only and read-only entries.
Without macOS cgo ACL support, inspection refuses.
These are tool checks on filesystem metadata; operating-system permissions supply the underlying restriction on modification.
(*source*: `internal/maccore/service_trust.go`, `openTrustedAt`, `checkTrustedFile`; `internal/maccore/trust_acl_darwin.go`, `requireSafeACL`; `internal/maccore/trust_acl_unsupported.go`, `requireSafeACL`.)

Daemon startup checks the installed executable and complete plist against their pins.
The pins include the executable digest and both files' inode/creation-time identities.
`verifyInstalledFiles` compares the plist byte-for-byte with `RenderServicePlist`, so an extra launchd setting is drift too.
Same-filesystem publication preserves those identities through renames.
Activation follows file verification, waits for confirmed launchd removal before bootstrap, then checks reachability.
(*source*: `internal/maccore/service_trust.go`, `validateDaemonInstallation`, `verifyInstalledFiles`; `internal/maccore/service_files.go`, `installReviewedSnapshotWithOwnerKey`; `internal/maccore/service_install.go`, `replaceLaunchServiceWith`; `internal/maccore/service.go`, `installServiceWithPreflight`.)

## Recovery restores files, with limits

A publication or activation failure triggers reverse-order file rollback.
The installer retains previous inodes because the previous plist pins them.
Injected rename and activation failures restore both bytes and identities in the fixture.
If restoration fails with an old file still displaced, the installer preserves the protected staging directory and reports its recovery path.
The recovery test checks that the previous plist inode survives there.
These fixtures execute neither sudo nor launchd.
(*source*: `internal/maccore/service_files.go`, `publishInstallation`, `installReviewedSnapshotWithOwnerKey`; *tested*: `TestInstallFailureRestoresPreviousFiles`, `TestInstallRollbackFailureRetainsRecoveryFiles`.)

The helper update is not crash-atomic.
Its executable, plist and launchd state cannot commit as one transaction; an optional owner-key pin adds another published file.
Deferred rollback handles returned errors, not process death or power loss.
Restoring files also does not restart a stopped service.
After failure, preserve any reported recovery directory and verify files and service availability separately before treating the helper as recovered.
(*source*: `internal/maccore/service_files.go`, `publishInstallation`; `internal/maccore/service_install.go`, `replaceLaunchServiceWith`; stated recovery limit: `agents/skills/mac-infra/SKILL.md`, “Privileged Daemon Installation Trust”.)

## Authorize one vpn-core mutation

Owner authorization gates vpn-core install and rollback, not every privileged action.
The root-helper installer accepts a reviewed P-256 SPKI public key with paired `--owner-key` and `--expect-owner-key-sha256` flags.
It verifies the key snapshot before the installer seam and publishes the pin root-owned with mode `0444`.
Omitting the key preserves an existing pin.
The daemon checks that pin before issuing or accepting authorizations.
(*source*: `cmd/mac-infra-core/main.go`, `runInstall`; `internal/maccore/service_files.go`, `installReviewedSnapshotWithOwnerKey`; `internal/maccore/vpn_core.go`, `handle`; `internal/maccore/vpn_core_authorization.go`, `readOwnerPublicKey`; *tested*: `TestInstallOwnerKeyPreflight` for CLI snapshot admission.)

The signed statement names an action, target `vpn-core`, package digest, random nonce and expiry.
The daemon separately binds its pending entry to the requesting UID.
Its lifetime is roughly 119–120 seconds, measured monotonically from issuance.
Verification requires the exact issued statement and a P-256 DER low-S signature under the pinned key.
The refusal fixture checks changed digests, actions, UIDs, statements, expiry and signatures without package reads, staging or launchctl calls.
After required inputs and syntax pass, a pending nonce is consumed before binding, expiry and signature verdicts; a later package failure consumes it too.
Recovery therefore requires a fresh authorization rather than replaying the failed request.
(*source*: `internal/maccore/vpn_core_authorization.go`, `issueAuthorization`, `authorizeMutation`; *tested*: `TestVPNOwnerAuthorizationRefusals`, `TestVPNOwnerAuthorizationFailedInstallReplay`.)

An Enclave owner key requiring user presence makes signing depend on Touch ID or the login password.
The Swift helper requests `.userPresence` and uses a fresh authentication context, relying on macOS enforcement described in chapter 3.
This costs an attended signing step.
The daemon verifies a public-key signature; SPKI does not attest Enclave storage or prove that a prompt occurred.
The CLI's recognized statement description helps the owner match action and digest prefix, but the signature does not certify the package's safety or authenticate an individual same-user agent.
(*source*: `cmd/mac-keyvault-enclave/main.swift`, `accessControl`, `sign`; `cmd/mac-keyvault/prompt.go`, `describeData`; `internal/maccore/vpn_core_authorization.go`, `ParseOwnerPublicKey`, `authorizeMutation`.)

## Admit builds and preserve working trust

Release builds use a clean standalone clone at the reviewed revision.
Normal setup preflight rejects linked worktrees and dirty trees.
Verification reads structured Go build information and requires exactly one `vcs.revision` matching source HEAD and one `vcs.modified=false`.
The nested-worktree test demonstrates why location matters: its inner build inherits the dirty outer repository's stamp.
`--allow-unprovable` bypasses provenance checks with warnings for developer use; it is no release guarantee.
(*source*: `scripts/provenance-guard.sh`, `preflight`, `verify_files`; `scripts/setup.sh`, `ALLOW_UNPROVABLE`; *tested*: `TestProvenanceNestedWorktree`.)

A stamp with `vcs.modified=true` names a revision without identifying the modifications.
It cannot establish that the artifact came solely from that reviewed commit.
The dirty-binary test refuses even when the revision matches.
Clean stamps still do not establish dependency provenance or authenticate the initial compiler and artifact.
Setup disables ambient Go workspaces with `GOWORK=off`, verifies all staged Go outputs before publication, then renames files individually.
That publication is not a transaction across tools.
The Swift helper has no Go stamp, and a kept vault is neither reverified nor republished.
(*source*: `scripts/provenance-guard.sh`, `verify_files`, publication loop; `scripts/setup.sh`, `GOWORK`, `BUILT_BINARIES`; `README.md`, release-build guidance; *tested*: `TestProvenanceDirtyBinary`.)

Setup keeps an existing vault executable unless `--rebuild-keyvault` is explicit; an absent binary is built without that flag.
A requested rebuild refuses when inspection reports an open binary, a running `mac-keyvault`, a loaded keyvault LaunchAgent or an inspection error.
This preserves unattended signing at the cost of delaying updates until the owner can re-establish trust as chapter 3 describes.
The guard only sees what its inspection tools report; setup does not coordinate concurrent runs.
It checks again before building, but cannot make inspection and replacement atomic.
(*source*: `scripts/setup.sh`, `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`, rebuild gates; *tested*: `TestKeyvaultBuildGuard`.)

## What this does not protect against

Same-user processes are not isolated: the daemon's kernel peer check identifies a UID, not an agent.
Userspace installation checks cannot authenticate the initial build, attest already mapped root code or defend against root.
Updating source or user tools does not replace a running helper.
Installed builds may lag source.
Treat privileged reinstallation, owner-authorized mutations and service recovery as separate decisions with their own evidence.
(*source*: `internal/maccore/service_peer_darwin.go`, `requireSocketPeer`; `internal/maccore/service.go`, `serviceDaemon.handleConn`; `scripts/setup.sh`, usage; `agents/skills/mac-infra/SKILL.md`, installation trust limits.)

**Status.** *Source* checked at `7fd0c8285dd13e31308777e5924e0a2f631eadd9`.
*Tested* identifies assertions read, not fresh test execution.
No particular installation is described; no keys, signatures or privileged operations were created or performed.

## Sources

| Paragraph | Repository-relative path and function or symbol | Test asserting the cited case |
| --- | --- | --- |
| Opening | `internal/maccore/service.go`: `InstallService`; `scripts/keyvault-build-guard.sh`: rebuild policy | Source only |
| Digest review | `cmd/mac-infra-core/main.go`: `runInstall`; `internal/maccore/service.go`: `installServiceWithPreflight` | `internal/maccore/install_digest_test.go`: `TestInstallDigestGateRunsBeforeSudo` |
| Snapshot and elevation | `internal/maccore/service.go`: `ensureSudoCredentials`; `internal/maccore/service_files.go`: `runInstallationCommand`, `installReviewedSnapshotWithOwnerKey` | `internal/maccore/service_files_test.go`: `TestInstallReviewedSnapshotSafeAndRepeatable` |
| Ancestors and ACLs | `internal/maccore/service_trust.go`: `openTrustedAt`, `checkTrustedFile`; `internal/maccore/trust_acl_darwin.go`, `internal/maccore/trust_acl_unsupported.go`: `requireSafeACL` | Source only |
| Pins and activation | `internal/maccore/service_trust.go`: `verifyInstalledFiles`, `validateDaemonInstallation`; `internal/maccore/service.go`: `RenderServicePlist`, `installServiceWithPreflight`; `internal/maccore/service_install.go`: `replaceLaunchServiceWith`; `internal/maccore/service_files.go`: `installReviewedSnapshotWithOwnerKey` | Source only |
| File rollback | `internal/maccore/service_files.go`: `publishInstallation`, `installReviewedSnapshotWithOwnerKey` | `internal/maccore/service_files_test.go`: `TestInstallFailureRestoresPreviousFiles`, `TestInstallRollbackFailureRetainsRecoveryFiles` |
| Crash and recovery limits | `internal/maccore/service_files.go`: `publishInstallation`, `installReviewedSnapshotWithOwnerKey`; `internal/maccore/service_install.go`: `replaceLaunchServiceWith`; `agents/skills/mac-infra/SKILL.md`: installation trust | Source and stated limits |
| Owner pin and scope | `cmd/mac-infra-core/main.go`: `runInstall`; `internal/maccore/service_files.go`: `installReviewedSnapshotWithOwnerKey`; `internal/maccore/vpn_core.go`: `handle`; `internal/maccore/vpn_core_authorization.go`: `readOwnerPublicKey` | `cmd/mac-infra-core/owner_authorization_test.go`: `TestInstallOwnerKeyPreflight` |
| Authorization binding | `internal/maccore/vpn_core_authorization.go`: `issueAuthorization`, `authorizeMutation` | `internal/maccore/vpn_core_authorization_test.go`: `TestVPNOwnerAuthorizationRefusals`, `TestVPNOwnerAuthorizationFailedInstallReplay` |
| Presence and its limits | `cmd/mac-keyvault-enclave/main.swift`: `accessControl`, `sign`; `cmd/mac-keyvault/prompt.go`: `describeData`; `internal/maccore/vpn_core_authorization.go`: `ParseOwnerPublicKey`, `authorizeMutation` | Source; macOS semantics relied on |
| Release admission | `scripts/provenance-guard.sh`: `preflight`, `verify_files`; `scripts/setup.sh`: `ALLOW_UNPROVABLE` | `scripts/provenance_guard_test.go`: `TestProvenanceNestedWorktree` |
| Modified stamp and publication | `scripts/provenance-guard.sh`: `verify_files`, publication loop; `scripts/setup.sh`: `GOWORK`, `BUILT_BINARIES`; `README.md`: release-build guidance | `scripts/provenance_guard_test.go`: `TestProvenanceDirtyBinary` |
| Vault freeze | `scripts/setup.sh`: `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`: rebuild gates | `scripts/keyvault_guard_test.go`: `TestKeyvaultBuildGuard` |
| Trust limits | `internal/maccore/service_peer_darwin.go`: `requireSocketPeer`; `internal/maccore/service.go`: `serviceDaemon.handleConn`; `scripts/setup.sh`: usage; `agents/skills/mac-infra/SKILL.md`: installation trust | Source and architectural limits |
| Status | Job pin and cited assertions | No execution claim |

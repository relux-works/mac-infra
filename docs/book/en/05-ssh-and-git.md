# 5. SSH and Git

An SSH agent socket gives its clients signing authority.
The vault bridge must limit which keys that authority reaches without giving
clients a private-key export interface.
How does `mac-keyvault ssh-agent` bound SSH authentication and Git signing,
and where does that boundary end?
This chapter follows identity selection, socket admission, consent and audit;
chapters 2–4 cover records, stores and the separate signer contract.
(*source*: `internal/keyvault/ssh_agent.go`, `NewSSHAgent`, `handleSSHFrom`.)

Existing SSH and Git trust is deliberately outside this onboarding path.
Owner policy admits only new keys, with separate authentication and signing
keys, isolated host configuration and signing settings for newly created
repositories.
It provides no migration or retirement step for existing SSH keys, GitHub
registrations or verification trust.
This limits adoption to new uses rather than making successful onboarding
permission to replace working identities.
Commands belong in the [new-key runbook](../../../agents/skills/mac-infra/references/keyvault-ssh-new-keys.md).
(*source*: `agents/skills/mac-infra/SKILL.md`, “SSH agent bridge”; runbook,
owner policy and “Optional signing for a newly created repository only”.)

## Select identities and admit connections

Each `--key` selects an explicit positive generation of a key record.
`NewSSHAgent` authorizes signing and parses its public half as P-256 before
adding the identity.
Enumeration returns that startup snapshot; rotation cannot silently select a
newer generation.
Signing rechecks the pinned public half and enters `Manager.SignIf` for current
record policy.
`TestSSHAgentPolicyChanges` changes usage, expiry, schema or public bytes, or
deletes the item, and requires refusal without another private signing call.
An unpinned generation is also refused.
(*source*: `internal/keyvault/ssh_agent.go`, `NewSSHAgent`, `sign`;
`internal/keyvault/keyvault.go`, `Manager.SignIf`; *tested*:
`TestSSHAgentPolicyChanges`.)

Clients can enumerate identities and submit zero-flag signing requests.
Import, removal, lock, unlock, smartcard and extension operations receive
agent failure, as does the test's attempted export extension.
This closes the bridge's export interface; it does not prove hardware
non-extractability, whose separate evidence belongs to chapter 3.
`TestSSHAgentClosedProtocol` verifies one permitted signature and then checks
that forbidden requests neither sign again nor mutate the backend.
(*source*: `internal/keyvault/ssh_agent.go`, `handleSSHFrom`; *tested*:
`TestSSHAgentClosedProtocol`.)

`ListenSSH` requires an absolute socket path inside a real directory owned by
the process UID with mode `0700`.
It creates that immediate parent if absent and sets the bound socket to `0600`.
It refuses existing files, symlinks and live or stale sockets.
Cleanup removes the path only when it still identifies the socket created by
this listener.
These are filesystem checks and permission settings, not authentication of
an individual agent.
(*source*: `internal/keyvault/ssh_agent.go`, `ListenSSH`; *tested*:
`TestSSHAgentSocketPrivacy`.)

Every admitted connection also needs kernel-reported credentials matching
the owner UID before protocol handling.
Darwin uses `LOCAL_PEERCRED` and checks credential version zero; Linux uses
`SO_PEERCRED`.
The fallback for other platforms returns an error, so credential failure or
mismatch closes the connection without protocol output.
The peer test obtains the current UID and exercises a deliberately different
expected UID; it does not connect as another real account.
(*source*: `internal/keyvault/ssh_peer_darwin.go`,
`internal/keyvault/ssh_peer_linux.go`, `internal/keyvault/ssh_peer_unsupported.go`,
`sshPeerUID`; `internal/keyvault/ssh_agent.go`, `serveSSHPeer`; *tested*:
`TestSSHAgentKernelPeerCredentials`.)

## Decide when consent expires

Without a confirmation hook, an admitted client can request ordinary signing.
`--confirm-exec` instead selects an absolute executable path with literal
arguments, no shell and only a fixed system PATH environment.
Its input contains identity metadata plus the request digest for signing or
the deadline for unlocking, never message bytes.
Exit zero grants; execution failure, cancellation and timeout refuse.
The CLI defaults to 15 seconds, with a positive maximum of one minute.
This adds a waiting dependency on the hook whenever confirmation is required.
(*source*: `cmd/mac-keyvault/ssh_agent.go`, `runSSHAgent`;
`internal/keyvault/ssh_agent.go`, `SSHConfirmHook`, `SSHConfirmation`;
*tested*: `TestSSHConfirmHook` for exit verdicts, timeout and invalid paths.)

The reviewed `confirm-dialog` hook makes Deny both default and cancel button.
It validates one input object of at most 4 KiB before invoking a fixed
AppleScript with validated fields passed as arguments.
Only the exact successful Sign or Unlock result grants.
The dialog defaults to 12 seconds and accepts waits from 1 to 55 seconds;
its wait should stay below the outer hook timeout.
Malformed-input tests assert that no dialog runner is called.
These tests stub the runner rather than inspect a rendered macOS dialog.
(*source*: `cmd/mac-keyvault/confirm_dialog.go`, `dialogScript`,
`readConfirmation`, `runConfirmDialog`; *tested*:
`TestConfirmDialogRefusesMalformedRequests`.)

`--unlock-for` bounds the serving session to a positive duration of at most
24 hours.
With a hook, `--confirm-when sign` is the default; `unlock` asks once per
selected identity before socket creation, and `both` also asks for signatures.
The latter two require an unlock duration.
Unlock-only consent removes repeated clicks but delegates signing throughout
the remaining session; it suits a consciously granted working interval.
A denied unlock exits with refusal before a socket exists.
(*source*: `cmd/mac-keyvault/ssh_agent.go`, `runSSHAgent`;
`internal/keyvault/ssh_agent.go`, `ConfirmUnlock`; *tested*:
`TestRunSSHAgentUnlockConfirmation`.)

The agent compares wall time with its deadline on requests, immediately
before private signing and after signing returns.
A one-second watchdog also stops serving; CLI cleanup removes its socket and
normal expiry exits zero.
A backend operation already running at expiry cannot be cancelled by Go,
but its late result is discarded at the post-sign check.
The blocked-backend test requires one computed signature and an agent failure
response, demonstrating withholding rather than cancellation.
(*source*: `internal/keyvault/ssh_agent.go`, `expired`, `sign`, `Serve`;
`cmd/mac-keyvault/ssh_agent.go`, `runSSHAgent`; *tested*:
`TestSSHAgentDiscardsSignatureFinishedAfterExpiry`.)

## Restrict unattended Git signing and record delivery

For a new unattended signing key, `--sign-namespace git` narrows signing to
well-formed SSHSIG data carrying namespace `git`.
The parser requires the magic, an empty reserved field, SHA-256 or SHA-512,
the corresponding hash length and no trailing bytes.
Authentication challenges and other namespaces are refused before confirmation
or private signing, so this agent cannot also serve ordinary SSH authentication.
The restriction identifies a namespace, not a Git object or an authorized author.
(*source*: `internal/keyvault/ssh_sshsig.go`, `ParseSSHSig`;
`internal/keyvault/ssh_agent.go`, `sign`; *tested*:
`TestSSHAgentGitNamespaceOnlyWithAudit` for accepted Git-namespace signing
and refused authentication, malformed data and another namespace.)

`--audit-log` records metadata rather than request bytes: time, outcome,
reason, identity, parsed namespace and hash algorithm, eight-byte hash
prefixes and an available peer PID.
Opening the log precedes socket creation.
The opener requires a private owned regular file with one link, takes an
exclusive lock, checks for an incomplete final line and requires sync to work.
Requests without an identifiable pinned key and requests stopped before
parsing have no audit entry; refusal records are best effort.
(*source*: `internal/keyvault/ssh_sshsig.go`, `SSHAuditRecord`,
`openSSHAuditLog`, `sshHashPrefix`; `internal/keyvault/ssh_agent.go`,
`handleSSHFrom`, `signAudited`; `cmd/mac-keyvault/ssh_agent.go`, `runSSHAgent`.)

With audit enabled, signature delivery waits for a successful write and sync.
A write or sync error permanently disables that log instance and withholds
the result, trading availability for recorded delivery.
It does not prevent subsequent private operations: the partial-write test
counts three signing calls although only the first request succeeds.
Restarting requires a usable log; the same test rejects reopening its
incomplete tail.
(*source*: `internal/keyvault/ssh_agent.go`, `signAudited`;
`internal/keyvault/ssh_sshsig.go`, `SSHAuditLog.Append`; *tested*:
`TestSSHAuditPartialWriteDisablesLog`.)

## What this does not protect against

Same-user processes are not isolated: the UID check cannot identify which
agent intended a request, and any such client can request Git-namespace
signatures over arbitrary message hashes.
The same user can alter the audit file; its peer PID is diagnostic because
connections can be inherited or passed and PIDs reused.
A same-user process with Accessibility permission can press the consent
button through automation.
Forwarding delegates signing without destination binding because extensions,
including `session-bind@openssh.com`, are refused.
Keep forwarding disabled unless deliberately granting that authority, and
leave existing SSH/Git/GitHub trust untouched when onboarding a new key.
(*source*: `internal/keyvault/ssh_agent.go`, `serveSSHPeer`, `handleSSHFrom`;
`cmd/mac-keyvault/confirm_dialog.go`, consent-boundary comment;
`agents/skills/mac-infra/references/keyvault-ssh-new-keys.md`, “Agent contract
and trust boundary”, “Autonomous signing keys” and owner policy.)

**Status.** Source checked at `602b57c16970767ccdeeb69a2a7e4e101098d279`.
*Tested* identifies assertions read, not a fresh run.
The fake-backend `TestSSHAgentGitSigning` uses Git to sign and verify an
isolated commit and reject a modified commit; it proves no live GitHub use or
installed Keychain authorization.
(*tested*: `internal/keyvault/ssh_agent_test.go`, `TestSSHAgentGitSigning`.)

## Sources

| Paragraph | Repository-relative path and function or symbol | Test asserting the cited case |
| --- | --- | --- |
| Opening | `internal/keyvault/ssh_agent.go`: `NewSSHAgent`, `handleSSHFrom` | Source only |
| New-key policy | `agents/skills/mac-infra/SKILL.md`: SSH agent bridge; `agents/skills/mac-infra/references/keyvault-ssh-new-keys.md`: owner policy, optional signing | Policy only |
| Pinned identities | `internal/keyvault/ssh_agent.go`: `NewSSHAgent`, `sign`; `internal/keyvault/keyvault.go`: `Manager.SignIf` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentPolicyChanges` |
| Closed protocol | `internal/keyvault/ssh_agent.go`: `handleSSHFrom` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentClosedProtocol` |
| Socket | `internal/keyvault/ssh_agent.go`: `ListenSSH` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentSocketPrivacy` |
| Peer credentials | `internal/keyvault/ssh_peer_darwin.go`, `internal/keyvault/ssh_peer_linux.go`, `internal/keyvault/ssh_peer_unsupported.go`: `sshPeerUID`; `internal/keyvault/ssh_agent.go`: `serveSSHPeer` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentKernelPeerCredentials` |
| Hook | `internal/keyvault/ssh_agent.go`: `SSHConfirmHook`, `SSHConfirmation`; `cmd/mac-keyvault/ssh_agent.go`: `runSSHAgent` | `internal/keyvault/ssh_agent_test.go`: `TestSSHConfirmHook` |
| Dialog | `cmd/mac-keyvault/confirm_dialog.go`: `dialogScript`, `readConfirmation`, `runConfirmDialog` | `cmd/mac-keyvault/confirm_dialog_test.go`: `TestConfirmDialogRefusesMalformedRequests` |
| Unlock consent | `cmd/mac-keyvault/ssh_agent.go`: `runSSHAgent`; `internal/keyvault/ssh_agent.go`: `ConfirmUnlock` | `cmd/mac-keyvault/ssh_agent_test.go`: `TestRunSSHAgentUnlockConfirmation` |
| Expiry | `internal/keyvault/ssh_agent.go`: `expired`, `sign`, `Serve`; `cmd/mac-keyvault/ssh_agent.go`: `runSSHAgent` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentDiscardsSignatureFinishedAfterExpiry` |
| Git namespace | `internal/keyvault/ssh_sshsig.go`: `ParseSSHSig`; `internal/keyvault/ssh_agent.go`: `sign` | `internal/keyvault/ssh_sshsig_test.go`: `TestSSHAgentGitNamespaceOnlyWithAudit` |
| Audit metadata and coverage | `internal/keyvault/ssh_sshsig.go`: `SSHAuditRecord`, `openSSHAuditLog`, `sshHashPrefix`; `internal/keyvault/ssh_agent.go`: `handleSSHFrom`, `signAudited`; `cmd/mac-keyvault/ssh_agent.go`: `runSSHAgent` | Source only |
| Audit delivery | `internal/keyvault/ssh_agent.go`: `signAudited`; `internal/keyvault/ssh_sshsig.go`: `SSHAuditLog.Append` | `internal/keyvault/ssh_sshsig_test.go`: `TestSSHAuditPartialWriteDisablesLog` |
| Limits | `internal/keyvault/ssh_agent.go`: `serveSSHPeer`, `handleSSHFrom`; `cmd/mac-keyvault/confirm_dialog.go`: consent-boundary comment; `agents/skills/mac-infra/references/keyvault-ssh-new-keys.md`: trust boundary, autonomous signing, policy | Source and stated limits |
| Status and Git integration | Job pin; `internal/keyvault/ssh_agent_test.go`: `sshFixture`, `TestSSHAgentGitSigning` | `internal/keyvault/ssh_agent_test.go`: `TestSSHAgentGitSigning` |

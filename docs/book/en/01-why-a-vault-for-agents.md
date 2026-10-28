# 1. Why a vault for agents

An agent signing Git commits, authenticating over SSH or requesting an
owner-authorized action needs a persistent identity without receiving its
private key.
The design requirement is to delegate signatures while keeping the private
half in its store.
The [Key Vault Workflow](../../../agents/skills/mac-infra/SKILL.md#key-vault-workflow)
states that requirement for `mac-keyvault` P-256 keys.
How much authority can an agent receive without holding the key, and where
does that protection end?
This opening chapter establishes the actors and boundaries for Part 1,
Keys and Security; chapters 2–7 explain the mechanisms.
(*source*: `agents/skills/mac-infra/SKILL.md`, “Key Vault Workflow”, “SSH
agent bridge” and “Privileged Daemon Installation Trust”.)

Giving an agent a usable private-key file makes possession of that file part of
its signing capability.
The vault instead offers public-key retrieval and signing without a
private-key export command.
Its CLI dispatch and signer operations contain no such export interface.
This bounds what those interfaces return; it does not establish every
store's resistance to extraction by other means.
(*source*: `cmd/mac-keyvault/main.go`, `run`;
`internal/keyvault/signer.go`, `SignerServer.handle`.)

## The owner, agents and root

The owner chooses which new identities to introduce and which operations
require attendance.
Agents run as the owner's user, so their requests share that user's
operating-system identity.
The new-key policy keeps authentication and signing keys separate and
limits onboarding to new uses.
It authorizes no migration of existing SSH or Git trust.
That makes adoption deliberate, at the cost of leaving existing identities
under their existing arrangements.
(*source*: `agents/skills/mac-infra/references/keyvault-ssh-new-keys.md`,
owner policy and “Agent contract and trust boundary”.)

An agent's address selects a record and generation rather than identifying
the calling agent.
Signing checks that record's policy, including usage and expiry, after
reading its metadata and before asking the backend to sign.
These are refusals implemented by the tool.
They do not authenticate which same-user process asked.
(*source*: `internal/keyvault/keyvault.go`, `Manager.SignIf`,
`Manager.authorize`; `cmd/mac-keyvault/main.go`, `run`, `newManager`.)

Store enforcement is a separate question.
The Keychain bridge requests non-extractability and returns signatures from
Security.framework.
`TestSecurityStorePrivateKeyIsNotExtractable` requires
`SecKeyCopyExternalRepresentation` and wrapped-PKCS8 `SecItemExport` to return
`errSecDataNotAvailable` with zero leaked bytes while the public half remains
readable.
That assertion covers those paths from the trusted executable, not all
possible compromises of macOS.
(*source*: `internal/keyvault/security_darwin.c`, `MacKeyVaultCreate`,
`MacKeyVaultSign`; *tested*: `internal/keyvault/security_darwin_test.go`,
`TestSecurityStorePrivateKeyIsNotExtractable`.)

Root operates the privileged helper, `mac-infra-core`.
For vpn-core install and rollback, the helper requires a signature under
its pinned owner public key over an issued authorization statement.
That check authorizes selected mutations; it is not a signature requirement
for every privileged action.
The verifier establishes a signature under that key, not whether the key
lives in an Enclave or whether a prompt appeared.
(*source*: `internal/maccore/vpn_core.go`, `vpnCoreService.handle`;
`internal/maccore/vpn_core_authorization.go`, `issueAuthorization`,
`authorizeMutation`; `internal/maccore/firewall_service.go`,
`firewallService.handle`.)

## Follow a signature through the book

An address, schema-2 record and generation identify the key whose policy a
signature request must satisfy.
Chapter 2 follows that model, distinguishing input refusals from checks that
need stored metadata.
(*source*: `internal/keyvault/signerclient/record.go`, `Record`;
`internal/keyvault/keyvault.go`, `Manager.SignIf`, `Manager.authorize`.)

Chapter 3 separates the login Keychain from the Swift helper's Secure
Enclave route, including the operating-system properties each relies on.
It explains why requesting user presence changes unattended signing into
work that waits for the owner.
(*source*: `internal/keyvault/security_darwin.c`, `MacKeyVaultCreate`;
`cmd/mac-keyvault-enclave/main.swift`, `create`, `accessControl`, `sign`.)

Chapter 4 follows signer contract 1, whose session binds a generation and
whose Go client checks replies against requests.
Its kvctl integration remains *proposed*: the runbook describes a contract,
not a live kvctl consumer.
(*source*: `internal/keyvault/signer.go`, `SignerServer.Serve`;
`internal/keyvault/signerclient/client.go`, `Client.call`;
`agents/skills/mac-infra/SKILL.md`, “Signer contract for kvctl”.)

Chapter 5 follows SSH authentication and Git signing through the agent
bridge's selected identities, socket admission, consent and audit controls.
Read its limits before delegating an unattended signing session.
(*source*: `internal/keyvault/ssh_agent.go`, `NewSSHAgent`, `serveSSHPeer`,
`sign`, `signAudited`; new-key runbook, “Autonomous signing keys”.)

Chapter 6 treats replacement of trusted executables as an operational
decision, covering reviewed installation bytes, owner authorization and
recovery.
It also explains why setup preserves an existing vault binary unless a
rebuild is explicitly requested, postponing updates to preserve working
Keychain trust.
(*source*: `internal/maccore/service.go`, `installServiceWithPreflight`;
`scripts/setup.sh`, `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`,
rebuild gates.)

Chapter 7 separates security evidence, firewall management, shadow
classification and operator-requested network enforcement.
Its coverage limits matter because an empty report cannot establish a
clean host.
(*source*: `internal/security/security.go`, `Summary`;
`internal/security/firewallwatch/classifier.go`, `Classifier.Classify`;
`internal/security/netfilterctl/ctl.go`, `Execute`;
`agents/skills/mac-infra/references/firewall.md`, “Commands”.)

Chapter 8 closes the part with installed-versus-source status, unresolved
decisions and the open question of swarma keyring reuse.
Its open questions remain decisions to make, not guarantees.
(*source*: `docs/book/editorial/outline.md`, chapter 8;
`docs/book/editorial/decisions-pending.md`; `UNRESOLVED_QUESTIONS.md`.)

## What this does not protect against

Same-user processes are not isolated from each other.
Any such process can invoke the CLI or connect to the agent socket;
signing remains subject to the selected controls.
The bridge checks kernel-reported UID, not an individual agent's identity.
`TestSSHAgentKernelPeerCredentials` accepts the current UID and refuses a
deliberately different expected UID; it does not connect as another account.
(*source*: `cmd/mac-keyvault/main.go`, `run`;
`internal/keyvault/ssh_agent.go`, `serveSSHPeer`; *tested*:
`internal/keyvault/ssh_agent_test.go`, `TestSSHAgentKernelPeerCredentials`.)

Consent dialogs add a user-experience check, not a hardware boundary.
A same-user process with Accessibility permission could press the button
through automation, as the dialog code explicitly warns.
An Enclave presence key instead requests `.userPresence` with a fresh
authentication context, relying on macOS enforcement and requiring an
attending owner.
That is unsuitable for unattended agent signing.
(*source*: `cmd/mac-keyvault/confirm_dialog.go`, consent-boundary comment;
`cmd/mac-keyvault-enclave/main.swift`, `accessControl`, `sign`.)

Defence against root is outside this model.
The installation checks inspect files and configuration; userspace
self-checks cannot authenticate the initial build or attest already mapped
root code.
Use the vault to separate signature use from private-key possession within
these limits.
Agents that must distrust one another need process isolation that the CLI
and socket do not provide.
(*source*: `internal/maccore/service_trust.go`, `validateDaemonInstallation`;
`agents/skills/mac-infra/SKILL.md`, “Privileged Daemon Installation Trust”;
`cmd/mac-keyvault/main.go`, `run`; `internal/keyvault/ssh_agent.go`,
`serveSSHPeer`.)

**Status.** *source* means implemented at the checked revision,
`91c0937049278644ba8c15ee742240edd7252cbc`.
*tested* names assertions read, not a fresh run or universal proof.
*installed* requires deployment evidence without host details; installed
builds may lag source.
*proposed* means defined but not live; *unknown* means not established.
Whether a particular installed binary provides these source behaviors is
*unknown* here.
(*source*: `docs/book/editorial/style.md`, status marks;
`scripts/setup.sh`, `usage`, `KEYVAULT_DECISION`.)

## Sources

| Paragraph | Evidence at `91c0937` (functions and tests named above) |
| --- | --- |
| 1 — Signing requirement | `agents/skills/mac-infra/SKILL.md`, vault and trust sections |
| 2 — Interface boundary | `cmd/mac-keyvault/main.go`; `internal/keyvault/signer.go` |
| 3 — Owner and onboarding | `agents/skills/mac-infra/references/keyvault-ssh-new-keys.md`, owner policy |
| 4 — Policy and caller | `internal/keyvault/keyvault.go`; `cmd/mac-keyvault/main.go` |
| 5 — Extraction evidence | `internal/keyvault/security_darwin.c`; `internal/keyvault/security_darwin_test.go` |
| 6 — Privileged authorization | `internal/maccore/vpn_core.go`; `internal/maccore/vpn_core_authorization.go`; `internal/maccore/firewall_service.go` |
| 7 — Chapter 2 | `internal/keyvault/signerclient/record.go`; `internal/keyvault/keyvault.go` |
| 8 — Chapter 3 | `internal/keyvault/security_darwin.c`; `cmd/mac-keyvault-enclave/main.swift` |
| 9 — Chapter 4 | `internal/keyvault/signer.go`; `internal/keyvault/signerclient/client.go`; signer runbook |
| 10 — Chapter 5 | `internal/keyvault/ssh_agent.go`; new-key runbook |
| 11 — Chapter 6 | `internal/maccore/service.go`; `scripts/{setup,keyvault-build-guard}.sh` |
| 12 — Chapter 7 | `internal/security/security.go`; `internal/security/firewallwatch/classifier.go`; `internal/security/netfilterctl/ctl.go`; firewall runbook |
| 13 — Chapter 8 | `docs/book/editorial/{outline,decisions-pending}.md`; `UNRESOLVED_QUESTIONS.md` |
| 14 — Same-user limit | `cmd/mac-keyvault/main.go`; `internal/keyvault/ssh_agent.go`; `internal/keyvault/ssh_agent_test.go` |
| 15 — Consent and presence | `cmd/mac-keyvault/confirm_dialog.go`; `cmd/mac-keyvault-enclave/main.swift` |
| 16 — Root and practical choice | `internal/maccore/service_trust.go`; installation-trust runbook; `cmd/mac-keyvault/main.go`; `internal/keyvault/ssh_agent.go` |
| 17 — Status | `docs/book/editorial/style.md`; `scripts/setup.sh`; assignment pin |

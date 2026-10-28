# 8. Status and open questions

Installed builds may lag the source whose guarantees chapters 2–7 describe.
Setup deliberately preserves an existing vault executable and does not replace the privileged daemon.
Which conclusions can an operator carry from reviewed source to a deployment, and which decisions remain open?
This closing chapter separates that deployment boundary from netfilter distribution questions and possible swarma keyring reuse.
(*source*: `scripts/setup.sh`, `usage`, `KEYVAULT_DECISION`; editorial policy: `docs/book/editorial/decisions.md`, decision 6.)

## Updating source does not update trust

The vault rebuild freeze preserves working Keychain trust while postponing source updates.
Setup keeps an existing executable unless `--rebuild-keyvault` is explicit.
The rebuild guard refuses reported consumers and inconclusive inspections.
The documented macOS behavior is that affected keys need renewed trust after rebuilding; this is relied-on operating-system behavior, not a repository proof.
Chapter 3 explains custody.
Chapter 6 explains replacement.
Rebuilds belong in a planned owner sitting because unattended signing can otherwise wait for a Keychain prompt.
(*source*: `scripts/setup.sh`, `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`, top-level gates; vault runbook, “ACL prompts”.)

Replacing the privileged helper also remains explicit work for an owner sitting under this book's operating policy.
Setup does not install or restart that daemon.
A source fix therefore does not establish that a running helper has changed.
The owner-attendance rule is operational policy, not an automatic enforcement claim.
Whether a particular installation supplies the behaviors in chapters 2–7 is *unknown* here.
(*source*: `scripts/setup.sh`, `usage`; installation-trust runbook.)

## Netfilter decisions still constrain distribution

Release-grade netfilter signing remains an owner decision about distribution beyond registered development devices.
The tracked route requires a Developer ID Application certificate, `content-filter-provider-systemextension`, profiles for both bundle IDs, notarization and a stapled ticket.
These are unresolved release requirements, not evidence of an adopted release build.
The decision also requires owner access to create the certificate.
(*proposed*: `UNRESOLVED_QUESTIONS.md`, “netfilter: release-grade signing (Developer ID, notarization)”.)

Removing the read-only `/` sandbox exception would affect signature attribution outside system paths and `/Applications`.
The tracked alternatives are an unsandboxed lookup helper over XPC, an unsandboxed extension if distribution requirements permit it, or path-only identity where signatures cannot be read.
The helper adds an IPC hop per new flow and requires caching by PID and PID version.
Path-only identity gives up signature detail.
Whether Apple permits the unsandboxed-extension option is *unknown* in this evidence.
The choice belongs with the signing decision.
(*proposed*: `UNRESOLVED_QUESTIONS.md`, “netfilter: the read-only `/` sandbox exception in a non-development build”.)

The protect-list has a separate source gap: neither loader verifies root ownership or permissions.
Go's `LoadProtectList` reads bytes and validates their contents.
Swift's `reloadProtectList` reads and decodes the file.
The owner-installed, root-owned requirement is consequently an installation contract, not a verified loader gate.
Chapter 7 states this limit.
A fix is tracked, but tracking does not supply enforcement.
(*source*: `internal/security/netfilterctl/ctl.go`, `LoadProtectList`; `apps/netfilter/Extension/Control.swift`, `EnforcementState.reloadProtectList`; firewall runbook, “Netfilter kill path (operator CLI)”; the fix is tracked on the mac-infra task board, outside this book.)

Book production also records its own choices.
“Renderer” still calls for identifying and reusing the shared PDF workflow.
“Producer” records how chapters 1 and 3–8 were drafted: by a writer session on the developer-writer profile, with every chapter checked by the keeper and independently reviewed before landing.
The persistent scribe-station route remains unqualified.
These entries concern delivery machinery, not additional security guarantees.
(Editorial record: `docs/book/editorial/decisions-pending.md`, “Renderer”, “Producer”.)

## Reuse patterns before claiming a keyring

A P-256 vault does not by itself supply swarma's agent keyring.
In an external assessment dated 2026-10-28, Ivan's keeper, `ivmbp_ivan_meta-keeper`, identified reusable patterns: semantic addresses, explicit kind/algorithm/version, retained generations, closed schemas, staged policy gates, structured refusals, strict signatures and no private-key-export operation.
The keeper distinguished local lookup handles from cryptographic key IDs and authority proofs.
Rotation would still need explicit validity and dependent-verifier rules.
This assessment is neither repository evidence nor design approval.
(`docs/book/editorial/decisions-pending.md`, “Swarma keyring reuse”; external assessment, points 1–3.)

Encoding compatibility needs a consumer adapter, according to the keeper.
The assessed waggle profile uses compressed SEC1 P-256 public keys of 33 bytes and low-S raw signatures of 64 bytes over its exact record preimage.
DER is not its wire substitute.
The keeper requires public-key conversion and validation, exact hashing without accidental double hashing, domain/version/role binding, and positive and negative vectors.
The assessment explicitly rejects enabling `--allow-high-s` for that profile.
(External assessment, point 2; no current waggle implementation audit is claimed.)

Algorithm roles prevent treating P-256 availability as a complete backend replacement.
The keeper reported Ed25519 agent-author and hardened-purpose keys, with operator devices and admitted roots serving distinct roles.
The assessed Memory contract also uses Ed25519 with different framing, key IDs, base64 and custody arrangements.
The keeper describes P-256 support there as a versioned reader-before-writer change.
Locally, the vault explicitly refuses Ed25519 rather than substituting another curve.
(*source*: `internal/keyvault/signerclient/invariants.go`, `validateAlgorithm`; external assessment, point 2.)

Caller authority is another missing contract in the keeper's assessment.
An agent keyring would need authenticated callers, per-key/purpose/role grants and revocation, freshness and replay controls, allowed signing preimages, separated roles and trust bindings, recovery rules, consumer-specific algorithms and secret-free audit outcomes.
The keeper also requires evidence for custody, presence and recovery.
A no-export interface does not establish those properties.
(External assessment, point 3; open design question under “Swarma keyring reuse”.)

Same-user processes remain unisolated by the vault interfaces described here.
Signer dispatch authenticates no individual agent.
The SSH bridge admits the owner's UID rather than an agent identity.
These tool boundaries do not establish operating-system isolation among mutually untrusted same-user callers.
The keeper's proposed grants would therefore need an actual isolation boundary.
No selected owner-activation profile or root-to-component authority chain follows from sharing an address or public key.
(*source*: `internal/keyvault/signer.go`, `SignerServer.handle`; `internal/keyvault/ssh_agent.go`, `serveSSHPeer`; external assessment, points 2–3.)

An adopted distribution or keyring decision would change the book's stated boundaries.
A code change adding protect-list ownership checks would change its source claims.
Neither an external assessment nor a tracked fix establishes adoption or enforcement.
If practice diverges, resolve the divergence through a decision or change the book; leaving both untouched is excluded by `docs/book/editorial/style.md`.
Record the deciding evidence before relying on a broader guarantee.

**Status.** Source checked at `77b76d8bbe6aa64156840a185bb0d85a7a19f479` supports only the cited implementation statements.
No tests were run or cited as proof here.
Deployment equivalence remains *unknown*.
Distribution alternatives remain *proposed*.
Swarma reuse remains an external assessment and an open design question.
An adoption decision must precede treating it as a platform contract.

## Sources

Paragraphs are numbered in reading order, excluding headings and this table.
“Vault runbook” and “installation-trust runbook” mean the corresponding sections of `agents/skills/mac-infra/SKILL.md`.
“External assessment” means a message from Ivan's keeper to the mac-infra keeper on 2026-10-28, recorded verbatim on the book's tracking story.

| Paragraph | Evidence |
| --- | --- |
| 1 — Deployment question | `scripts/setup.sh`: `usage`, `KEYVAULT_DECISION`; `docs/book/editorial/decisions.md`: decision 6 |
| 2 — Vault freeze | `scripts/setup.sh`: `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`: top-level gates; vault runbook: “ACL prompts” |
| 3 — Helper replacement | `scripts/setup.sh`: `usage`; runbook: “Privileged Daemon Installation Trust” |
| 4 — Release signing | `UNRESOLVED_QUESTIONS.md`: “netfilter: release-grade signing (Developer ID, notarization)” |
| 5 — Sandbox choice | `UNRESOLVED_QUESTIONS.md`: “netfilter: the read-only `/` sandbox exception in a non-development build” |
| 6 — Loader gap | `internal/security/netfilterctl/ctl.go`: `LoadProtectList`; `apps/netfilter/Extension/Control.swift`: `reloadProtectList`; `agents/skills/mac-infra/references/firewall.md`: kill-path heading; fix tracked on the task board |
| 7 — Production choices | `docs/book/editorial/decisions-pending.md`: “Renderer”, “Producer” |
| 8 — Reusable patterns | External assessment: points 1–3; `docs/book/editorial/decisions-pending.md`: “Swarma keyring reuse” |
| 9 — Encoding adapter | External assessment: point 2 |
| 10 — Algorithm roles | External assessment: point 2; `internal/keyvault/signerclient/invariants.go`: `validateAlgorithm` |
| 11 — Missing contract | External assessment: point 3; pending decisions: “Swarma keyring reuse” |
| 12 — Caller boundary | `internal/keyvault/signer.go`: `SignerServer.handle`; `internal/keyvault/ssh_agent.go`: `serveSSHPeer`; external assessment: points 2–3 |
| 13 — Revision trigger | `docs/book/editorial/style.md`: divergence rule; unresolved and pending decisions above |
| 14 — Status | Source pin above; cited source and assessment boundaries |
| 15 — Citation key | External assessment as defined above; runbook section headings |

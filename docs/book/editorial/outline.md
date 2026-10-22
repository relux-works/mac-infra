# mac-infra book — Part 1: Keys and Security (outline)

Audience: engineers and agents who operate or extend mac-infra. Prose explains
the design and its limits; runbooks are linked, not copied. Each chapter ends
with "What this does not protect against" and "Status" (source / tested /
installed / proposed). The section-to-evidence map is packet.md §1–7.

1. **Why a vault for agents** — the problem (agents need signatures, must not
   hold keys), actors (owner, agents, root), trust boundaries, and the
   explicit non-goals (same-UID isolation, root adversary).
2. **Records and policy** — schema-2 records, addressing and generations,
   invariants and unreadable records, policy refusals before any Security
   call, signing/verification strictness (DER low-S), extraction policy.
3. **Where keys live** — Keychain versus Secure Enclave: ACL binding to the
   binary and re-trust after rebuild, the Enclave helper and device-bound
   blobs, user presence and what the prompt shows, no store fallback.
4. **Programs that sign** — signer contract 1: session binding, the closed
   error set, raw-line judgement in the client, golden fixtures; kvctl as a
   defined but not yet live consumer.
5. **SSH and Git** — the agent bridge: pinned identities, socket and peer
   credentials, consent hooks, expiring unlocks, namespace-restricted
   autonomous keys and the audit log; why only new keys go in.
6. **Changing trusted things safely** — privileged helper install and update,
   owner-presence authorization, provenance of release builds, the keyvault
   rebuild freeze, recovery and what is not atomic.
7. **Seeing and limiting the network** — the security evidence tools, the
   ALF keep-on firewall, firewall watch (shadow classification, honest
   coverage), netfilter (attribution, journal-first kill path, protect-list).
8. **Status and open questions** — what is installed versus source, open
   decisions (UNRESOLVED_QUESTIONS.md), and the swarma keyring reuse question.

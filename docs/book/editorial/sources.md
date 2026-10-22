# Sources (public map)

Pin for Part 1: relux-works/mac-infra `2351093511181fc497240714d9950461ffe3edce`.
Re-verify every path when the pin moves.

| Chapter | Primary sources (repository-relative) |
| --- | --- |
| 1 Why a vault | agents/skills/mac-infra/SKILL.md (Key Vault Workflow, Privileged Daemon Installation Trust) |
| 2 Records and policy | internal/keyvault/{record,registry,invariants,keyvault,ecdsa,signer}.go and tests; cmd/mac-keyvault/main.go and tests |
| 3 Where keys live | internal/keyvault/security_darwin.{c,go,h}; internal/keyvault/enclave_*.go; cmd/mac-keyvault-enclave/main.swift; scripts/setup.sh (keyvault rebuild rules) |
| 4 Programs that sign | internal/keyvault/signer.go; internal/keyvault/signerclient/; internal/keyvault/testdata/signer-v1/; SKILL.md (Signer contract) |
| 5 SSH and Git | internal/keyvault/ssh_agent.go, ssh_peer_*.go, ssh_sshsig.go; cmd/mac-keyvault/{ssh_agent,confirm_dialog,prompt}.go; agents/skills/mac-infra/references/keyvault-ssh-new-keys.md |
| 6 Changing trusted things safely | cmd/mac-infra-core/; internal/maccore/; scripts/provenance-guard.sh; scripts/setup.sh |
| 7 Seeing and limiting the network | internal/security/ (incl. firewall, firewallwatch, journal, netfilterctl); cmd/mac-security; cmd/mac-firewall; apps/netfilter/; references/security.md, references/firewall.md |
| 8 Status and open questions | UNRESOLVED_QUESTIONS.md; docs/book/editorial/decisions*.md |

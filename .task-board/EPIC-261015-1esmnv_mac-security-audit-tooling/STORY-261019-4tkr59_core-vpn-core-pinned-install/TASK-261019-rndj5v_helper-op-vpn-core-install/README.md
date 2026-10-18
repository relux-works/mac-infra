# TASK-261019-rndj5v: helper-op-vpn-core-install

## Description
Add helper actions vpn_core_install (and vpn_core_rollback) to mac-infra-core plus a client subcommand. The root daemon copies the keeper-staged package (vpn-core, bin/sing-box, manifest.json) with O_NOFOLLOW into a root-owned 0700 staging dir, hashes there, checks the manifest and the request-pinned digest D = sha256(vpn-core || manifest.json), lays out /Library/PrivilegedHelperTools/works.relux.vpn-core root:wheel, swaps atomically keeping the previous tree, renders the fixed plist template (only the two shas vary; client uid/gid = the authorized client, never 0), restarts works.relux.vpn-core via bootout/wait/enable/bootstrap, and appends a root-owned audit line. Must not run vpn-core install as root.

## Scope
(define task scope)

## Acceptance Criteria
1) Unknown target, non-absolute or symlinked source path or component, non-regular or oversized file, extra/missing manifest entries, per-file sha mismatch and digest mismatch each refuse with a stable error, before any change under /Library. 2) TOCTOU: a source file replaced after the copy cannot change what is installed (test hook between copy and hash). 3) Swap is atomic and keeps the previous tree; rollback restores it; a failed restart leaves a recoverable state that is reported. 4) Rendered plist is byte-identical to the multi-tun reference for the same inputs (golden). 5) Audit line per attempt (accepted and refused). 6) All filesystem and launchctl effects are injectable; tests never touch real /Library or launchd. 7) go test, vet, build green; Codex independent review ACCEPT; sysadmin keeper security review (H03).

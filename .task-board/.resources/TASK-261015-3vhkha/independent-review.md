# Independent SSH-agent security review — TASK-261015-3vhkha

Status: ACCEPTED after Unix peer identity enforcement. The initial finding below
is historical and resolved; the final recheck records the current verdict.

## Review scope

Read-only inspection of new `internal/keyvault/ssh_agent.go`, `cmd/mac-keyvault/ssh_agent.go`, their tests and SSHSIG fixture, tracked integration/dependency diffs, and manual migration runbook. Relevant mac-infra skill was read in the preceding security review. No host keys, SSH/Git configuration, keychain items, GitHub settings, launchd jobs, or other host state was read or changed. Scratch/readiness/results live in `.temp/ssh-review`.

## Material finding

**High — socket mode checks do not authenticate the signing-authority recipient.**
`internal/keyvault/ssh_agent.go`, original ListenSSH (lines 233–280) and Serve (lines 288–326): the directory/file modes are checked/set to 0700/0600, but every accepted Unix connection proceeds to ServeConn without peer credential validation. Named/inherited macOS ACL grants can permit another UID despite those mode bits. Require kernel peer credentials on each accepted UnixConn and reject mismatch/unavailable credentials before identities or signing. Same-UID socket clients remain trusted signing principals, including deliberately forwarded remote agents. Owner notified early; producer fix pending.

Primary local API evidence: `golang.org/x/sys@v0.47.0/unix/syscall_darwin.go` exposes `GetsockoptXucred(fd, SOL_LOCAL, LOCAL_PEERCRED)`; its own Darwin test checks the returned UID against the process UID. No host ACL/account changes were used as a plant. Suggested bounded tests: real same-UID socket positive; the same production matcher against a deliberately different expected UID negative; closed/uninspectable peer failure; assert no private backend operation and no identity output on rejection.

## Passing verification

Tool readiness logs: `tool-readiness-01.log`, `openssh-readiness-01.log`. Go 1.25.5 darwin/arm64, OpenSSH 10.2p1/LibreSSL 3.3.6, Apple Git 2.50.1. ssh-keygen usage probe deliberately exits with usage without opening a key; expected usage output is preserved.

```
MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -race ./internal/keyvault ./cmd/mac-keyvault -run 'TestSSH|TestRunSSH' -count=1
```

`tests-01.log`: both packages pass. Existing native linker LC_DYSYMTAB warnings are preserved; no test failure. Tests cover actual OpenSSH SSHSIG golden verification plus altered-message rejection; actual isolated Git SSH commit signing plus altered-commit rejection; actual local SSH Git push via a synthetic server and pinned fake backend identity; protocol add/remove/lock/flags/extension/export refusals with no private backend effects; malformed/oversized packets; socket no-overwrite and cleanup identity; cancellation; runtime revocation/expiry/forged record/public-key replacement/deletion; literal hook arguments, stripped inherited environment, timeout/denial; concurrent clients. No live keychain tests selected.

## Positive review observations and limits

Selected identities require explicit positive key generations and valid P-256 public halves. Every request signs only after existing Manager.Sign policy gates and rechecks returned SPKI plus signature verification against the pinned identity. Forwarded-style requests expose signing authority without an export path; destination-binding extensions are explicitly refused. All framing is bounded, mutation opcodes fail, unsupported flags fail, arbitrary backend error text and request bytes are not emitted. Hook stdin carries only public identity metadata and SHA-256 digest; process environment is fixed, output discarded, timeout kills the process group. The manual runbook separates auth/signing keys, preserves historical signer material, requires owner execution and real verification before old-key retirement, and does not execute migration.

Documented limits are appropriate: platform Security.framework calls cannot be interrupted, identities are a startup list even after later expiry/deletion, forwarding grants signing capability, and no destination binding is implemented. Same-UID local malware can use signing authority and cannot be excluded by this socket design. Optional additional test coverage communicated: startup-expired/verify-only selection rejection and v1 selection remaining v1 after v2 rotation. These are not material blockers given explicit constructor/resolve code and existing Manager policy coverage.

## Final recheck — ACCEPTED

The sole material blocker is resolved. `SSHAgent.Serve` now dispatches every accepted UnixConn through `serveSSHPeer` before protocol handling. That helper obtains kernel credentials, compares UID to the agent owner, and closes without output on mismatch or retrieval failure. Darwin uses LOCAL_PEERCRED with an explicit supported Xucred version check; Linux uses SO_PEERCRED; unsupported platforms fail closed. This supplements filesystem modes and prevents named/inherited ACL grants from becoming cross-UID signing authority.

`tests-02.log` records the passing complete SSH/CLI race subset after this fix. `TestSSHAgentKernelPeerCredentials` exercises a real accepted UnixConn with owner-positive, deliberately mismatched expected-owner negative, and closed-connection credential error. An additional independent overlay plant (`peer_probe_test.go` plus `overlay.json`) establishes the intended rejection, not merely any client error: a UID mismatch yields immediate empty EOF, the handler finishes, and no private backend sign occurs. `peer-probe-01.log` passes. No actual user/account/ACL change was needed or performed.

Final verdict: no remaining material security blockers found in the inspected SSH-agent change. Fake-backend protocol, policy, OpenSSH golden/modified-data, real isolated Git signing/modified-commit, local SSH push, socket lifecycle, hook boundaries, cancellation and concurrency checks pass. `git diff --check` passes. Darwin is the tested platform; Linux/unsupported-platform peer implementations were inspected only and are not claimed runtime-validated.

Reviewed base commit and exact source/doc/dependency object hashes are frozen in `reviewed-base.txt` and `reviewed-files.txt`. Parent owns integration, signatures, hosted exact-head review/checks and publication. This verdict does not authorize or claim live installation/migration, live keychain ACL trust, GitHub auth/push verification, or retirement of any historical key.

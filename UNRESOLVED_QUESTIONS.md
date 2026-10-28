# Unresolved questions

Open decisions that are not blocking current work. Each entry gives the
question, the constraint, the options, and who decides. Remove an entry
when it is decided, recording where the decision lives.

## netfilter: release-grade signing (Developer ID, notarization)

- **Status**: open, not now (owner scope, 2026-10-23; TASK-261023-symfp6).
- **Today**: development signing in the Relux Works team. The profiles
  include only this Mac and expire 2027-10-22. The extension can run only on
  registered devices, and the profiles must be renewed before expiry.
- **Release route**:
  - a Developer ID Application certificate for the team;
  - the `content-filter-provider-systemextension` entitlement value (not the
    development `content-filter-provider`);
  - Developer ID provisioning profiles for both bundle IDs;
  - hardened runtime (already on);
  - notarization with `notarytool` and a stapled ticket.
- **Needs**: an owner decision on whether the tool should ever run beyond
  this Mac, and access to create the Developer ID certificate (an owner
  action in the developer portal).

## netfilter: the read-only `/` sandbox exception in a non-development build

- **Status**: open (TASK-261023-symfp6). The rationale is in
  `apps/netfilter/DESIGN.md`.
- **Today**: the extension carries
  `com.apple.security.temporary-exception.files.absolute-path.read-only = [/]`.
  Without it, signature lookups fail for programs outside system paths and
  `/Applications`. Before the exception that was about 60% of flows (run 01).
- **Constraint**: temporary exceptions are acceptable for development
  signing; a distributed build should not rely on one.
- **Options**:
  1. A separate unsandboxed helper process (a launchd service of the
     containing app) that resolves signatures for the extension over XPC.
     This adds an IPC hop per new flow; results must be cached per pid and
     pid version.
  2. Keep the extension unsandboxed, if Apple's requirements for content-filter
     system extensions allow it for Developer ID distribution (to verify
     against current documentation).
  3. Report `pid_path` identity without signature details for programs
     outside readable paths. This weakens attribution.
- **Needs**: a decision together with the signing route above. No change is
  needed while the tool stays development-signed on this Mac.

## netfilter: the CLI protect-list path versus the extension's fixed path

- **Status**: open (raised by BUG-261029-1a1xjl, which added the ownership
  checks to both loaders but kept this out of scope).
- **Today**: `mac-firewall netfilter kill|block|unblock` loads the list named
  by `--protect-list FILE`; the extension always reads
  `/Library/Application Support/works.relux.mac-infra.netfilter/protect.json`.
  Both now require a root-owned file under root-owned ancestors, but they can
  name different files. The CLI could then judge "protected" against a
  different list from the one the extension enforces.
- **Options**:
  1. Drop the flag and make the CLI read the extension's fixed path.
  2. Keep the flag, and refuse unless it resolves to the fixed path.
  3. Keep both as they are, and document that the extension's list is
     authoritative.
- **Decides**: the mac-infra keeper together with the operator (the
  local-sysadmin keeper), because it changes the operator CLI contract.

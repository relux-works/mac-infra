# AnyConnect socket-filter cleanup tooling

## Description
Add safe mac-infra support for the observed Cisco AnyConnect disconnected-state resource leak: the VPN CLI reports disconnected, but com.cisco.anyconnect.macos.acsockext remains activated as a NetworkExtension socket filter and can burn CPU/RSS while seeing NEFlow traffic.

## Scope
Read-only diagnostics, explicit dry-run/apply cleanup command design, allowlisted mac-infra-core privileged action(s), README and mac-infra skill workflow updates, and tests. Do not add broad sudo command execution, packet capture, traffic blocking, TLS interception, or direct edits in installed ~/.agents artifacts.

## Acceptance Criteria
mac-load-profile or a companion mac-infra CLI can report AnyConnect CLI connection state, acsockext/vpnagentd PID/resource state, and system extension activation state; cleanup has dry-run output that lists exact actions; apply path uses mac-infra-core allowlisted actions only; docs explain when cleanup is appropriate and what may restart or be unloaded; tests cover command planning and allowlist behavior.

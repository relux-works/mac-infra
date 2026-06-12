# AnyConnect Disconnected Socket-Filter Resource Evidence

Date: 2026-06-12
Source investigation: `/Users/alexis/src/multi-tun` BUG-260612-pjbw1n live resource profiling.

## Observed State

- Cisco AnyConnect CLI reported VPN state as disconnected:
  - `/opt/cisco/anyconnect/bin/vpn status`: `Disconnected`
- Cisco socket filter system extension remained active:
  - `com.cisco.anyconnect.macos.acsockext`
  - `systemextensionsctl list`: activated/enabled
- `com.cisco.anyconnect.macos.acsockext` had high resource usage during the VLESS/gRPC storm:
  - CPU: around `97-100%` in the initial sample
  - RSS: around `866-869 MB`
- Unified logs showed `acsockext` receiving NetworkExtension flow events while AnyConnect VPN was disconnected:
  - `NEFlow`
  - `handleNewUDPFlow`
- After fixing/reconnecting VLESS on TCP, `acsockext` remained loaded but was no longer a top CPU process in the post-fix sample:
  - RSS still around `869 MB`
  - CPU near `0%` in the sampled snapshot

## Interpretation

The Cisco VPN connection being disconnected does not unload the AnyConnect NetworkExtension socket filter. The filter can still observe flows and may amplify unrelated tunnel churn. mac-infra needs an explicit, safe workflow for this state instead of ad hoc `sudo`, broad `killall`, or manual System Settings poking.

## Desired Tooling Shape

1. Read-only diagnostic:
   - AnyConnect CLI connection state
   - `vpnagentd` PID/CPU/RSS
   - `acsockext` PID/CPU/RSS
   - system extension activation/enabled state
   - recent log hints for flow handling
2. Cleanup dry-run:
   - Print exact actions and likely side effects
   - Refuse to run if AnyConnect VPN is connected unless a future explicit force mode is designed
3. Cleanup apply:
   - Use `mac-infra-core` allowlisted privileged actions only
   - No generic command runner
   - No packet capture, TLS interception, or traffic blocking
4. Docs/skill:
   - Document when cleanup is appropriate
   - Document expected result and how to verify with `mac-load-profile`

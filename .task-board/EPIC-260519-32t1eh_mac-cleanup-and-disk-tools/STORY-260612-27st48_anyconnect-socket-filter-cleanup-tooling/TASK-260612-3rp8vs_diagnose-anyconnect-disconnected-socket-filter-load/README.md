# Diagnose disconnected AnyConnect socket-filter load

## Description
Add read-only diagnostics for the state where AnyConnect VPN is disconnected but acsockext/vpnagentd still exist and consume resources.

## Scope
Process/resource inspection, AnyConnect CLI status, system extension state, bounded recent log hints. No mutation.

## Acceptance Criteria
Command output shows connected/disconnected state, acsockext and vpnagentd PID/CPU/RSS, system extension activation/enabled state, and warning when disconnected acsockext load is suspicious; tests cover parser/planner output.

# Mac Bastion (`mac-bastion`) — Workspace Instructions

- **Axiloom Board:** `Mac Bastion` (`mac-bastion`, `proj_xqgisz7wvigfq23tcoa52pgrhi`), bound via local `.axiloom.json` (gitignored).
- **Lead Role Profile:** `sysadmin (ap-role-sysadmin)` supervised under `archon-sanctuary` (see `LAUNCH.md` for launch runbook).
- **Orientation:** Run `axiloom guide --with-status`, `axiloom validate --strict`, and `archon-sanctuary guide` at session start.
- **Sibling Repo:** `/Users/alexis/src/local-sysadmin` (`mac-firewall`, `apps/netfilter`, `host-watch`, `mac-security`, `mac-keyvault`).
- **CRITICAL SAFETY RULE:** NEVER test, restart, or mutate VPN/TUN tunnels (`utun*`, `sing-box`, `multi-tun`, `vless-tun`) on this primary Mac (`m1max`). All live tunnel tests MUST run on `work-mac` over SSH after stopping all Claude/Codex sessions on `work-mac`.

## Work-Mac Remote Host

- **SSH:** `ssh work-mac`; alias defined in `~/.ssh/config`. Hostname: `0000NBB03R25NR7`; user: `aagrigore1`; key: `~/.ssh/work-mac_ed25519`; current LAN DHCP IP / SSH `HostName`: `192.168.1.23`.
- **DHCP shift fallback:** If `192.168.1.23` times out, scan `192.168.1.0/24` for open TCP port 22. Authenticate to candidates as `aagrigore1` with `~/.ssh/work-mac_ed25519`, preserving known-host verification, and confirm `hostname` is `0000NBB03R25NR7`. Update only the `work-mac` stanza's `HostName` in `~/.ssh/config` to the verified address, then reconnect with `ssh work-mac`.
- **Remote checkout:** `/Users/aagrigore1/src/relux-works/mac-infra` is the Mac Bastion repository (`relux-works/mac-infra`, branch `main`).
- **Anti-sleep:** Persistent user LaunchAgent `~/Library/LaunchAgents/works.relux.caffeinate.plist`, label `works.relux.caffeinate`, runs `/usr/bin/caffeinate -dimsu` with `RunAtLoad=true` and `KeepAlive=true`. It loads in the user's GUI login session; verify remotely with `launchctl list works.relux.caffeinate` and `pgrep -fl caffeinate`.
- **Mandatory tunnel safety:** Stop all Claude/Codex sessions on `work-mac` before starting, stopping, testing, or otherwise changing tunnels or routing there. Verify each process's exact PID, birth time, and working directory before stopping it. Live tunnel operations remain forbidden on the primary Mac (`m1max`).

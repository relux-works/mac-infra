# Mac Bastion (`mac-bastion`) — Workspace Instructions

- **Axiloom Board:** `Mac Bastion` (`mac-bastion`, `proj_xqgisz7wvigfq23tcoa52pgrhi`), bound via local `.axiloom.json` (gitignored).
- **Lead Role Profile:** `sysadmin (ap-role-sysadmin)` supervised under `archon-sanctuary` (see `LAUNCH.md` for launch runbook).
- **Orientation:** Run `axiloom guide --with-status`, `axiloom validate --strict`, and `archon-sanctuary guide` at session start.
- **Sibling Repo:** `/Users/alexis/src/local-sysadmin` (`mac-firewall`, `apps/netfilter`, `host-watch`, `mac-security`, `mac-keyvault`).
- **CRITICAL SAFETY RULE:** NEVER test, restart, or mutate VPN/TUN tunnels (`utun*`, `sing-box`, `multi-tun`, `vless-tun`) on this primary Mac (`m1max`). All live tunnel tests MUST run on `work-mac` over SSH after stopping all Claude/Codex sessions on `work-mac`.

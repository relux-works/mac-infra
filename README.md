# mac-infra

macOS operations tooling and agent skills for local workstation maintenance.

## Tools

| Tool | Purpose | Command | Artifacts |
| --- | --- | --- | --- |
| `mac-audio-reset` | Diagnose and reset CoreAudio glitches without rebooting the Mac | `mac-audio-reset diagnose`, `mac-audio-reset reset --dry-run`, `mac-audio-reset reset` | none; diagnostic output only |
| `mac-load-profile` | Capture read-only CPU, memory, process, thermal, pressure, disk, and network diagnostics | `mac-load-profile capture`, `mac-load-profile snapshot`, `mac-load-profile inspect sing-box`, `mac-load-profile tunnel`, `mac-load-profile anyconnect` | `.temp/mac-load-profile/capture-*`, optional `sample-*.txt` |
| `mac-video-profile` | Diagnose macOS video/display smoothness loss, WindowServer/GPU pressure, and Docker/VM rendering load | `mac-video-profile snapshot`, `mac-video-profile capture --logs` | `.temp/mac-video-profile/capture-*` |
| `mac-disk-profile` | Profile disk usage and explain heavy paths without deleting files | `mac-disk-profile scan PATH`, `mac-disk-profile top PATH`, `mac-disk-profile explain PATH` | optional JSON artifact via `--json PATH` |
| `mac-cleanup` | Plan allowlisted cleanup candidates and clean unsupported CoreSimulator runtimes only when explicitly requested | `mac-cleanup scan`, `mac-cleanup target PATH`, `mac-cleanup xcode`, `mac-cleanup xcode-runtimes`, `mac-cleanup permissions`, optional `--json PATH` | optional Plan JSON/report files under `.temp/mac-cleanup/` |
| `mac-safari-session` | Read and harvest authenticated Safari pages through Apple Events without exporting cookies | `mac-safari-session open-bg URL`, `mac-safari-session check-js`, `mac-safari-session snapshot --url URL --json PATH`, `mac-safari-session fetch-file --page URL --resource URL --out PATH` | temporary JS under `.temp/mac-safari-session/`, optional snapshots/download metadata wherever specified |
| `mac-infra-core` | Privileged LaunchDaemon helper for allowlisted macOS maintenance actions | `mac-infra-core request-permissions sudo`, `mac-infra-core install`, `mac-infra-core status`, `mac-infra-core anyconnect-cleanup`, `mac-infra-core uninstall` | `/Library/LaunchDaemons/works.relux.mac-infra-core.plist`, `/var/run/works.relux.mac-infra-core.sock` |
| `go test` | Verify Go command planning and CLI behavior | `go test ./...` | test cache only |
| `scripts/setup.sh` | Build the CLIs and install global skill symlinks | `./scripts/setup.sh` | `bin/mac-audio-reset`, `bin/mac-load-profile`, `bin/mac-video-profile`, `bin/mac-disk-profile`, `bin/mac-cleanup`, `bin/mac-safari-session`, `bin/mac-infra-core`, `~/.local/bin/*`, `~/.agents/skills/mac-infra`, `~/.codex/skills/mac-infra`, `~/.claude/skills/mac-infra` |
| `scripts/deinit.sh` | Remove user-level installation | `./scripts/deinit.sh` | removes symlinks and runtime skill copy |

## Audio Reset Workflow

Use this when macOS audio starts crackling or distorting and restarting the player app is not enough.

```bash
mac-audio-reset diagnose
mac-audio-reset reset --dry-run
mac-infra-core install
mac-audio-reset reset
```

The reset path shuts down booted iOS simulators first, then restarts CoreAudio. This targets the common failure mode where Simulator audio, Apple Music, and high sample-rate USB or Bluetooth output leave CoreAudio in an underrun-prone state.

`mac-infra-core` is intentionally not a generic command runner. The daemon accepts only fixed JSON actions over its Unix socket and executes hardcoded absolute-path commands without shell evaluation.

When sudo credentials are needed for helper setup or privileged actions, request them through the tool itself:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core status
```

This caches sudo for the current interactive session only. It does not grant Full Disk Access and does not grant permissions to Terminal, iTerm2, Cursor, VS Code, or another broad launcher.

## AnyConnect Socket Filter Cleanup

Use this when Cisco AnyConnect reports disconnected but `com.cisco.anyconnect.macos.acsockext` or `vpnagentd` still eats CPU/RSS.

Start read-only:

```bash
mac-load-profile anyconnect
mac-load-profile anyconnect --logs
```

Review the cleanup plan:

```bash
mac-infra-core anyconnect-cleanup
```

Apply only after confirming AnyConnect is disconnected:

```bash
mac-infra-core anyconnect-cleanup --apply
```

The apply path is an allowlisted `mac-infra-core` action. It verifies `vpn status` is disconnected, terminates the Cisco socket-filter extension process, and restarts `com.cisco.anyconnect.vpnagentd` through `launchctl kickstart`. It refuses to run while AnyConnect appears connected unless `--force` is passed explicitly.

## Load Profiling Workflow

Use this when the Mac is hot, fans are up, UI is sluggish, or a process appears to be eating CPU or memory.

```bash
mac-load-profile capture
mac-load-profile snapshot --top 20
mac-load-profile inspect sing-box
mac-load-profile tunnel
```

`capture` writes a broad read-only artifact bundle under `.temp/mac-load-profile/capture-*`. It includes process, CPU, memory, pressure, thermal, disk, network, power assertion, route, and OS/hardware evidence. It does not stop, restart, kill, or mutate processes. Use `--logs` only when recent system pressure logs are needed.

## Video Smoothness Workflow

Use this when video playback, scrolling, UI animations, or Docker/VM-heavy work
start looking discrete or slideshow-like while the Mac still responds.

```bash
mac-video-profile snapshot --top 20
mac-video-profile capture --logs
```

`snapshot` prints read-only triage for compositor, display services, GPU/media,
Docker/virtualization, and browser/Electron/video process groups. `capture`
writes a durable bundle under `.temp/mac-video-profile/capture-*` with
`summary.txt`, display/GPU topology, thermal and memory pressure, power
assertions, process snapshots, display registry state, and optional bounded
WindowServer/display/GPU/Metal/frame logs. It does not reset WindowServer, kill
apps, change refresh rate, or require privileged sampling.

## Disk Profiling Workflow

Use this when disk space is disappearing and you need DaisyDisk-style heavy path evidence in the terminal.

```bash
mac-disk-profile scan "$HOME" --depth 3 --json .temp/mac-disk-profile/home.json
mac-disk-profile top "$HOME" --limit 30
mac-disk-profile explain "$HOME/Library/Developer"
```

The profiler is read-only. It skips symlink traversal by default, deduplicates hard links, reports permission errors separately, and can exclude common generated trees unless `--no-default-excludes` is set.

## Cleanup Planning Workflow

Use this when you want cleanup candidates and totals before deciding what to remove.

```bash
mac-cleanup scan --json
mac-cleanup target --json .temp/mac-cleanup/project-plan.json /path/to/project
mac-cleanup xcode --json
mac-cleanup xcode-runtimes --json
mac-cleanup permissions
```

`scan`, `target`, and `xcode` are read-only planners. They print category, risk, default selection, byte totals, candidate counts, and reasons. If macOS denies access to protected paths, the plan continues with warnings. Avoid granting Full Disk Access to broad launchers such as Terminal, iTerm2, Cursor, or VS Code; every process launched from that app may inherit the access. `mac-cleanup permissions --open` intentionally returns `not implemented` until a dedicated narrow Full Disk Access runner exists. The optional JSON output is a versioned cleanup `Plan` written with `0600` file permissions; using `--json` without a path writes under `.temp/mac-cleanup/`.

`mac-cleanup xcode-runtimes` is a narrow exception for stale simulator runtimes: it cross-checks `xcrun simctl runtime list --json` with `xcrun simctl list runtimes`, reports only `unavailable` and `deletable` runtimes, and is dry-run by default. Pass `--delete` to remove those runtimes via `xcrun simctl runtime delete <identifier>`.

## Safari Browser Session Workflow

Use this when an agent needs to inspect or harvest a page that is already authenticated in the user's Safari profile.

Core safety rule: Safari keeps the cookies. `mac-safari-session` does not export, print, copy, or persist cookies, authorization headers, or browser storage. Authenticated downloads are performed inside the Safari page context with `fetch(..., { credentials: "include" })`, and only the response body plus sanitized response metadata are returned to the local project.

Before JavaScript extraction works, enable Safari automation manually:

```bash
# Safari UI
Safari -> Settings -> Advanced -> Show features for web developers
Develop -> Allow JavaScript from Apple Events
```

Check the permission:

```bash
mac-safari-session check-js
```

Open a page without activating Safari and minimize the new Safari window:

```bash
mac-safari-session open-bg "https://example.com/private/page"
```

Capture page text and links:

```bash
mac-safari-session snapshot \
  --url "https://example.com/private/page" \
  --json .temp/mac-safari-session/page-snapshot.json
```

Run guarded DOM JavaScript against the current Safari front document:

```bash
mac-safari-session run-js --script 'document.body.innerText.slice(0, 5000)'
mac-safari-session run-js --file .temp/mac-safari-session/extract.js --out .temp/mac-safari-session/result.txt
```

The guarded JS path refuses obvious browser-secret reads such as `document.cookie`, `cookieStore`, `localStorage`, and `sessionStorage`. Use it for DOM extraction and page-state inspection, not credential dumping.

Fetch a resource that direct `curl` cannot access because authentication lives in Safari:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --resource "/api/private/file.pdf" \
  --out documents/raw/file.pdf \
  --meta documents/raw/file.pdf.json
```

`fetch-file` stores the base64 body in Safari memory as chunks, pulls the chunks back through Apple Events, decodes locally, writes the output file with `0600` permissions, and clears the Safari fetch job after the final chunk.

Safari has no true headless mode with the live user profile. Background mode avoids focus churn by using Apple Events without `activate` and then minimizing the created Safari window. Screenshots are intentionally outside this CLI because they require Screen Recording permission for the terminal app.

# mac-infra

macOS operations tooling and agent skills for local workstation maintenance.

## Tools

| Tool | Purpose | Command | Artifacts |
| --- | --- | --- | --- |
| `mac-audio-reset` | Diagnose and reset CoreAudio glitches without rebooting the Mac | `mac-audio-reset diagnose`, `mac-audio-reset reset --dry-run`, `mac-audio-reset reset` | none; diagnostic output only |
| `mac-audio-sweep` | Generate and play local frequency sweeps without streaming-platform compression or silent sample-rate mismatch | `mac-audio-sweep device`, `mac-audio-sweep tui`, `mac-audio-sweep tui --rerender`, `mac-audio-sweep generate --out .temp/mac-audio-sweep/sweep.wav` | cached TUI WAVs in `.temp/mac-audio-sweep/cache/*.wav`; one-shot/generated WAVs under `.temp/mac-audio-sweep/` unless `--out` points elsewhere |
| `mac-load-profile` | Capture read-only CPU, memory, process, thermal, pressure, disk, and network diagnostics | `mac-load-profile capture`, `mac-load-profile snapshot`, `mac-load-profile inspect sing-box`, `mac-load-profile tunnel`, `mac-load-profile anyconnect` | `.temp/mac-load-profile/capture-*`, optional `sample-*.txt` |
| `mac-video-profile` | Diagnose macOS video/display smoothness loss, WindowServer/GPU pressure, and Docker/VM rendering load | `mac-video-profile snapshot`, `mac-video-profile capture --logs` | `.temp/mac-video-profile/capture-*` |
| `mac-disk-profile` | Profile disk usage and explain heavy paths without deleting files | `mac-disk-profile scan PATH`, `mac-disk-profile top PATH`, `mac-disk-profile explain PATH` | optional JSON artifact via `--json PATH` |
| `mac-cleanup` | Plan allowlisted cleanup candidates and clean unsupported CoreSimulator runtimes only when explicitly requested | `mac-cleanup scan`, `mac-cleanup target PATH`, `mac-cleanup xcode`, `mac-cleanup xcode-runtimes`, `mac-cleanup permissions`, optional `--json PATH` | optional Plan JSON/report files under `.temp/mac-cleanup/` |
| `mac-safari-session` | Read and harvest authenticated Safari pages through Apple Events without exporting cookies | `mac-safari-session open-bg URL`, `mac-safari-session run-js --window-id ID --script JS`, `mac-safari-session close-window --id ID`, `mac-safari-session check-js`, `mac-safari-session snapshot --url URL --json PATH`, `mac-safari-session fetch-file --page URL --resource URL --out PATH` | temporary JS under `.temp/mac-safari-session/`, optional snapshots/download metadata wherever specified |
| `mac-document-sanitize` | Extract document text and redact common personal data or secrets before agent inspection | `mac-document-sanitize --json PATH`, optional `--redact-from PRIVATE_DICTIONARY` | hash-named `*.sanitized.txt` and `*.redaction.json` files under `.temp/mac-document-sanitize/` by default |
| `mac-infra-core` | Privileged LaunchDaemon helper plus user-scoped controls for allowlisted macOS maintenance actions | `mac-infra-core request-permissions sudo`, `mac-infra-core install`, `mac-infra-core status`, `mac-infra-core sleep-prevention enable\|disable\|status`, `mac-infra-core display-sleep-prevention enable\|disable\|status`, `mac-infra-core idle-lock-prevention enable\|disable\|status`, `mac-infra-core anyconnect-cleanup`, `mac-infra-core uninstall` | daemon files under `/Library/LaunchDaemons/` and `/var/run/`; display LaunchAgent under `~/Library/LaunchAgents/`; idle-lock restore snapshot under `~/Library/Application Support/mac-infra/` |
| `/usr/bin/textutil` | Extract text from HTML, RTF, DOC, and DOCX inputs for sanitization | invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `pdftotext` | Extract PDF text for sanitization | installed with `brew install poppler`; invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `go test` | Verify Go command planning and CLI behavior | `go test ./...` | test cache only |
| `scripts/setup.sh` | Build the CLIs and install global skill symlinks | `./scripts/setup.sh` | `bin/mac-audio-reset`, `bin/mac-audio-sweep`, `bin/mac-load-profile`, `bin/mac-video-profile`, `bin/mac-disk-profile`, `bin/mac-cleanup`, `bin/mac-safari-session`, `bin/mac-document-sanitize`, `bin/mac-infra-core`, `~/.local/bin/*`, `~/.agents/skills/mac-infra`, `~/.codex/skills/mac-infra`, `~/.claude/skills/mac-infra` |
| `scripts/deinit.sh` | Remove user-level installation | `./scripts/deinit.sh` | disables the managed display assertion when possible, then removes symlinks and runtime skill copy |

## Privacy-Safe Document Intake

Sanitize a local document before an agent reads or persists its extracted text:

```bash
mac-document-sanitize --json documents/raw/input.docx
```

The command treats the source as read-only, keeps extracted raw text in memory,
and writes two private (`0600`) artifacts by default:

- `.temp/mac-document-sanitize/document-<sha256>.sanitized.txt`
- `.temp/mac-document-sanitize/document-<sha256>.redaction.json`

The output name is content-hash based so a sensitive source filename is not
copied into the artifact name. The report contains only extraction metadata,
category counts, and warnings; it never stores matched values.

Supported inputs are TXT, Markdown, JSON, XML, YAML, CSV, TSV, HTML, RTF, DOC,
DOCX, PDF, and XLSX. HTML/RTF/Word extraction uses macOS `textutil`; PDF uses
`pdftotext` from Homebrew `poppler`; XLSX extraction is built in. Legacy XLS and
ODS files must first be exported as XLSX, CSV, or TSV.

Automatic redaction covers labeled and tabular names, email addresses, phone
numbers, residential/postal addresses, dates of birth, passports, SNILS,
12-digit personal tax IDs, valid payment-card numbers, IP addresses, JWT-like
secrets, and sensitive JSON keys. Repeated values receive stable placeholders.
For known project-specific values that heuristics miss, pass a private
one-value-per-line dictionary:

```bash
chmod 600 .temp/mac-document-sanitize/extra-redactions.txt
mac-document-sanitize \
  --redact-from .temp/mac-document-sanitize/extra-redactions.txt \
  documents/raw/input.pdf
```

For authenticated browser downloads, keep the raw file task-scoped, sanitize it
immediately, and inspect only the returned `sanitized_path`:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --resource "/api/private/file.pdf" \
  --out .temp/mac-document-sanitize/raw.pdf
mac-document-sanitize --json .temp/mac-document-sanitize/raw.pdf
```

Redaction is deterministic but heuristic, not a legal guarantee of anonymity.
Review the sanitized output before external disclosure and use `--redact-from`
for known values when necessary.

## Sleep Prevention Workflow

Inspect the current policy without changing it:

```bash
mac-infra-core sleep-prevention status
```

The status command reads the one system-wide `SleepDisabled` value from `/usr/bin/pmset -g`. Output reports `sleep_prevention: enabled`, `disabled`, or `unavailable` and `applies_to: AC,battery`. AC and battery do not have independent `disablesleep` values; the coverage line describes the two power sources governed by the global setting.

Enable or disable the persistent policy only when that change is intended:

```bash
mac-infra-core sleep-prevention enable
mac-infra-core sleep-prevention disable
```

These mutations route through the root LaunchDaemon and can execute only `/usr/bin/pmset -a disablesleep 1` or `/usr/bin/pmset -a disablesleep 0`. The setting remains in effect after the command exits until it is explicitly changed; it is not a temporary `caffeinate` assertion. Neither action changes ordinary `sleep` timers, standby, `hibernatemode`, or `displaysleep`. The display can still turn off while system sleep prevention is enabled.

`scripts/setup.sh` installs the user-level binary and skill but does not restart an already running privileged daemon. After the first setup and after every `mac-infra-core` binary update, install/reinstall the daemon before using `enable` or `disable`:

```bash
./scripts/setup.sh
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core sleep-prevention status
```

## Separate Display And Idle-Lock Prevention

System sleep, display sleep, and automatic screen saver start are independent
policies. Inspect or change each one separately:

```bash
mac-infra-core sleep-prevention status
mac-infra-core display-sleep-prevention status
mac-infra-core idle-lock-prevention status

mac-infra-core display-sleep-prevention enable
mac-infra-core idle-lock-prevention enable
```

`display-sleep-prevention enable` installs a current-user LaunchAgent that keeps
one `/usr/bin/caffeinate -d` assertion alive. The assertion prevents idle display
sleep on AC and battery while that user session is logged in. It does not change
`pmset` timers, system sleep, UPS policy, or other assertions. `disable` boots
out the LaunchAgent and removes its plist, so there are no timer values to
restore and no sudo requirement.

`idle-lock-prevention enable` prevents the automatic screen-saver trigger that
leads to idle Lock Screen. Internally it captures the current user's ByHost
`com.apple.screensaver idleTime`, then sets it to `0`. `disable` restores the
captured value or removes the key when it was originally absent. This command
runs as the current user and does not need the privileged daemon.

Enable both display sleep and idle-lock prevention to eliminate the two idle
triggers that lead to automatic Lock Screen. The commands deliberately do not call
`sysadminctl -screenLock off`: manual Lock Screen remains available and the
existing password-after-lock policy remains unchanged.

## Audio Sweep Workflow

Use this when you need a local hearing or output-chain frequency sweep and do not want YouTube or another streaming path to compress, resample, or filter the signal.

```bash
mac-audio-sweep device
mac-audio-sweep tui
mac-audio-sweep tui --rerender
mac-audio-sweep generate --out .temp/mac-audio-sweep/manual-sweep.wav
```

Defaults generate a 96 kHz, 16-bit PCM WAV from 1 Hz to 44 kHz. The first low-frequency ramp goes from 1 Hz to 50 Hz over 90 seconds, starting near +1 Hz per 5 seconds and then accelerating smoothly before the high-frequency exponential sweep. The TUI shows the current frequency, slope, elapsed time, sample-rate/Nyquist limit, and supports `r` to restart and `q`, `esc`, or `ctrl+c` to exit.

`mac-audio-sweep tui` caches rendered WAVs by normalized sweep parameters under `.temp/mac-audio-sweep/cache/`. If the matching WAV exists, playback starts from the cached file; if it is missing, the tool renders it. Use `--rerender` to force overwriting the cached WAV for the same parameters, or `--no-cache` for a one-shot temporary WAV.

`44 kHz` output requires a sample rate above `88 kHz`; the default is `96 kHz`, with Nyquist at `48 kHz`. The TUI default `--output-rate set` checks the current default output device, switches it to the WAV sample rate when supported, and restores the previous rate when playback stops. Use `--output-rate strict` to refuse playback unless the device is already at the WAV rate, or `--output-rate off` to bypass this guard. Hardware, Bluetooth codecs, DACs, headphones, and macOS output paths may still filter ultrasonic content. Keep volume low: high-frequency tones can be hard to perceive while still being unsafe.

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

The command prints a `window-id`. Close that exact agent-created window after
use:

```bash
mac-safari-session close-window --id 12345
```

Capture page text and links:

```bash
mac-safari-session snapshot \
  --url "https://example.com/private/page" \
  --json .temp/mac-safari-session/page-snapshot.json
```

When `--url` is present, `snapshot` pins DOM extraction to that exact background
window and closes the window automatically even when capture fails.

Run guarded DOM JavaScript against the current Safari front document:

```bash
mac-safari-session run-js --script 'document.body.innerText.slice(0, 5000)'
mac-safari-session run-js --file .temp/mac-safari-session/extract.js --out .temp/mac-safari-session/result.txt
```

To keep a multi-step interaction in the exact agent-created background window,
pass the `window-id` printed by `open-bg`. Do not use this option for a
pre-existing user window; close the agent-created target after use:

```bash
mac-safari-session run-js --window-id 12345 --script 'document.title'
mac-safari-session close-window --id 12345
```

The guarded JS path refuses obvious browser-secret reads such as `document.cookie`, `cookieStore`, `localStorage`, and `sessionStorage`. Page status and metadata redact OAuth-style query values. Use it for DOM extraction and page-state inspection, not credential dumping.

Fetch a resource that direct `curl` cannot access because authentication lives in Safari:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --resource "/api/private/file.pdf" \
  --out documents/raw/file.pdf \
  --meta documents/raw/file.pdf.json
```

`fetch-file` stores the base64 body in Safari memory as chunks, pulls the chunks back through Apple Events, decodes locally, writes the output file with `0600` permissions, and clears the Safari fetch job after the final chunk. When `--page` is present, it also pins all fetch steps to the exact background window and closes that window automatically on success or failure.

Safari has no true headless mode with the live user profile. Background mode avoids focus churn by using Apple Events without `activate` and then minimizing the created Safari window. Screenshots are intentionally outside this CLI because they require Screen Recording permission for the terminal app.

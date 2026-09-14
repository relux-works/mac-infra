# mac-infra

macOS operations tooling and agent skills for local workstation maintenance.

## Tools

| Tool | Purpose | Command | Artifacts |
| --- | --- | --- | --- |
| `mac-audio-reset` | Diagnose and reset CoreAudio glitches without rebooting the Mac | `mac-audio-reset diagnose`, `mac-audio-reset reset --dry-run`, `mac-audio-reset reset` | none; diagnostic output only |
| `mac-audio-sweep` | Generate and play local frequency sweeps without streaming-platform compression or silent sample-rate mismatch | `mac-audio-sweep device`, `mac-audio-sweep tui`, `mac-audio-sweep tui --rerender`, `mac-audio-sweep generate --out .temp/mac-audio-sweep/sweep.wav` | cached TUI WAVs in `.temp/mac-audio-sweep/cache/*.wav`; one-shot/generated WAVs under `.temp/mac-audio-sweep/` unless `--out` points elsewhere |
| `mac-load-profile` | Capture read-only CPU, memory, process, thermal, pressure, disk, and network diagnostics | `mac-load-profile capture`, `mac-load-profile snapshot`, `mac-load-profile inspect sing-box`, `mac-load-profile tunnel`, `mac-load-profile anyconnect`, `mac-load-profile fsevents` | `.temp/mac-load-profile/capture-*`, optional `sample-*.txt` |
| `mac-video-profile` | Diagnose macOS video/display smoothness loss, WindowServer/GPU pressure, and Docker/VM rendering load | `mac-video-profile snapshot`, `mac-video-profile capture --logs` | `.temp/mac-video-profile/capture-*` |
| `mac-disk-profile` | Profile disk usage and explain heavy paths without deleting files | `mac-disk-profile scan PATH`, `mac-disk-profile top PATH`, `mac-disk-profile explain PATH` | optional JSON artifact via `--json PATH` |
| `mac-cleanup` | Plan allowlisted cleanup candidates and clean unsupported CoreSimulator runtimes only when explicitly requested | `mac-cleanup scan`, `mac-cleanup target PATH`, `mac-cleanup xcode`, `mac-cleanup xcode-runtimes`, `mac-cleanup permissions`, optional `--json PATH` | optional Plan JSON/report files under `.temp/mac-cleanup/` |
| `mac-safari-session` | Guarded, window-exact authenticated Safari page access and finite named keepalives without exporting browser secrets | `mac-safari-session open-bg URL`, guarded `run-js`/`snapshot`/`fetch-file`, `heartbeat start\|restart\|status\|list\|stop`, explicit `focus --window-id ID` | private temporary JS under `.temp/mac-safari-session/`; optional `0600` artifacts; heartbeat state/logs and one stable launcher under `~/Library/Application Support/mac-infra/browser-session/` |
| `mac-chrome-session` | Guarded exact Chrome tab access, explicit exact-tab handoff, trusted form input and native file upload, sealed authenticated same-origin downloads and Slack reads, bounded extraction, and finite named Chrome/Safari heartbeats without focus churn | `mac-chrome-session list`, guarded `run-js`/`fetch-file`/`slack-read`/`extract`, explicit `focus`, `trusted-input`, or `upload` with exact IDs/origin plus `--human-authorized`; upload/trusted input and protected fetch requests arrive through `--request-stdin`; `heartbeat start\|restart\|status\|stop\|list`, exact `close` | atomic private `run-js --out` and `fetch-file --out` artifacts; protected resource URLs, trusted values, and upload source paths stay out of argv and normal output; upload uses a short-lived private staging directory and reports only guarded origin, accepted basenames, and count; other private outputs and heartbeat state use the paths described below |
| `mac-browser-site` | Token-efficient agent-facing `q`/`grep`/`m` facade over declared Chrome/Safari site adapters | `mac-browser-site q --adapter FILE --format compact 'list(take=20) { id title }'`, `mac-browser-site grep --adapter FILE --format compact PATTERN`, `mac-browser-site m --adapter FILE --format compact --dry-run\|--confirm 'invoke(name=ACTION)'` | projected and sanitized `0600` JSONL under `~/Library/Application Support/mac-infra/browser-site-cache/<site>/`; no cookies, browser storage, authorization material, or cursor/session state |
| `mac-document-sanitize` | Extract document text and redact common personal data or secrets before agent inspection | `mac-document-sanitize --json PATH`, optional `--redact-from PRIVATE_DICTIONARY` | hash-named `*.sanitized.txt` and `*.redaction.json` files under `.temp/mac-document-sanitize/` by default |
| `mac-infra-core` | Privileged LaunchDaemon helper plus user-scoped controls for allowlisted macOS maintenance actions | `mac-infra-core request-permissions sudo`, `mac-infra-core install`, `mac-infra-core status`, `mac-infra-core sleep-prevention enable\|disable\|status`, `mac-infra-core display-sleep-prevention enable\|disable\|status`, `mac-infra-core idle-lock-prevention enable\|disable\|status`, `mac-infra-core anyconnect-cleanup`, `mac-infra-core fseventsd-restart [--force]`, `mac-infra-core fseventsd-watchdog enable\|disable\|status`, `mac-infra-core uninstall` | daemon files under `/Library/LaunchDaemons/` and `/var/run/`; display and fseventsd-watchdog LaunchAgents under `~/Library/LaunchAgents/`; idle-lock restore snapshot and fseventsd-watchdog state under `~/Library/Application Support/mac-infra/` |
| `/usr/bin/textutil` | Extract text from HTML, RTF, DOC, and DOCX inputs for sanitization | invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `pdftotext` | Extract PDF text for sanitization | installed with `brew install poppler`; invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `go test` | Verify Go command planning and CLI behavior | `go test ./...` | test cache only |
| `scripts/setup.sh` | Build the CLIs and install global skill symlinks | `./scripts/setup.sh` | `bin/mac-audio-reset`, `bin/mac-audio-sweep`, `bin/mac-load-profile`, `bin/mac-video-profile`, `bin/mac-disk-profile`, `bin/mac-cleanup`, `bin/mac-safari-session`, `bin/mac-chrome-session`, `bin/mac-browser-site`, `bin/mac-document-sanitize`, `bin/mac-infra-core`, `~/.local/bin/*`, `~/.agents/skills/mac-infra`, `~/.codex/skills/mac-infra`, `~/.claude/skills/mac-infra` |
| `scripts/deinit.sh` | Remove user-level installation without stranding managed jobs | `./scripts/deinit.sh` | stops all `works.relux.mac-infra-browser-heartbeat.*` LaunchAgents and removes the stable launcher plus legacy pinned copies before removing binary symlinks and the runtime skill copy |
| `/usr/bin/codesign` | Give the shared heartbeat launcher a complete stable designated identity so macOS Automation consent can retain it across rebuilds | invoked by `scripts/setup.sh`; verify with `codesign --verify --strict "$HOME/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher"` | signs `bin/mac-chrome-session`; setup atomically installs those signed bytes at the single managed launcher path |

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
  --origin "https://example.com" \
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

## FSEvents Bloat Workflow

Use this when `fseventsd` shows gigabytes of RSS or sustained CPU. It buffers
events for slow consumers (Colima `mountInotify`, sync agents) and never frees
that memory on its own; CPU tracks file-event volume (git-heavy test loops).

```bash
mac-load-profile fsevents
mac-infra-core fseventsd-restart
mac-infra-core fseventsd-watchdog enable
mac-infra-core fseventsd-watchdog enable --auto-restart
mac-infra-core fseventsd-watchdog status
```

`fsevents` is read-only and needs no sudo: it reports fseventsd against RSS/CPU
thresholds, lists known consumers from a pattern allowlist, parses
`~/.colima/*/colima.yaml` for `mountInotify`/`mounts`, and sizes `go-build*`
leftovers. `fseventsd-restart` is an allowlisted root-daemon action
(`launchctl kickstart -k system/com.apple.fseventsd`) that refuses below the
512 MB threshold unless `--force` is given; update the installed daemon with
`mac-infra-core install` first. The watchdog is a current-user LaunchAgent that
checks every 10 minutes, notifies over the threshold, and restarts only with
the opt-in `--auto-restart`. Do not renice or throttle fseventsd: dropped
events make every FSEvents client rescan the volume.

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

## Guarded Browser Session Workflows

Both browser tools operate through Apple Events without focusing a browser in
their normal paths. JavaScript automation must be enabled manually; the tools
never toggle browser preferences with UI scripting:

- Safari: `Develop -> Allow JavaScript from Apple Events`
- Chrome: `View -> Developer -> Allow JavaScript from Apple Events`

The targeting asymmetry is load-bearing. Chrome exposes stable window and tab
ids, so `mac-chrome-session` pins every operation to the exact pair. Safari has
stable window ids but no tab ids; `mac-safari-session` therefore acts on the
current tab of one exact window. A Safari tab switch is target drift, so
`--origin` is mandatory for `run-js`, `snapshot`, and `fetch-file`. The atomic
page-context origin check refuses before the payload runs.

```bash
# Chrome: exact tab, background by default
mac-chrome-session list
mac-chrome-session run-js \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --script 'document.readyState' \
  --out .temp/mac-chrome-session/result.txt

# Safari: exact window, current tab, mandatory origin
mac-safari-session run-js \
  --window-id 55138 \
  --origin https://example.com \
  --script 'document.readyState'
```

Chrome permits `run-js` without `--origin` for exceptional bounded reads, but
prints `guard: unguarded` so the result cannot be mistaken for a guarded call.
Safari does not permit that exception. Chrome `focus`, `trusted-input`, and
`upload` are the only commands allowed to activate or raise Chrome, and all
require exact window/tab/origin guards plus `--human-authorized`. Safari `focus` likewise
requires an explicitly requested visible handoff. `close`/`close-window` also
require an exact target and should be used only for agent-owned state or an
explicit user request.

Chrome `run-js` accepts exactly one of `--script` or `--file`. Optional
`--out PATH` preflights a private temporary file in the destination directory,
then atomically publishes the page result with mode `0600`; stdout reports only
the artifact path and never duplicates page content. Missing, blank, invalid,
or unwritable output paths fail without falling back to stdout.

For an explicitly authorized visible Chrome handoff, use the IDs and origin
from `list` rather than a tab position:

```bash
mac-chrome-session focus \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --human-authorized
```

The focus path re-enumerates fresh Chrome window/tab arrays, selects only the
unique matching IDs, verifies the origin before and after selection, moves that
exact Chrome window to index 1, activates Chrome, then verifies that the same
window is frontmost and the same tab is active. It never finds a window by
title or falls back to whichever window/tab was already frontmost.
Missing/duplicate targets, origin drift, unreadable attestation, or failed
post-focus verification refuse the operation.

Use `trusted-input` only when the user explicitly authorizes visible text entry
and, optionally, one named autocomplete choice. The versioned JSON request is
bounded and read from stdin so field and option values do not enter argv or
normal logs:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=search]","text":"non-secret test text","optionSelector":"[role=option]","optionText":"Named option","timeoutMs":5000}' |
  mac-chrome-session trusted-input \
    --window-id 704793720 \
    --tab-id 704793726 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The command first completes the same exact-target focus verification. It then
admits exactly one visible editable text/search input, temporarily marks it
with an unguessable Accessibility description, focuses that exact native
element, sets the bounded value and caret semantically, then posts only a fixed
non-secret append/Backspace pair while Chrome is active, the exact window is
the unique native main window, and the nonce element stays focused. The nonce
correlates the native element back to the exact tab without title matching.
Success requires a trusted DOM `input` event and an exact value match. Optional
selection admits at most 20 visible
matches, requires one normalized exact-text option, presses its nonce-marked
native element, and requires a trusted click plus the selected input value.
Selectors are capped at 512 bytes, text at 512 characters/2048 bytes, option
text at 256 characters/1024 bytes, and the deadline at 10 seconds. Output is
only version, origin, and `ok`/`typed`/`selected` booleans; field values are not
printed or persisted. Any target/origin/element drift fails closed.

All explicit visible paths require Chrome JavaScript from Apple Events.
`trusted-input` and `upload` also require macOS Accessibility access for the installed, signed
`mac-chrome-session` identity. Grant that executable access in System Settings
-> Privacy & Security -> Accessibility when macOS requests it; do not automate
the consent UI.

Use `upload` only after the user explicitly authorizes the visible native file
chooser interaction. The request is a bounded JSON object on private stdin so
absolute source paths never enter argv or normal logs:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=file]","paths":["/private/task/evidence.pdf","/private/task/order.doc"],"allowedExtensions":[".pdf",".doc"],"maxFileBytes":33554432,"maxTotalBytes":67108864,"timeoutMs":15000}' |
  mac-chrome-session upload \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The command validates one to eight clean absolute paths as regular non-symlink
files, enforces explicit extension and byte ceilings under fixed 32 MiB
per-file and 64 MiB total hard limits, and rejects duplicate basenames. It
copies only those files into a mode-`0700` temporary directory with mode-`0600`
entries, then focuses only the exact guarded Chrome target. A cryptographic DOM
nonce identifies one visible enabled file input in Chrome's Accessibility tree.
The native bridge first requires a successfully read zero-sheet state, presses
that element, retains the one resulting file-chooser sheet by exact AX identity,
navigates to the otherwise-empty staging directory, selects all staged entries,
and retains the same identity through the close wait without coordinates or
`System Events`. Only proven empty/same-chooser snapshots are retryable; an
Accessibility read error, null/wrong-type value, ambiguity, or replacement
refuses immediately instead of being treated as chooser absence. Staging is
removed on exit.
Multi-file requests require the DOM input's `multiple` property.

When the input declares `accept`, upload validates it during preparation,
immediately before native interaction, and again before success attestation.
The bounded contract admits at most 512 characters and 32 unique
comma-separated tokens: dot extensions up to 16 characters, exact MIME types,
and the standard `image/*`, `audio/*`, or `video/*` wildcards. Every staged
filename must match a declared extension or its fixed known MIME mapping;
unsupported tokens, unknown MIME evidence, and mismatches fail closed. The
visibility gate walks at most 64 element ancestors, rejects hidden/ARIA-hidden,
collapsed, zero-opacity, non-default filter or mask, non-displayed, or
non-targetable ancestry, and requires the exact input to win a bounded viewport
hit test. The type, enabled, visibility, hit-test, `multiple`, and `accept`
decisions are rebound to the same nonce-bearing input at every upload phase.

Success requires a trusted DOM `change` event and an exact browser-observed
filename, size, and count match after the chooser closes. Target/origin drift,
ambiguous or hidden inputs, chooser ambiguity, unsupported extensions, changed
files, unsupported or mismatched DOM acceptance, untrusted events, metadata
mismatch, and timeouts fail closed. Stdout
contains only version, guarded origin, accepted basenames, and count; it never
contains file bytes or absolute paths. This intentionally brings Chrome
forward and requires Accessibility permission, so it is not a silent primitive.

For protected Chrome files, use the sealed `fetch-file` command instead of
clicking download links. It performs each start, poll, and chunk read against
the same exact window/tab and canonical HTTPS origin, so it neither focuses
Chrome nor enters Chrome's native multiple-download flow:

```bash
printf '%s' '{"version":1,"resource":"/api/private/document.pdf","maxBytes":26214400,"timeoutMs":90000}' \
  | mac-chrome-session fetch-file \
      --window-id 704793720 \
      --tab-id 704793726 \
      --origin https://example.com \
      --out .temp/BUG-000000-example/document.pdf \
      --request-stdin
```

The protected resource is supplied only through that bounded versioned stdin
envelope; `mac-chrome-session` declares no `--resource` flag and refuses one if
passed. This is the outer privacy boundary: a command line is durable agent
session and tool evidence and an interactive shell may persist it in history, so
a document or sticky identifier must never reach argv. The envelope is a single
JSON object of at most 8192 bytes accepting only `version` (must be `1`),
`resource` (at most 4096 bytes), `maxBytes`, and `timeoutMs`; unknown fields,
trailing JSON, and out-of-range bounds are refused before any browser call and
no refusal echoes the envelope.

The resource must resolve to the guarded HTTPS origin and may not contain user
info or a fragment; cross-origin and redirecting requests fail closed. The
tool-authored page request uses browser-owned same-origin credentials without
reading or returning cookies, authorization headers, or browser storage. The
resource URL is carried to Apple Events over private stdin and is never emitted
in stdout, stderr, or response metadata.

That promise is structural, not a rule applied per failure site. Every
`fetch-file` failure — invocation, request envelope, validation, output
preflight, transfer, and output publication alike — is collapsed into one closed
internal diagnostic type (`chromectl.FetchFileDiagnostic`) that holds a single
private enum code and nothing else: no wrapped error, no path, no origin, no
child text. A fixed code selects a fixed literal, and one emitter in
`mac-chrome-session` performs the only failure print on this path. Failure
output is therefore always exactly one line, `fetch-file: <fixed message>`, and
never a formatted error. Exit status is `2` for a refused invocation or an
unverifiable request envelope and `1` for every other failure.

The closed vocabulary is: invocation refused; request could not be verified;
request refused; browser target is no longer available; browser target origin
changed; page-context transport unavailable; page-context transport failed;
page-context response could not be verified; another sealed fetch is already
running; size limit; timeout; non-success HTTP status; redirect refused;
page-context fetch failed; private output could not be prepared; private output
could not be published; and a catch-all safe failure. An error that reaches the
boundary without a recognized classification collapses to that catch-all instead
of being rendered, so a missed conversion fails closed rather than becoming the
next leak.

Everything below that boundary is a classification input only. The stdin program
handed to `osascript` embeds the resource, so a failing child could otherwise
quote it back through its own stderr or stdout; sealed page-context calls
discard both child streams and produce a fixed Go-chosen kind
(`child-exit-status`, `child-unavailable`, `page-context-execute-failed`,
`unverifiable-response`) that selects a code and is then dropped — those kinds
are no longer printed for `fetch-file`. Target loss keeps its own classification
because the JXA program returns a sentinel-sealed `window-missing` /
`tab-missing` envelope instead of throwing, and the page-context `catch` arm
drops the caught error whole because a JXA execution error can quote the program
it failed on.

The nested browser-session guard envelope is authenticated by shape, not by
provenance, so a sealed child can mint a well-formed `origin-mismatch` response
whose `origin` field is a copy of the resource-bearing program it received. That
observed value is dropped at the transport and cannot be reconstructed at the
boundary. `errors.Is` against `browsersession.ErrTargetMissing` and
`ErrOriginMismatch` still classifies correctly for Go callers, while `errors.As`
to the detail-bearing `TargetMissingError` / `OriginMismatchError` types fails by
construction. Output preflight and atomic-publish failures are treated the same
way: the underlying filesystem error names the explicit output path, so only the
fixed code crosses. Expect no page source, URL, query name, query value, output
path, or syscall text in any `fetch-file` failure output, whatever the child or
the filesystem returns.

`timeoutMs` is bounded in integer milliseconds before it becomes a
`time.Duration`. `time.Duration` is int64 nanoseconds, so comparing after the
conversion let a large millisecond count wrap back into range — `288230376151711754`
became `10ms`. Response streaming is capped in page
context and checked again before publication. Only status, byte count, and a
validated media type leave page context. `--out` is preflighted before browser
execution and published by same-directory atomic rename with mode `0600`; a
target/origin change, timeout, size refusal, decode error, or write error leaves
the prior destination untouched. The hard limits are 100 MiB and five minutes.

The shared JavaScript guard refuses case-insensitive occurrences of
`document.cookie`, `cookieStore`, `localStorage`, `sessionStorage`, `indexedDB`,
`navigator.credentials`, and `openDatabase` on every CLI path that reaches page
context. This blocklist is an accident-prevention speed bump, not a JavaScript
sandbox: constructed property names can bypass substring checks. The actual
tool guarantee is narrower and enforceable: it never intentionally reads,
prints, persists, or transports browser session material, and URLs, fragments,
and response headers leaving the tool are sanitized. URL sanitization is
structural rather than name-based: scheme, host (with any nonstandard port) and
path survive, the entire query string is replaced with `[redacted-query]`, the
fragment with `[redacted]`, user info is dropped, and payload-carrying opaque
URLs (`data:`, `javascript:`, `view-source:`, `mailto:`) become
`[redacted-opaque-url]`. A parameter-name denylist cannot fail closed against an
authenticated site that names its document and sticky identifiers freely, so no
query byte survives `list`. Keep returned page content bounded and store raw
evidence only in task-scoped private (`0600`) artifacts.

### Sealed Slack reads

`slack-read` is the sole exception that may locate Slack Web authorization in
browser storage. It does so only inside compiled, tool-authored JavaScript and
never returns, prints, logs, persists, or places the token in argv or the
environment. Generic `run-js --script` and `--file` continue to refuse
`localStorage`, cookies, authorization data, and the other blocked sources.

The command requires the exact Chrome window/tab, the literal
`https://app.slack.com` origin, and a `T...` workspace id. The origin and
`/client/<workspace-id>` path are checked in the same page evaluation that
locates the selected workspace's supported `localConfig_v2` token and starts
the request. Origin/workspace drift dispatches nothing. Missing or changed
browser storage schema returns `capability-unavailable`; there is no credential
export fallback.

Only these compiled read methods are admitted: `auth.test`,
`conversations.list`, `conversations.info`, `conversations.history`,
`conversations.replies`, `users.list`, and `search.messages`. One versioned
request arrives over bounded stdin; caller JavaScript, writes, unknown
methods/arguments, oversized input/output, deep JSON, and token-shaped input or
output are refused or redacted:

```bash
printf '%s\n' \
  '{"version":1,"method":"conversations.list","args":{"limit":1}}' |
  mac-chrome-session slack-read \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://app.slack.com \
    --workspace-id T0123456789 \
    --request-stdin
```

Method arguments are typed and closed to unknown fields:

- `conversations.info`: required conversation `channel`; optional
  `include_locale` and `include_num_members` booleans.
- `conversations.history`: required `channel`; optional bounded `cursor`,
  `limit` from 1 through 100, Slack `oldest`/`latest` timestamps, `inclusive`,
  and `include_all_metadata`.
- `conversations.replies`: the history arguments plus a required Slack `ts`.
- `users.list`: optional bounded `cursor`, `limit` from 1 through 100,
  `include_locale`, and `team_id`; when supplied, `team_id` must exactly match
  `--workspace-id`.
- `search.messages`: required query of at most 512 bytes; optional `count` from
  1 through 100, `page` from 1 through 1000, bounded `cursor`, `sort` (`score`
  or `timestamp`), `sort_dir` (`asc` or `desc`), `highlight`, and a matching
  `team_id`.

Conversation ids, Slack timestamps, cursors, queries, and team ids are
validated before Chrome execution. Secret-shaped values, trailing JSON, and
unknown fields are refused. `auth.test` still accepts no arguments, and the
existing bounded `conversations.list` contract is unchanged.

The response is a versioned JSON envelope. It can contain ordinary Slack data.
Xox/xapp, Bearer, and JWT-shaped spans inside response strings and JSON object
keys are replaced in place with `[redacted]` while surrounding non-secret text
and safe keys are preserved. A response is refused when key redaction would
make two object keys collide, so sanitization never overwrites a value. Compact
JWT/JWE-like spans extend through every contiguous dot-delimited token segment,
favoring fail-closed redaction over returning a possible token tail. Keep live
evidence to booleans/counts with a bounded projection and never
persist channel, user, or message content unless the task explicitly requires a
private artifact.

Safari agent-created background windows are closed automatically by
`snapshot --url` and `fetch-file --page`; otherwise close the exact id returned
by `open-bg`. Authenticated fetches remain in Safari page context with
`credentials: "include"`. Screenshots remain out of scope because they require
Screen Recording permission.

### Agent-facing site facade

Use `mac-browser-site` when an agent needs structured repeated-item reads,
cache-only full-text search, or one declared page mutation. The adapter JSON
pins a Chrome exact window/tab or Safari exact window, a mandatory origin, the
existing deterministic extraction template, a bounded pagination contract,
and an allowlist of mutation selectors. Query syntax follows the separate
`q`/`grep`/`m` contract:

```bash
mac-browser-site q --adapter .temp/browser/marketplace.json --format compact \
  'schema(); list(skip=0,take=20,max_pages=3,where_field=title,where_value=lamp) { id title price }'

mac-browser-site grep --adapter .temp/browser/marketplace.json \
  --format compact --file query-0123456789abcdef.jsonl -i 'lamp'

mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --dry-run 'invoke(name=install)'
mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --confirm 'invoke(name=install)'
```

`q` supports semicolon-separated batches, field projection, the extractor's
`equals`/`contains`/`prefix` predicate, and a hard 100-item result / 1,000-item
scan bound. `next-page`, page-owned `cursor`, and `infinite-scroll` adapters are
bounded by `maxPages <= 20`; cursor values stay inside the site's own click
handler and never enter output, command arguments, URLs, or cache. `grep` never
opens a browser and searches only canonical validated JSONL records inside a
descriptor-rooted site cache; every facade-owned path component is checked
before the physical root is opened, and symlinked components are refused. An
explicit `grep --file` naming a final symlink fails with
`CACHE_SCOPE_REFUSED`; it is never reported as an empty search result. `m`
prevalidates the whole batch and dispatches no
page action without both an adapter-declared mutation and `--confirm`;
`--dry-run` is a no-write preview.

`hasMore` is tri-state evidence: `true` requires an observed record beyond the
requested window, `false` requires either the complete `none` page or an
explicit adapter `advanced:false`, and `unknown` covers duplicate/stale pages,
caller or adapter page bounds, and the global scan bound. Partial or malformed
extract/advance envelopes are typed failures rather than false exhaustion.

Adapter origins containing credentials, paths, query strings, or fragments are
refused. Public field names and returned records are checked for cookie,
storage, credential, authorization, token, and opaque session-state shapes;
one canonical outbound boundary classifies every schema/list/cache/grep/error
and compact/JSON render as `clean`, `redacted`, `refused`, or `unknown`.
Bearer/JWT and recognized opaque credential families—including GitHub,
GitLab, `sk-proj-*`, `sk-*`, and Stripe-style `sk_*` forms—are refused. This is
a fail-closed scanner for named/recognizable secret shapes; ambiguous long
opaque credential candidates report `SENSITIVE_RESPONSE_UNKNOWN` rather than
being declared public. It is not a claim that every arbitrary string can be
semantically identified as a token. One normalized name policy covers fields,
JSON keys, assignments, and URL query names, including cookie, local/session
storage, session id/state, authorization, credential, key, and token families.
HTTP(S)
schemes, hosts, decoded query names, and query values are parsed
case-insensitively. The decoded hostname and every bounded-decoded path
component pass that same name policy plus recognized/opaque credential
classification before the URL is released. Every duplicate sensitive query
value, user info, and fragment is redacted. A secret-bearing query name or
nested/repeatedly encoded secret URL is refused. A bounded normalization queue covers literal,
percent-encoded, nested, JSON-escaped, backslash-escaped, and case-varied
representations, then rescans transformed output to a fixed point. Malformed or
ambiguous URL/JSON input fails closed as
`SENSITIVE_RESPONSE_UNKNOWN`. Extractor, pagination-advance, and mutation
evidence—and adapter JSON metadata—are duplicate-key and scalar checked before
lossy decoding. Browser transport stdout/stderr is never used as public error
detail; failures expose only a stable typed kind and generic message. Cache grep never
re-emits source JSONL bytes: it rejects duplicate keys and renders only a
canonical re-encoding of the exact validated record. See the
[site facade reference](agents/skills/mac-infra/references/browser-site-facade.md)
for the adapter schema and pagination semantics.

### Named persistent heartbeats

Both browser CLIs use the same Go heartbeat manager and managed namespace.
Use `mac-chrome-session heartbeat` for Chrome and
`mac-safari-session heartbeat` for Safari. Every heartbeat has a validated
name, exact target, required origin, interval of at least `15s`, private log,
state file, and one LaunchAgent. Chrome uses an exact window/tab pair; Safari
uses an exact window plus its current tab and the mandatory origin guard.

```bash
mac-chrome-session heartbeat start \
  --name example-chrome \
  --browser chrome \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --interval 45s \
  --ttl 8h

mac-safari-session heartbeat start \
  --name example-safari \
  --window-id 55138 \
  --origin https://example.com \
  --interval 45s \
  --deadline 2026-08-26T06:00:00Z

mac-chrome-session heartbeat status --name example-chrome
mac-chrome-session heartbeat list
mac-chrome-session heartbeat restart --name example-chrome --ttl 8h
mac-chrome-session heartbeat stop --name example-chrome
mac-safari-session heartbeat status --name example-safari
mac-safari-session heartbeat list
mac-safari-session heartbeat stop --name example-safari
```

`start` performs a live guarded preflight before installing anything, then
waits for the first bounded outcome from the installed background process. A
failed background preflight is booted out and its managed artifacts are
removed instead of reporting a false successful start. Every start requires
exactly one future `--ttl` or RFC3339 `--deadline`. Every LaunchAgent runs the
same signed installed launcher at
`~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`;
setup atomically updates that path instead of creating a new background-item
identity for every build. Multiple names run concurrently. Origin drift dispatches no
synthetic input, logs only `refused` plus the observed origin, and appears as
`drifted`; missing targets appear as `target-missing`. Other states are
`not-configured`, `configured-not-loaded`, `running`, `unavailable`, `expired`,
`migration-required`, or `unknown` when launchd state cannot be read safely.
Status/list expose `deadline`, `expired`, and `migrationRequired`. Logs contain only timestamp,
outcome, origin, and ready state—never page title or body text.

The first heartbeat through the stable launcher may require macOS Automation
consent for Chrome and Safari. Setup applies the complete ad-hoc designated
requirement `works.relux.mac-infra.browser-session` to that shared heartbeat
launcher; direct Safari CLI actions retain `works.relux.mac-infra.safari-session`. A raw Go linker
signature does not provide an actionable TCC identity. Handle the system prompt
manually; the tool never clicks it or brings a browser forward. Until a bounded
heartbeat outcome exists, `status` reports `unavailable` rather than guessing
that a loaded LaunchAgent can reach page context.

Every scheduled check is limited to three 10-second attempts with short bounded
delays; this deadline does not grow with the heartbeat interval. Status also
validates outcome freshness, so a loaded process with an expired last success
reports `unavailable` and `errorKind: stale-outcome` instead of a false
`running` state.

At the configured deadline, both the runtime and a later `status`/`list` call
remove the managed state, plist, and private log before booting out the job; the
expiry path performs no browser probe and never focuses a browser. Legacy
content-addressed or deadline-free state reports `migration-required`. Restart
it safely with `heartbeat restart --name NAME --ttl DURATION` (or
`--deadline RFC3339`): the replacement target is preflighted before the old job
is stopped, then the old pinned copy is garbage-collected.

`scripts/deinit.sh` stops all managed browser heartbeats and removes the stable
launcher plus legacy pinned copies before deleting the installed CLI, so no respawn-failing
LaunchAgent is stranded. See the detailed
[Chrome](agents/skills/mac-infra/references/chrome-session.md) and
[Safari](agents/skills/mac-infra/references/safari-session.md) references.

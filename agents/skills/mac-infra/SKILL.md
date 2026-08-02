---
name: mac-infra
description: >
  macOS workstation infrastructure tooling for diagnosing and fixing local Mac
  audio crackling, CoreAudio daemon glitches, Simulator audio issues, Apple
  Music distortion, USB DAC output problems, Bluetooth output problems, macOS
  video/display smoothness loss, WindowServer/GPU stutter, Docker/VM slideshow
  symptoms, and broad CPU, memory, thermal, process load, authenticated Safari
  browser-session inspection/harvesting, and related maintenance tasks.
triggers:
  - mac load
  - load profile
  - CPU profile
  - memory profile
  - disk profile
  - disk usage
  - disk space
  - storage profile
  - cleanup plan
  - mac cleanup
  - cleanup mac
  - high CPU
  - high memory
  - hot mac
  - overheating mac
  - process load
  - top processes
  - activity monitor
  - Mac is hot
  - mac video
  - macOS video
  - video stutter
  - display stutter
  - WindowServer
  - GPU stutter
  - slideshow
  - Docker slideshow
  - video smoothness
  - плавность видео
  - видео лагает
  - слайдшоу на маке
  - дискретность видео
  - дергается видео
  - WindowServer жрет
  - mac audio
  - macOS audio
  - audio crackle
  - crackling audio
  - distorted audio
  - CoreAudio
  - coreaudiod
  - usbaudiod
  - Apple Music crackle
  - TA-22
  - USB DAC
  - AirPods crackle
  - Simulator audio
  - reset audio
  - clean audio
  - звук трещит
  - трещит звук
  - звук хрипит
  - хрипит звук
  - дребезг
  - дребезжит
  - перезапусти звук
  - почисть звук
  - сбрось аудио
  - аудио на маке
  - кор аудио
  - кореаудио
  - audio sweep
  - frequency sweep
  - hearing test
  - local audio test
  - sine sweep
  - 44 kHz audio
  - sleep prevention
  - prevent Mac sleep
  - disable system sleep
  - pmset disablesleep
  - prevent display sleep
  - disable display sleep
  - prevent screen lock
  - prevent idle lock
  - prevent screen saver
  - частотный тест
  - аудиотест
  - тест слуха
  - свип частоты
  - синус свип
  - 44 кГц
  - запретить сон мака
  - не давать маку спать
  - отключить сон macOS
  - не гасить экран
  - не выключать монитор
  - не блокировать экран
  - запретить локскрин
  - что жрет проц
  - жрет процессор
  - жрет память
  - греется мак
  - мак греется
  - профайли нагрузку
  - нагрузка на маке
  - мониторинг компа
  - что жрет диск
  - жрет диск
  - место на диске
  - профайли диск
  - почистить мак
  - чистка мака
  - клинап мака
  - safari automation
  - Safari Apple Events
  - browser automation
  - browser harvest
  - authenticated browser
  - authenticated Safari
  - Safari cookies
  - reuse browser cookies
  - read browser page
  - harvest browser page
  - сафари
  - браузер
  - автоматизация сафари
  - кукисы
  - вычитать браузер
  - потрошить браузер
  - харвестить браузер
---

# mac-infra

Use this skill for macOS local maintenance workflows backed by the `mac-infra`
Go tools.

## Sleep Prevention Workflow

Start with the read-only system-wide status:

```bash
mac-infra-core sleep-prevention status
```

The command reads `SleepDisabled` from `/usr/bin/pmset -g` and reports one
`enabled`, `disabled`, or `unavailable` state with `applies_to: AC,battery`.
`disablesleep` is global; do not infer separate values from AC/battery `sleep`
timers in `pmset -g custom`.

Enable or disable only when the user explicitly requests the mutation:

```bash
mac-infra-core sleep-prevention enable
mac-infra-core sleep-prevention disable
```

- Mutations go through the root daemon and expose only the fixed actions backed
  by `/usr/bin/pmset -a disablesleep 1` and
  `/usr/bin/pmset -a disablesleep 0`.
- The setting persists after the command exits until explicitly changed. It is
  not a process-scoped `caffeinate` assertion.
- The policy covers AC and battery but does not change `sleep` timers, standby,
  `hibernatemode`, or `displaysleep`. The display may still turn off.
- `scripts/setup.sh` updates the user binary and installed skill but does not
  restart an existing privileged daemon. Run `mac-infra-core install` after the
  first setup and after core binary updates before using `enable` or `disable`.

## Separate Display And Idle-Lock Prevention Workflow

Do not collapse system sleep, display sleep, and idle Lock Screen behavior into
one mutation. Inspect and control the independent policies separately:

```bash
mac-infra-core sleep-prevention status
mac-infra-core display-sleep-prevention status
mac-infra-core idle-lock-prevention status
```

When the user explicitly requests that the monitor stay on, use:

```bash
mac-infra-core display-sleep-prevention enable
```

This installs a current-user LaunchAgent that keeps one fixed
`/usr/bin/caffeinate -d` assertion alive. It applies on AC and battery while the
user is logged in, does not rewrite `pmset` timers, and does not need the root
daemon. Disable boots out the assertion and removes the LaunchAgent plist:

```bash
mac-infra-core display-sleep-prevention disable
```

When the user explicitly requests prevention of automatic idle Lock Screen,
use the current-user command:

```bash
mac-infra-core idle-lock-prevention enable
mac-infra-core idle-lock-prevention disable
```

The command prevents the automatic screen-saver lock trigger by capturing and
restoring the current host's `com.apple.screensaver idleTime` value. Enable both
display sleep and idle-lock prevention to prevent the two idle triggers that
lead to Lock Screen. Status reports that display sleep remains a separate policy.

Never use `sysadminctl -screenLock off` for this workflow. Manual Lock Screen
and the existing password-after-lock policy must remain intact. Idle-lock
disable refuses to invent an `idleTime` restore value when no saved snapshot
exists.

## Audio Frequency Sweep Workflow

Use this when the user wants a local frequency/hearing/output-chain test without
YouTube or streaming-platform compression.

```bash
mac-audio-sweep device
mac-audio-sweep tui
mac-audio-sweep tui --rerender
mac-audio-sweep generate --out .temp/mac-audio-sweep/manual-sweep.wav
```

`mac-audio-sweep device` prints the current default output device sample rate,
whether the rate is settable, and whether the target rate is supported.

`mac-audio-sweep tui` reuses a cached PCM WAV when the current normalized sweep
parameters already have one under `.temp/mac-audio-sweep/cache/`; otherwise it
renders the WAV. Pass `--rerender` to force overwriting the cached WAV for the
same parameters, or `--no-cache` for a one-shot temporary WAV. Playback uses
`afplay` while a Bubble Tea TUI shows the current frequency, slope, elapsed time,
and sample-rate/Nyquist limits. Press `r` to restart from the beginning. Press
`q`, `esc`, or `ctrl+c` to stop playback and exit.

Defaults:

- `96 kHz`, stereo, 16-bit PCM WAV.
- `1 Hz -> 44 kHz` total sweep.
- `1 Hz -> 50 Hz` slow low ramp over `90s`, starting near `+1 Hz / 5s` and then
  accelerating smoothly.
- Low amplitude default (`0.20`) for safer startup.
- TUI output-rate policy `set`: switch the default output device to the WAV
  sample rate when supported, then restore the previous rate on stop/exit.

Important caveats:

- A true `44 kHz` signal requires sample rate above `88 kHz`; default `96 kHz`
  gives a `48 kHz` Nyquist limit.
- Use `--output-rate strict` to refuse playback unless the default output device
  is already at the WAV sample rate. Use `--output-rate off` only when explicit
  CoreAudio sample-rate management is not wanted.
- `0 Hz` is DC, not an audible tone; use `1 Hz` as the practical "0-ish" start.
- DACs, Bluetooth codecs, headphones, macOS output paths, or hearing protection
  can still resample/filter ultrasonic content. Keep volume low.

## Safari Browser Session Workflow

Use this when the user asks to inspect, click, extract, or download from a page
that is already authenticated in their local Safari profile.

Core rule: use Safari as the authenticated browser and do not export, dump, copy,
log, or persist cookies, browser storage, authorization headers, or tokens. Let
Safari make same-origin/authenticated requests. Persist only page content,
downloaded files, sanitized response metadata, endpoint shapes, and notes.

Safari has no real headless mode with the user's live profile. Prefer background
Apple Events to avoid focus churn:

```bash
mac-safari-session open-bg "https://example.com/private/page"
```

`open-bg` prints the exact `window-id`. Close that agent-owned window when the
workflow finishes:

```bash
mac-safari-session close-window --id 12345
```

### Agent-created browser cleanup

Treat every Safari tab or window opened by the agent as a task-scoped resource.
Track it when it is created and close it as soon as the browser work that needs
it is finished. This is mandatory for separate background windows created by
`open-bg`, `snapshot --url`, or `fetch-file --page`, including minimized
windows. Reuse one agent-owned page during a multi-step workflow instead of
leaving a new window behind after each read or download.

- Cleanup runs on success, failure, cancellation, and handoff; do not postpone
  it until a later conversation turn.
- Close only the exact tab or window created by the agent. Never close a
  pre-existing user tab or window merely because its URL or title matches.
- If the available tooling cannot distinguish agent-owned browser state from
  user-owned state, do not guess. Avoid creating another window, preserve the
  user's browser state, and explicitly report the ambiguous leftover.
- Before ending browser work, account for every page the agent opened and
  confirm that no agent-created Safari windows remain.

`snapshot --url` and `fetch-file --page` pin their JavaScript to the exact
background window they create and close that window automatically on success
or failure. Do not add a second manual close for those commands.

Before DOM extraction or page-context fetch, verify JavaScript-from-Apple-Events
permission:

```bash
mac-safari-session check-js
```

If Safari blocks the command, the user must enable it manually:

```text
Safari -> Settings -> Advanced -> Show features for web developers
Develop -> Allow JavaScript from Apple Events
```

For a page read, capture DOM text and links:

```bash
mac-safari-session snapshot \
  --url "https://example.com/private/page" \
  --json .temp/mac-safari-session/page-snapshot.json
```

For custom DOM extraction, use guarded JavaScript:

```bash
mac-safari-session run-js --script 'document.body.innerText.slice(0, 5000)'
mac-safari-session run-js --file .temp/mac-safari-session/extract.js --out .temp/mac-safari-session/result.txt
```

For multi-step work in an agent-created background window, address the exact
`window-id` printed by `open-bg`. Never target a pre-existing user window with
this option; close the agent-created window when finished:

```bash
mac-safari-session run-js --window-id 12345 --script 'document.title'
mac-safari-session close-window --id 12345
```

`run-js` refuses obvious browser-secret reads such as `document.cookie`,
`cookieStore`, `localStorage`, and `sessionStorage`. Do not bypass this by
writing ad hoc AppleScript for secret extraction. Page status and metadata
redact OAuth-style query values before printing or persistence.

For authenticated downloads where direct `curl` returns `401` or otherwise lacks
the Safari session, fetch inside the page context and pull the response body back
as base64 chunks:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --resource "/api/private/file.pdf" \
  --out documents/raw/file.pdf \
  --meta documents/raw/file.pdf.json
```

Operational notes:

- `fetch-file` uses `fetch(..., { credentials: "include" })` inside Safari.
- The CLI writes output files with `0600` permissions.
- Response headers are sanitized before metadata is written.
- Screenshots are not part of this CLI because they require Screen Recording
  permission for the terminal app.
- Store durable endpoint/selector/limitation notes in the active project's
  research or task flow. Do not leave browser-harvest discoveries only in chat.

## Load Profiling Workflow

- For broad CPU, memory, thermal, pressure, and process evidence, start here:

```bash
mac-load-profile capture
```

- For quick terminal triage without writing a full bundle:

```bash
mac-load-profile snapshot --top 20
```

- To inspect one suspicious process or family:

```bash
mac-load-profile inspect sing-box
mac-load-profile inspect 12345
```

- To gather a CPU sample, use it only when profiling needs stack evidence:

```bash
mac-load-profile inspect sing-box --sample 5
```

- Use specific profilers only after the broad profile points there. For tunnel
  issues:

```bash
mac-load-profile tunnel
```

- For Cisco AnyConnect disconnected-state socket filter leaks:

```bash
mac-load-profile anyconnect
mac-load-profile anyconnect --logs
```

- `mac-load-profile` is read-only. It must not stop, restart, kill, or mutate
  processes.

## Video Smoothness Workflow

- For subtle slideshow-like video/UI animation stutter, especially when Docker
  or VM work is active, start with read-only video/display triage:

```bash
mac-video-profile snapshot --top 20
```

- For a durable bundle with display/GPU topology, WindowServer/process evidence,
  thermal and memory pressure, power assertions, display registry state, and
  optional recent WindowServer/display/GPU/Metal/frame logs:

```bash
mac-video-profile capture --logs
```

- Capture artifacts are written under `.temp/mac-video-profile/capture-*`.
- `mac-video-profile` is read-only. It must not reset WindowServer, kill apps,
  change refresh rate, change display settings, run privileged `powermetrics`,
  or mutate Docker/VM state.
- Use `mac-load-profile capture` after this only when the evidence points to a
  broader CPU, memory, thermal, disk, network, or process-load issue.

## Disk Space Profiling Workflow

- Use this when the user needs to understand where disk space went:

```bash
mac-disk-profile scan "$HOME" --depth 3 --json .temp/mac-disk-profile/home.json
mac-disk-profile top "$HOME" --limit 30
mac-disk-profile explain "$HOME/Library/Developer"
```

- `mac-disk-profile` is read-only. It must not delete, move, or mutate files.
- Prefer `scan` when a persisted JSON artifact is useful for later analysis.
- Use `explain` for one suspicious path after `scan` or `top` identifies it.

## Cleanup Planning Workflow

- Start with read-only planning only:

```bash
mac-cleanup scan --json
mac-cleanup target --json .temp/mac-cleanup/project-plan.json /path/to/project
mac-cleanup xcode --json
mac-cleanup xcode-runtimes --json
```

- If macOS denies access to protected paths or the scan reports permission
  warnings, do not casually grant Full Disk Access to Terminal, iTerm2, Cursor,
  VS Code, or another broad launcher. Every process launched from that app may
  inherit the access. Prefer partial scans until a dedicated narrow mac-infra
  Full Disk Access runner exists.
- Show the guidance instead:

```bash
mac-cleanup permissions
```

- `mac-cleanup permissions --open` intentionally returns `not implemented`
  until a dedicated narrow Full Disk Access runner exists.

- `mac-cleanup xcode-runtimes` detects unsupported CoreSimulator runtimes that
  Xcode can still list even after their devices are gone. It is dry-run by
  default and deletes only with explicit `--delete`.
- Other `mac-cleanup` flows currently plan cleanup candidates only. They do not
  delete or move files.
- Treat cleanup output as review material. Ask the user before any future apply
  flow removes or trashes files.

```bash
mac-cleanup xcode-runtimes
mac-cleanup xcode-runtimes --delete
```

## Audio Crackle Workflow

- Start with read-only diagnostics:

```bash
mac-audio-reset diagnose
```

- If Apple Music restart does not help and the symptom survives across USB DAC
  and Bluetooth output, inspect for CoreAudio/Simulator involvement:

```bash
mac-audio-reset diagnose --logs
mac-audio-reset reset --dry-run
```

- Do not run the reset unless the user explicitly agrees. It shuts down booted
  iOS simulators and restarts CoreAudio through the privileged helper.
- If the user directly asks to clean/reset/fix Mac audio, treat that as explicit
  agreement and run the reset without another confirmation prompt.

```bash
mac-audio-reset reset
```

- One-time privileged helper setup:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core status
```

- Use `mac-infra-core request-permissions sudo` when sudo credentials are
  needed. Do not run ad hoc `sudo` commands from the shell for mac-infra work;
  let the Go CLI own the sudo prompt and permission scope.
- This is separate from Full Disk Access. Do not grant Full Disk Access to
  Terminal, iTerm2, Cursor, VS Code, or another broad launcher.

After installation, `mac-audio-reset reset` should not need interactive `sudo`.

## AnyConnect Socket Filter Cleanup Workflow

- Start with read-only diagnostics:

```bash
mac-load-profile anyconnect
```

- If AnyConnect reports disconnected but `com.cisco.anyconnect.macos.acsockext`
  is still hot or large, inspect the cleanup plan:

```bash
mac-infra-core anyconnect-cleanup
```

- Run cleanup only when the user explicitly asks to kill/clean/reset Cisco
  AnyConnect, or after they approve the dry-run plan:

```bash
mac-infra-core anyconnect-cleanup --apply
```

- The apply path is allowlisted in `mac-infra-core`: it verifies AnyConnect is
  disconnected, terminates the Cisco socket-filter extension process, and
  restarts `com.cisco.anyconnect.vpnagentd` through `launchctl kickstart`.
- Do not use ad hoc `sudo`, broad `killall`, packet capture, traffic blocking,
  or TLS interception for this workflow.

## Operational Notes

- The reset intentionally runs `simctl shutdown all` as the current user before
  calling the root helper. Simulator state is user-scoped.
- The root helper only exposes allowlisted actions; it is not a generic command
  executor.
- If a USB DAC is running at `192000 Hz`, recommend trying `48000 Hz` or
  `96000 Hz` in Audio MIDI Setup when crackle repeats under Apple Music.
- Reboot is the last resort, not the first move.

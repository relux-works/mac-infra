---
name: mac-infra
description: >
  macOS workstation infrastructure tooling for diagnosing and fixing local Mac
  audio crackling, CoreAudio daemon glitches, Simulator audio issues, Apple
  Music distortion, USB DAC output problems, Bluetooth output problems, macOS
  video/display smoothness loss, WindowServer/GPU stutter, Docker/VM slideshow
  symptoms, broad CPU, memory, thermal, and process load, authenticated Safari
  and Google Chrome browser-session inspection/harvesting, privacy-safe document
  intake, PII redaction, and related maintenance tasks.
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
  - caffeinate background activity
  - caffeinate can run in the background
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
  - caffeinate работает в фоне
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
  - Chrome automation
  - Slack browser read
  - Slack sealed read
  - browser heartbeat
  - Chrome heartbeat
  - Safari heartbeat
  - browser automation
  - browser harvest
  - authenticated browser
  - authenticated Safari
  - Safari cookies
  - reuse browser cookies
  - read browser page
  - harvest browser page
  - document sanitizer
  - sanitize document
  - redact PII
  - PII redaction
  - privacy-safe document
  - clean personal data
  - обезличить документ
  - почистить персональные данные
  - убрать персданные
  - персуха в документе
  - анонимизировать документ
  - сафари
  - браузер
  - автоматизация сафари
  - автоматизация хрома
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

macOS may show an App Background Activity notification saying that
`“caffeinate” can run in the background`. Recognize it as this managed
`works.relux.mac-infra-display-sleep-prevention` LaunchAgent, not an unknown
third-party process. Keep the `caffeinate` name; do not rename or disable it
solely because of the notification. Turning it off in Login Items & Extensions
defeats persistent display-sleep prevention. If ownership is uncertain, verify
the LaunchAgent label, `/usr/bin/caffeinate -d` arguments, and
`PreventUserIdleDisplaySleep` assertion before changing anything.

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

For local frequency/hearing/output-chain tests, read
[audio-frequency-sweep.md](references/audio-frequency-sweep.md) before running
the sweep tools. Start with:

```bash
mac-audio-sweep device
mac-audio-sweep tui
```

## Authenticated Browser Session Workflows

Read [Safari](references/safari-session.md) or [Chrome](references/chrome-session.md) before page-context work; those references own the exact `run-js`, output, focus, trusted-input, native upload, download, Slack, permission, and secret-boundary contracts.
Safari is exact-window/current-tab and always requires `--origin`; Chrome is exact-window/exact-tab. Keep either browser in the background unless the user explicitly requests visible handoff. Never export cookies, storage, authorization headers, credentials, or tokens. Start with `mac-safari-session check-js` or `mac-chrome-session list`; the user must manually enable JavaScript from Apple Events.

For a user-authorized Chrome attachment, use `mac-chrome-session upload` with
exact window/tab IDs, mandatory origin, `--human-authorized`, and one bounded
versioned request on private stdin. It admits one visible file input and one to
eight explicit regular files under declared extension/size bounds, requires a
native chooser zero-to-one transition, retains that exact Accessibility sheet
identity through selection and closure, refuses any unreadable or malformed
sheet snapshot instead of retrying it as absence, and checks a bounded declared DOM `accept`
contract plus effective ancestor visibility/hit targeting during preparation,
immediately before native work, and again before success attestation, rejects
non-default ancestor filter or mask effects, and verifies a trusted change plus
exact filename/size/count metadata. Do not
put source paths in argv, use an active-tab fallback, or claim success from the
chooser action alone.

Use `mac-chrome-session heartbeat` or `mac-safari-session heartbeat` for named keepalives in the shared private namespace and stable installed launcher. Every start requires exactly one finite `--ttl` or RFC3339 `--deadline`; `status`/`list` expose deadline and expiry. Migrate legacy deadline-free/content-addressed state with `heartbeat restart --name NAME --ttl DURATION` without focusing either browser.

## Agent-Facing Browser Site Facade

For structured repeated-item reads, cache-scoped search, or guarded site
mutations, read [browser-site-facade.md](references/browser-site-facade.md).
Use `mac-browser-site q|grep|m` with a private task-scoped adapter and retain the
underlying exact-target/origin guard.

## Privacy-Safe Document Intake Workflow

Use this before reading or persisting extracted content when a local or
browser-downloaded document may contain personal data or secrets:

```bash
mac-document-sanitize --json PATH
```

Read only the returned `sanitized_path`. The command keeps raw extracted text in
memory, never changes the source, writes `0600` artifacts, names default outputs
from the source SHA-256 rather than its filename, and reports categories/counts
without storing matched values.

Supported inputs: TXT, Markdown, JSON, XML, YAML, CSV, TSV, HTML, RTF, DOC,
DOCX, PDF, and XLSX. PDF extraction needs `pdftotext` from Homebrew `poppler`.
Export legacy XLS or ODS files as XLSX, CSV, or TSV first.

If automatic heuristics miss a known value, put exact values one-per-line in a
task-scoped `0600` file and rerun:

```bash
mac-document-sanitize --redact-from .temp/mac-document-sanitize/extra.txt PATH
```

Do not claim guaranteed anonymization. Review sanitized output before external
disclosure. Delete only raw files the agent itself created under `.temp/`; never
delete or modify the user's source document.

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

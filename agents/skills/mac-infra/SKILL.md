---
name: mac-infra
description: >
  macOS workstation infrastructure tooling for diagnosing and fixing local Mac
  audio crackling, CoreAudio daemon glitches, Simulator audio issues, Apple
  Music distortion, USB DAC output problems, Bluetooth output problems, and
  broad CPU, memory, thermal, process load, and related maintenance tasks.
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
---

# mac-infra

Use this skill for macOS local maintenance workflows backed by the `mac-infra`
Go tools.

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

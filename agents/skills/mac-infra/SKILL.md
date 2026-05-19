---
name: mac-infra
description: >
  macOS workstation infrastructure tooling for diagnosing and fixing local Mac
  audio crackling, CoreAudio daemon glitches, Simulator audio issues, Apple
  Music distortion, USB DAC output problems, Bluetooth output problems, and
  related maintenance tasks.
triggers:
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
---

# mac-infra

Use this skill for macOS local maintenance workflows backed by the `mac-infra`
Go tools.

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
mac-infra-core install
mac-infra-core status
```

After installation, `mac-audio-reset reset` should not need interactive `sudo`.

## Operational Notes

- The reset intentionally runs `simctl shutdown all` as the current user before
  calling the root helper. Simulator state is user-scoped.
- The root helper only exposes allowlisted actions; it is not a generic command
  executor.
- If a USB DAC is running at `192000 Hz`, recommend trying `48000 Hz` or
  `96000 Hz` in Audio MIDI Setup when crackle repeats under Apple Music.
- Reboot is the last resort, not the first move.

# Video Smoothness Diagnostics

## Problem

macOS can enter a state where video playback, UI animation, and Docker-backed
workloads still run but lose smoothness and start to look discrete or
slideshow-like. Existing mac-infra audio tooling can diagnose CoreAudio symptoms;
the project also needs a read-only video/display diagnostic workflow.

## Requirements

- Provide a user-facing CLI for video/display smoothness triage.
- Keep the workflow read-only: no killing processes, no display setting changes,
  no WindowServer reset, no privileged mutation.
- Capture evidence for likely stutter sources:
  - WindowServer/compositor pressure
  - GPU/display configuration
  - Docker, VM, and virtualization load
  - browser/Electron/video app rendering load
  - media encoder/decoder processes
  - thermal and memory pressure
  - recent bounded display/render logs when explicitly requested
- Write durable capture artifacts under `.temp/` by default.
- Integrate the tool into setup/deinit, README, and the `mac-infra` skill.

## Non-Goals

- Automated fixes for video stutter.
- Screen recording or frame capture.
- Privileged `powermetrics` sampling.
- Resetting WindowServer or restarting user applications.

# Video smoothness diagnostic CLI

## Description
Implement a read-only CLI workflow for diagnosing macOS video/display smoothness loss, where animations and video playback become discrete or slideshow-like even under Docker/VM load.

## Scope
Add focused diagnostics without changing system state. Capture display/GPU/process/thermal/pressure/log evidence and integrate the command into install and docs. Keep the output actionable for deciding whether the likely source is WindowServer, GPU/display config, Docker/virtualization load, thermal pressure, memory pressure, or a specific app/process.

## Acceptance Criteria
1. A command exists for video smoothness diagnostics and is built by setup.sh. 2. The command has a quick summary mode and a durable capture mode. 3. Capture artifacts live under .temp/mac-video-profile or an overridden artifact directory. 4. Optional logs are only collected behind an explicit --logs flag. 5. The implementation is read-only and documented as such.

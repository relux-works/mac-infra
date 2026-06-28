# Mac video smoothness diagnostics

## Description
Add read-only macOS video/display smoothness diagnostics for subtle slideshow/stutter symptoms, including WindowServer, GPU/display, animation, Docker/VM, thermal, pressure, and process evidence. The workflow must fit existing mac-infra CLI, setup, README, and skill patterns without privileged mutation.

## Scope
In scope: a CLI workflow for collecting display/video smoothness evidence; Go planning/model code and tests; setup/deinit/docs/skill integration. Out of scope: fixing GPU drivers, killing processes, resetting WindowServer, changing display settings automatically, packet capture, screen recording, or privileged mutation.

## Acceptance Criteria
1. A user can run a read-only video/display smoothness diagnostic command from the installed mac-infra tools. 2. The command captures actionable evidence for WindowServer, GPU/display configuration, display link symptoms, animation/rendering load, Docker/VM involvement, thermal/pressure state, and recent relevant logs when requested. 3. Diagnostics write durable artifacts under .temp/ and print a concise summary. 4. Existing setup/deinit and README/tool docs mention the new workflow. 5. Unit tests cover the command planning/model behavior and all Go tests pass.

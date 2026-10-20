# STORY-261021-3zqzr9: netnone-gradle-test-runner

## Description
mac-netnone: run a JVM/Gradle test task in a dedicated colima profile with all outbound network denied (--network=none), after a networked PREP that warms a Gradle cache volume. Requested by meta-keeper 2026-10-21 ($L7YzGTK topic netnone-test-runner-261021). Design: .temp/netnone-test-runner-261021/design-01.md (posted $rzCQn_Ja).

## Scope
cmd/mac-netnone, internal/netnone, README tools row and section, agents/skills/mac-infra reference; skill mirror update.

## Acceptance Criteria
1) prep/run/selftest/status/stop commands per the design note. 2) Dedicated profile netnone only; refuses if it was already running; stops on every exit path; one run at a time. 3) No shared Docker/colima state changed (current context, existing contexts, ~/.docker/config.json, ~/.colima/ssh_config, ~/.colima/docker.sock, other profiles) - proven by selftest snapshots. 4) Base image pinned by digest; toolchain Dockerfile must FROM the pinned base; RUN uses the recorded image id. 5) RUN: --network=none, cap-drop ALL, no-new-privileges, non-root, read-only rootfs, repo mounted read-only and copied to a work volume, --offline. 6) Negative control: probe DNS and raw-IP connect succeed in PREP and fail in RUN; fixture JUnit HTTP test green in PREP, red with a network error in RUN while a sibling offline test is green. 7) Host load refusal above --max-load (default CPU count). 8) Unit tests with a fake runner incl. negative cases; a qualification log from a real selftest.

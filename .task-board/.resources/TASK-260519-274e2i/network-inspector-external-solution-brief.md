# External Network Inspector Requirements

Date: 2026-05-19
Epic: EPIC-260519-3glbk7
Task: TASK-260519-274e2i

## Intent

Before mac-infra builds native network inspection, evaluate and choose an
external-first solution for observing local Mac network behavior. The goal is to
understand which local processes connect where, enrich those observations with
process identity, and preserve structured artifacts for later threat and malware
analytics.

This is intentionally separate from the cleanup and disk profiling work.

## What We Want

The external solution should provide passive or low-risk local connection
visibility:

- process name, PID, parent PID, executable path, user, and command line
- remote IP, remote port, local port, protocol, connection state, and timestamps
- DNS context when available: queried hostname, resolved addresses, and cache
  hints
- route and interface context: Wi-Fi, VPN/tunnel, loopback, external interface,
  and default route at capture time
- process identity enrichment: code signing status, team ID, bundle ID,
  notarization hints where available, quarantine xattrs, and LaunchAgent/Daemon
  persistence hints
- structured JSON artifacts under `.temp/mac-net-inspector/`
- CLI output suitable for quick triage and saved artifacts suitable for later
  correlation

## Threat Analytics Inputs

The future analytics layer should be able to correlate network observations with
other mac-infra evidence:

- high CPU or memory from `mac-load-profile`
- suspicious persistence paths
- unsigned or ad-hoc signed binaries
- recently created or modified executables
- unusual parent-child process trees
- rare or unexpected remote destinations
- connections from user-writable app/script locations
- VPN/tunnel routing context

The first useful signal shape is:

`process identity + connection destination + persistence/origin + local load`

## V1 Boundaries

Do not build native MITM or packet inspection in v1.

Out of scope for v1:

- installing a root certificate
- decrypting TLS
- modifying system proxy settings automatically
- Network Extension packet filters
- privileged packet capture
- blocking traffic
- malware verdicts or automatic remediation

The initial solution should observe and explain. It should not mutate traffic or
the system.

## External Solution Evaluation Criteria

Evaluate external tools or approaches against:

- works on current macOS without kernel extensions
- does not require long-lived privileged daemons unless explicitly reviewed
- can export structured data or can be wrapped safely
- can attribute connections to processes reliably
- handles VPN/tunnel context well enough for multi-tun workflows
- has clear privacy boundaries and does not collect payload by default
- can run on demand and write artifacts under `.temp/`
- can be documented in the `mac-infra` skill as an explicit, user-approved
  diagnostic workflow

## Blocker Decision

Native implementation is blocked until an external-solution review answers:

- which external tool or API is the baseline
- whether passive connection snapshots are enough for v1
- which data fields are trustworthy on macOS
- what requires elevated privileges
- what artifact schema downstream analytics will consume
- what privacy and retention rules apply

## Likely Future Stories

- passive connection snapshot
- process identity enrichment
- DNS and route context capture
- network artifact schema
- threat signal rules v1
- optional controlled proxy mode


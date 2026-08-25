# BUG-260825-2qoq0a: chrome-heartbeat-launchagent-never-reaches-ok

## Description
Chrome exact-tab heartbeat LaunchAgent stays unavailable with no outcome or log and can block concurrent Chrome commands

## Scope
Diagnose and fix heartbeat worker startup/runtime behavior without focusing Chrome or exposing authenticated data

## Acceptance Criteria
A freshly installed mac-chrome-session starts a 10m exact-tab Gosuslugi heartbeat that reaches running/ok; focused regression tests cover the root cause; unrelated work remains untouched

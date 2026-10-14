# TASK-261015-2ftdza: root-owned-core-installation

## Description
Fix mac-infra-core root daemon installation at source: reviewed executable in root-owned non-user-writable directory; root-owned launch plist; safe config/socket boundary. Refuse writable/replaced executable/config/ancestors via meaningful negative controls. No live reinstall/restart, sudo, VPN/audio disruption. vpn-core pattern is reported but outside this repo unless source already in scope.

## Scope
(define task scope)

## Acceptance Criteria
Root-owned installation boundary; writable/replacement/ancestor controls; local full tests/vet/build; independent review; signed PR; no live mutation

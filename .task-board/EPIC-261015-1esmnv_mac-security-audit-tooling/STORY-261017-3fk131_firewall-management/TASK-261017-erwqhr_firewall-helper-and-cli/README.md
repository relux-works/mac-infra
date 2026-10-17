# TASK-261017-erwqhr: firewall-helper-and-cli

## Description
Firewall management via the mac-infra-core root helper. Plan accepted by meta-keeper 2026-10-17: .temp/firewall-261017/plan.md (posted in #mac-infra-lobby topic firewall-tool-261017).

## Scope
internal/security/firewall (config, parse, plan, validate), maccore daemon actions firewall-status/plan/apply + keep-on enforcement + root audit log, service disable allowlist (apache), cmd/mac-firewall CLI, install prints binary sha256 before sudo, README/skill/docs

## Acceptance Criteria
1) dry-run by default, apply validates everything first and readback-verifies; 2) compensating rollback on mid-apply failure, readback equals pre-state; 3) no off action, loosening only for codesign-verified apps; 4) unknown action/field/service refused; 5) idempotent second apply; 6) install prints sha256 before sudo; 7) go test/vet/build green

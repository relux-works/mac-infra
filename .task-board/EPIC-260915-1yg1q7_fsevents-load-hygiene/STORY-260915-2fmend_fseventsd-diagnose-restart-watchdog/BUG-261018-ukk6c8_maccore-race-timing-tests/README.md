# BUG-261018-ukk6c8: maccore-race-timing-tests

## Description
Under go test -race, TestRestartFSEventsSlowInspectionRespectsRespawnBudget (8.05s vs budget) and TestInstallServiceWaitsForRemovalBeforeBootstrap (removal verification exceeded 1s) fail deterministically on main fe74a59 at load ~3 since 2026-10-18; both pass without -race. They passed under -race on 2026-10-17. Changed since: the application firewall was turned on (14:07 local). Hypothesis, unverified: per-exec firewall evaluation of new unsigned race binaries adds latency. Evidence: .temp/listener-parse-261018/race-main-01.log and race-isolated-01.log in the mac-infra checkout.

## Scope
(define bug scope / affected area)

## Acceptance Criteria
(define fix acceptance criteria)

## Status
done

## Review
required

## Task Class
code

## Estimate
estimated(fibonacci(1))

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Root cause (2026-10-18): not the firewall. The Go race runtime sleeps atexit_sleep_ms=1000 before exit; a trivial -race binary takes 1.0s, 0.01s with GORACE=atexit_sleep_ms=0. Both tests re-exec the race test binary as fake commands, so each helper costs +1s and overruns their budgets. Fix: helper envs carry GORACE=atexit_sleep_ms=0 (test-only). Race lane on maccore green after the fix; red before (race-main-01.log). Why it passed on 2026-10-17 is unexplained.

## Precondition Resources
(none)

## Outcome Resources
(none)

## Created
2026-10-18T11:18:01Z

## Last Update
2026-10-18T12:50:54Z

## Assigned To
m1max_mac-infra_keeper

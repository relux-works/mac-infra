## Status
done

## Review
required

## Task Class
code

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Executed inline by the primary session that produced the 2026-09-14 diagnosis (casual-talks/.research + .temp/fsevents sample evidence); no child spawn because the slice is single-repo and all evidence is already in session context. Worktree: .temp/STORY-260915-2fmend/worktree
Implementation complete in worktree .temp/STORY-260915-2fmend/worktree (branch story/fsevents-load-hygiene). Validation: go vet ./..., go build ./..., go test -count=1 ./... all green (2026-09-15). Live smoke: mac-load-profile fsevents ran against the real machine; fseventsd-restart refused at 12MB below 4GB threshold; forced call against the installed pre-change daemon returned unsupported action as expected (daemon must be reinstalled). Awaiting owner confirmation for signed commit (version_control.confirm=true).
Landed: PR https://github.com/relux-works/mac-infra/pull/3 merged at exact head ba25f54 (fast-forward push, self-review comment as verdict, no CI configured). setup.sh run; mac-infra-core install pending owner sudo.

## Precondition Resources
(none)

## Outcome Resources
(none)

## Created
2026-09-15T08:01:21Z

## Last Update
2026-09-15T09:21:29Z

## Assigned To
claude-opus-5

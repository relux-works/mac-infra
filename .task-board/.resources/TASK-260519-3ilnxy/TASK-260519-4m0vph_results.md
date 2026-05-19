# TASK-260519-4m0vph Results

## Code

- Added `internal/cleanup/policy.go`.
- Added `internal/cleanup/policy_test.go`.
- Added a logbook entry in `LOGBOOK.md`.

## Safe Default-Selected Categories

- `xcode-derived-data`: Xcode build/index/intermediate data under `~/Library/Developer/Xcode/DerivedData`.
- `target-generated-data`: allowlisted generated directories inside an explicit target root: `.temp`, `.build`, `build`, `dist`, `.dart_tool`, `node_modules/.cache`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `coverage`, `DerivedData`.
- `rotated-user-logs`: old rotated/compressed logs under `~/Library/Logs`, with a 14-day minimum age.

All default-selected categories are `safe_generated`.

## Review-Only Categories

- `downloads`: user-saved data.
- `large-files`: size does not imply disposable data.
- `old-files`: age does not imply disposable data.
- `app-caches`: app-specific state and cache semantics.
- `ios-device-backups`: recovery copies of user data.
- `xcode-archives`: release/dSYM/reproducibility artifacts.
- `xcode-device-support`: debugging/symbolication support.
- `xcode-simulators`: runtimes, apps, and test data.

All review-only categories are not default-selected.

## Out Of Scope V1

- Malware scanning.
- RAM cleaning.
- Forced purgeable-space cleanup.
- App uninstall leftovers.
- Browser privacy cleanup.
- Mail/browser/chat attachment cleanup.
- Language stripping.
- Binary thinning.
- Automatic duplicate deletion.

## Safety Policy

- Dangerous roots refused: `/`, `$HOME`, `/Users`, `/System`, `/Library`, `/Applications`, `/bin`, `/sbin`, `/usr`, `/private`, `/var`, `/Volumes`.
- System-root descendants are refused for `/System`, `/Library`, `/Applications`, `/bin`, `/sbin`, `/usr`, `/private`, and `/var`.
- External volume roots `/Volumes` and `/Volumes/<name>` are refused.
- External volume child paths under `/Volumes/<name>/...` are allowed only as explicit targets and still require ownership, symlink, and realpath containment checks.
- Symlink roots and symlink candidates are refused.
- Roots and candidates must be owned by the current user.
- Candidate real paths must remain contained within the configured root real path.

## Verification

- `go test ./... -count=1` with local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-4m0vph/go-test-04.log`.
- `go vet ./...` with local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-4m0vph/go-vet-03.log`.
- `go build ./cmd/...` with local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-4m0vph/go-build-03.log`.
- `git diff --check`: passed. Log: `.temp/TASK-260519-4m0vph/git-diff-check-02.log`.

Note: a first raw `go test ./...` attempted to write Go cache data under `~/Library/Caches/go-build` and failed under the sandbox. The passing commands above use task-local writable caches.

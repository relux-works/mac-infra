# TASK-260519-3vfq4z Results

## Summary

- Added `internal/diskprofile` with versioned scan model, traversal, size accounting, explain notes, and restrictive JSON artifact writer.
- Added `cmd/mac-disk-profile` with `scan`, `top`, `explain`, and `version` commands.
- Documented the model contract in package docs: `ScanOptions`, `Entry`, `ScanResult`, `ScanError`, symlink/depth/exclude/permission/one-file-system traversal, APFS caveats, hard-link de-dupe, and artifact permissions.

## Verification

- Baseline: `go test ./...` initially failed because `/Users/alexis/Library/Caches/go-build` was not accessible.
- Passing test run: `GOCACHE=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-build GOPATH=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-path go test ./...`
- Vet: `GOCACHE=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-build GOPATH=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-path go vet ./...`
- Build: `GOCACHE=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-build GOPATH=/Users/alexis/src/mac-infra/.temp/TASK-260519-3vfq4z/go-path go build ./...`

## Logs

- `.temp/TASK-260519-3vfq4z/go-test-01.log` - first cache-permission failure.
- `.temp/TASK-260519-3vfq4z/go-test-02.log` - passing tests.
- `.temp/TASK-260519-3vfq4z/go-vet-01.log` - passing vet.
- `.temp/TASK-260519-3vfq4z/go-build-01.log` - passing build with module-cache warning from the host environment.
- `.temp/TASK-260519-3vfq4z/go-test-03.log` - passing tests with task-local `GOCACHE` and `GOPATH`.
- `.temp/TASK-260519-3vfq4z/go-vet-02.log` - clean vet with task-local `GOCACHE` and `GOPATH`.
- `.temp/TASK-260519-3vfq4z/go-build-02.log` - clean build with task-local `GOCACHE` and `GOPATH`.

Implemented window-targeted guarded JavaScript for agent-created Safari windows, OAuth query-value redaction for status/snapshot/fetch metadata, tests, and README/skill guidance. Validation: `go test ./...` and `./scripts/setup.sh` both passed; installed CLI exposes `--window-id`.

Commits: `9a401ca` (exact-window targeting), `0ea274d` (URL redaction), and `e9e1100` (documentation and installed workflow guidance).

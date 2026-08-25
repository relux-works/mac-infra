# Reproduction

Observed on 2026-08-25 during a read-only authenticated court audit.

Command: `mac-chrome-session run-js --window-id ID --tab-id ID --origin https://mos-sud.ru --file SCRIPT --out RESULT`

Installed CLI result: exit 2, `flag provided but not defined: -out`. No page payload was dispatched. `run-js --help` exposes `--file` but not `--out`.

The sibling `mac-safari-session run-js` supports both `--file` and `--out` and writes through its artifact helper. Chrome workflows therefore require a shell redirect under `umask 077`, splitting the cross-browser privacy-safe capture contract.

Additional drift found in the dirty source checkout: the current `cmd/mac-chrome-session/main.go` accepts only `--script`, while the installed CLI and Chrome skill reference expose `--file`. Implementation must reconcile source, tests, installed artifact, README, and skill docs rather than patching only one surface.

The safe fallback succeeded with exact window/tab/origin guards and a task-scoped `0600` redirect; this bug did not block the user workflow.
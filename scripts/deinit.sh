#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
SKILL_NAME="mac-infra"
BROWSER_STATE_DIR="$HOME/Library/Application Support/mac-infra/browser-session"
BROWSER_LABEL_PREFIX="works.relux.mac-infra-browser-heartbeat."

usage() {
  cat <<EOF
Usage: ./scripts/deinit.sh

Removes user-level mac-infra binary symlinks and global skill copies.
Managed browser heartbeats are stopped before their executable is removed.
The current-user display-sleep-prevention and fseventsd-watchdog LaunchAgents are disabled when possible.
Run 'mac-infra-core uninstall' separately if the privileged daemon is installed.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

shopt -s nullglob
heartbeat_plists=("$HOME/Library/LaunchAgents/${BROWSER_LABEL_PREFIX}"*.plist)
heartbeat_states=("$BROWSER_STATE_DIR"/*.json)
pinned_binaries=("$BROWSER_STATE_DIR"/bin/mac-browser-session-*)
if (( ${#heartbeat_plists[@]} + ${#heartbeat_states[@]} > 0 )); then
  if [[ ! -x "$BIN_DIR/mac-chrome-session" ]]; then
    echo "ERROR: managed browser heartbeat artifacts exist but $BIN_DIR/mac-chrome-session is unavailable; refusing to strand LaunchAgents" >&2
    exit 1
  fi
  for plist in "${heartbeat_plists[@]}"; do
    label="$(basename "$plist" .plist)"
    name="${label#${BROWSER_LABEL_PREFIX}}"
    "$BIN_DIR/mac-chrome-session" heartbeat stop --name "$name"
  done
  "$BIN_DIR/mac-chrome-session" heartbeat stop --all
  heartbeat_plists=("$HOME/Library/LaunchAgents/${BROWSER_LABEL_PREFIX}"*.plist)
  heartbeat_states=("$BROWSER_STATE_DIR"/*.json)
  pinned_binaries=("$BROWSER_STATE_DIR"/bin/mac-browser-session-*)
  if (( ${#heartbeat_plists[@]} + ${#heartbeat_states[@]} + ${#pinned_binaries[@]} > 0 )); then
    echo "ERROR: managed browser heartbeat cleanup left artifacts; refusing to remove the CLI" >&2
    exit 1
  fi
fi
rm -rf -- "$BROWSER_STATE_DIR"

if [[ -x "$BIN_DIR/mac-infra-core" ]]; then
  "$BIN_DIR/mac-infra-core" idle-lock-prevention disable || {
    echo "WARNING: could not disable idle-lock-prevention before removing the CLI" >&2
  }
  "$BIN_DIR/mac-infra-core" display-sleep-prevention disable || {
    echo "WARNING: could not disable display-sleep-prevention before removing the CLI" >&2
  }
  "$BIN_DIR/mac-infra-core" fseventsd-watchdog disable || {
    echo "WARNING: could not disable fseventsd-watchdog before removing the CLI" >&2
  }
fi

rm -f "$BIN_DIR/mac-audio-reset" "$BIN_DIR/mac-audio-sweep" "$BIN_DIR/mac-load-profile" "$BIN_DIR/mac-video-profile" "$BIN_DIR/mac-disk-profile" "$BIN_DIR/mac-cleanup" "$BIN_DIR/mac-infra-core" "$BIN_DIR/mac-safari-session" "$BIN_DIR/mac-chrome-session" "$BIN_DIR/mac-browser-site" "$BIN_DIR/mac-document-sanitize"
rm -f "$HOME/.codex/skills/$SKILL_NAME" "$HOME/.claude/skills/$SKILL_NAME"
rm -rf "$HOME/.agents/skills/$SKILL_NAME"

echo "Removed mac-infra user-level installation, managed browser heartbeats, and managed idle policies."
echo "Privileged daemon, if installed, is left alone. Remove it with:"
echo "  mac-infra-core uninstall"

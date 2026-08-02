#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
SKILL_NAME="mac-infra"

usage() {
  cat <<EOF
Usage: ./scripts/deinit.sh

Removes user-level mac-infra binary symlinks and global skill copies.
The current-user display-sleep-prevention LaunchAgent is disabled when possible.
Run 'mac-infra-core uninstall' separately if the privileged daemon is installed.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ -x "$BIN_DIR/mac-infra-core" ]]; then
  "$BIN_DIR/mac-infra-core" idle-lock-prevention disable || {
    echo "WARNING: could not disable idle-lock-prevention before removing the CLI" >&2
  }
  "$BIN_DIR/mac-infra-core" display-sleep-prevention disable || {
    echo "WARNING: could not disable display-sleep-prevention before removing the CLI" >&2
  }
fi

rm -f "$BIN_DIR/mac-audio-reset" "$BIN_DIR/mac-audio-sweep" "$BIN_DIR/mac-load-profile" "$BIN_DIR/mac-video-profile" "$BIN_DIR/mac-disk-profile" "$BIN_DIR/mac-cleanup" "$BIN_DIR/mac-infra-core" "$BIN_DIR/mac-safari-session" "$BIN_DIR/mac-document-sanitize"
rm -f "$HOME/.codex/skills/$SKILL_NAME" "$HOME/.claude/skills/$SKILL_NAME"
rm -rf "$HOME/.agents/skills/$SKILL_NAME"

echo "Removed mac-infra user-level installation and managed idle policies."
echo "Privileged daemon, if installed, is left alone. Remove it with:"
echo "  mac-infra-core uninstall"

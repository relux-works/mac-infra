#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
SKILL_NAME="mac-infra"

usage() {
  cat <<EOF
Usage: ./scripts/deinit.sh

Removes user-level mac-infra binary symlinks and global skill copies.
Run 'mac-infra-core uninstall' separately if the privileged daemon is installed.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

rm -f "$BIN_DIR/mac-audio-reset" "$BIN_DIR/mac-load-profile" "$BIN_DIR/mac-video-profile" "$BIN_DIR/mac-disk-profile" "$BIN_DIR/mac-cleanup" "$BIN_DIR/mac-infra-core" "$BIN_DIR/mac-safari-session"
rm -f "$HOME/.codex/skills/$SKILL_NAME" "$HOME/.claude/skills/$SKILL_NAME"
rm -rf "$HOME/.agents/skills/$SKILL_NAME"

echo "Removed mac-infra user-level installation."
echo "Privileged daemon, if installed, is left alone. Remove it with:"
echo "  mac-infra-core uninstall"

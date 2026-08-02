#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
BUILD_DIR="$PROJECT_ROOT/bin"
SKILL_NAME="mac-infra"
SKILL_SOURCE="$PROJECT_ROOT/agents/skills/$SKILL_NAME"
SKILL_RUNTIME="$HOME/.agents/skills/$SKILL_NAME"
BUILD_VERSION="dev"
BUILD_COMMIT="unknown"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

usage() {
  cat <<EOF
Usage: ./scripts/setup.sh [--bin-dir PATH]

Builds mac-infra Go tools and installs the global agent skill.
The privileged LaunchDaemon is not installed or restarted automatically.
After first setup and after mac-infra-core updates, run:
  mac-infra-core install
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      BIN_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v go >/dev/null 2>&1; then
  echo "go is required" >&2
  exit 1
fi

if git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  BUILD_VERSION="$(git -C "$PROJECT_ROOT" describe --tags --always 2>/dev/null || echo dev)"
  BUILD_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi
LDFLAGS="-X main.Version=$BUILD_VERSION -X main.Commit=$BUILD_COMMIT -X main.BuildDate=$BUILD_DATE"

echo "=== mac-infra setup ==="
echo "Testing Go packages..."
go -C "$PROJECT_ROOT" test ./...

mkdir -p "$BUILD_DIR" "$BIN_DIR"
echo "Building mac-audio-reset..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-audio-reset" ./cmd/mac-audio-reset
echo "Building mac-audio-sweep..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-audio-sweep" ./cmd/mac-audio-sweep
echo "Building mac-load-profile..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-load-profile" ./cmd/mac-load-profile
echo "Building mac-video-profile..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-video-profile" ./cmd/mac-video-profile
echo "Building mac-disk-profile..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-disk-profile" ./cmd/mac-disk-profile
echo "Building mac-cleanup..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-cleanup" ./cmd/mac-cleanup
echo "Building mac-safari-session..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-safari-session" ./cmd/mac-safari-session
echo "Building mac-infra-core..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-infra-core" ./cmd/mac-infra-core

ln -sf "$BUILD_DIR/mac-audio-reset" "$BIN_DIR/mac-audio-reset"
ln -sf "$BUILD_DIR/mac-audio-sweep" "$BIN_DIR/mac-audio-sweep"
ln -sf "$BUILD_DIR/mac-load-profile" "$BIN_DIR/mac-load-profile"
ln -sf "$BUILD_DIR/mac-video-profile" "$BIN_DIR/mac-video-profile"
ln -sf "$BUILD_DIR/mac-disk-profile" "$BIN_DIR/mac-disk-profile"
ln -sf "$BUILD_DIR/mac-cleanup" "$BIN_DIR/mac-cleanup"
ln -sf "$BUILD_DIR/mac-safari-session" "$BIN_DIR/mac-safari-session"
ln -sf "$BUILD_DIR/mac-infra-core" "$BIN_DIR/mac-infra-core"
echo "Installed binary symlinks:"
echo "  $BIN_DIR/mac-audio-reset -> $BUILD_DIR/mac-audio-reset"
echo "  $BIN_DIR/mac-audio-sweep -> $BUILD_DIR/mac-audio-sweep"
echo "  $BIN_DIR/mac-load-profile -> $BUILD_DIR/mac-load-profile"
echo "  $BIN_DIR/mac-video-profile -> $BUILD_DIR/mac-video-profile"
echo "  $BIN_DIR/mac-disk-profile -> $BUILD_DIR/mac-disk-profile"
echo "  $BIN_DIR/mac-cleanup     -> $BUILD_DIR/mac-cleanup"
echo "  $BIN_DIR/mac-safari-session -> $BUILD_DIR/mac-safari-session"
echo "  $BIN_DIR/mac-infra-core  -> $BUILD_DIR/mac-infra-core"

if [[ ! -d "$SKILL_SOURCE" ]]; then
  echo "missing skill source: $SKILL_SOURCE" >&2
  exit 1
fi

mkdir -p "$HOME/.agents/skills" "$HOME/.codex/skills" "$HOME/.claude/skills"
rm -rf "$SKILL_RUNTIME"
mkdir -p "$SKILL_RUNTIME"
cp -R "$SKILL_SOURCE/." "$SKILL_RUNTIME/"
find "$SKILL_RUNTIME" \( -name .git -o -name .gitignore -o -name .gitattributes -o -name .gitmodules \) -prune -exec rm -rf {} +
ln -sfn "$SKILL_RUNTIME" "$HOME/.codex/skills/$SKILL_NAME"
ln -sfn "$SKILL_RUNTIME" "$HOME/.claude/skills/$SKILL_NAME"
echo "Installed skill:"
echo "  $SKILL_RUNTIME"
echo "  $HOME/.codex/skills/$SKILL_NAME -> $SKILL_RUNTIME"
echo "  $HOME/.claude/skills/$SKILL_NAME -> $SKILL_RUNTIME"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "WARNING: $BIN_DIR is not in PATH"
fi

echo
echo "Next privileged setup/reinstall (required after mac-infra-core updates):"
echo "  mac-infra-core install"
echo
echo "Inspect system-wide sleep prevention without mutation:"
echo "  mac-infra-core sleep-prevention status"
echo
echo "Inspect separate display and idle-lock prevention policies:"
echo "  mac-infra-core display-sleep-prevention status"
echo "  mac-infra-core idle-lock-prevention status"
echo
echo "Then reset audio without sudo:"
echo "  mac-audio-reset reset"

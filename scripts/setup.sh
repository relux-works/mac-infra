#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
BUILD_DIR="$PROJECT_ROOT/bin"
HEARTBEAT_LAUNCHER_DIR="$HOME/Library/Application Support/mac-infra/browser-session/bin"
HEARTBEAT_LAUNCHER="$HEARTBEAT_LAUNCHER_DIR/mac-browser-heartbeat-launcher"
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
if [[ ! -x /usr/bin/codesign ]]; then
  echo "/usr/bin/codesign is required for the managed browser heartbeat" >&2
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
echo "Signing mac-safari-session for an actionable Automation identity..."
SAFARI_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.safari-session"'
/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.safari-session --requirements "=$SAFARI_DESIGNATED_REQUIREMENT" "$BUILD_DIR/mac-safari-session"
/usr/bin/codesign --verify --strict "$BUILD_DIR/mac-safari-session"
SAFARI_OBSERVED_REQUIREMENT=$(/usr/bin/codesign -d -r- "$BUILD_DIR/mac-safari-session" 2>&1)
if [[ "$SAFARI_OBSERVED_REQUIREMENT" != *"$SAFARI_DESIGNATED_REQUIREMENT"* ]]; then
  echo "mac-safari-session signing did not produce the stable designated requirement" >&2
  exit 1
fi
echo "Building mac-chrome-session..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-chrome-session" ./cmd/mac-chrome-session
echo "Signing mac-chrome-session for an actionable Automation identity..."
CHROME_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.browser-session"'
/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.browser-session --requirements "=$CHROME_DESIGNATED_REQUIREMENT" "$BUILD_DIR/mac-chrome-session"
/usr/bin/codesign --verify --strict "$BUILD_DIR/mac-chrome-session"
CHROME_OBSERVED_REQUIREMENT=$(/usr/bin/codesign -d -r- "$BUILD_DIR/mac-chrome-session" 2>&1)
if [[ "$CHROME_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]; then
  echo "mac-chrome-session signing did not produce the stable designated requirement" >&2
  exit 1
fi
echo "Installing stable Chrome/Safari heartbeat launcher identity..."
mkdir -p "$HEARTBEAT_LAUNCHER_DIR"
chmod 700 "$HEARTBEAT_LAUNCHER_DIR"
HEARTBEAT_LAUNCHER_TMP="$(mktemp "$HEARTBEAT_LAUNCHER_DIR/.mac-browser-heartbeat-launcher.XXXXXX")"
cp "$BUILD_DIR/mac-chrome-session" "$HEARTBEAT_LAUNCHER_TMP"
chmod 700 "$HEARTBEAT_LAUNCHER_TMP"
mv -f "$HEARTBEAT_LAUNCHER_TMP" "$HEARTBEAT_LAUNCHER"
/usr/bin/codesign --verify --strict "$HEARTBEAT_LAUNCHER"
HEARTBEAT_OBSERVED_REQUIREMENT=$(/usr/bin/codesign -d -r- "$HEARTBEAT_LAUNCHER" 2>&1)
if [[ "$HEARTBEAT_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]; then
  echo "stable heartbeat launcher lost its designated requirement" >&2
  exit 1
fi
echo "Building mac-browser-site..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-browser-site" ./cmd/mac-browser-site
echo "Building mac-document-sanitize..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-document-sanitize" ./cmd/mac-document-sanitize
echo "Building mac-infra-core..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-infra-core" ./cmd/mac-infra-core
echo "Building mac-keyvault..."
go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/mac-keyvault" ./cmd/mac-keyvault

ln -sf "$BUILD_DIR/mac-audio-reset" "$BIN_DIR/mac-audio-reset"
ln -sf "$BUILD_DIR/mac-audio-sweep" "$BIN_DIR/mac-audio-sweep"
ln -sf "$BUILD_DIR/mac-load-profile" "$BIN_DIR/mac-load-profile"
ln -sf "$BUILD_DIR/mac-video-profile" "$BIN_DIR/mac-video-profile"
ln -sf "$BUILD_DIR/mac-disk-profile" "$BIN_DIR/mac-disk-profile"
ln -sf "$BUILD_DIR/mac-cleanup" "$BIN_DIR/mac-cleanup"
ln -sf "$BUILD_DIR/mac-safari-session" "$BIN_DIR/mac-safari-session"
ln -sf "$BUILD_DIR/mac-chrome-session" "$BIN_DIR/mac-chrome-session"
ln -sf "$BUILD_DIR/mac-browser-site" "$BIN_DIR/mac-browser-site"
ln -sf "$BUILD_DIR/mac-document-sanitize" "$BIN_DIR/mac-document-sanitize"
ln -sf "$BUILD_DIR/mac-infra-core" "$BIN_DIR/mac-infra-core"
ln -sf "$BUILD_DIR/mac-keyvault" "$BIN_DIR/mac-keyvault"
echo "Installed binary symlinks:"
echo "  $BIN_DIR/mac-audio-reset -> $BUILD_DIR/mac-audio-reset"
echo "  $BIN_DIR/mac-audio-sweep -> $BUILD_DIR/mac-audio-sweep"
echo "  $BIN_DIR/mac-load-profile -> $BUILD_DIR/mac-load-profile"
echo "  $BIN_DIR/mac-video-profile -> $BUILD_DIR/mac-video-profile"
echo "  $BIN_DIR/mac-disk-profile -> $BUILD_DIR/mac-disk-profile"
echo "  $BIN_DIR/mac-cleanup     -> $BUILD_DIR/mac-cleanup"
echo "  $BIN_DIR/mac-safari-session -> $BUILD_DIR/mac-safari-session"
echo "  $BIN_DIR/mac-chrome-session -> $BUILD_DIR/mac-chrome-session"
echo "  heartbeat launcher: $HEARTBEAT_LAUNCHER"
echo "  $BIN_DIR/mac-browser-site -> $BUILD_DIR/mac-browser-site"
echo "  $BIN_DIR/mac-document-sanitize -> $BUILD_DIR/mac-document-sanitize"
echo "  $BIN_DIR/mac-infra-core  -> $BUILD_DIR/mac-infra-core"
echo "  $BIN_DIR/mac-keyvault    -> $BUILD_DIR/mac-keyvault"

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

if ! command -v pdftotext >/dev/null 2>&1; then
  echo "WARNING: PDF sanitization requires pdftotext (install with: brew install poppler)"
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

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
BUILD_DIR="$PROJECT_ROOT/bin"
HEARTBEAT_LAUNCHER_DIR="$HOME/Library/Application Support/mac-infra/browser-session/bin"
HEARTBEAT_LAUNCHER="$HEARTBEAT_LAUNCHER_DIR/mac-browser-heartbeat-launcher"
BUILD_VERSION="dev"
BUILD_COMMIT="unknown"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REBUILD_KEYVAULT=0
ALLOW_UNPROVABLE=0
ONLY=0
SELECTED_BINARIES=()

usage() {
  cat <<EOF
Usage: ./scripts/setup.sh [--bin-dir PATH] [--only NAME[,NAME...]] [--rebuild-keyvault] [--allow-unprovable]

Builds and links mac-infra Go tools. --only selects tools and tests only
those commands and their in-module dependencies; otherwise all packages
are tested and all tools are installed. --only mac-keyvault requires
--rebuild-keyvault. Agent skills are distributed through Curator profiles:
https://github.com/relux-works/skill-mac-infra
Refuses worktree, dirty or unprovable builds. --allow-unprovable skips
provenance checks for a developer's own checkout, with a WARNING.
An existing bin/mac-keyvault is kept: keyvault keys trust exactly that
binary, and a rebuild makes each key wait on a keychain prompt. Pass
--rebuild-keyvault only in a planned owner sitting, after booting out
every keyvault agent; it refuses while a process uses the binary or a
keyvault LaunchAgent is loaded.
The privileged LaunchDaemon is not installed or restarted automatically.
After first setup and after mac-infra-core updates, run:
  mac-infra-core install
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      if [[ $# -lt 2 || -z "$2" || "$2" == ,* || "$2" == *, || "$2" == *,,* || "$2" == *$'\n'* ]]; then
        echo "--only requires NAME[,NAME...]" >&2
        usage >&2
        exit 2
      fi
      ONLY=1
      IFS=, read -r -a names <<< "$2"
      SELECTED_BINARIES+=("${names[@]}")
      shift 2
      ;;
    --bin-dir)
      if [[ $# -lt 2 || -z "$2" ]]; then
        usage >&2
        exit 2
      fi
      BIN_DIR="$2"
      shift 2
      ;;
    --rebuild-keyvault)
      REBUILD_KEYVAULT=1
      shift
      ;;
    --allow-unprovable)
      ALLOW_UNPROVABLE=1
      shift
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

ALL_BINARIES=(
  "mac-audio-reset"
  "mac-audio-sweep"
  "mac-load-profile"
  "mac-video-profile"
  "mac-disk-profile"
  "mac-cleanup"
  "mac-safari-session"
  "mac-chrome-session"
  "mac-browser-site"
  "mac-document-sanitize"
  "mac-infra-core"
  "mac-security"
  "mac-netnone"
  "mac-firewall"
  "mac-keyvault"
)
selected() {
  local name
  if [[ "$ONLY" == 0 ]]; then
    return 0
  fi
  for name in ${SELECTED_BINARIES[@]+"${SELECTED_BINARIES[@]}"}; do
    if [[ "$name" == "$1" ]]; then
      return 0
    fi
  done
  return 1
}
for name in ${SELECTED_BINARIES[@]+"${SELECTED_BINARIES[@]}"}; do
  known=0
  for candidate in "${ALL_BINARIES[@]}"; do
    if [[ "$name" == "$candidate" ]]; then
      known=1
      break
    fi
  done
  if [[ "$known" == 0 ]]; then
    echo "unknown --only name: $name" >&2
    usage >&2
    exit 2
  fi
done
if [[ "$ONLY" == 1 && "$REBUILD_KEYVAULT" != 1 ]] && selected mac-keyvault; then
  echo "--only mac-keyvault requires --rebuild-keyvault (planned owner sitting only)" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go is required" >&2
  exit 1
fi

warn_unprovable() {
  echo "WARNING: --allow-unprovable: installed binaries are not provably built from a reviewed commit." >&2
}
if [[ "$ALLOW_UNPROVABLE" == 1 ]]; then
  warn_unprovable
else
  "$SCRIPT_DIR/provenance-guard.sh" preflight "$PROJECT_ROOT"
fi

# Linking the build directory onto itself would replace every binary with a
# symlink to itself.
mkdir -p "$BIN_DIR"
if [[ -e "$BUILD_DIR" && "$BIN_DIR" -ef "$BUILD_DIR" ]]; then
  echo "--bin-dir must not be the build directory $BUILD_DIR" >&2
  exit 1
fi

# Decided before any build, so a refusal changes nothing; checked again right
# before mac-keyvault is built. Two setup.sh runs at once are not coordinated.
KEYVAULT_DECISION=skip
if selected mac-keyvault; then
  KEYVAULT_DECISION="$("$SCRIPT_DIR/keyvault-build-guard.sh" "$BUILD_DIR/mac-keyvault" "$REBUILD_KEYVAULT")"
fi
# Repointing an installed mac-keyvault at this checkout replaces the binary its
# users run, so the binary it points at now must pass the same guard.
keyvault_link_guard() {
  local link="$BIN_DIR/mac-keyvault"
  if selected mac-keyvault && [[ "$REBUILD_KEYVAULT" == 1 && -e "$link" && ! "$link" -ef "$BUILD_DIR/mac-keyvault" ]]; then
    "$SCRIPT_DIR/keyvault-build-guard.sh" "$(cd "$(dirname "$link")" && pwd -P)/$(basename "$link")" 1 >/dev/null
  fi
}
keyvault_link_guard
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
# Release builds must not select dependencies through an ambient go.work.
export GOWORK=off
if [[ "$ONLY" == 1 ]]; then
  COMMAND_PACKAGES=()
  for name in "${ALL_BINARIES[@]}"; do
    if selected "$name"; then
      COMMAND_PACKAGES+=("./cmd/$name")
    fi
  done
  # go list deduplicates the dependency graph; exclude stdlib and other modules.
  DEPENDENCIES="$(go -C "$PROJECT_ROOT" list -deps -f '{{if .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}' "${COMMAND_PACKAGES[@]}")"
  TEST_PACKAGES=()
  while IFS= read -r package; do
    if [[ -n "$package" ]]; then
      TEST_PACKAGES+=("$package")
    fi
  done <<< "$DEPENDENCIES"
  go -C "$PROJECT_ROOT" test "${TEST_PACKAGES[@]}"
else
  go -C "$PROJECT_ROOT" test ./...
fi
if [[ "$ALLOW_UNPROVABLE" != 1 ]]; then
  "$SCRIPT_DIR/provenance-guard.sh" preflight "$PROJECT_ROOT"
fi

mkdir -p "$BUILD_DIR" "$BIN_DIR"
STAGE_DIR="$(mktemp -d "$BUILD_DIR/.staging.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if selected mac-audio-reset; then
  echo "Building mac-audio-reset..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-audio-reset" ./cmd/mac-audio-reset
fi
if selected mac-audio-sweep; then
  echo "Building mac-audio-sweep..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-audio-sweep" ./cmd/mac-audio-sweep
fi
if selected mac-load-profile; then
  echo "Building mac-load-profile..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-load-profile" ./cmd/mac-load-profile
fi
if selected mac-video-profile; then
  echo "Building mac-video-profile..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-video-profile" ./cmd/mac-video-profile
fi
if selected mac-disk-profile; then
  echo "Building mac-disk-profile..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-disk-profile" ./cmd/mac-disk-profile
fi
if selected mac-cleanup; then
  echo "Building mac-cleanup..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-cleanup" ./cmd/mac-cleanup
fi
if selected mac-safari-session; then
  echo "Building mac-safari-session..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-safari-session" ./cmd/mac-safari-session
  echo "Signing mac-safari-session for an actionable Automation identity..."
  SAFARI_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.safari-session"'
  /usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.safari-session --requirements "=$SAFARI_DESIGNATED_REQUIREMENT" "$STAGE_DIR/mac-safari-session"
  /usr/bin/codesign --verify --strict "$STAGE_DIR/mac-safari-session"
  SAFARI_OBSERVED_REQUIREMENT=$(/usr/bin/codesign -d -r- "$STAGE_DIR/mac-safari-session" 2>&1)
  if [[ "$SAFARI_OBSERVED_REQUIREMENT" != *"$SAFARI_DESIGNATED_REQUIREMENT"* ]]; then
    echo "mac-safari-session signing did not produce the stable designated requirement" >&2
    exit 1
  fi
fi
if selected mac-chrome-session; then
  echo "Building mac-chrome-session..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-chrome-session" ./cmd/mac-chrome-session
  echo "Signing mac-chrome-session for an actionable Automation identity..."
  CHROME_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.browser-session"'
  /usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.browser-session --requirements "=$CHROME_DESIGNATED_REQUIREMENT" "$STAGE_DIR/mac-chrome-session"
  /usr/bin/codesign --verify --strict "$STAGE_DIR/mac-chrome-session"
  CHROME_OBSERVED_REQUIREMENT=$(/usr/bin/codesign -d -r- "$STAGE_DIR/mac-chrome-session" 2>&1)
  if [[ "$CHROME_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]; then
    echo "mac-chrome-session signing did not produce the stable designated requirement" >&2
    exit 1
  fi
fi
if selected mac-browser-site; then
  echo "Building mac-browser-site..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-browser-site" ./cmd/mac-browser-site
fi
if selected mac-document-sanitize; then
  echo "Building mac-document-sanitize..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-document-sanitize" ./cmd/mac-document-sanitize
fi
if selected mac-infra-core; then
  echo "Building mac-infra-core..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-infra-core" ./cmd/mac-infra-core
fi
if selected mac-security; then
  echo "Building mac-security..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-security" ./cmd/mac-security
fi
if selected mac-netnone; then
  echo "Building mac-netnone..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-netnone" ./cmd/mac-netnone
fi
if selected mac-firewall; then
  echo "Building mac-firewall..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-firewall" ./cmd/mac-firewall
fi
if [[ "$KEYVAULT_DECISION" == build ]]; then
  KEYVAULT_DECISION="$("$SCRIPT_DIR/keyvault-build-guard.sh" "$BUILD_DIR/mac-keyvault" "$REBUILD_KEYVAULT")"
fi
if [[ "$KEYVAULT_DECISION" == build ]]; then
  echo "Building mac-keyvault..."
  go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-keyvault" ./cmd/mac-keyvault
  # The Secure Enclave helper sits next to mac-keyvault, which runs it by that
  # path only. Its blobs are bound to this Mac, not to the helper binary, so
  # rebuilding it never strands a key.
  if command -v swiftc >/dev/null 2>&1; then
    echo "Building mac-keyvault-enclave..."
    swiftc -O -o "$STAGE_DIR/mac-keyvault-enclave" "$PROJECT_ROOT/cmd/mac-keyvault-enclave/main.swift"
  else
    echo "swiftc not found: mac-keyvault-enclave not built; --enclave keys are refused as unsupported_primitive" >&2
  fi
elif [[ "$KEYVAULT_DECISION" == keep ]]; then
  echo "Keeping the existing bin/mac-keyvault (keyvault keys trust exactly this binary; see --rebuild-keyvault)"
fi
BUILT_BINARIES=(
  "mac-audio-reset"
  "mac-audio-sweep"
  "mac-load-profile"
  "mac-video-profile"
  "mac-disk-profile"
  "mac-cleanup"
  "mac-safari-session"
  "mac-chrome-session"
  "mac-browser-site"
  "mac-document-sanitize"
  "mac-infra-core"
  "mac-security"
  "mac-netnone"
  "mac-firewall"
)
SELECTED_BUILDS=()
for name in "${BUILT_BINARIES[@]}"; do
  if selected "$name"; then
    SELECTED_BUILDS+=("$name")
  fi
done
BUILT_BINARIES=(${SELECTED_BUILDS[@]+"${SELECTED_BUILDS[@]}"})
if [[ "$KEYVAULT_DECISION" == build ]]; then
  BUILT_BINARIES+=("mac-keyvault")
fi
if [[ "$ALLOW_UNPROVABLE" == 1 ]]; then
  "$SCRIPT_DIR/provenance-guard.sh" publish "$PROJECT_ROOT" "$STAGE_DIR" "$BUILD_DIR" --allow-unprovable "${BUILT_BINARIES[@]}"
else
  "$SCRIPT_DIR/provenance-guard.sh" preflight "$PROJECT_ROOT"
  "$SCRIPT_DIR/provenance-guard.sh" publish "$PROJECT_ROOT" "$STAGE_DIR" "$BUILD_DIR" "${BUILT_BINARIES[@]}"
fi
# The Swift helper has no Go buildinfo; install it only after Go publication.
if [[ -f "$STAGE_DIR/mac-keyvault-enclave" ]]; then
  if [[ -d "$BUILD_DIR/mac-keyvault-enclave" ]]; then
    echo "mac-keyvault-enclave destination is a directory" >&2
    exit 3
  fi
  mv -f "$STAGE_DIR/mac-keyvault-enclave" "$BUILD_DIR/mac-keyvault-enclave"
fi

if selected mac-chrome-session; then
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
fi

if selected mac-audio-reset; then
  ln -sf "$BUILD_DIR/mac-audio-reset" "$BIN_DIR/mac-audio-reset"
fi
if selected mac-audio-sweep; then
  ln -sf "$BUILD_DIR/mac-audio-sweep" "$BIN_DIR/mac-audio-sweep"
fi
if selected mac-load-profile; then
  ln -sf "$BUILD_DIR/mac-load-profile" "$BIN_DIR/mac-load-profile"
fi
if selected mac-video-profile; then
  ln -sf "$BUILD_DIR/mac-video-profile" "$BIN_DIR/mac-video-profile"
fi
if selected mac-disk-profile; then
  ln -sf "$BUILD_DIR/mac-disk-profile" "$BIN_DIR/mac-disk-profile"
fi
if selected mac-cleanup; then
  ln -sf "$BUILD_DIR/mac-cleanup" "$BIN_DIR/mac-cleanup"
fi
if selected mac-safari-session; then
  ln -sf "$BUILD_DIR/mac-safari-session" "$BIN_DIR/mac-safari-session"
fi
if selected mac-chrome-session; then
  ln -sf "$BUILD_DIR/mac-chrome-session" "$BIN_DIR/mac-chrome-session"
fi
if selected mac-browser-site; then
  ln -sf "$BUILD_DIR/mac-browser-site" "$BIN_DIR/mac-browser-site"
fi
if selected mac-document-sanitize; then
  ln -sf "$BUILD_DIR/mac-document-sanitize" "$BIN_DIR/mac-document-sanitize"
fi
if selected mac-infra-core; then
  ln -sf "$BUILD_DIR/mac-infra-core" "$BIN_DIR/mac-infra-core"
fi
if selected mac-security; then
  ln -sf "$BUILD_DIR/mac-security" "$BIN_DIR/mac-security"
fi
if selected mac-netnone; then
  ln -sf "$BUILD_DIR/mac-netnone" "$BIN_DIR/mac-netnone"
fi
if selected mac-firewall; then
  ln -sf "$BUILD_DIR/mac-firewall" "$BIN_DIR/mac-firewall"
fi
# An installed mac-keyvault that points at another checkout's binary is kept
# unless a rebuild was requested: its keys trust that binary.
if selected mac-keyvault; then
  KEYVAULT_LINK="$BIN_DIR/mac-keyvault"
  if [[ "$REBUILD_KEYVAULT" == 1 || ! -e "$KEYVAULT_LINK" || "$KEYVAULT_LINK" -ef "$BUILD_DIR/mac-keyvault" ]]; then
    keyvault_link_guard
    ln -sf "$BUILD_DIR/mac-keyvault" "$KEYVAULT_LINK"
  else
    echo "Keeping $KEYVAULT_LINK -> $(readlink "$KEYVAULT_LINK" || echo "a regular file") (see --rebuild-keyvault)"
  fi
fi
echo "Installed binary symlinks:"
if selected mac-audio-reset; then
  echo "  $BIN_DIR/mac-audio-reset -> $BUILD_DIR/mac-audio-reset"
fi
if selected mac-audio-sweep; then
  echo "  $BIN_DIR/mac-audio-sweep -> $BUILD_DIR/mac-audio-sweep"
fi
if selected mac-load-profile; then
  echo "  $BIN_DIR/mac-load-profile -> $BUILD_DIR/mac-load-profile"
fi
if selected mac-video-profile; then
  echo "  $BIN_DIR/mac-video-profile -> $BUILD_DIR/mac-video-profile"
fi
if selected mac-disk-profile; then
  echo "  $BIN_DIR/mac-disk-profile -> $BUILD_DIR/mac-disk-profile"
fi
if selected mac-cleanup; then
  echo "  $BIN_DIR/mac-cleanup     -> $BUILD_DIR/mac-cleanup"
fi
if selected mac-safari-session; then
  echo "  $BIN_DIR/mac-safari-session -> $BUILD_DIR/mac-safari-session"
fi
if selected mac-chrome-session; then
  echo "  $BIN_DIR/mac-chrome-session -> $BUILD_DIR/mac-chrome-session"
fi
if selected mac-chrome-session; then
  echo "  heartbeat launcher: $HEARTBEAT_LAUNCHER"
fi
if selected mac-browser-site; then
  echo "  $BIN_DIR/mac-browser-site -> $BUILD_DIR/mac-browser-site"
fi
if selected mac-document-sanitize; then
  echo "  $BIN_DIR/mac-document-sanitize -> $BUILD_DIR/mac-document-sanitize"
fi
if selected mac-infra-core; then
  echo "  $BIN_DIR/mac-infra-core  -> $BUILD_DIR/mac-infra-core"
fi
if selected mac-security; then
  echo "  $BIN_DIR/mac-security -> $BUILD_DIR/mac-security"
fi
if selected mac-netnone; then
  echo "  $BIN_DIR/mac-netnone -> $BUILD_DIR/mac-netnone"
fi
if selected mac-firewall; then
  echo "  $BIN_DIR/mac-firewall -> $BUILD_DIR/mac-firewall"
fi
if selected mac-keyvault; then
  echo "  $BIN_DIR/mac-keyvault    -> $BUILD_DIR/mac-keyvault"
fi

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

if [[ "$ALLOW_UNPROVABLE" == 1 ]]; then
  warn_unprovable
fi

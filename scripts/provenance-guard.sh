#!/usr/bin/env bash
# Offline admission, structured Go buildinfo checks and staged publication.
# Refusal exits 3; malformed arguments exit 2.
set -euo pipefail

usage() {
  echo 'usage: provenance-guard.sh preflight ROOT | verify ROOT BINARY... | publish ROOT STAGE_DIR DEST_DIR [--allow-unprovable] NAME...' >&2
  exit 2
}
[[ $# -ge 2 ]] || usage
command="$1"
project_root="$2"
shift 2
case "$command" in
  preflight) [[ $# -eq 0 ]] || usage ;;
  verify) [[ $# -gt 0 ]] || usage ;;
  publish) [[ $# -ge 3 ]] || usage ;;
  *) usage ;;
esac

# Refuse before any Git lookup, including diagnostic lookups or bypassed publish.
for variable in GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE; do
  if [[ -n "${!variable:-}" ]]; then
    echo 'refusing release build: git environment override' >&2
    exit 3
  fi
  # Git treats some empty overrides as paths; empty means absent here.
  unset "$variable"
done

refuse_preflight() {
  local origin sha
  origin="$(git -C "$project_root" remote get-url origin 2>/dev/null || echo '<origin>')"
  sha="$(git -C "$project_root" rev-parse HEAD 2>/dev/null || echo '<sha>')"
  printf 'refusing release build: %s\n' "$1" >&2
  printf 'build from a standalone clone: git clone %s DIR && git -C DIR checkout --detach %s\n' "$origin" "$sha" >&2
  exit 3
}

if [[ "$command" == preflight ]]; then
  project_root="$(cd "$project_root" 2>/dev/null && pwd -P)" || refuse_preflight "not repository top"
  toplevel="$(git -C "$project_root" rev-parse --show-toplevel 2>/dev/null)" || refuse_preflight "not repository top"
  toplevel="$(cd "$toplevel" 2>/dev/null && pwd -P)" || refuse_preflight "not repository top"
  if [[ "$toplevel" != "$project_root" ]]; then
    refuse_preflight "not repository top"
  fi
  if [[ ! -d "$project_root/.git" ]]; then
    refuse_preflight "worktree (.git is not a directory)"
  fi
  git_dir="$(git -C "$project_root" rev-parse --absolute-git-dir 2>/dev/null)" || refuse_preflight "not checkout git directory"
  git_dir="$(cd "$git_dir" 2>/dev/null && pwd -P)" || refuse_preflight "not checkout git directory"
  checkout_git_dir="$(cd "$project_root/.git" && pwd -P)"
  if [[ "$git_dir" != "$checkout_git_dir" ]]; then
    refuse_preflight "not checkout git directory"
  fi
  porcelain="$(git -C "$project_root" -c status.showUntrackedFiles=all status --porcelain=v1 --untracked-files=all --ignore-submodules=none 2>/dev/null)" || refuse_preflight "dirty tree (cannot read status)"
  if [[ -n "$porcelain" ]]; then
    refuse_preflight "dirty tree"
  fi
  exit 0
fi

verify_files() {
  local expected_revision binary info readable failed=0
  if ! expected_revision="$(git -C "$project_root" rev-parse HEAD 2>/dev/null)"; then
    echo "refusing release build: cannot read source HEAD for $project_root" >&2
    return 3
  fi
  for binary in "$@"; do
    readable=1
    info=''
    # A directory makes go version recurse; a symlink is not a staged file.
    if [[ ! -f "$binary" || -L "$binary" ]]; then
      readable=0
    elif ! info="$(GOTOOLCHAIN=local go version -m -json "$binary" 2>/dev/null)"; then
      readable=0
    fi
    # json.loads admits exactly one JSON document, never filename header lines.
    # Isolated Python ignores user imports and PYTHON* environment overrides.
    if ! printf '%s' "$info" | python3 -I -c '
import json, sys
binary, expected, readable = sys.argv[1:]
revisions, modified = [], []
try:
    info = json.load(sys.stdin)
    if not isinstance(info, dict) or not isinstance(info.get("Settings"), list):
        raise ValueError("not one buildinfo object")
    for setting in info["Settings"]:
        if not isinstance(setting, dict) or not isinstance(setting.get("Key"), str) or not isinstance(setting.get("Value", ""), str):
            raise ValueError("invalid setting")
        if setting["Key"] == "vcs.revision":
            revisions.append(setting.get("Value", ""))
        if setting["Key"] == "vcs.modified":
            modified.append(setting.get("Value", ""))
except (ValueError, TypeError):
    readable = "0"
if readable == "1" and revisions == [expected] and modified == ["false"]:
    sys.exit(0)
print("refusing %s: vcs.revision=[%s] (count %s; expected %s); vcs.modified=[%s] (count %s; expected false); go version -m readable=%s" %
      (binary, ", ".join(revisions) or "missing", len(revisions), expected,
       ", ".join(modified) or "missing", len(modified), readable), file=sys.stderr)
sys.exit(3)
' "$binary" "$expected_revision" "$readable"; then
      failed=3
    fi
  done
  return "$failed"
}

if [[ "$command" == verify ]]; then
  verify_files "$@"
  exit $?
fi

stage_dir="$1"
dest_dir="$2"
shift 2
allow_unprovable=0
if [[ "${1:-}" == --allow-unprovable ]]; then
  allow_unprovable=1
  shift
fi
[[ $# -gt 0 ]] || usage
binaries=()
for name in "$@"; do
  if [[ "$name" == */* || "$name" == . || "$name" == .. || -z "$name" ]]; then
    usage
  fi
  if [[ ! -f "$stage_dir/$name" || -L "$stage_dir/$name" || -d "$dest_dir/$name" ]]; then
    printf 'refusing publish: not a regular staged file or destination is a directory: %s\n' "$name" >&2
    exit 3
  fi
  binaries+=("$stage_dir/$name")
done
# mv must rename on one filesystem, rather than fall back to copy-and-delete.
if ! python3 -I -c 'import os, sys; sys.exit(0 if all(os.path.isdir(p) for p in sys.argv[1:]) and os.stat(sys.argv[1]).st_dev == os.stat(sys.argv[2]).st_dev else 3)' "$stage_dir" "$dest_dir"; then
  echo 'refusing publish: staging and destination must be directories on the same filesystem' >&2
  exit 3
fi
# Complete the entire verification pass before replacing even the first file.
if [[ "$allow_unprovable" != 1 ]]; then
  verify_files "${binaries[@]}" || exit 3
fi
for name in "$@"; do
  mv -f "$stage_dir/$name" "$dest_dir/$name"
done

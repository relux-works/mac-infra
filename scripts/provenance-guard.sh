#!/usr/bin/env bash
# Offline admission and Go buildinfo checks for setup.sh. Refusal exits 3;
# malformed arguments exit 2. Ignored build artifacts do not dirty the tree.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: provenance-guard.sh preflight PROJECT_ROOT | verify PROJECT_ROOT BINARY..." >&2
  exit 2
fi
command="$1"
project_root="$2"
shift 2
if [[ ( "$command" == preflight && $# -ne 0 ) || ( "$command" == verify && $# -eq 0 ) || ( "$command" != preflight && "$command" != verify ) ]]; then
  echo "usage: provenance-guard.sh preflight PROJECT_ROOT | verify PROJECT_ROOT BINARY..." >&2
  exit 2
fi

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
  porcelain="$(git -C "$project_root" status --porcelain 2>/dev/null)" || refuse_preflight "dirty tree (cannot read status)"
  if [[ -n "$porcelain" ]]; then
    refuse_preflight "dirty tree"
  fi
  exit 0
fi

if ! expected_revision="$(git -C "$project_root" rev-parse HEAD 2>/dev/null)"; then
  echo "refusing release build: cannot read source HEAD for $project_root" >&2
  exit 3
fi
failed=0
for binary in "$@"; do
  revision_count=0
  modified_count=0
  revisions=""
  modified=""
  readable=1
  # Inspect with the installed toolchain; never download one for this check.
  if ! info="$(GOTOOLCHAIN=local go version -m "$binary" 2>&1)"; then
    readable=0
  fi
  while IFS= read -r line; do
    case "$line" in
      $'\tbuild\tvcs.revision='*)
        revision_count=$((revision_count + 1))
        revisions="${revisions:+$revisions, }${line#*=}"
        ;;
      $'\tbuild\tvcs.modified='*)
        modified_count=$((modified_count + 1))
        modified="${modified:+$modified, }${line#*=}"
        ;;
    esac
  done <<<"$info"
  if [[ "$readable" != 1 || "$revision_count" != 1 || "$revisions" != "$expected_revision" || "$modified_count" != 1 || "$modified" != false ]]; then
    printf 'refusing %s: vcs.revision=[%s] (count %s; expected %s); vcs.modified=[%s] (count %s; expected false); go version -m readable=%s\n' \
      "$binary" "${revisions:-missing}" "$revision_count" "$expected_revision" "${modified:-missing}" "$modified_count" "$readable" >&2
    failed=3
  fi
done
exit "$failed"

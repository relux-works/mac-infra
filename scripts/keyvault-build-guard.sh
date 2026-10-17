#!/usr/bin/env bash
# Decides whether setup.sh may (re)build mac-keyvault.
#
# A keyvault key in the login keychain trusts exactly the binary that created
# it (its cdhash). After a rebuild, the next private-key use of every key
# waits on a macOS keychain prompt, so an unattended signing agent stops
# until the owner answers it. An existing binary is therefore kept unless a
# rebuild is requested explicitly, and a requested rebuild is refused while
# anything still uses the binary. Inspection errors refuse too.
#
# usage: keyvault-build-guard.sh BINARY REBUILD
#   REBUILD is 1 (requested) or 0.
# Prints "build" or "keep" and exits 0; refuses with exit 1; usage exit 2.
# KEYVAULT_GUARD_LSOF, _PS and _LAUNCHCTL replace the tools in tests only.
set -euo pipefail

if [[ $# -ne 2 || ( "$2" != 0 && "$2" != 1 ) ]]; then
  echo "usage: keyvault-build-guard.sh BINARY 0|1" >&2
  exit 2
fi
binary="$1"
rebuild="$2"
lsof_tool="${KEYVAULT_GUARD_LSOF:-/usr/sbin/lsof}"
ps_tool="${KEYVAULT_GUARD_PS:-/bin/ps}"
launchctl_tool="${KEYVAULT_GUARD_LAUNCHCTL:-/bin/launchctl}"

refuse() {
  echo "refusing to rebuild $binary: $1" >&2
  exit 1
}

if [[ ! -e "$binary" && ! -L "$binary" ]]; then
  echo build
  exit 0
fi
if [[ "$rebuild" != 1 ]]; then
  echo keep
  exit 0
fi

# 1. Processes that have this file open, including as their executable,
#    whichever path or symlink started them. lsof exits 1 with no output and
#    no diagnostics when nothing has it open; anything else refuses.
lsof_err="$(mktemp)"
trap 'rm -f "$lsof_err"' EXIT
set +e
pids="$("$lsof_tool" -t -- "$binary" 2>"$lsof_err")"
lsof_status=$?
set -e
if [[ -n "$pids" ]]; then
  refuse "a running process uses it (pid ${pids//$'\n'/, }); boot out its keyvault agents first"
fi
if [[ $lsof_status -ne 1 || -s "$lsof_err" ]]; then
  refuse "cannot tell whether a process uses it (lsof exit $lsof_status)"
fi

# 2. Any running mac-keyvault program, by the name it was started with: a
#    process whose file was replaced since (lsof then sees a different file)
#    still names this path or an alias of it, such as ~/.local/bin.
if ! listing="$("$ps_tool" -axo args= 2>/dev/null)"; then
  refuse "cannot list processes"
fi
while IFS= read -r args; do
  program="${args%% *}"
  if [[ "$args" == "$binary" || "$args" == "$binary "* || "${program##*/}" == mac-keyvault ]]; then
    refuse "a mac-keyvault process is running; boot out its keyvault agents first"
  fi
done <<<"$listing"

# 3. Loaded keyvault LaunchAgents, running or not: they start this binary
#    again on their own.
if ! jobs="$("$launchctl_tool" list 2>/dev/null)"; then
  refuse "cannot list LaunchAgents"
fi
if grep -q 'works\.relux\.mac-keyvault\.' <<<"$jobs"; then
  refuse "a works.relux.mac-keyvault.* LaunchAgent is loaded; boot it out first"
fi
echo build

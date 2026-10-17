#!/usr/bin/env bash
# Decides whether setup.sh may (re)build mac-keyvault.
#
# A keyvault key in the login keychain trusts exactly the binary that created
# it (its cdhash). After a rebuild, the next private-key use of every key
# waits on a macOS keychain prompt, so an unattended signing agent stops
# until the owner answers it. An existing binary is therefore kept unless a
# rebuild is requested explicitly, and never replaced while a process runs it.
#
# usage: keyvault-build-guard.sh BINARY REBUILD
#   REBUILD is 1 (requested) or 0.
# Prints "build" or "keep" and exits 0; refuses with exit 1; usage exit 2.
set -euo pipefail

if [[ $# -ne 2 || ( "$2" != 0 && "$2" != 1 ) ]]; then
  echo "usage: keyvault-build-guard.sh BINARY 0|1" >&2
  exit 2
fi
binary="$1"
rebuild="$2"

if [[ ! -e "$binary" ]]; then
  echo build
  exit 0
fi
if [[ "$rebuild" != 1 ]]; then
  echo keep
  exit 0
fi
# lsof reports every process that has the file open, including as its
# executable, whichever path or symlink started it.
if /usr/sbin/lsof -t -- "$binary" >/dev/null 2>&1; then
  echo "refusing to rebuild $binary: a running process uses it; boot out its keyvault agents first" >&2
  exit 1
fi
echo build

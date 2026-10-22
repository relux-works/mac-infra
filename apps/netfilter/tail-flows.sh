#!/usr/bin/env bash
# Append each netfilter flow event (JSON object) from the unified log to OUT.jsonl.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $(basename "$0") OUT.jsonl" >&2
  exit 2
fi
out="$1"

/usr/bin/log stream --style ndjson --level info \
  --predicate 'subsystem == "works.relux.mac-infra.netfilter" AND category == "flow"' \
| python3 -I -u -c '
import json, sys
out = open(sys.argv[1], "a", buffering=1)
for line in sys.stdin:
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if not isinstance(rec, dict):
        continue
    msg = rec.get("eventMessage")
    if not isinstance(msg, str) or not msg:
        continue
    out.write(msg.replace("\n", " ") + "\n")
    out.flush()
' "$out"

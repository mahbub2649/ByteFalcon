#!/bin/bash
# Start diskscan. Builds it first if needed.
#   ./run.sh                     open the glassy window (pick a folder or disk to scan)
#   ./run.sh --cli ~ --smart     terminal report with cleanup suggestions
#   ./run.sh --cli / --dupes 50  find duplicate files of 50 MB or more
cd "$(dirname "$(readlink -f "$0")")"
[ -x ./diskscan ] && [ -z "$(find src ui -newer diskscan -print -quit 2>/dev/null)" ] || make -j"$(nproc)" >/dev/null || exit 1
exec ./diskscan "$@"

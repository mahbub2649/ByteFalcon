#!/bin/bash
# Start bytefalcon. Builds it first if needed.
#   ./run.sh                     open the glassy window (pick a folder or disk to scan)
#   ./run.sh --cli ~ --smart     terminal report with cleanup suggestions
#   ./run.sh --cli / --dupes 50  find duplicate files of 50 MB or more
cd "$(dirname "$(readlink -f "$0")")"
[ -x ./bytefalcon ] && [ -z "$(find src ui -newer bytefalcon -print -quit 2>/dev/null)" ] || make -j"$(nproc)" >/dev/null || exit 1
exec ./bytefalcon "$@"

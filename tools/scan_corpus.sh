#!/bin/bash
# Scan a directory of Noir packages with the static pass. Compilation only: no
# inputs and no execution are needed, which is what lets it cover corpora that
# ship no Prover.toml at all.
SP="$1"; DIR="$2"; WORK="$3"; ADAPTER="$4"; NARGO="$5"
mkdir -p "$WORK"; quiet=0; hits=0; skipped=0
for p in "$DIR"/*/; do
  name=$(basename "$p"); [ -f "$p/Nargo.toml" ] || continue
  t="$WORK/$name"; rm -rf "$t"; cp -r "$p" "$t"
  out=$(cd "$t" && timeout 200 "$NARGO" compile --force --silence-warnings -Z enums 2>&1)
  if [ $? -ne 0 ]; then skipped=$((skipped+1)); continue; fi
  flagged=$(echo "$out" | grep -cE '^bug:')
  art=$(ls "$t"/target/*.json 2>/dev/null | head -1)
  [ -z "$art" ] && { skipped=$((skipped+1)); continue; }
  n=$(timeout 200 "$ADAPTER" unpinned "$art" 2>/dev/null | tail -1 | grep -oE '^[0-9]+')
  [ -z "$n" ] && n=0
  if [ "$n" = "0" ]; then quiet=$((quiet+1)); else hits=$((hits+1)); echo "  HIT $name: $n candidate(s), compiler bug lines: $flagged"; fi
done
echo "== $(basename $DIR): $quiet quiet, $hits with candidates, $skipped skipped"

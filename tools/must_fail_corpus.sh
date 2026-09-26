#!/bin/bash
# Every program here is expected to be rejected. Run each at three optimization
# settings: one that accepts where the others refuse has been miscompiled, and a
# program that is accepted at *every* setting means the corpus expectation and
# the compiler disagree. Either is worth seeing.
SP="$1"; DIR="$2"; WORK="$3"; NARGO="$4"
mkdir -p "$WORK"; rejected=0; accepted=0; split=0; skipped=0
for p in "$DIR"/*/; do
  name=$(basename "$p"); [ -f "$p/Nargo.toml" ] || continue
  [ -f "$p/Prover.toml" ] || { skipped=$((skipped+1)); continue; }
  t="$WORK/$name"; rm -rf "$t"; cp -r "$p" "$t"
  outs=""
  for lvl in -9223372036854775808 0 9223372036854775807; do
    if (cd "$t" && timeout 200 "$NARGO" execute --force --silence-warnings -Z enums \
          --inliner-aggressiveness "$lvl" >/dev/null 2>&1); then outs="${outs}A"; else outs="${outs}R"; fi
  done
  case "$outs" in
    RRR) rejected=$((rejected+1)) ;;
    AAA) accepted=$((accepted+1)); echo "  ACCEPTED EVERYWHERE $name" ;;
    *)   split=$((split+1));       echo "  *** SPLIT $name -> $outs" ;;
  esac
done
echo "== $(basename $DIR): $rejected rejected, $accepted accepted, $split split, $skipped skipped"

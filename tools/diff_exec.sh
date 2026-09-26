#!/bin/bash
# Differential execution: the same program and inputs must produce the same
# output at every optimization setting. A divergence is a miscompilation —
# not a heuristic complaint, but two compilations of one program disagreeing.
#
# This is a different question from Noir's own fuzzer, which compares the ACIR
# and Brillig pipelines against each other at one setting.
SP="$1"; DIR="$2"; WORK="$3"; NARGO="$4"
mkdir -p "$WORK"; same=0; diff=0; skip=0
for p in "$DIR"/*/; do
  name=$(basename "$p"); [ -f "$p/Nargo.toml" ] || continue
  [ -f "$p/Prover.toml" ] || { skip=$((skip+1)); continue; }
  t="$WORK/$name"; rm -rf "$t"; cp -r "$p" "$t"
  outs=""
  for lvl in -9223372036854775808 0 9223372036854775807; do
    o=$(cd "$t" && timeout 200 "$NARGO" execute --force --silence-warnings -Z enums \
          --inliner-aggressiveness "$lvl" 2>&1 | grep -E "Circuit output|Failed|error" | head -1)
    outs="$outs|$o"
  done
  a=$(echo "$outs" | cut -d'|' -f2); b=$(echo "$outs" | cut -d'|' -f3); c=$(echo "$outs" | cut -d'|' -f4)
  if [ -z "$a$b$c" ]; then skip=$((skip+1)); continue; fi
  if [ "$a" = "$b" ] && [ "$b" = "$c" ]; then same=$((same+1)); else
    diff=$((diff+1)); echo "  DIVERGENCE $name"; echo "    min: $a"; echo "    zero: $b"; echo "    max: $c"
  fi
done
echo "== $(basename $DIR): $same agree, $diff diverge, $skip skipped"

#!/bin/bash
# Run a package's own Noir tests at three optimization settings. These suites
# encode what the authors believe their code does, so a test that passes at one
# setting and fails at another is the compiler disagreeing with itself about a
# property someone wrote down deliberately.
SP="$1"; DIR="$2"; WORK="$3"; NARGO="$4"
mkdir -p "$WORK"; same=0; split=0; skipped=0
for p in "$DIR"/*/; do
  name=$(basename "$p"); [ -f "$p/Nargo.toml" ] || continue
  t="$WORK/$name"; rm -rf "$t"; cp -r "$p" "$t"
  outs=""
  for lvl in -9223372036854775808 0 9223372036854775807; do
    if (cd "$t" && timeout 300 "$NARGO" test --silence-warnings -Z enums \
          --inliner-aggressiveness "$lvl" >/dev/null 2>&1); then outs="${outs}P"; else outs="${outs}F"; fi
  done
  case "$outs" in
    PPP|FFF) same=$((same+1)) ;;
    *) split=$((split+1)); echo "  *** SPLIT $name -> $outs" ;;
  esac
done
echo "== $(basename $DIR): $same consistent, $split split"

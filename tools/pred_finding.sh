#!/usr/bin/env bash
# Predicate: program is "still interesting" for delta debugging.
set -euo pipefail

NARGO="/home/said/.nargo/bin/nargo"
ADAPTER="/home/said/noir-picus-adapter/target/release/noir-picus-adapter"
VF="/tmp/claude-1000/-home-said/2a6a48a6-cee3-4623-bac6-765c0631d66f/scratchpad/vf"

# 1. Must compile with no diagnostic
OUTPUT=$(cd "$VF" && "$NARGO" compile --force -Z enums --silence-warnings 2>&1) || {
    echo "compile failed" >&2
    exit 1
}
if echo "$OUTPUT" | grep -q "^bug:"; then
    echo "self-flagged" >&2
    exit 2
fi

# 2. Must also be silent with both limits raised
OUTPUT=$(cd "$VF" && "$NARGO" compile --force -Z enums --silence-warnings \
    --brillig-constraints-check-max-array-output-length 4096 \
    --brillig-constraints-check-max-ancestor-distance 500 2>&1) || {
    echo "compile-with-limits failed" >&2
    exit 1
}
if echo "$OUTPUT" | grep -q "^bug:"; then
    echo "self-flagged-when-limits-raised" >&2
    exit 2
fi

# 3. Must execute honestly
(cd "$VF" && timeout 30 "$NARGO" execute --force -Z enums --silence-warnings 2>/dev/null) || {
    echo "execute failed" >&2
    exit 1
}

# 4. Search must find a second witness
ARTIFACT=$(ls "$VF/target"/*.json 2>/dev/null | head -1)
WITNESS=$(ls "$VF/target"/*.gz 2>/dev/null | head -1)
[ -n "$ARTIFACT" ] || { echo "no artifact" >&2; exit 1; }
[ -n "$WITNESS" ] || { echo "no witness" >&2; exit 1; }

RESULT=$(timeout 60 "$ADAPTER" mutate "$ARTIFACT" --witness "$WITNESS" --attempts 4 2>&1) || true
# Match only positive findings: "N finding(s)" where N > 0
if echo "$RESULT" | grep -Eq "^mutation search: [0-9]+ attempt\(s\), [1-9][0-9]* finding\(s\)"; then
    exit 0  # interesting
fi
echo "no finding" >&2
exit 1
#!/usr/bin/env bash
set -euo pipefail
NARGO="/home/said/.nargo/bin/nargo"
ADAPTER="/home/said/noir-picus-adapter/target/release/noir-picus-adapter"
PKG="$1"

cd "$PKG"
cd /tmp/variants

# Must compile silently
OUT=$(cd "$PKG" && $NARGO compile --force -Z enums --silence-warnings 2>&1)
if echo "$OUT" | grep -q "^bug:"; then exit 2; fi

# Must execute honestly
cd "$PKG" && timeout 10 $NARGO execute --force -Z enums --silence-warnings 2>/dev/null

# Adapter must find something
ARTIFACT=$(ls "$PKG/target"/*.json | head -1)
WITNESS=$(ls "$PKG/target"/*.gz | head -1)
RESULT=$(timeout 20 $ADAPTER mutate "$ARTIFACT" --witness "$WITNESS" --attempts 4 2>&1)
if echo "$RESULT" | grep -Eq "finding\(s\)\$" && ! echo "$RESULT" | grep -q "0 finding"; then
  exit 0
fi
exit 1
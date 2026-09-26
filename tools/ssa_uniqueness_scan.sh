#!/bin/bash
# Ask the uniqueness question of programs produced by Noir's SSA fuzzer.
#
# That fuzzer compares ACIR against Brillig, which is what Noir's own CI already
# does millions of times. It never asks whether a circuit pins its outputs — no
# fuzzer here does. This consumes the artifacts the driver writes and puts that
# question to each one.
#
# Files are deleted once examined, so the producer can outrun the consumer
# without filling the disk; anything with candidates is moved aside instead.
DUMP="$1"; KEEP="$2"; ADAPTER="$3"
mkdir -p "$KEEP"
seen=0; quiet=0; refuted=0; hits=0
while true; do
  for f in "$DUMP"/*.json; do
    [ -e "$f" ] || { sleep 2; continue; }
    w="${f%.json}.gz"
    seen=$((seen+1))
    # The static pass is the cheap filter; the search is what decides. A
    # candidate the search cannot move is not a finding.
    n=$(timeout 60 "$ADAPTER" unpinned "$f" 2>/dev/null | tail -1 | grep -oE '^[0-9]+')
    [ -z "$n" ] && n=0
    if [ "$n" = "0" ]; then quiet=$((quiet+1)); rm -f "$f" "$w"; continue; fi
    if [ -e "$w" ]; then
      found=$(timeout 120 "$ADAPTER" mutate "$f" --witness "$w" --attempts 6 2>/dev/null               | grep -oE '[0-9]+ finding\(s\)' | grep -oE '^[0-9]+')
    else found=""; fi
    if [ "$found" = "0" ] || [ -z "$found" ]; then
      refuted=$((refuted+1)); rm -f "$f" "$w"
    else
      hits=$((hits+1)); mv "$f" "$KEEP/"; mv "$w" "$KEEP/" 2>/dev/null
      echo "CONFIRMED $found finding(s), $n candidate(s) -> $(basename $f)"
    fi
    if [ $((seen % 200)) -eq 0 ]; then
      echo "examined $seen, $quiet quiet, $refuted refuted by the search, $hits confirmed"
    fi
  done
  sleep 2
done

#!/usr/bin/env python3
"""High-throughput hunt for the non-pinning class.

The mutation search needs an honest witness, so it never starts on a program
that fails to execute — about one in seven of the generated ones. The static
pass needs only a compile, which makes it both broader and much faster, so it
can be run first and the search kept for confirming what it finds.

A case is kept when the compiler says nothing and the static pass reports a
candidate. That pairing is the whole point: a candidate the compiler already
flagged is not news, and a candidate is only interesting because nobody was
told about it.

Kept cases are then put to the search, and the three outcomes are kept apart
because they mean different things:

* `confirmed` — a second witness was actually produced. A real finding.
* `refuted` — the program ran and the search found nothing, so the static shape
  did not survive. These are the measurement of the static pass's precision.
* `not_executable` — no honest witness could be produced, so nothing could
  confirm or refute the shape. These need a look by hand, and they are the
  reason the static pass exists: the search cannot reach them at all.

Collapsing the last two, as a first version of this script did, makes every
refuted candidate look like an open question and badly overstates how much is
left to investigate.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time

UNSTABLE = ["-Z", "enums"]
FINDINGS = re.compile(r"(\d+) attempt\(s\), (\d+) finding\(s\)")
CANDIDATES = re.compile(r"(\d+) candidate\(s\)")


def run(cmd, cwd=None, timeout=300):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--sample", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--keep", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--prover", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent / "make_prover_toml.py")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--draws", type=int, default=3,
                        help="input assignments to try before calling a program unrunnable")
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    args.keep.mkdir(parents=True, exist_ok=True)
    counts = {"compiled": 0, "skipped": 0, "self_flagged": 0, "quiet": 0,
              "confirmed": 0, "refuted": 0, "not_executable": 0}
    kept, started = [], time.time()

    for index in range(args.count):
        package = args.work / "case"
        if package.exists():
            shutil.rmtree(package)
        (package / "src").mkdir(parents=True)
        (package / "Nargo.toml").write_text(
            '[package]\nname = "case"\ntype = "bin"\nauthors = [""]\n')
        generated = run([str(args.sample)], timeout=120)
        if generated is None or generated.returncode != 0:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        source = generated.stdout
        (package / "src" / "main.nr").write_text(source)

        compiled = run([args.nargo, "compile", "--force", "--silence-warnings", *UNSTABLE],
                       cwd=package)
        if compiled is None or compiled.returncode != 0:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        counts["compiled"] += 1
        if re.search(r"^bug:", compiled.stdout + compiled.stderr, re.M):
            counts["self_flagged"] += 1
            print("f", end="", flush=True)
            continue

        artifact = next(iter(sorted((package / "target").glob("*.json"))), None)
        if artifact is None:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        static = run([args.adapter, "unpinned", str(artifact)], timeout=120)
        found = CANDIDATES.search(static.stdout) if static else None
        if found is None or int(found.group(1)) == 0:
            counts["quiet"] += 1
            print(".", end="", flush=True)
            continue

        # Kept: the compiler said nothing and the static pass did.
        target = args.keep / f"case_{index:05d}"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
        (target / "unpinned.txt").write_text(static.stdout)

        status, detail = "not_executable", ""
        # Several draws, because one unlucky assignment failing an assertion is
        # not the same as a program that cannot be run at all.
        for attempt in range(args.draws):
            drawn = run([sys.executable, str(args.prover), str(package), "--artifact",
                         str(artifact), "--seed", str(index * 7 + attempt)], timeout=120)
            if drawn is None or drawn.returncode != 0:
                continue
            executed = run([args.nargo, "execute", "--force", "--silence-warnings", *UNSTABLE],
                           cwd=package)
            witness = next(iter(sorted((package / "target").glob("*.gz"))), None)
            if executed is None or executed.returncode != 0 or witness is None:
                continue
            searched = run([args.adapter, "mutate", str(artifact), "--witness", str(witness),
                            "--attempts", str(args.attempts), "--explain"], timeout=600)
            if searched is None:
                continue
            match = FINDINGS.search(searched.stdout)
            if match and int(match.group(2)) > 0:
                status, detail = "confirmed", searched.stdout[:4000]
                shutil.copy(witness, target / "witness.gz")
                break
            status, detail = "refuted", searched.stdout[:2000]
        counts[status] += 1
        (target / "status.txt").write_text(status + "\n" + detail)
        kept.append({"case": target.name, "status": status,
                     "candidates": int(found.group(1))})
        print({"confirmed": "C", "refuted": "r", "not_executable": "u"}[status],
              end="", flush=True)

    print(f"\n{args.count} cases in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}")
    args.out.write_text(json.dumps(kept, indent=2))


if __name__ == "__main__":
    main()

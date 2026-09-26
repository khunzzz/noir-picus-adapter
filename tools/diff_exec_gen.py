#!/usr/bin/env python3
"""Differential execution of generated programs across optimization settings.

One program, one input, three inliner levels: the outputs must match. A
divergence is a miscompilation — two compilations of the same program
disagreeing about what it computes.

Noir's own fuzzer compares its ACIR and Brillig pipelines against each other at
a single setting. This compares one pipeline against itself across settings,
which is a different axis and catches optimizer-introduced differences the
cross-pipeline check cannot see.

A failure counts as an output: "the program rejects" is as much a result as a
number, and a level that accepts where another rejects is exactly the kind of
divergence worth finding.
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

LEVELS = ["-9223372036854775808", "0", "9223372036854775807"]
UNSTABLE = ["-Z", "enums"]
RESULT = re.compile(r"(Circuit output:.*|Failed assertion.*|Cannot satisfy constraint.*|Index out of bounds.*)")


def run(cmd, cwd=None, timeout=200):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def outcome(text: str) -> str:
    found = RESULT.search(text)
    return found.group(1).strip() if found else ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--sample", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--keep", type=pathlib.Path, required=True)
    parser.add_argument("--prover", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent / "make_prover_toml.py")
    parser.add_argument("--compilers", nargs="*", default=[],
                        help="name=/path/to/nargo entries; when given, the axis becomes "
                             "the compiler rather than the inliner level. A divergence "
                             "here is a regression: one version computes something the "
                             "others do not.")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--draws", type=int, default=2)
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    args.keep.mkdir(parents=True, exist_ok=True)
    if args.compilers:
        settings = [(name, [path, "execute", "--force", "--silence-warnings", *UNSTABLE])
                    for name, path in (entry.split("=", 1) for entry in args.compilers)]
    else:
        settings = [(level, [args.nargo, "execute", "--force", "--silence-warnings",
                             *UNSTABLE, "--inliner-aggressiveness", level])
                    for level in LEVELS]
    counts = {"agree": 0, "diverge": 0, "skipped": 0}
    started = time.time()

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
        (package / "src" / "main.nr").write_text(generated.stdout)

        if run([args.nargo, "compile", "--force", "--silence-warnings", *UNSTABLE],
               cwd=package) is None:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        artifact = next(iter(sorted((package / "target").glob("*.json"))), None)
        if artifact is None:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue

        diverged = False
        for draw in range(args.draws):
            drawn = run([sys.executable, str(args.prover), str(package), "--artifact",
                         str(artifact), "--seed", str(index * 11 + draw)], timeout=120)
            if drawn is None or drawn.returncode != 0:
                continue
            results, labels = [], []
            for label, command in settings:
                executed = run(command, cwd=package)
                if executed is None:
                    results = []
                    break
                results.append(outcome(executed.stdout + executed.stderr))
                labels.append(label)
            # Every setting has to produce an outcome. An empty one means that
            # setting could not run the program at all — an older compiler
            # meeting syntax it does not know, say — and comparing it against
            # ones that did run reports a divergence that is really an absence.
            # Three of the first ninety-two cases were exactly that.
            if len(results) != len(settings) or not all(results):
                continue
            if len(set(results)) > 1:
                diverged = True
                target = args.keep / f"case_{index:05d}_{draw}"
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
                (target / "divergence.txt").write_text(
                    "\n".join(f"{lbl}: {res}" for lbl, res in zip(labels, results)))
                break

        if diverged:
            counts["diverge"] += 1
            print("D", end="", flush=True)
        else:
            counts["agree"] += 1
            print(".", end="", flush=True)

    print(f"\n{args.count} cases in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}")


if __name__ == "__main__":
    main()

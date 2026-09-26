#!/usr/bin/env python3
"""Metamorphic soundness testing across compiler settings.

Whether a program is under-constrained is a property of the program, not of how
aggressively the compiler inlines it. So for a fixed program, the soundness
verdict must be the same at every `--inliner-aggressiveness` level. A
divergence is not a heuristic complaint about the source — it says one of the
compilations produced a constraint system the others did not, and at least one
of them is wrong.

This is a different question from what Noir's own fuzzers ask. Theirs compare
the *honest* execution of two pipelines, which agree even when a circuit is
under-constrained; only a malicious prover separates them. Ours compares the
*existence of a second witness* across settings of a single pipeline.

The witness layout differs between levels, so findings are not compared
value-by-value — only the verdict is, which is what has to be invariant.

Output is a triage list, not a verdict: a divergence where one side merely
failed to search deeply enough is reported as `weak` and needs the SMT
uniqueness query to settle. Only `strong` rows are worth reducing.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

LEVELS = ["-9223372036854775808", "0", "9223372036854775807"]
UNSTABLE = ["-Z", "enums"]
FINDINGS = re.compile(r"(\d+) attempt\(s\), (\d+) finding\(s\)")


def run(cmd, cwd=None, timeout=300, env=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        return None


def verdict_at(args, package: pathlib.Path, level: str, nargo: str | None = None):
    """Compile, execute and search at one setting.

    A setting is either an inliner level of one compiler, or — when `nargo` is
    given — a whole compiler at its default level. Soundness has to be
    invariant under both, so the same comparison serves for both axes.

    Returns (findings, attempts) or None when the program does not get far
    enough at this setting to be comparable.
    """
    nargo = nargo or args.nargo
    flags = [] if args.axis == "compiler" else ["--inliner-aggressiveness", level]
    compiled = run([nargo, "compile", "--force", "--silence-warnings",
                    *UNSTABLE, *flags], cwd=package)
    if compiled is None or compiled.returncode != 0:
        return None
    # A program the compiler itself flags is not interesting here: the
    # divergence we are after is one nobody was told about.
    if re.search(r"^bug:", compiled.stdout + compiled.stderr, re.M):
        return "self_flagged"
    executed = run([nargo, "execute", "--force", "--silence-warnings",
                    *UNSTABLE, *flags], cwd=package)
    if executed is None or executed.returncode != 0:
        return None
    target = package / "target"
    artifact = next(iter(sorted(target.glob("*.json"))), None)
    witness = next(iter(sorted(target.glob("*.gz"))), None)
    if artifact is None or witness is None:
        return None
    searched = run([args.adapter, "mutate", str(artifact), "--witness",
                    str(witness), "--attempts", str(args.attempts)],
                   timeout=args.search_timeout)
    if searched is None:
        return None
    match = FINDINGS.search(searched.stdout)
    if match is None:
        return None
    return (int(match.group(2)), int(match.group(1)))


def classify(results: dict):
    """Turn per-level verdicts into a divergence class."""
    usable = {k: v for k, v in results.items()
              if isinstance(v, tuple)}
    if len(usable) < 2:
        return None
    found = {k: v for k, v in usable.items() if v[0] > 0}
    empty = {k: v for k, v in usable.items() if v[0] == 0}
    if not found or not empty:
        return None
    # A level that searched far less than the one that found something did not
    # really disagree, it just gave up earlier.
    deepest_found = max(a for _, a in found.values())
    if all(a >= deepest_found for _, a in empty.values()):
        return "strong"
    return "weak"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--sample", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--prover", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent / "make_prover_toml.py")
    parser.add_argument("--corpus", type=pathlib.Path, required=True,
                        help="directory of kept programs; generated on first use, "
                             "re-used afterwards so runs are comparable")
    parser.add_argument("--seed-start", type=int, default=900000)
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--size", type=int, default=8192,
                        help="kept for interface compatibility; `sample` ignores it")
    parser.add_argument("--axis", choices=["inliner", "compiler"], default="inliner",
                        help="vary the inliner level of one compiler, or vary the compiler")
    parser.add_argument("--compilers", nargs="*", default=[],
                        help="for --axis compiler: name=/path/to/nargo entries")
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--search-timeout", type=int, default=300)
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    args.corpus.mkdir(parents=True, exist_ok=True)
    compilers = [tuple(entry.split("=", 1)) for entry in args.compilers]
    if args.axis == "compiler" and len(compilers) < 2:
        parser.error("--axis compiler needs at least two --compilers entries")
    divergences, counts = [], {"skipped": 0, "agreed": 0, "self_flagged": 0}
    started = time.time()

    for index in range(args.count):
        seed = args.seed_start + index
        package = args.work / f"case_{seed}"
        if package.exists():
            shutil.rmtree(package)
        (package / "src").mkdir(parents=True)
        (package / "Nargo.toml").write_text(
            f'[package]\nname = "case{seed}"\ntype = "bin"\nauthors = [""]\n')
        # `sample` seeds itself from OS entropy and ignores both
        # NOIR_AST_FUZZER_SEED and Config size, so a "seed" identifies nothing.
        # The corpus on disk is the reproducible artifact instead: a case is
        # generated once, kept, and re-used by every later run.
        stored = args.corpus / f"case_{seed}.nr"
        if stored.exists():
            source = stored.read_text()
        else:
            generated = run([str(args.sample)], timeout=120)
            if generated is None or generated.returncode != 0:
                counts["skipped"] += 1
                print("x", end="", flush=True)
                continue
            source = generated.stdout
            stored.write_text(source)
        (package / "src" / "main.nr").write_text(source)

        # A first compile is needed before the ABI exists to draw inputs from.
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
        drawn = run([sys.executable, str(args.prover), str(package),
                     "--artifact", str(artifact), "--seed", str(seed)], timeout=120)
        if drawn is None or drawn.returncode != 0:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue

        if args.axis == "compiler":
            results = {name: verdict_at(args, package, "", path)
                       for name, path in compilers}
        else:
            results = {level: verdict_at(args, package, level) for level in LEVELS}
        if any(v == "self_flagged" for v in results.values()):
            counts["self_flagged"] += 1
            print("f", end="", flush=True)
            continue
        kind = classify(results)
        if kind is None:
            counts["agreed"] += 1
            print(".", end="", flush=True)
            continue
        divergences.append({"seed": seed, "kind": kind,
                            "results": {k: v for k, v in results.items()},
                            "source": (package / "src" / "main.nr").read_text()})
        print("D" if kind == "strong" else "d", end="", flush=True)

    print(f"\n{args.count} cases in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}  divergences: {len(divergences)}")
    args.out.write_text(json.dumps(divergences, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Check Noir's hash gadgets against an independent implementation.

`blake2s` has a reference in Python's `hashlib`, so this is a true differential:
Noir's circuit against a implementation that shares no code with it. A mismatch
is a wrong digest, which is a miscompilation of the gadget rather than a
disagreement between two of Noir's own pipelines.

Compilation of a hash circuit is slow and depends only on the input length, so
each length is compiled once and then run over many inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import shutil
import subprocess
import time

UNSTABLE = ["-Z", "enums"]


def run(cmd, cwd=None, timeout=400):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--keep", type=pathlib.Path, required=True)
    parser.add_argument("--lengths", type=int, nargs="*",
                        # Around the 64-byte block boundary, where a padding or
                        # counter mistake would show, plus a couple of longer ones.
                        default=[1, 31, 32, 55, 56, 63, 64, 65, 100, 128])
    parser.add_argument("--per-length", type=int, default=40)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    args.keep.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    counts = {"ok": 0, "wrong": 0, "skipped": 0}
    started = time.time()

    for length in args.lengths:
        package = args.work / f"len_{length}"
        if package.exists():
            shutil.rmtree(package)
        (package / "src").mkdir(parents=True)
        (package / "Nargo.toml").write_text(
            '[package]\nname = "hash"\ntype = "bin"\nauthors = [""]\n')
        (package / "src" / "main.nr").write_text(
            f"fn main(x: [u8; {length}]) -> pub [u8; 32] {{\n"
            f"    std::hash::blake2s(x)\n}}\n")
        (package / "Prover.toml").write_text(
            "x = [" + ", ".join('"0"' for _ in range(length)) + "]\n")
        if run([args.nargo, "compile", "--force", "--silence-warnings", *UNSTABLE],
               cwd=package) is None:
            counts["skipped"] += args.per_length
            print("x" * args.per_length, end="", flush=True)
            continue

        for _ in range(args.per_length):
            data = bytes(rng.randrange(0, 256) for _ in range(length))
            (package / "Prover.toml").write_text(
                "x = [" + ", ".join(f'"{b}"' for b in data) + "]\n")
            executed = run([args.nargo, "execute", "--force", "--silence-warnings", *UNSTABLE],
                           cwd=package)
            if executed is None or executed.returncode != 0:
                counts["skipped"] += 1
                print("x", end="", flush=True)
                continue
            line = [l for l in executed.stdout.splitlines() if "Circuit output" in l]
            if not line:
                counts["skipped"] += 1
                print("x", end="", flush=True)
                continue
            got = [int(t.strip()) for t in
                   line[0].split("Circuit output: ")[-1].strip().strip("[]").split(",")]
            expected = list(hashlib.blake2s(data).digest())
            if got == expected:
                counts["ok"] += 1
                print(".", end="", flush=True)
                continue
            counts["wrong"] += 1
            target = args.keep / f"len_{length}_{counts['wrong']}"
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
            (target / "mismatch.txt").write_text(
                f"input: {list(data)}\nexpected: {expected}\ngot: {got}\n")
            print("W", end="", flush=True)

    print(f"\ndone in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}")


if __name__ == "__main__":
    main()

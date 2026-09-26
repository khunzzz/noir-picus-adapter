#!/usr/bin/env python3
"""Run the soundness search over Noir's own `test_programs` corpus.

These are programs the Noir team wrote and maintains, with inputs already
committed. They are a harsher audience than generated programs: anything found
here is in code someone intended to be correct.

Each package is copied out before use so the checkout is never modified.
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

FINDINGS = re.compile(r"(\d+) attempt\(s\), (\d+) finding\(s\)")
UNSTABLE = ["-Z", "enums"]


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
    parser.add_argument("--corpus", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--attempts", type=int, default=6)
    # Предел по времени на программу. В наборе Noir есть эталонные тесты
    # (`bench_2_to_17` и родственные) на сотни тысяч ограничений: поиск на них
    # не завершается, а без предела он останавливает весь обход. Пропуск такой
    # программы честнее, чем зависший прогон, и он попадает в счётчик.
    parser.add_argument("--per-program", type=int, default=90,
                        help="предел времени на поиск в одной программе, с")
    parser.add_argument("--skip", default="bench_,regression_bench",
                        help="пропускать пакеты, чьё имя содержит одну из подстрок")
    parser.add_argument("--only-hints", action="store_true",
                        help="restrict to packages that use an unsafe block")
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    packages = sorted(p for p in args.corpus.iterdir()
                      if (p / "Prover.toml").exists() and (p / "Nargo.toml").exists())
    skip = [t for t in args.skip.split(",") if t]
    if skip:
        packages = [p for p in packages if not any(t in p.name for t in skip)]
    if args.only_hints:
        packages = [p for p in packages
                    if any("unsafe {" in f.read_text(errors="ignore")
                           for f in p.rglob("*.nr"))]

    results, counts = [], {"findings": 0, "clean": 0, "self_flagged": 0, "skipped": 0}
    started = time.time()
    for package in packages:
        target = args.work / package.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(package, target)
        compiled = run([args.nargo, "compile", "--force", "--silence-warnings", *UNSTABLE],
                       cwd=target)
        if compiled is None or compiled.returncode != 0:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        flagged = bool(re.search(r"^bug:", compiled.stdout + compiled.stderr, re.M))
        executed = run([args.nargo, "execute", "--force", "--silence-warnings", *UNSTABLE],
                       cwd=target)
        if executed is None or executed.returncode != 0:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        artifact = next(iter(sorted((target / "target").glob("*.json"))), None)
        witness = next(iter(sorted((target / "target").glob("*.gz"))), None)
        if artifact is None or witness is None:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        searched = run([args.adapter, "mutate", str(artifact), "--witness", str(witness),
                        "--attempts", str(args.attempts)], timeout=args.per_program)
        if searched is None:
            counts["skipped"] += 1
            print("t", end="", flush=True)
            continue
        match = FINDINGS.search(searched.stdout)
        if match is None:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        attempts, found = int(match.group(1)), int(match.group(2))
        if found == 0:
            counts["clean"] += 1
            print(".", end="", flush=True)
            continue
        if flagged:
            # The compiler already told the author about this one.
            counts["self_flagged"] += 1
            print("f", end="", flush=True)
            continue
        counts["findings"] += 1
        results.append({"package": package.name, "attempts": attempts,
                        "findings": found, "report": searched.stdout[:4000]})
        print("F", end="", flush=True)

    print(f"\n{len(packages)} packages in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}")
    args.out.write_text(json.dumps(results, indent=2))
    for row in results:
        print(f"  FINDING {row['package']}: {row['findings']} in {row['attempts']} attempts")


if __name__ == "__main__":
    main()

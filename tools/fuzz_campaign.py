#!/usr/bin/env python3
"""Compiler-soundness fuzzing campaign for the Noir ACIR pipeline.

For every generated program the campaign runs:

    noir_gen.py -> nargo compile -> noir-picus-adapter scan

with `--fixed all-params`, i.e. every declared parameter is shared between the
two self-composition copies. A generated program is a total deterministic
function of its parameters, so ACIR that admits two witness assignments which
agree on all parameters and disagree on a target is underconstrained *by the
compiler*, not by the programmer. Every `unsafe` verdict is therefore a
candidate Noir compiler soundness bug rather than a property of the source.

Findings are stored with everything needed to reproduce and to file upstream:
the generator seed and command line, the Noir source, the compiled artifact and
the scanner report.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
GENERATOR = HERE / "noir_gen.py"


class CaseResult:
    __slots__ = ("seed", "outcome", "detail", "elapsed", "statuses")

    def __init__(self, seed: int, outcome: str, detail: str = "", elapsed: float = 0.0):
        self.seed = seed
        self.outcome = outcome
        self.detail = detail
        self.elapsed = elapsed
        self.statuses: dict[str, int] = {}


def run(cmd: list[str], cwd: pathlib.Path | None = None, timeout: int = 120):
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def scan_statuses(report: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for program in report.get("programs", []):
        for circuit in program.get("circuits", []):
            for target in circuit.get("targets", []):
                status = target.get("status", "?")
                counts[status] = counts.get(status, 0) + 1
    return counts


def findings_of(report: dict) -> list[dict]:
    out = []
    for program in report.get("programs", []):
        for circuit in program.get("circuits", []):
            for target in circuit.get("targets", []):
                if target.get("status") == "unsafe":
                    out.append({"circuit": circuit.get("name"), **target})
    return out


def run_case(args, seed: int, work: pathlib.Path) -> CaseResult:
    started = time.monotonic()
    case_dir = work / f"case_{seed}"
    if case_dir.exists():
        shutil.rmtree(case_dir)

    generated = run(
        [
            sys.executable,
            str(GENERATOR),
            "--seed",
            str(seed),
            "--mode",
            args.mode,
            "--size",
            str(args.size),
            "--out",
            str(case_dir),
        ]
    )
    if generated.returncode != 0:
        return CaseResult(seed, "gen_failed", generated.stderr.strip()[:200])

    compiled = run([args.nargo, "compile"], cwd=case_dir, timeout=args.compile_timeout)
    if compiled.returncode != 0:
        return CaseResult(seed, "compile_failed", compiled.stderr.strip()[:200])

    artifacts = sorted((case_dir / "target").glob("*.json"))
    if not artifacts:
        return CaseResult(seed, "no_artifact")

    scanned = run(
        [
            args.adapter,
            "scan",
            str(artifacts[0]),
            "--fixed",
            "all-params",
            "--targets",
            args.targets,
            "--format",
            "json",
            "--timeout",
            str(args.solver_timeout_ms),
            "--target-timeout",
            str(args.target_timeout_ms),
            "--refine-budget",
            str(args.refine_budget_ms),
        ],
        timeout=args.scan_timeout,
    )
    if scanned.returncode != 0 or not scanned.stdout.strip():
        return CaseResult(seed, "scan_failed", (scanned.stderr or scanned.stdout).strip()[:300])

    try:
        report = json.loads(scanned.stdout)
    except json.JSONDecodeError as error:
        return CaseResult(seed, "bad_report", str(error)[:200])

    elapsed = time.monotonic() - started
    statuses = scan_statuses(report)
    hits = findings_of(report)
    result = CaseResult(seed, "finding" if hits else "clean", elapsed=elapsed)
    result.statuses = statuses

    if hits:
        keep = args.out / f"finding_{args.mode}_{seed}"
        if keep.exists():
            shutil.rmtree(keep)
        keep.mkdir(parents=True)
        shutil.copy(case_dir / "src" / "main.nr", keep / "main.nr")
        shutil.copy(artifacts[0], keep / "artifact.json")
        (keep / "report.json").write_text(json.dumps(report, indent=2))
        (keep / "repro.sh").write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"python3 {GENERATOR} --seed {seed} --mode {args.mode} "
            f"--size {args.size} --out ./case\n"
            "(cd case && nargo compile)\n"
            f"{args.adapter} scan case/target/*.json --fixed all-params "
            "--targets all --verbose\n"
        )
        (keep / "findings.json").write_text(json.dumps(hits, indent=2))

    if not args.keep_cases:
        shutil.rmtree(case_dir, ignore_errors=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="path to noir-picus-adapter")
    parser.add_argument("--nargo", required=True, help="path to nargo")
    parser.add_argument("--out", type=pathlib.Path, required=True, help="findings directory")
    parser.add_argument("--work", type=pathlib.Path, default=None, help="scratch directory")
    parser.add_argument(
        "--mode", choices=["pure", "hints", "field", "control"], default="control"
    )
    # `returns` is the sharp filter: a hint that is under-constrained but never
    # reaches a public output cannot be exploited, and every one that can does
    # show up as a non-unique return value.
    parser.add_argument(
        "--targets", choices=["returns", "brillig-outputs", "all"], default="returns"
    )
    parser.add_argument("--size", type=int, default=8)
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--solver-timeout-ms", type=int, default=5000)
    # cvc5 overruns its own time limit inside a Groebner basis computation, so
    # the brake that actually holds is the per-target process kill.
    parser.add_argument("--target-timeout-ms", type=int, default=8000)
    parser.add_argument("--refine-budget-ms", type=int, default=4000)
    parser.add_argument("--compile-timeout", type=int, default=120)
    parser.add_argument("--scan-timeout", type=int, default=300)
    parser.add_argument("--keep-cases", action="store_true")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    work = args.work or (args.out / "work")
    work.mkdir(parents=True, exist_ok=True)

    tally: dict[str, int] = {}
    status_tally: dict[str, int] = {}
    started = time.monotonic()

    for offset in range(args.count):
        seed = args.seed_start + offset
        try:
            result = run_case(args, seed, work)
        except subprocess.TimeoutExpired as error:
            result = CaseResult(seed, "timeout", str(error)[:200])
        tally[result.outcome] = tally.get(result.outcome, 0) + 1
        for status, count in result.statuses.items():
            status_tally[status] = status_tally.get(status, 0) + count
        marker = {"clean": ".", "finding": "!", "compile_failed": "c"}.get(result.outcome, "x")
        sys.stdout.write(marker)
        sys.stdout.flush()
        if result.outcome not in ("clean", "finding"):
            print(f"\n  seed {seed}: {result.outcome}: {result.detail}", file=sys.stderr)

    elapsed = time.monotonic() - started
    print(f"\n\ncases: {args.count} in {elapsed:.1f}s ({args.count / max(elapsed, 1e-9):.2f}/s)")
    print("outcomes:", json.dumps(tally, sort_keys=True))
    print("target statuses:", json.dumps(status_tally, sort_keys=True))
    print(f"findings kept in {args.out}")


if __name__ == "__main__":
    main()

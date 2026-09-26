#!/usr/bin/env python3
"""Soundness campaign driven by Noir's own AST fuzzer.

`tooling/ast_fuzzer` in the Noir repository has years of tuning behind it and
reaches language corners a hand-written generator does not: enums, matches,
nested closures, references, the data bus, unconstrained blocks, generics. Its
own oracle compares the *honest* execution of the ACIR and Brillig pipelines,
which finds miscompilation but by construction cannot find an under-constrained
circuit — the honest run agrees there, only a malicious one diverges.

This pairs their generator with that missing oracle. The `sample` example
prints a random program as Noir source; from there the program is compiled,
executed honestly, and handed to the mutation search, which looks for a second
witness the constraint system would also accept.

Build the generator once:

    cd <noir checkout> && cargo build --release -p noir_ast_fuzzer --example sample
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PROVER = HERE / "make_prover_toml.py"

# The generator uses these; a released `nargo` gates them behind a flag.
UNSTABLE = ["-Z", "enums"]


# Noir runs its own under-constrained check during compilation and reports
# "Brillig function call isn't properly covered by a manual constraint" when a
# hint's outputs are not tied back to the circuit. A program it flags is
# known-bad by construction — the programmer's fault, not the compiler's — and
# finding a second witness in one proves nothing.
#
# Rejecting those turns the oracle into the sharpest form available: the
# compiler has asserted that this program *is* properly constrained, so a
# second witness contradicts the compiler's own guarantee.
# Noir runs its own under-constrained checks during compilation and reports
# them at `bug:` level. There is more than one message — "Brillig function call
# isn't properly covered by a manual constraint" and "Input to Brillig function
# is in a separate subgraph to output" — and matching only the first one let
# through a whole class of programs whose hints are unconstrained by
# construction. Matching the level catches every check, including ones added
# later.
#
# Rejecting these is what makes the oracle sharp: the compiler has asserted
# that the program *is* properly constrained, so a second witness contradicts
# the compiler's own guarantee.
UNDERCONSTRAINED_MARKER = "bug:"

# Inlining decides how much of the program ACIR generation sees at once, and
# several published advisories are in passes that run after it, so the same
# source compiled at different aggressiveness exercises different code. The
# three values are the ones Noir's own differential fuzzer uses.
INLINER_LEVELS = ["-9223372036854775808", "0", "9223372036854775807"]


def run(cmd, cwd=None, timeout=180):
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def generate(args, seed: int, case: pathlib.Path) -> bool:
    (case / "src").mkdir(parents=True, exist_ok=True)
    (case / "Nargo.toml").write_text(
        f'[package]\nname = "af_{seed}"\ntype = "bin"\nauthors = [""]\n'
    )
    # The low 32 bits of the seed carry the input size the generator draws
    # from, so vary the high half per case and keep the size band fixed.
    result = subprocess.run(
        [str(args.sample)],
        cwd=args.noir_src,
        capture_output=True,
        text=True,
        env={**os.environ, "NOIR_AST_FUZZER_SEED": f"0x{seed:08x}{args.size:08x}"},
        timeout=60,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    (case / "src" / "main.nr").write_text(result.stdout)
    return True


def run_case(args, seed: int) -> tuple[str, dict | None]:
    case = args.work / f"case_{seed}"
    shutil.rmtree(case, ignore_errors=True)

    if not generate(args, seed, case):
        return "gen_failed", None
    inliner = (
        ["--inliner-aggressiveness", INLINER_LEVELS[seed % len(INLINER_LEVELS)]]
        if args.inliner == "vary"
        else []
    )
    compiled = run(
        [args.nargo, "compile", "--force", "--silence-warnings", *UNSTABLE, *inliner],
        cwd=case,
    )
    if compiled.returncode != 0:
        return "compile_failed", None
    if UNDERCONSTRAINED_MARKER in compiled.stderr + compiled.stdout:
        return "self_flagged", None
    artifacts = sorted((case / "target").glob("*.json"))
    if not artifacts:
        return "no_artifact", None

    for draw in range(args.draws):
        made = run([sys.executable, str(PROVER), str(case),
                    "--artifact", str(artifacts[0]),
                    "--emit-witness-map", str(case / "inputs.json"), "--seed", str(seed * 131 + draw)])
        if made.returncode != 0:
            return "prover_toml_failed", None
        executed = run([args.nargo, "execute", "--silence-warnings", *UNSTABLE, *inliner],
                       cwd=case)
        if executed.returncode != 0 and rejected_the_inputs(
            executed.stderr + executed.stdout
        ):
            # The program rejects this draw. Every rejection is supposed to
            # survive compilation as a constraint, so a circuit that still
            # accepts it would let a verifier take a proof of a false
            # statement. This is where the draws a uniqueness search throws
            # away become the sharpest signal available.
            verdict = feasibility(args, artifacts[0], case)
            if verdict == "accepted":
                keep_rejection(args, case, artifacts[0], seed, executed)
                return "accepts_rejected", None
            continue
        witnesses = sorted((case / "target").glob("*.gz"))
        if not witnesses:
            continue
        if args.feasibility and layout_confirmed(args, artifacts[0], case, witnesses[0]):
            (case / "layout.ok").touch()

        searched = run([args.adapter, "mutate", str(artifacts[0]),
                        "--witness", str(witnesses[0]),
                        "--attempts", str(args.attempts), "--format", "json"])
        if not searched.stdout.strip():
            return "mutate_failed", None
        report = json.loads(searched.stdout)
        if report["findings"]:
            keep = args.out / f"finding_{seed}"
            shutil.rmtree(keep, ignore_errors=True)
            keep.mkdir(parents=True)
            shutil.copy(case / "src" / "main.nr", keep / "main.nr")
            shutil.copy(case / "Prover.toml", keep / "Prover.toml")
            shutil.copy(artifacts[0], keep / "artifact.json")
            (keep / "findings.json").write_text(json.dumps(report, indent=2))
            (keep / "seed.txt").write_text(f"0x{seed:08x}{args.size:08x}\n")
            return "finding", report
        return "clean", report

    return "no_honest_run", None


def layout_confirmed(args, artifact, case, witness) -> bool:
    """Check that this program's parameters really do sit where we assume.

    Which witness a parameter lands on is a convention, and a feasibility
    answer computed under the wrong layout is worse than no answer — it was
    reporting circuits as rejecting inputs they plainly accept. So the layout
    is confirmed against a run that succeeded before any verdict from it is
    believed.
    """
    inputs = case / "inputs.json"
    if not inputs.is_file():
        return False
    actual = run([args.adapter, "witness-inputs", str(artifact), "--witness", str(witness)])
    if actual.returncode != 0:
        return False
    try:
        assumed = json.loads(inputs.read_text())
        return json.loads(actual.stdout) == assumed
    except json.JSONDecodeError:
        return False


# `nargo` reports a malformed `Prover.toml` the same way it reports a failing
# program: a non-zero exit. Only the second is a rejection of the *inputs*, and
# counting the first as one turned every value this pipeline encoded slightly
# wrong into a "finding".
INPUT_DECODE_MARKERS = (
    "Failed to deserialize inputs",
    "invalid digit found in string",
    "cannot be represented as",
)


def rejected_the_inputs(output: str) -> bool:
    """Whether a failed run is the program rejecting its inputs."""
    return not any(marker in output for marker in INPUT_DECODE_MARKERS)


def feasibility(args, artifact, case):
    """Ask the scanner whether the constraint system accepts these inputs."""
    if not args.feasibility or not case.joinpath("layout.ok").is_file():
        return "skipped"
    inputs = case / "inputs.json"
    if not inputs.is_file():
        return "unknown"
    # cvc5 runs past its own time limit inside a Groebner basis computation,
    # so the wall clock here is the brake that actually holds. A verdict this
    # does not reach in time is simply not available.
    try:
        asked = run([args.adapter, "feasible", str(artifact), "--inputs",
                     inputs.read_text(), "--timeout", str(args.feasible_timeout_ms)],
                    timeout=args.feasible_timeout_ms / 1000 + 5)
    except subprocess.TimeoutExpired:
        return "unknown"
    return asked.stdout.strip() if asked.returncode == 0 else "unknown"


def keep_rejection(args, case, artifact, seed, executed) -> None:
    keep = args.out / f"rejects_{seed}"
    shutil.rmtree(keep, ignore_errors=True)
    keep.mkdir(parents=True)
    shutil.copy(case / "src" / "main.nr", keep / "main.nr")
    shutil.copy(case / "Prover.toml", keep / "Prover.toml")
    shutil.copy(case / "inputs.json", keep / "inputs.json")
    shutil.copy(artifact, keep / "artifact.json")
    (keep / "nargo_error.txt").write_text((executed.stderr or executed.stdout)[:4000])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--noir-src", type=pathlib.Path, required=True)
    parser.add_argument("--sample", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--seed-start", type=int, default=0x1000)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--size", type=int, default=0x2000)
    parser.add_argument("--inliner", choices=["vary", "default"], default="vary")
    parser.add_argument("--feasible-timeout-ms", type=int, default=12000)
    # Off by default: a rejected draw costs a full satisfiability query, which
    # on a circuit of any size usually times out without a verdict, and paying
    # that on every draw costs an order of magnitude in throughput. Worth it on
    # small programs, where the query is cheap and the answer is real.
    parser.add_argument("--feasibility", action="store_true")
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--draws", type=int, default=3)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)

    tally: dict[str, int] = {}
    funnel: dict[str, int] = {}
    started = time.monotonic()
    for offset in range(args.count):
        seed = args.seed_start + offset
        try:
            outcome, report = run_case(args, seed)
        except subprocess.TimeoutExpired:
            outcome, report = "timeout", None
        tally[outcome] = tally.get(outcome, 0) + 1
        if report:
            for key, value in report.get("funnel", {}).items():
                funnel[key] = funnel.get(key, 0) + value
        sys.stdout.write({"clean": ".", "finding": "!"}.get(outcome, "x"))
        sys.stdout.flush()
        if outcome == "accepts_rejected":
            print(f"\n*** CIRCUIT ACCEPTS A REJECTED INPUT at seed {seed}", flush=True)
        if outcome == "finding":
            print(f"\n*** FINDING at seed {seed} — kept in {args.out}", flush=True)
        shutil.rmtree(args.work / f"case_{seed}", ignore_errors=True)

    elapsed = time.monotonic() - started
    print(f"\n{args.count} cases in {elapsed:.1f}s ({args.count / max(elapsed, 1e-9):.2f}/s)")
    print("outcomes:", json.dumps(tally, sort_keys=True))
    print("funnel:", json.dumps(funnel, sort_keys=True))


if __name__ == "__main__":
    main()

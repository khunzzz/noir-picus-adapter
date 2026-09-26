#!/usr/bin/env python3
"""Fuzzing campaign driven by the mutation search rather than the solver.

The SMT path proves uniqueness but gives up on circuits of any size. This one
looks for a concrete second witness instead: generate a program, compile it,
execute it honestly, then try to perturb a hint output and repair the rest. A
success is a finished proof — two assignments, same inputs, different public
output, every ACIR opcode satisfied — and it costs no solver time, so the
campaign runs orders of magnitude more programs per hour.

A generated program is a deterministic function of its parameters, so any
second witness means the *compiler* emitted an under-constrained circuit.
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
PROVER = HERE / "make_prover_toml.py"
INVERTER = HERE / "witness_to_prover.py"


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


def run(cmd, cwd=None, timeout=120):
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def run_case(args, seed: int, work: pathlib.Path) -> tuple[str, dict | None]:
    case = work / f"case_{seed}"
    shutil.rmtree(case, ignore_errors=True)

    generated = run(
        [sys.executable, str(GENERATOR), "--seed", str(seed), "--mode", args.mode,
         "--size", str(args.size), "--out", str(case)]
    )
    if generated.returncode != 0:
        return "gen_failed", None

    inliner = (
        ["--inliner-aggressiveness", INLINER_LEVELS[seed % len(INLINER_LEVELS)]]
        if args.inliner == "vary"
        else []
    )
    compiled = run(
        [args.nargo, "compile", "--force", "--silence-warnings", *inliner], cwd=case
    )
    if compiled.returncode != 0:
        return "compile_failed", None
    if UNDERCONSTRAINED_MARKER in compiled.stderr + compiled.stdout:
        return "self_flagged", None
    artifacts = sorted((case / "target").glob("*.json"))
    if not artifacts:
        return "no_artifact", None

    # Several input draws: a program can reject one and accept the next, and a
    # hint is only mutable along a path the honest run actually took.
    for draw in range(args.draws):
        made = run([sys.executable, str(PROVER), str(case),
                    "--artifact", str(artifacts[0]),
                    "--emit-witness-map", str(case / "inputs.json"), "--seed", str(seed * 97 + draw)])
        if made.returncode != 0:
            return "prover_toml_failed", None
        executed = run([args.nargo, "execute", "--silence-warnings", *inliner], cwd=case)
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

        rejected = check_accepts_what_program_rejects(args, case, artifacts[0], report, inliner)
        if rejected:
            keep = args.out / f"rejects_{args.mode}_{seed}"
            shutil.rmtree(keep, ignore_errors=True)
            keep.mkdir(parents=True)
            shutil.copy(case / "src/main.nr", keep / "main.nr")
            shutil.copy(case / "Prover.toml", keep / "honest.toml")
            shutil.copy(artifacts[0], keep / "artifact.json")
            (keep / "accepting.toml").write_text(rejected["toml"])
            (keep / "detail.json").write_text(json.dumps(rejected["detail"], indent=2))
            return "accepts_rejected", report

        if report["findings"]:
            keep = args.out / f"finding_{args.mode}_{seed}"
            shutil.rmtree(keep, ignore_errors=True)
            keep.mkdir(parents=True)
            shutil.copy(case / "src/main.nr", keep / "main.nr")
            shutil.copy(case / "Prover.toml", keep / "Prover.toml")
            shutil.copy(artifacts[0], keep / "artifact.json")
            (keep / "findings.json").write_text(json.dumps(report, indent=2))
            return "finding", report
        return "clean", report

    return "no_honest_run", None


def check_accepts_what_program_rejects(args, case, artifact, report, inliner):
    """Look for inputs the constraint system accepts but the program rejects.

    Every published advisory where a check failed to survive compilation has
    this shape: the source rejects an input, the circuit does not, and a
    verifier would take a proof of a false statement. It also recycles the
    cases a plain output-divergence search throws away.

    A program abort inside an `unconstrained` block does not count — a prover
    supplies hints itself and is under no obligation to run that code — so the
    honest Prover.toml is re-checked first to make sure the abort is about the
    inputs and not about this particular run.
    """
    honest_toml = case / "Prover.toml"
    for accepted in report.get("accepted_inputs", []):
        assignment = accepted["inputs"]
        honest = dict(assignment)
        honest[str(accepted["witness"])] = accepted["original"]

        candidate = case / "Candidate.toml"
        built = run([sys.executable, str(INVERTER),
                     "--artifact", str(artifact),
                     "--assignment", json.dumps(assignment),
                     "--honest", json.dumps(honest),
                     "--honest-toml", str(honest_toml),
                     "--out", str(candidate)])
        if built.returncode != 0:
            continue

        shutil.copy(honest_toml, case / "Honest.toml")
        shutil.copy(candidate, honest_toml)
        executed = run([args.nargo, "execute", "--silence-warnings", *inliner], cwd=case)
        toml = candidate.read_text()
        shutil.copy(case / "Honest.toml", honest_toml)

        if executed.returncode == 0 or not rejected_the_inputs(
            executed.stderr + executed.stdout
        ):
            continue
        return {
            "toml": toml,
            "detail": {
                "accepted": accepted,
                "nargo_error": (executed.stderr or executed.stdout).strip()[:2000],
            },
        }
    return None


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
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument(
        "--mode",
        choices=["pure", "hints", "field", "control", "math"],
        default="control",
    )
    parser.add_argument("--size", type=int, default=6)
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--inliner", choices=["vary", "default"], default="vary")
    parser.add_argument("--feasible-timeout-ms", type=int, default=12000)
    # Off by default: a rejected draw costs a full satisfiability query, which
    # on a circuit of any size usually times out without a verdict, and paying
    # that on every draw costs an order of magnitude in throughput. Worth it on
    # small programs, where the query is cheap and the answer is real.
    parser.add_argument("--feasibility", action="store_true")
    parser.add_argument("--attempts", type=int, default=4)
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
            outcome, report = run_case(args, seed, args.work)
        except subprocess.TimeoutExpired:
            outcome, report = "timeout", None
        if report:
            for key, value in report.get("funnel", {}).items():
                funnel[key] = funnel.get(key, 0) + value
        tally[outcome] = tally.get(outcome, 0) + 1
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

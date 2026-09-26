#!/usr/bin/env python3
"""Systematic audit of the gadgets the Noir compiler emits.

Random programs are good at reaching combinations, and bad at guaranteeing that
any particular primitive was ever tried. The set of primitives is small and
finite — a cast between two types, an integer division, a variable shift, a
comparison, a dynamic array read — and each one lowers to a fixed gadget with
its own range checks and boundary conditions. Those gadgets are where an
under-constrained circuit would come from, so enumerating them one per program
covers the space a random walk only samples.

The programs are deliberately minimal, which is the other half of the point: a
few opcodes each, so the solver decides them exactly, with no range budget cut
and no abstraction. A `unsafe` verdict here is about one operation and comes
with a machine-checked certificate.
"""

from __future__ import annotations

import argparse
import itertools
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PROVER = HERE / "make_prover_toml.py"

UINTS = ["u8", "u16", "u32", "u64", "u128"]
SINTS = ["i8", "i16", "i32", "i64"]
INTS = UINTS + SINTS
NUMERIC = ["Field"] + INTS

# Noir reports its own under-constrained findings at this level; a program it
# flags is the programmer's fault and proves nothing about the compiler.
COMPILER_FLAG = "bug:"

# BN254 scalar field, the only field Noir targets today.
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def casts() -> list[tuple[str, str]]:
    """Every cast the language accepts, as (name, body)."""
    out = []
    for source, target in itertools.product(NUMERIC, NUMERIC):
        if source == target:
            continue
        # Only unsigned integers may be cast to `Field`.
        if target == "Field" and source in SINTS:
            continue
        out.append((
            f"cast_{source}_to_{target}",
            f"fn main(a: {source}) -> pub {target} {{ a as {target} }}",
        ))
    return out


def arithmetic() -> list[tuple[str, str]]:
    out = []
    for ty in NUMERIC:
        for op, name in [("+", "add"), ("-", "sub"), ("*", "mul")]:
            out.append((
                f"{name}_{ty}",
                f"fn main(a: {ty}, b: {ty}) -> pub {ty} {{ a {op} b }}",
            ))
    for ty in INTS:
        for op, name in [("/", "div"), ("%", "rem")]:
            # Guard the divisor so the honest run has something to do.
            guard = "| 1" if ty in UINTS else "| 1"
            out.append((
                f"{name}_{ty}",
                f"fn main(a: {ty}, b: {ty}) -> pub {ty} {{ a {op} (b {guard}) }}",
            ))
    out.append((
        "div_field",
        "fn main(a: Field, b: Field) -> pub Field { assert(b != 0); a / b }",
    ))
    return out


def shifts() -> list[tuple[str, str]]:
    return [
        (
            f"{name}_{ty}",
            f"fn main(a: {ty}, s: {ty}) -> pub {ty} {{ a {op} (s % {bits}) }}",
        )
        for ty, bits in [("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("u128", 128)]
        for op, name in [("<<", "shl"), (">>", "shr")]
    ]


def comparisons() -> list[tuple[str, str]]:
    out = []
    for ty in NUMERIC:
        operators = ["==", "!="] if ty == "Field" else ["==", "!=", "<", "<=", ">", ">="]
        for op in operators:
            name = {"==": "eq", "!=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge"}[op]
            out.append((
                f"cmp_{name}_{ty}",
                f"fn main(a: {ty}, b: {ty}) -> pub bool {{ a {op} b }}",
            ))
    return out


def bitwise() -> list[tuple[str, str]]:
    return [
        (f"{name}_{ty}", f"fn main(a: {ty}, b: {ty}) -> pub {ty} {{ a {op} b }}")
        for ty in INTS
        for op, name in [("&", "and"), ("|", "or"), ("^", "xor")]
    ]


def memory() -> list[tuple[str, str]]:
    out = []
    for length in (2, 4, 8):
        out.append((
            f"array_read_{length}",
            f"fn main(a: [Field; {length}], i: u32) -> pub Field {{ a[i % {length}] }}",
        ))
        out.append((
            f"array_write_{length}",
            f"fn main(a: [Field; {length}], i: u32, v: Field) -> pub Field {{\n"
            f"    let mut b = a;\n"
            f"    b[i % {length}] = v;\n"
            f"    b[({length} - 1) - (i % {length})]\n"
            f"}}",
        ))
        out.append((
            f"array_guarded_{length}",
            f"fn main(a: [Field; {length}], i: u32) -> pub Field {{\n"
            f"    if i < {length} {{ a[i] }} else {{ 0 }}\n"
            f"}}",
        ))
    out.append((
        "vector_push_pop",
        "fn main(a: Field, b: Field, c: bool) -> pub Field {\n"
        "    let mut v: [Field] = @[a, b];\n"
        "    if c { v = v.push_back(a); } else { v = v.push_front(b); }\n"
        "    v[1]\n"
        "}",
    ))
    return out


def conditionals() -> list[tuple[str, str]]:
    return [
        (
            f"predicated_{ty}",
            f"fn main(a: {ty}, b: {ty}, c: bool) -> pub {ty} {{\n"
            f"    let mut out = a;\n"
            f"    if c {{ out = a + b; }}\n"
            f"    out\n"
            f"}}",
        )
        for ty in NUMERIC
    ]


def compositions() -> list[tuple[str, str]]:
    """Each primitive placed inside a construct that changes how it is lowered.

    Single operations are the obvious place to look and the least likely place
    to find anything: they are small, heavily used, and heavily tested. The
    published advisories cluster one level up, on the interaction — a slice
    operation under a condition, a fold across a disabled predicate, an array
    only used inside a loop condition. What breaks is the *combination*, where
    one pass has to preserve what another pass assumed.

    So each primitive is wrapped six ways: under a predicate, inside a loop,
    behind an array write, inside a nested conditional, inside a vector push,
    and inside a `#[fold]` function.

    `#[fold]` deserves its own note. It is the one construct that stops a
    function being inlined, so the program compiles to *several* ACIR circuits
    joined by `Opcode::Call` instead of one flat circuit. That is a different
    code path in the compiler, it is used far less than the inlined one, and no
    fuzzer targets it — which is exactly the combination that leaves bugs
    alive.
    """
    primitives = [
        ("cast_u128", "Field", "u128", "({x} as u128)"),
        ("cast_u64", "Field", "u64", "({x} as u64)"),
        ("cast_u32", "u64", "u32", "({x} as u32)"),
        ("cast_i32", "u32", "i32", "({x} as i32)"),
        ("div_u32", "u32", "u32", "({x} / ({x} | 1))"),
        ("rem_u64", "u64", "u64", "({x} % ({x} | 1))"),
        ("div_i32", "i32", "i32", "({x} / ({x} | 1))"),
        ("shl_u32", "u32", "u32", "({x} << ({x} % 32))"),
        ("shr_u64", "u64", "u64", "({x} >> ({x} % 64))"),
        ("lt_u32", "u32", "bool", "({x} < 7)"),
        ("xor_u32", "u32", "u32", "({x} ^ 4919)"),
        ("inv_field", "Field", "Field", "(if {x} == 0 { 0 } else { 1 / {x} })"),
    ]

    out = []
    for name, source, target, body in primitives:
        expr = body.replace("{x}", "a")
        zero = "false" if target == "bool" else "0"

        out.append((
            f"pred_{name}",
            f"fn main(a: {source}, c: bool) -> pub {target} {{\n"
            f"    let mut out: {target} = {zero};\n"
            f"    if c {{ out = {expr}; }}\n"
            f"    out\n"
            f"}}",
        ))
        out.append((
            f"loop_{name}",
            f"fn main(a: {source}) -> pub {target} {{\n"
            f"    let mut out: {target} = {zero};\n"
            f"    for _i in 0..3 {{ out = {expr}; }}\n"
            f"    out\n"
            f"}}",
        ))
        out.append((
            f"array_{name}",
            f"fn main(a: {source}, i: u32) -> pub {target} {{\n"
            f"    let mut v: [{target}; 4] = [{zero}; 4];\n"
            f"    v[i % 4] = {expr};\n"
            f"    v[(i + 1) % 4]\n"
            f"}}",
        ))
        out.append((
            f"nested_{name}",
            f"fn main(a: {source}, c: bool, d: bool) -> pub {target} {{\n"
            f"    let mut out: {target} = {zero};\n"
            f"    if c {{ if d {{ out = {expr}; }} else {{ out = {zero}; }} }}\n"
            f"    out\n"
            f"}}",
        ))
        out.append((
            f"fold_{name}",
            f"#[fold]\n"
            f"fn helper(a: {source}) -> {target} {{ {expr} }}\n\n"
            f"fn main(a: {source}, b: {source}) -> pub {target} {{\n"
            f"    let _unused = helper(b);\n"
            f"    helper(a)\n"
            f"}}",
        ))
        out.append((
            f"vector_{name}",
            f"fn main(a: {source}, c: bool) -> pub {target} {{\n"
            f"    let mut v: [{target}] = @[{zero}, {zero}];\n"
            f"    if c {{ v = v.push_back({expr}); }} else {{ v = v.push_front({expr}); }}\n"
            f"    v[1]\n"
            f"}}",
        ))
    return out


def stdlib() -> list[tuple[str, str]]:
    """Library functions written in constrained Noir.

    These sit a level above the primitives and below whole programs: real code
    calls them constantly, and each carries its own soundness argument that the
    primitives underneath do not supply. `to_le_bits` has to prove the bits
    recompose to the field element and that there is only one such
    decomposition; `from_be_bytes` has to reject a byte string that overflows
    the field; `lt` and `sgn0` are the comparison machinery everything else is
    built on. A missing check in any of them is a soundness bug in every
    program that calls it.
    """
    out = [
        (
            "std_to_le_bits",
            "fn main(a: Field) -> pub [bool; 8] { a.to_le_bits() }",
        ),
        (
            "std_to_be_bits",
            "fn main(a: Field) -> pub [bool; 8] { a.to_be_bits() }",
        ),
        (
            "std_to_le_bytes",
            "fn main(a: Field) -> pub [u8; 4] { a.to_le_bytes() }",
        ),
        (
            "std_to_be_bytes",
            "fn main(a: Field) -> pub [u8; 4] { a.to_be_bytes() }",
        ),
        (
            "std_from_le_bytes",
            "fn main(a: [u8; 4]) -> pub Field { Field::from_le_bytes(a) }",
        ),
        (
            "std_from_be_bytes",
            "fn main(a: [u8; 4]) -> pub Field { Field::from_be_bytes(a) }",
        ),
        (
            "std_from_le_bytes_checked",
            "fn main(a: [u8; 4]) -> pub Field { Field::from_le_bytes_checked(a) }",
        ),
        (
            "std_from_be_bytes_checked",
            "fn main(a: [u8; 4]) -> pub Field { Field::from_be_bytes_checked(a) }",
        ),
        (
            "std_assert_max_bit_size",
            "fn main(a: Field) -> pub Field { a.assert_max_bit_size::<16>(); a }",
        ),
        (
            "std_field_lt",
            "fn main(a: Field, b: Field) -> pub bool { a.lt(b) }",
        ),
        (
            "std_field_sgn0",
            "fn main(a: Field) -> pub bool { a.sgn0() }",
        ),
        (
            "std_field_pow32",
            "fn main(a: Field, b: u8) -> pub Field { a.pow_32((b % 8) as Field) }",
        ),
        (
            "std_roundtrip_le_bytes",
            "fn main(a: u32) -> pub Field {\n"
            "    let bytes: [u8; 4] = (a as Field).to_le_bytes();\n"
            "    Field::from_le_bytes(bytes)\n"
            "}",
        ),
        (
            "std_roundtrip_bits",
            "fn main(a: Field) -> pub Field {\n"
            "    let bits: [bool; 16] = a.to_le_bits();\n"
            "    let mut out: Field = 0;\n"
            "    for i in 0..16 { out += (bits[15 - i] as Field) * 2 * out; }\n"
            "    out\n"
            "}",
        ),
    ]
    for ty in ("u8", "u16", "u32", "u64"):
        out.append((
            f"std_min_{ty}",
            f"fn main(a: {ty}, b: {ty}) -> pub {ty} {{ if a < b {{ a }} else {{ b }} }}",
        ))
        for name, method in [("add", "wrapping_add"), ("sub", "wrapping_sub"), ("mul", "wrapping_mul")]:
            out.append((
                f"std_wrapping_{name}_{ty}",
                f"use std::ops::{{WrappingAdd, WrappingSub, WrappingMul}};\n\n"
                f"fn main(a: {ty}, b: {ty}) -> pub {ty} {{ a.{method}(b) }}",
            ))
    return out


def hashes() -> list[tuple[str, str]]:
    """The hash and curve gadgets real circuits are built on.

    Every non-trivial ZK program hashes something, so these dominate the
    constraint count of anything real. They also mark the edge of what this
    crate can evaluate: their semantics live in the proving backend, not in
    ACIR, so a witness that reaches one of them can be neither confirmed nor
    refuted here. Auditing them is worth it precisely to see that edge
    reported honestly rather than as a clean result.
    """
    return [
        (
            "hash_poseidon2_permutation",
            "fn main(a: Field, b: Field, c: Field, d: Field) -> pub [Field; 4] {\n"
            "    std::hash::poseidon2_permutation([a, b, c, d])\n"
            "}",
        ),
        (
            "hash_blake2s",
            "fn main(a: [u8; 4]) -> pub [u8; 32] { std::hash::blake2s(a) }",
        ),
        (
            "hash_blake3",
            "fn main(a: [u8; 4]) -> pub [u8; 32] { std::hash::blake3(a) }",
        ),
        (
            "hash_keccakf1600",
            "fn main(a: [u64; 25]) -> pub [u64; 25] { std::hash::keccakf1600(a) }",
        ),
        (
            "hash_sha256_compression",
            "fn main(a: [u32; 16], b: [u32; 8]) -> pub [u32; 8] {\n"
            "    std::hash::sha256_compression(a, b)\n"
            "}",
        ),
        (
            "hash_pedersen_commitment",
            "fn main(a: Field, b: Field) -> pub Field {\n"
            "    std::hash::pedersen_commitment([a, b]).x\n"
            "}",
        ),
        (
            "hash_pedersen",
            "fn main(a: Field, b: Field) -> pub Field {\n"
            "    std::hash::pedersen_hash([a, b])\n"
            "}",
        ),
        (
            "curve_multi_scalar_mul",
            "fn main(a: Field) -> pub Field {\n"
            "    let g = std::embedded_curve_ops::EmbeddedCurvePoint::generator();\n"
            "    let s = std::embedded_curve_ops::EmbeddedCurveScalar::new(a, 0);\n"
            "    std::embedded_curve_ops::multi_scalar_mul([g], [s]).x\n"
            "}",
        ),
    ]


def field_widths() -> list[tuple[str, str]]:
    """Generic gadgets instantiated at the edge of the field.

    The one advisory that allowed proof forgery was a bound sitting exactly at
    the top of the field: a quotient range that left `p / 2^128` reachable. The
    generic width parameters in the standard library are where that same
    question is asked over and over — `to_le_bits::<N>` has to prove a unique
    decomposition, `assert_max_bit_size::<N>` has to prove a bound — and the
    answer only gets interesting as `N` approaches the 254 bits of the field.
    A suite that only ever instantiates them at 8 or 32 never asks.
    """
    out = []
    for bits in (1, 2, 127, 128, 129, 200, 253, 254):
        out.append((
            f"width_to_le_bits_{bits}",
            f"fn main(a: Field) -> pub bool {{\n"
            f"    let bits: [bool; {bits}] = a.to_le_bits();\n"
            f"    bits[{bits - 1}]\n"
            f"}}",
        ))
        # The compiler rejects a width that is not strictly below the modulus
        # bit count, so 253 is the top of this ladder.
        if bits < 254:
            out.append((
                f"width_assert_max_bit_size_{bits}",
                f"fn main(a: Field) -> pub Field {{ a.assert_max_bit_size::<{bits}>(); a }}",
            ))
    for bytes_len in (1, 2, 15, 16, 17, 31, 32):
        out.append((
            f"width_to_le_bytes_{bytes_len}",
            f"fn main(a: Field) -> pub u8 {{\n"
            f"    let bytes: [u8; {bytes_len}] = a.to_le_bytes();\n"
            f"    bytes[{bytes_len - 1}]\n"
            f"}}",
        ))
        out.append((
            f"width_from_le_bytes_{bytes_len}",
            f"fn main(a: [u8; {bytes_len}]) -> pub Field {{ Field::from_le_bytes(a) }}",
        ))
    return out


# One operation each, as (name, input type, output type, body template). The
# pair generator chains them, so the output type of the first has to be usable
# as the input of the second.
CHAINABLE = [
    ("castu128", "Field", "u128", "({x} as u128)"),
    ("castu32", "Field", "u32", "({x} as u32)"),
    ("castfield", "u32", "Field", "({x} as Field)"),
    ("divu32", "u32", "u32", "({x} / ({x} | 1))"),
    ("remu32", "u32", "u32", "({x} % ({x} | 1))"),
    ("shlu32", "u32", "u32", "({x} << ({x} % 32))"),
    ("shru32", "u32", "u32", "({x} >> ({x} % 32))"),
    ("xoru32", "u32", "u32", "({x} ^ 4919)"),
    ("mulu32", "u32", "u32", "({x} * ({x} % 4))"),
    ("subu32", "u32", "u32", "({x} - ({x} % 4))"),
    ("divu128", "u128", "u128", "({x} / ({x} | 1))"),
    ("shru128", "u128", "u128", "({x} >> ({x} % 128))"),
    ("castu8", "u32", "u8", "({x} as u8)"),
    ("addfield", "Field", "Field", "({x} + {x})"),
]


def pairs() -> list[tuple[str, str]]:
    """Two primitives chained, output of one into the input of the next.

    Single operations are individually simple and individually well tested.
    What is neither is the seam between two of them: one pass lowers a cast
    assuming a bound another pass is responsible for, an optimiser folds a
    shift through a division, a truncation lands on a value that a previous
    truncation already narrowed. Every published advisory about ACIR generation
    is a seam like that, and a suite of single operations never puts two of
    them together.

    The set is finite and small — chaining is only defined where the types line
    up — which is the whole appeal compared to hoping a random program stumbles
    onto the right pair.
    """
    out = []
    for first_name, first_in, first_out, first_body in CHAINABLE:
        for second_name, second_in, second_out, second_body in CHAINABLE:
            if first_out != second_in:
                continue
            inner = first_body.replace("{x}", "a")
            outer = second_body.replace("{x}", "t")
            out.append((
                f"pair_{first_name}_{second_name}",
                f"fn main(a: {first_in}) -> pub {second_out} {{\n"
                f"    let t: {first_out} = {inner};\n"
                f"    {outer}\n"
                f"}}",
            ))
    return out


def gadgets() -> list[tuple[str, str]]:
    return (
        casts() + arithmetic() + shifts() + comparisons()
        + bitwise() + memory() + conditionals() + compositions() + stdlib()
        + hashes() + field_widths() + pairs()
    )


# Values assigned positionally to the parameters, one row per attempt. The
# rows are chosen so that a two-argument gadget sees both orderings and a
# couple of small magnitudes.
INPUT_GRID = [(7, 3), (3, 7), (1, 1), (9, 2), (2, 9), (5, 0)]


def write_grid_inputs(artifact: pathlib.Path, case: pathlib.Path, row) -> bool:
    """Write a `Prover.toml` assigning `row` positionally. False if unsupported."""
    abi = json.loads(artifact.read_text()).get("abi", {})
    parameters = abi.get("parameters", [])
    if not parameters:
        return False

    lines = []
    for index, parameter in enumerate(parameters):
        kind = parameter["type"].get("kind")
        value = row[index % len(row)]
        if kind == "boolean":
            rendered = json.dumps(bool(value % 2))
        elif kind in ("field", "integer"):
            rendered = json.dumps(str(value))
        else:
            return False
        lines.append(f"{parameter['name']} = {rendered}")
    (case / "Prover.toml").write_text("\n".join(lines) + "\n")
    return True


def run(cmd, cwd=None, timeout=180):
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def audit_one(args, name: str, source: str) -> tuple[str, dict | None]:
    case = args.work / name
    shutil.rmtree(case, ignore_errors=True)
    (case / "src").mkdir(parents=True)
    (case / "Nargo.toml").write_text(
        f'[package]\nname = "g_{name}"\ntype = "bin"\nauthors = [""]\n'
    )
    (case / "src" / "main.nr").write_text(source + "\n")

    compiled = run([args.nargo, "compile", "--force", "--silence-warnings"], cwd=case)
    if compiled.returncode != 0:
        return "compile_failed", None
    if COMPILER_FLAG in compiled.stderr + compiled.stdout:
        return "self_flagged", None
    artifacts = sorted((case / "target").glob("*.json"))
    if not artifacts:
        return "no_artifact", None

    # A fixed grid before any random draw. Random values leave whole gadgets
    # unexercised by bad luck: `a - b` on unsigned integers only runs when
    # `a >= b`, and four independent draws left every subtraction gadget in the
    # suite without a single honest run. The grid puts both orderings and a few
    # small values on the table by construction.
    report = None
    for draw in range(args.draws + len(INPUT_GRID)):
        if draw < len(INPUT_GRID):
            if not write_grid_inputs(artifacts[0], case, INPUT_GRID[draw]):
                continue
        else:
            made = run([sys.executable, str(PROVER), str(case),
                        "--artifact", str(artifacts[0]),
                        "--seed", str(draw - len(INPUT_GRID))])
            if made.returncode != 0:
                return "prover_toml_failed", None
        if run([args.nargo, "execute", "--silence-warnings"], cwd=case).returncode != 0:
            continue
        witnesses = sorted((case / "target").glob("*.gz"))
        if not witnesses:
            continue

        searched = run([args.adapter, "mutate", str(artifacts[0]),
                        "--witness", str(witnesses[0]),
                        "--attempts", str(args.attempts), "--format", "json"])
        if not searched.stdout.strip():
            return "mutate_failed", None
        report = json.loads(searched.stdout)
        if report["findings"]:
            keep = args.out / name
            shutil.rmtree(keep, ignore_errors=True)
            keep.mkdir(parents=True)
            shutil.copy(case / "src" / "main.nr", keep / "main.nr")
            shutil.copy(case / "Prover.toml", keep / "Prover.toml")
            shutil.copy(artifacts[0], keep / "artifact.json")
            (keep / "findings.json").write_text(json.dumps(report, indent=2))
            return "finding", report

    rejected = boundary_rejections(args, case, artifacts[0], name)
    if rejected:
        return "accepts_rejected", None

    if report is None:
        return "no_honest_run", None
    # A gadget whose search never saw a single hint was not checked, it was
    # skipped. Reporting that as "clean" is the worst possible answer: it reads
    # as coverage where there is none. `#[fold]` programs looked exactly like
    # this until every circuit of the program was searched rather than only the
    # entry one.
    funnel = report["funnel"]
    # A gadget counts as searched when at least one attempt was *decided*:
    # either a constraint refuted it, or a full assignment was accepted.
    #
    # Refutation matters here and it is easy to get wrong. An attempt the
    # forward solve abandons half-way is no information, but an attempt a
    # constraint rejects is the circuit doing its job — that is the answer, not
    # the absence of one. Conflating the two reported 27 of 30 well-constrained
    # width gadgets as unsearched.
    decided = funnel.get("refuted", 0) + funnel["accepted"]
    if funnel["hints"] == 0 or decided == 0:
        return "vacuous", report
    if funnel["accepted"] == 0 and funnel.get("unjudged", 0) >= decided:
        return "unjudged", report
    return "clean", report


def boundary_values(abi_type: dict) -> list:
    """The inputs an operation is most likely to be mishandled at."""
    kind = abi_type.get("kind")
    if kind == "boolean":
        return [True, False]
    if kind == "field":
        return ["0", "1", "2"]
    if kind == "integer":
        width = abi_type.get("width", 32)
        if abi_type.get("sign") == "signed":
            top = (1 << (width - 1)) - 1
            # `INT_MIN / -1` is the case a published advisory guarded with an
            # off-by-one bound, so the guard never fired.
            return [str(v) for v in (0, 1, -1, top, -top - 1)]
        top = (1 << width) - 1
        return [str(v) for v in (0, 1, 2, top - 1, top)]
    return []


def boundary_rejections(args, case, artifact, name: str):
    """Look for boundary inputs the program rejects but the circuit accepts.

    An overflow check, a division-by-zero guard, an out-of-range index — each
    is a rejection the source makes and the circuit is supposed to inherit.
    They only ever misbehave at the edge of a type's range, which a random draw
    essentially never reaches, so the edges are enumerated instead.
    """
    abi = json.loads(artifact.read_text()).get("abi", {})
    parameters = abi.get("parameters", [])
    if not parameters or any(
        parameter["type"].get("kind") not in ("field", "integer", "boolean")
        for parameter in parameters
    ):
        return None

    columns = [boundary_values(parameter["type"]) for parameter in parameters]
    if any(not column for column in columns):
        return None

    honest_toml = case / "Prover.toml"
    for combination in itertools.islice(itertools.product(*columns), args.boundary_limit):
        lines = []
        flat = []
        for parameter, value in zip(parameters, combination):
            lines.append(f"{parameter['name']} = {json.dumps(value)}")
            flat.append(1 if value is True else 0 if value is False else int(value) % PRIME)
        honest_toml.write_text("\n".join(lines) + "\n")

        executed = run([args.nargo, "execute", "--silence-warnings"], cwd=case)
        if executed.returncode == 0:
            continue
        if "Failed to deserialize inputs" in executed.stderr + executed.stdout:
            continue

        inputs = json.dumps({str(i): str(v) for i, v in enumerate(flat)})
        asked = run([args.adapter, "feasible", str(artifact), "--inputs", inputs,
                     "--timeout", "8000"], timeout=25)
        if asked.returncode != 0 or asked.stdout.strip() != "accepted":
            continue

        keep = args.out / f"rejects_{name}"
        shutil.rmtree(keep, ignore_errors=True)
        keep.mkdir(parents=True)
        shutil.copy(case / "src" / "main.nr", keep / "main.nr")
        shutil.copy(honest_toml, keep / "accepting.toml")
        shutil.copy(artifact, keep / "artifact.json")
        (keep / "nargo_error.txt").write_text((executed.stderr or executed.stdout)[:4000])
        return combination
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--draws", type=int, default=4)
    parser.add_argument("--boundary-limit", type=int, default=40,
                        help="boundary input combinations to try per gadget")
    parser.add_argument("--only", help="substring filter over gadget names")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)

    tally: dict[str, int] = {}
    for name, source in gadgets():
        if args.only and args.only not in name:
            continue
        try:
            outcome, _ = audit_one(args, name, source)
        except subprocess.TimeoutExpired:
            outcome = "timeout"
        tally[outcome] = tally.get(outcome, 0) + 1
        marker = {
            "clean": ".",
            "finding": "!",
            "accepts_rejected": "!",
            "self_flagged": "s",
            "vacuous": "-",
            "unjudged": "?",
        }.get(outcome, "x")
        sys.stdout.write(marker)
        sys.stdout.flush()
        if outcome in ("finding", "accepts_rejected"):
            print(f"\n*** {outcome}: {name}", flush=True)
        shutil.rmtree(args.work / name, ignore_errors=True)

    print(f"\n{sum(tally.values())} gadgets audited")
    print("outcomes:", json.dumps(tally, sort_keys=True))


if __name__ == "__main__":
    main()

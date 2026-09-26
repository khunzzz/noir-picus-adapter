#!/usr/bin/env python3
"""Generate programs in the shapes that stress the risk-bearing SSA passes.

Noir's own generator produces broad, generic programs. The passes most likely to
be wrong are narrower than that: conditional array writes whose result leaves the
conditional window, references aliasing the same storage, loops whose bounds come
from data, and chains of casts between widths. This generator only builds those.

Each program is emitted with the value it must produce, computed here in Python
from the same semantics. That makes the check a real oracle rather than a
comparison of the compiler against itself: a mismatch is wrong output, not merely
a disagreement.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import shutil
import subprocess
import time

UNSTABLE = ["-Z", "enums"]

# Marks a case whose expected outcome is that the program refuses to run.
MUST_FAIL = "<must-fail>"


def run(cmd, cwd=None, timeout=200):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def gen_conditional_writes(rng: random.Random):
    """Conditional array writes whose result escapes the conditional."""
    size = rng.choice([2, 4, 8])
    base = [rng.randrange(0, 50) for _ in range(size)]
    steps = []
    expected = list(base)
    params, values = [], {}
    for step in range(rng.randrange(1, 5)):
        cond = rng.random() < 0.5
        idx = rng.randrange(0, size)
        val = rng.randrange(0, 50)
        params.append(f"c{step}: bool")
        values[f"c{step}"] = "1" if cond else "0"
        steps.append(f"    if c{step} {{ arr[{idx}] = {val}; }}")
        if cond:
            expected[idx] = val
    body = "\n".join(steps)
    source = (
        f"fn main({', '.join(params)}) -> pub [Field; {size}] {{\n"
        f"    let mut arr: [Field; {size}] = {base};\n"
        f"{body}\n"
        f"    arr\n}}\n"
    )
    return source, values, "[" + ", ".join(str(v) for v in expected) + "]"


def gen_dynamic_index(rng: random.Random):
    """Writes and reads at indices that come from inputs."""
    size = rng.choice([4, 8])
    base = [rng.randrange(0, 50) for _ in range(size)]
    write_at = rng.randrange(0, size)
    read_at = rng.randrange(0, size)
    val = rng.randrange(0, 50)
    cond = rng.random() < 0.5
    expected = list(base)
    if cond:
        expected[write_at] = val
    source = (
        f"fn main(i: u32, j: u32, c: bool) -> pub Field {{\n"
        f"    let mut arr: [Field; {size}] = {base};\n"
        f"    if c {{ arr[i] = {val}; }}\n"
        f"    arr[j]\n}}\n"
    )
    values = {"i": str(write_at), "j": str(read_at), "c": "1" if cond else "0"}
    return source, values, str(expected[read_at])


def gen_cast_chain(rng: random.Random):
    """Chains of casts, where the width analysis drives overflow decisions."""
    widths = [8, 16, 32, 64]
    rng.shuffle(widths)
    start = rng.randrange(0, 200)
    chain, value = [], start
    for width in widths[:3]:
        chain.append(f" as u{width}")
        value %= 1 << width
    expr = "x" + "".join(chain)
    source = (
        f"fn main(x: u8) -> pub u{widths[2]} {{\n"
        f"    {expr}\n}}\n"
    )
    return source, {"x": str(start)}, str(value)


def gen_reference(rng: random.Random):
    """A `&mut` binding written under a predicate.

    Exercises the alias analysis and store forwarding: the write goes through a
    reference, so deciding whether it reaches the later read of `x` requires
    knowing the two name the same storage.
    """
    a = rng.randrange(0, 100)
    b = rng.randrange(0, 100)
    cond = rng.random() < 0.5
    source = (
        "fn main(a: Field, b: Field, c: bool) -> pub Field {\n"
        "    let mut x = a;\n"
        "    let r = &mut x;\n"
        "    if c { *r = b; }\n"
        "    x\n}\n"
    )
    values = {"a": str(a), "b": str(b), "c": "1" if cond else "0"}
    return source, values, str(b if cond else a)


def gen_nested_array(rng: random.Random):
    """A conditional write into a nested array, read back at swapped indices."""
    grid = [[rng.randrange(0, 50) for _ in range(2)] for _ in range(2)]
    i, j = rng.randrange(0, 2), rng.randrange(0, 2)
    val = rng.randrange(0, 50)
    cond = rng.random() < 0.5
    expected = [row[:] for row in grid]
    if cond:
        expected[i][j] = val
    literal = "[" + ", ".join("[" + ", ".join(str(v) for v in row) + "]" for row in grid) + "]"
    source = (
        "fn main(i: u32, j: u32, v: Field, c: bool) -> pub Field {\n"
        f"    let mut m: [[Field; 2]; 2] = {literal};\n"
        "    if c { m[i][j] = v; }\n"
        "    m[j][i]\n}\n"
    )
    values = {"i": str(i), "j": str(j), "v": str(val), "c": "1" if cond else "0"}
    return source, values, str(expected[j][i])


def gen_signed(rng: random.Random):
    """Signed arithmetic, kept inside the range so the program must succeed.

    `expand_signed_math` and `expand_signed_checks` rewrite these into unsigned
    operations plus explicit checks, which is a rewrite worth testing directly.
    """
    a = rng.randrange(-60, 60)
    b = rng.randrange(-60, 60)
    op = rng.choice(["+", "-", "*"])
    if op == "*":
        a, b = rng.randrange(-11, 11), rng.randrange(-11, 11)
    value = {"+": a + b, "-": a - b, "*": a * b}[op]
    if not -128 <= value <= 127:
        return gen_signed(rng)
    source = f"fn main(a: i8, b: i8) -> pub i8 {{\n    a {op} b\n}}\n"
    return source, {"a": str(a), "b": str(b)}, str(value)


def gen_shift(rng: random.Random):
    """A dynamic shift, kept where the result fits so the program must succeed.

    `remove_bit_shifts` turns these into multiplications and divisions by powers
    of two, which is where a width mistake would show.
    """
    shift = rng.randrange(0, 8)
    x = rng.randrange(0, (1 << (16 - shift)))
    # Both operands of a shift must share a bit width in Noir.
    source = "fn main(x: u16, s: u16) -> pub u16 {\n    x << s\n}\n"
    return source, {"x": str(x), "s": str(shift)}, str((x << shift) % (1 << 16))


def gen_vector(rng: random.Random):
    """A vector built by pushes, then indexed.

    Vectors carry a length the compiler tracks separately from the data, which
    is a second thing to get wrong.
    """
    values = [rng.randrange(0, 60) for _ in range(rng.randrange(2, 5))]
    read_at = rng.randrange(0, len(values))
    pushes = "\n".join(f"    v = v.push_back({value});" for value in values)
    source = (
        "fn main(i: u32) -> pub Field {\n"
        "    let mut v: [Field] = [].as_vector();\n"
        f"{pushes}\n"
        "    v[i]\n}\n"
    )
    return source, {"i": str(read_at)}, str(values[read_at])


def gen_struct(rng: random.Random):
    """A struct field updated under a predicate, then read back."""
    a, b, c = (rng.randrange(0, 60) for _ in range(3))
    cond = rng.random() < 0.5
    source = (
        "struct Pair { left: Field, right: Field }\n\n"
        "fn main(c: bool, v: Field) -> pub Field {\n"
        f"    let mut p = Pair {{ left: {a}, right: {b} }};\n"
        "    if c { p.left = v; }\n"
        "    p.left + p.right\n}\n"
    )
    left = c if cond else a
    return source, {"c": "1" if cond else "0", "v": str(c)}, str(left + b)


def gen_loop_predicate(rng: random.Random):
    """A loop whose body is predicated on data.

    `break` is rejected in constrained code — "constrained code must always have
    a known number of loop iterations" — so the data-dependent trip count is
    expressed as a predicate on the body instead, which is what the compiler
    would have produced anyway.
    """
    limit = rng.randrange(1, 6)
    expected = sum(k for k in range(8) if k < limit)
    source = (
        "fn main(limit: u32) -> pub u32 {\n"
        "    let mut total: u32 = 0;\n"
        "    for k in 0..8 {\n"
        "        if k < limit { total += k; }\n"
        "    }\n"
        "    total\n}\n"
    )
    return source, {"limit": str(limit)}, str(expected)


def gen_must_overflow(rng: random.Random):
    """Arithmetic that has to overflow, so the program has to reject it.

    A case whose expected outcome is *failure* is as much an oracle as one with a
    number, and it aims at a different thing: the passes that decide an overflow
    check is unnecessary. If any of them is wrong, the program quietly succeeds
    where it must not.
    """
    width = rng.choice([8, 16, 32, 64])
    top = (1 << width) - 1
    op = rng.choice(["+", "*", "-"])
    if op == "+":
        a, b = rng.randrange(top // 2 + 1, top + 1), rng.randrange(top // 2 + 1, top + 1)
    elif op == "*":
        a, b = rng.randrange(1 << (width // 2), top + 1), rng.randrange(1 << (width // 2), top + 1)
        if a * b <= top:
            a, b = top, top
    else:
        a = rng.randrange(0, top // 2)
        b = rng.randrange(a + 1, top + 1)
    source = f"fn main(a: u{width}, b: u{width}) -> pub u{width} {{\n    a {op} b\n}}\n"
    return source, {"a": str(a), "b": str(b)}, MUST_FAIL


def gen_must_index_out_of_bounds(rng: random.Random):
    """A read past the end of an array, which has to be rejected."""
    size = rng.choice([2, 4, 8])
    index = rng.randrange(size, size + 40)
    literal = "[" + ", ".join(str(rng.randrange(0, 50)) for _ in range(size)) + "]"
    source = (
        "fn main(i: u32) -> pub Field {\n"
        f"    let arr: [Field; {size}] = {literal};\n"
        "    arr[i]\n}\n"
    )
    return source, {"i": str(index)}, MUST_FAIL


def normalize(text: str) -> str:
    """Compare by value, not by spelling.

    `nargo` prints integer outputs in decimal and `Field` outputs in hex, so a
    string comparison reports every cast program as wrong. Ten of the first
    twenty cases failed that way before this was added — the values matched all
    along.
    """
    pieces = []
    for token in text.replace("[", "").replace("]", "").replace("(", "").replace(")", "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            pieces.append(str(int(token, 16) if token.startswith("0x") else int(token)))
        except ValueError:
            pieces.append(token)
    return ",".join(pieces)


GENERATORS = [
    gen_conditional_writes,
    gen_dynamic_index,
    gen_cast_chain,
    gen_reference,
    gen_nested_array,
    gen_signed,
    gen_shift,
    gen_vector,
    gen_struct,
    gen_loop_predicate,
    gen_must_overflow,
    gen_must_index_out_of_bounds,
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True)
    parser.add_argument("--keep", type=pathlib.Path, required=True)
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--brillig", action="store_true",
                        help="also run the same source as an `unconstrained fn main`. "
                             "That takes the Brillig pipeline instead of the ACIR one, so "
                             "a disagreement is one pipeline miscompiling what the other "
                             "gets right — the check Noir's own fuzzer performs, aimed "
                             "here at shapes chosen to stress the ACIR passes.")
    parser.add_argument("--adapter",
                        help="also check that the constraint system pins the output. "
                             "None of these programs contains a user-written hint, so "
                             "every Brillig call in them was emitted by the compiler "
                             "itself — for a division, a comparison, a cast. A hint the "
                             "compiler generated and failed to constrain is a codegen "
                             "defect, with none of the ambiguity that surrounds a hint a "
                             "person wrote.")
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    args.keep.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    counts = {"ok": 0, "wrong": 0, "skipped": 0, "unpinned": 0}
    started = time.time()

    for index in range(args.count):
        source, values, expected = rng.choice(GENERATORS)(rng)
        package = args.work / "case"
        if package.exists():
            shutil.rmtree(package)
        (package / "src").mkdir(parents=True)
        (package / "Nargo.toml").write_text(
            '[package]\nname = "case"\ntype = "bin"\nauthors = [""]\n')
        (package / "src" / "main.nr").write_text(source)
        (package / "Prover.toml").write_text(
            "\n".join(f'{k} = "{v}"' for k, v in values.items()) + "\n")

        seen = set()
        for level in ["-9223372036854775808", "0", "9223372036854775807"]:
            executed = run([args.nargo, "execute", "--force", "--silence-warnings",
                            *UNSTABLE, "--inliner-aggressiveness", level], cwd=package)
            if executed is None or executed.returncode != 0:
                seen.add("<failed>")
                continue
            line = [l for l in executed.stdout.splitlines() if "Circuit output" in l]
            seen.add(line[0].split("Circuit output: ")[-1].strip() if line else "<none>")

        if args.brillig:
            unconstrained = package.parent / "case_brillig"
            if unconstrained.exists():
                shutil.rmtree(unconstrained)
            shutil.copytree(package, unconstrained, ignore=shutil.ignore_patterns("target"))
            (unconstrained / "src" / "main.nr").write_text(
                source.replace("fn main(", "unconstrained fn main(", 1))
            executed = run([args.nargo, "execute", "--force", "--silence-warnings", *UNSTABLE],
                           cwd=unconstrained)
            if executed is not None and executed.returncode == 0:
                line = [l for l in executed.stdout.splitlines() if "Circuit output" in l]
                if line:
                    seen.add(line[0].split("Circuit output: ")[-1].strip())

        if expected is MUST_FAIL:
            # Every setting has to refuse. One that produces a number instead
            # accepted an overflow or a read past the end of an array.
            if seen == {"<failed>"}:
                counts["ok"] += 1
                print(".", end="", flush=True)
                continue
            counts["wrong"] += 1
            target = args.keep / f"accepted_{index:05d}"
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
            (target / "expected.txt").write_text(
                f"expected: the program must reject these inputs\ngot: {sorted(seen)}\n")
            print("A", end="", flush=True)
            continue

        seen = {normalize(item) for item in seen}
        expected = normalize(expected)
        if seen == {expected}:
            counts["ok"] += 1
            if args.adapter:
                artifact = next(iter(sorted((package / "target").glob("*.json"))), None)
                checked = run([args.adapter, "unpinned", str(artifact)]) if artifact else None
                if checked is not None and checked.returncode != 0:
                    counts["unpinned"] += 1
                    target = args.keep / f"unpinned_{index:05d}"
                    if target.exists():
                        shutil.rmtree(target)
                    shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
                    (target / "unpinned.txt").write_text(checked.stdout)
                    print("U", end="", flush=True)
                    continue
            print(".", end="", flush=True)
            continue
        if "<failed>" in seen and len(seen) == 1:
            counts["skipped"] += 1
            print("x", end="", flush=True)
            continue
        counts["wrong"] += 1
        target = args.keep / f"case_{index:05d}"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(package, target, ignore=shutil.ignore_patterns("target"))
        (target / "expected.txt").write_text(f"expected: {expected}\ngot: {sorted(seen)}\n")
        print("W", end="", flush=True)

    print(f"\n{args.count} cases in {time.time() - started:.1f}s")
    print(f"counts: {json.dumps(counts)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Expression-level reducer for a Noir program.

Line-based delta debugging is useless on generator output: a fuzzer emits whole
programs on a handful of very long lines, so deleting a line deletes everything.
This works on the structure instead — collapse a braced block to one of its
parts, drop a `match` arm, shrink a literal, delete a statement — and keeps any
rewrite that leaves the case interesting.

The predicate is an external command run in the package directory; exit 0 means
still interesting.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess


def matching(source: str, start: int) -> int:
    """Index just past the delimiter matching the one at `start`."""
    opening = source[start]
    closing = {"{": "}", "(": ")", "[": "]"}[opening]
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return -1


def blocks(source: str, opening: str) -> list[tuple[int, int]]:
    spans = []
    for index, character in enumerate(source):
        if character == opening:
            end = matching(source, index)
            if end > 0:
                spans.append((index, end))
    # Largest first: collapsing an outer block subsumes everything inside it.
    return sorted(spans, key=lambda span: span[0] - span[1])


def candidates(source: str) -> list[str]:
    """Every one-step simplification worth trying, roughly cheapest-first."""
    out = []

    # Replace an `unsafe { ... }` call with a plain use of a parameter, which
    # is what usually carries the interesting behaviour away.
    for match in re.finditer(r"unsafe\s*\{", source):
        end = matching(source, source.index("{", match.start()))
        if end > 0:
            out.append(source[: match.start()] + "a" + source[end:])

    # Collapse a braced block to its last statement.
    for start, end in blocks(source, "{"):
        inner = source[start + 1 : end - 1].strip()
        if not inner or "\n" not in inner:
            continue
        last = inner.rsplit(";", 1)[-1].strip()
        if last and last != inner:
            out.append(source[:start] + "{ " + last + " }" + source[end:])

    # Drop a `match` arm.
    for match in re.finditer(r"\n\s*[^\n]{1,120}=>", source):
        line_start = match.start()
        arrow = source.index("=>", line_start) + 2
        rest = source[arrow:].lstrip()
        end = matching(source, arrow + (len(source[arrow:]) - len(rest))) if rest[:1] in "{([" else source.find(",", arrow) + 1
        if end > arrow:
            tail = source[end:]
            if tail.lstrip().startswith(","):
                end = source.index(",", end) + 1
            out.append(source[:line_start] + source[end:])

    # Collapse a `match` to a single arm's body. Dropping arms one at a time
    # cannot remove the last one, and the scrutinee often keeps the whole
    # expression alive; this replaces the construct outright.
    for match in re.finditer(r"\bmatch\s+\w+\s*\{", source):
        brace = source.index("{", match.start())
        end = matching(source, brace)
        if end < 0:
            continue
        body = source[brace + 1 : end - 1]
        for arm in re.finditer(r"=>\s*", body):
            rest = body[arm.end() :]
            if rest[:1] in "{([":
                arm_end = matching(rest, 0)
                value = rest[:arm_end] if arm_end > 0 else None
            else:
                comma = rest.find(",")
                value = rest[:comma] if comma > 0 else None
            if value and value.strip():
                out.append(source[: match.start()] + value.strip() + source[end:])

    # Shrink a long numeric literal.
    for match in re.finditer(r"\b\d{6,}\b", source):
        out.append(source[: match.start()] + "3" + source[match.end() :])

    # Delete a whole statement line.
    lines = source.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip().endswith(";"):
            out.append("".join(lines[:index] + lines[index + 1 :]))

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("--predicate", required=True)
    parser.add_argument("--rounds", type=int, default=40)
    args = parser.parse_args()

    target = args.package / "src" / "main.nr"
    source = target.read_text()

    def interesting(candidate: str) -> bool:
        target.write_text(candidate)
        return subprocess.run([args.predicate], cwd=args.package,
                              capture_output=True, check=False).returncode == 0

    if not interesting(source):
        raise SystemExit("the predicate does not hold on the original program")

    for _ in range(args.rounds):
        for candidate in candidates(source):
            if len(candidate) < len(source) and interesting(candidate):
                source = candidate
                print(f"reduced to {len(source)} chars", flush=True)
                break
        else:
            break

    interesting(source)
    print(source)


if __name__ == "__main__":
    main()

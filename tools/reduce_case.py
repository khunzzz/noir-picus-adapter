#!/usr/bin/env python3
"""Line-based delta debugger for a Noir program.

Shrinks a program while a predicate keeps holding. Used to turn a fuzzer
finding — which is typically hundreds of lines of nested nonsense — into
something small enough to read and to file upstream.

The predicate is an external command run inside the package directory; a zero
exit status means "still interesting".
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess


def still_interesting(package: pathlib.Path, source: str, predicate: list[str]) -> bool:
    (package / "src" / "main.nr").write_text(source)
    return (
        subprocess.run(predicate, cwd=package, capture_output=True, check=False).returncode
        == 0
    )


def reduce(package: pathlib.Path, source: str, predicate: list[str]) -> str:
    lines = source.splitlines(keepends=True)
    chunk = max(len(lines) // 2, 1)

    while chunk >= 1:
        index = 0
        while index < len(lines):
            candidate = lines[:index] + lines[index + chunk:]
            if candidate and still_interesting(package, "".join(candidate), predicate):
                lines = candidate
            else:
                index += chunk
        if chunk == 1:
            break
        chunk = max(chunk // 2, 1)

    reduced = "".join(lines)
    still_interesting(package, reduced, predicate)
    return reduced


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("--predicate", required=True, nargs=argparse.REMAINDER,
                        help="command that exits 0 while the case is still interesting")
    args = parser.parse_args()

    source = (args.package / "src" / "main.nr").read_text()
    if not still_interesting(args.package, source, args.predicate):
        raise SystemExit("the predicate does not hold on the original program")

    reduced = reduce(args.package, source, args.predicate)
    print(reduced)


if __name__ == "__main__":
    main()

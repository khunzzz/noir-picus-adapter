#!/usr/bin/env python3
"""Recompile every checked-in Noir package into a sanitized ACIR artifact.

ACIR's serialization is not stable across Noir releases — between
`1.0.0-beta.21` and `1.0.0-beta.22` the `Circuit` tuple lost a field and `MemOp`
changed shape — so an artifact compiled by one `nargo` cannot be read by an
adapter built against a different `acir` revision. Whenever the pin in
`Cargo.toml` moves, every artifact in the repository has to be regenerated with
a matching `nargo`, which is what this script does.

Artifacts are sanitized down to `{noir_version, bytecode}`: debug symbols and
file maps embed absolute paths from the machine that compiled them, and source
text does not belong in a checked-in fixture.

    python3 corpus/regenerate_artifacts.py --nargo "$(which nargo)"
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def packages() -> list[tuple[pathlib.Path, pathlib.Path]]:
    """Every (package directory, output artifact) pair in the repository."""
    found: list[tuple[pathlib.Path, pathlib.Path]] = []

    for package in sorted((ROOT / "examples").iterdir()):
        if (package / "Nargo.toml").is_file():
            found.append((package, ROOT / "examples/artifacts" / f"{package.name}.json"))

    for package in sorted((ROOT / "corpus/vulnerable").iterdir()):
        if (package / "Nargo.toml").is_file():
            found.append((package, ROOT / "corpus/artifacts" / f"{package.name}.json"))

    for case in sorted((ROOT / "corpus/realistic").iterdir()):
        for variant in ("vulnerable", "fixed"):
            package = case / variant
            if (package / "Nargo.toml").is_file():
                found.append((
                    package,
                    ROOT / "corpus/realistic_artifacts" / f"{case.name}_{variant}.json",
                ))

    for package in sorted((ROOT / "corpus/compiler_regression").iterdir()):
        if (package / "Nargo.toml").is_file():
            found.append((
                package,
                ROOT / "corpus/compiler_regression_artifacts" / f"{package.name}.json",
            ))

    return found


def compile_package(nargo: str, package: pathlib.Path, artifact: pathlib.Path) -> str | None:
    """Compile one package and write its sanitized artifact. Returns an error."""
    target = package / "target"
    shutil.rmtree(target, ignore_errors=True)

    result = subprocess.run(
        [nargo, "compile", "--force", "--silence-warnings"],
        cwd=package,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return (result.stderr or result.stdout).strip().splitlines()[-1:][0] if (
            result.stderr or result.stdout
        ) else "nargo compile failed"

    produced = sorted(target.glob("*.json"))
    if not produced:
        return "nargo produced no artifact"

    compiled = json.loads(produced[0].read_text())
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {"noir_version": compiled["noir_version"], "bytecode": compiled["bytecode"]},
            indent=2,
        )
        + "\n"
    )
    shutil.rmtree(target, ignore_errors=True)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nargo", required=True)
    parser.add_argument("--only", help="substring filter over package paths")
    args = parser.parse_args()

    failures = []
    written = 0
    for package, artifact in packages():
        if args.only and args.only not in str(package):
            continue
        error = compile_package(args.nargo, package, artifact)
        if error:
            failures.append((package, error))
            sys.stdout.write("x")
        else:
            written += 1
            sys.stdout.write(".")
        sys.stdout.flush()

    print(f"\n{written} artifact(s) regenerated, {len(failures)} failure(s)")
    for package, error in failures:
        print(f"  {package.relative_to(ROOT)}: {error}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

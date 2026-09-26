#!/usr/bin/env python3
"""Rebuild a `Prover.toml` from an input assignment over ACIR witnesses.

The scanner reports input assignments as witness indices, because that is what
the constraint system speaks. Running the *program* on them needs the ABI form,
so this maps back: Noir lays the flattened parameters out over the first
witnesses in declaration order, and this walks the same order to invert it.

That layout is an assumption, so the script verifies it rather than trusting
it: the caller passes the honest assignment as well, and if re-encoding it does
not reproduce the values the honest run actually had, the mapping is wrong for
this program and the script refuses rather than emitting nonsense.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# BN254 scalar field, the only field Noir targets today.
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def slots(abi_type: dict) -> int:
    """How many witnesses a type occupies once flattened."""
    kind = abi_type.get("kind")
    if kind in ("field", "boolean", "integer"):
        return 1
    if kind == "string":
        return abi_type.get("length", 0)
    if kind == "array":
        return abi_type.get("length", 0) * slots(abi_type["type"])
    if kind == "tuple":
        return sum(slots(field) for field in abi_type.get("fields", []))
    if kind == "struct":
        return sum(slots(field["type"]) for field in abi_type.get("fields", []))
    raise ValueError(f"unsupported ABI kind {kind!r}")


def decode(abi_type: dict, values: list[int]):
    """Turn the next witnesses into the TOML value for `abi_type`."""
    kind = abi_type.get("kind")
    if kind == "field":
        # The scanner prints field elements signed, so `-1` can arrive here.
        # The ABI wants the canonical residue.
        return str(values.pop(0) % PRIME)
    if kind == "boolean":
        return bool(values.pop(0))
    if kind == "integer":
        raw = values.pop(0)
        if abi_type.get("sign") == "signed":
            # Two's complement within the type's width, not a field residue.
            width = abi_type.get("width", 32)
            if raw >= 1 << (width - 1):
                raw -= 1 << width
        return str(raw)
    if kind == "string":
        return "".join(chr(values.pop(0)) for _ in range(abi_type.get("length", 0)))
    if kind == "array":
        return [decode(abi_type["type"], values) for _ in range(abi_type.get("length", 0))]
    if kind == "tuple":
        return [decode(field, values) for field in abi_type.get("fields", [])]
    if kind == "struct":
        return {field["name"]: decode(field["type"], values) for field in abi_type["fields"]}
    raise ValueError(f"unsupported ABI kind {kind!r}")


def render(name: str, value) -> list[str]:
    if isinstance(value, dict):
        return [f"[{name}]"] + [f"{key} = {json.dumps(inner)}" for key, inner in value.items()]
    return [f"{name} = {json.dumps(value)}"]


def build(abi: dict, assignment: dict[int, int]) -> str:
    parameters = abi.get("parameters", [])
    total = sum(slots(parameter["type"]) for parameter in parameters)
    ordered = [assignment[index] for index in range(total)]

    lines: list[str] = []
    for parameter in parameters:
        lines.extend(render(parameter["name"], decode(parameter["type"], ordered)))
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--assignment", required=True,
                        help='JSON object mapping witness index to decimal value')
    parser.add_argument("--honest", required=True,
                        help="the same shape for the honest run, used to check the layout")
    parser.add_argument("--honest-toml", type=pathlib.Path, required=True,
                        help="the honest Prover.toml the honest assignment came from")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    abi = json.loads(args.artifact.read_text()).get("abi", {})
    honest = {int(k): int(v) % PRIME for k, v in json.loads(args.honest).items()}
    assignment = {int(k): int(v) % PRIME for k, v in json.loads(args.assignment).items()}

    try:
        rebuilt_honest = build(abi, honest)
    except (ValueError, KeyError, IndexError) as error:
        print(f"cannot invert the ABI layout: {error}", file=sys.stderr)
        raise SystemExit(2)

    # The layout assumption has to hold on the honest run before its result on
    # a mutated one means anything.
    if rebuilt_honest.split() != args.honest_toml.read_text().split():
        print("ABI layout check failed: honest inputs do not round-trip", file=sys.stderr)
        raise SystemExit(3)

    args.out.write_text(build(abi, assignment))


if __name__ == "__main__":
    main()

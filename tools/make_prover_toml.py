#!/usr/bin/env python3
"""Write a `Prover.toml` of concrete inputs for a Noir package.

The mutation search starts from an honest witness, and an honest witness comes
from `nargo execute`, which needs values for every parameter. Parsing them out
of the ABI in the compiled artifact is more reliable than re-parsing the source.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random


def value_for(abi_type: dict, rng: random.Random, booleans: list[bool] | None = None):
    kind = abi_type.get("kind")
    if kind == "boolean":
        # Walk the branch combinations rather than drawing them. A predicated
        # gadget only runs on one branch, so a draw that takes the other one
        # exercises nothing, and random draws can miss a combination entirely
        # across a handful of seeds.
        if booleans is not None:
            return booleans.pop(0) if booleans else rng.random() < 0.5
        return rng.random() < 0.5
    if kind == "field":
        if rng.random() < 0.2:
            return str(rng.choice([0, 1, 2]))
        return str(rng.randint(1, 1 << 32))
    if kind == "integer":
        width = abi_type.get("width", 32)
        # Small values on purpose. Generated programs multiply and add their
        # inputs, and Noir traps on integer overflow, so a wide draw mostly
        # produces runs that abort before they reach anything interesting —
        # measured at over half the cases wasted. Occasional edge values keep
        # the boundary cases reachable.
        if rng.random() < 0.15:
            top = (1 << width) - 1
            if abi_type.get("sign") == "signed":
                return str(rng.choice([0, 1, -1, (1 << (width - 1)) - 1, -(1 << (width - 1))]))
            return str(rng.choice([0, 1, 2, top, top - 1]))
        if abi_type.get("sign") == "signed":
            return str(rng.randint(-8, 8))
        return str(rng.randint(0, 15))
    if kind == "array":
        length = abi_type.get("length", 0)
        return [value_for(abi_type["type"], rng, booleans) for _ in range(length)]
    if kind == "tuple":
        return [value_for(field, rng, booleans) for field in abi_type.get("fields", [])]
    if kind == "struct":
        return {
            field["name"]: value_for(field["type"], rng, booleans)
            for field in abi_type.get("fields", [])
        }
    if kind == "string":
        return "a" * abi_type.get("length", 0)
    return "1"


# BN254 scalar field, the only field Noir targets today.
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def flatten(abi_type: dict, value, out: list[int]) -> None:
    """Append the field elements a value occupies, in witness order.

    Noir lays the flattened parameters over the first witnesses in declaration
    order, so walking the ABI in the same order gives the assignment the
    constraint system sees. That is what the feasibility check needs: it speaks
    witness indices, not parameter names.
    """
    kind = abi_type.get("kind")
    if kind == "boolean":
        out.append(1 if value else 0)
    elif kind == "field":
        out.append(int(value) % PRIME)
    elif kind == "integer":
        # A negative integer is stored as its two's complement *within the
        # type's width*, not as its residue in the field. Getting this wrong
        # silently shifts every signed parameter and makes any answer computed
        # from the layout meaningless.
        width = abi_type.get("width", 32)
        out.append(int(value) % (1 << width))
    elif kind == "string":
        out.extend(ord(character) for character in value)
    elif kind == "array":
        for element in value:
            flatten(abi_type["type"], element, out)
    elif kind == "tuple":
        for field, element in zip(abi_type.get("fields", []), value):
            flatten(field, element, out)
    elif kind == "struct":
        for field in abi_type.get("fields", []):
            flatten(field["type"], value[field["name"]], out)
    else:
        raise ValueError(f"unsupported ABI kind {kind!r}")


def render(name: str, value) -> list[str]:
    if isinstance(value, dict):
        lines = [f"[{name}]"]
        for key, inner in value.items():
            lines.append(f"{key} = {json.dumps(inner)}")
        return lines
    return [f"{name} = {json.dumps(value)}"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--emit-witness-map", type=pathlib.Path,
                        help="also write the inputs as a witness-index -> value JSON map")
    args = parser.parse_args()

    abi = json.loads(args.artifact.read_text()).get("abi", {})
    rng = random.Random(args.seed)

    # The seed doubles as the branch-combination index, so consecutive seeds
    # walk every combination of the program's boolean parameters.
    booleans = [bool(args.seed >> bit & 1) for bit in range(16)]

    lines: list[str] = []
    flat: list[int] = []
    for parameter in abi.get("parameters", []):
        value = value_for(parameter["type"], rng, booleans)
        lines.extend(render(parameter["name"], value))
        if args.emit_witness_map:
            flatten(parameter["type"], value, flat)

    (args.package / "Prover.toml").write_text("\n".join(lines) + "\n")
    if args.emit_witness_map:
        args.emit_witness_map.write_text(
            json.dumps({str(index): str(value) for index, value in enumerate(flat)})
        )


if __name__ == "__main__":
    main()

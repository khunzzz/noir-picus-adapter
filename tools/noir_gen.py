#!/usr/bin/env python3
"""Random Noir program generator for compiler-soundness fuzzing.

The generator emits *pure* Noir programs: no `unsafe` blocks, no unconstrained
functions, no foreign calls. Such a program denotes a total deterministic
function of its parameters, so the ACIR the compiler produces for it MUST
determine every witness once all parameters are fixed.

That gives an oracle that needs no reference implementation:

    if the scanner finds two witness assignments that agree on every parameter
    and disagree anywhere, the Noir compiler emitted an underconstrained
    circuit.

Mode `hints` additionally emits properly-constrained unconstrained hints
(`let q = unsafe { div_hint(a, b) }; assert(q * b == a);`), which is the
pattern real Noir code uses and the pattern most compiler soundness advisories
live in. In that mode a finding is a candidate rather than a proof, because a
generated hint may be genuinely under-determined.
"""

from __future__ import annotations

import argparse
import pathlib
import random
import textwrap

FIELD = "Field"
# `u128` matters out of proportion to its frequency: the one published Noir
# advisory that allowed outright proof forgery was a `Field as u128` cast whose
# quotient bound left the top of the field reachable. Leaving it out of the
# grammar left that whole shape ungenerated.
UINTS = ["u8", "u16", "u32", "u64", "u128"]
SINTS = ["i8", "i16", "i32", "i64"]
INTS = UINTS + SINTS
NUMERIC = [FIELD] + INTS
ALL_TYPES = NUMERIC + ["bool"]

BITS = {
    "u8": 8,
    "u16": 16,
    "u32": 32,
    "u64": 64,
    "u128": 128,
    "i8": 8,
    "i16": 16,
    "i32": 32,
    "i64": 64,
}


class Var:
    __slots__ = ("name", "ty")

    def __init__(self, name: str, ty: str) -> None:
        self.name = name
        self.ty = ty


class Generator:
    def __init__(self, seed: int, mode: str, size: int) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self.mode = mode
        self.size = size
        # `Field` arithmetic compiles to plain `AssertZero`, while every integer
        # operation drags in a `RANGE` that the finite-field solver has to
        # expand one boolean unknown per bit. A program built from `Field` and
        # `bool` alone therefore stays decidable at sizes where an integer-heavy
        # one does not, which is what makes control-flow bugs reachable at all.
        self.types = [FIELD, "bool"] if mode in ("field", "control") else ALL_TYPES
        self.numeric = [FIELD] if mode in ("field", "control") else NUMERIC
        # Dedicated `u32` parameters used as array indices. A `Field as u32`
        # cast compiles to a five-constraint gadget plus a `RANGE(222)`, and
        # that range alone expands to 222 boolean unknowns per copy — enough to
        # bury the solver before it reaches anything interesting. Taking the
        # index as a parameter costs one `RANGE(32)` and no cast at all.
        self.index_params: list[Var] = []
        self.counter = 0
        self.lines: list[str] = []
        self.scope: list[Var] = []
        self.helpers: list[str] = []
        self.depth = 0

    # ---------------------------------------------------------------- helpers
    def fresh(self, ty: str) -> Var:
        self.counter += 1
        return Var(f"v{self.counter}", ty)

    def pick(self, ty: str) -> str | None:
        """An in-scope variable of `ty`, or None."""
        candidates = [v for v in self.scope if v.ty == ty]
        if not candidates:
            return None
        return self.rng.choice(candidates).name

    def literal(self, ty: str) -> str:
        if ty == "bool":
            return self.rng.choice(["true", "false"])
        if ty == FIELD:
            return str(self.rng.randint(0, 1 << 32))
        bits = BITS[ty]
        if ty.startswith("u"):
            return f"{self.rng.randint(0, min(1 << bits, 1 << 16) - 1)}"
        return f"{self.rng.randint(0, min(1 << (bits - 1), 1 << 15) - 1)}"

    # ------------------------------------------------------------ expressions
    def expr(self, ty: str, depth: int = 0) -> str:
        """A side-effect-free expression of type `ty`."""
        if ty in INTS and ty not in self.numeric:
            ty = FIELD
        if depth >= 3 or self.rng.random() < 0.3:
            name = self.pick(ty)
            if name is not None and self.rng.random() < 0.92:
                return name
            return self.literal(ty)

        if ty == "bool":
            return self.bool_expr(depth)

        choice = self.rng.random()
        if choice < 0.5:
            op = self.rng.choice(["+", "-", "*"])
            lhs = self.expr(ty, depth + 1)
            rhs = self.expr(ty, depth + 1)
            if ty == FIELD:
                return f"({lhs} {op} {rhs})"
            # Integer arithmetic traps on overflow; keep operands small so the
            # circuit stays satisfiable for most inputs.
            return f"({lhs} {op} {self.small(ty, rhs)})"
        if choice < 0.65 and ty != FIELD and ty in self.numeric:
            op = self.rng.choice(["&", "|", "^"])
            return f"({self.expr(ty, depth + 1)} {op} {self.expr(ty, depth + 1)})"
        if choice < 0.75 and ty in UINTS and ty in self.numeric:
            shift = self.rng.randint(1, max(1, BITS[ty] // 2))
            op = self.rng.choice(["<<", ">>"])
            return f"({self.expr(ty, depth + 1)} {op} {shift})"
        if choice < 0.9:
            return self.cast_expr(ty, depth)
        cond = self.bool_expr(depth + 1)
        return f"(if {cond} {{ {self.expr(ty, depth + 1)} }} else {{ {self.expr(ty, depth + 1)} }})"

    def small(self, ty: str, expr: str) -> str:
        """Reduce an integer operand so arithmetic rarely overflows."""
        if ty in UINTS:
            return f"({expr} % {1 << max(2, BITS[ty] // 4)})"
        return f"({expr} % {1 << max(2, BITS[ty] // 4 - 1)})"

    def cast_expr(self, ty: str, depth: int) -> str:
        source = self.rng.choice(self.numeric)
        inner = self.expr(source, depth + 1)
        if ty == FIELD:
            if source == FIELD:
                return inner
            if source in SINTS:
                # Noir only casts unsigned integers to Field, so signed values
                # go through the same-width unsigned type first.
                return f"(({inner} as u{BITS[source]}) as Field)"
            return f"({inner} as Field)"
        if source == FIELD:
            # Field -> integer truncates; this is the shape of several known
            # Noir cast advisories, so keep it in the grammar.
            return f"({inner} as {ty})"
        return f"({inner} as {ty})"

    def bool_expr(self, depth: int) -> str:
        if depth >= 3:
            name = self.pick("bool")
            return name if name is not None else self.literal("bool")
        choice = self.rng.random()
        if choice < 0.55:
            ty = self.rng.choice(self.numeric)
            op = self.rng.choice(["==", "!="] + ([] if ty == FIELD else ["<", "<=", ">", ">="]))
            return f"({self.expr(ty, depth + 1)} {op} {self.expr(ty, depth + 1)})"
        if choice < 0.8:
            op = self.rng.choice(["&", "|"])
            return f"({self.bool_expr(depth + 1)} {op} {self.bool_expr(depth + 1)})"
        return f"(!{self.bool_expr(depth + 1)})"

    # ------------------------------------------------------------- statements
    def emit(self, line: str) -> None:
        self.lines.append("    " * (self.depth + 1) + line)

    def stmt_let(self) -> None:
        ty = self.rng.choice(self.types)
        var = self.fresh(ty)
        self.emit(f"let {var.name}: {ty} = {self.expr(ty)};")
        self.scope.append(var)

    def stmt_if(self) -> None:
        ty = self.rng.choice(self.numeric)
        var = self.fresh(ty)
        cond = self.bool_expr(0)
        self.emit(f"let mut {var.name}: {ty} = {self.expr(ty)};")
        self.emit(f"if {cond} {{")
        self.depth += 1
        self.emit(f"{var.name} = {self.expr(ty)};")
        self.depth -= 1
        self.emit("} else {")
        self.depth += 1
        self.emit(f"{var.name} = {self.expr(ty)};")
        self.depth -= 1
        self.emit("}")
        self.scope.append(var)

    def stmt_array(self) -> None:
        ty = FIELD if self.numeric == [FIELD] else self.rng.choice([FIELD] + UINTS)
        length = self.rng.choice([2, 4, 8])
        arr = self.fresh(ty)
        elements = ", ".join(self.expr(ty, 2) for _ in range(length))
        self.emit(f"let mut arr_{arr.name}: [{ty}; {length}] = [{elements}];")
        # A dynamic index produces ACIR memory opcodes.
        idx = self.index_expr(length)
        self.emit(f"let idx_{arr.name}: u32 = {idx};")
        if self.rng.random() < 0.5:
            self.emit(f"arr_{arr.name}[idx_{arr.name}] = {self.expr(ty, 2)};")
        out = self.fresh(ty)
        self.emit(f"let {out.name}: {ty} = arr_{arr.name}[idx_{arr.name}];")
        self.scope.append(out)

    def stmt_loop(self) -> None:
        ty = FIELD if self.numeric == [FIELD] else self.rng.choice([FIELD] + UINTS)
        acc = self.fresh(ty)
        count = self.rng.choice([2, 3, 4])
        self.emit(f"let mut {acc.name}: {ty} = {self.expr(ty, 2)};")
        self.emit(f"for i_{acc.name} in 0..{count} {{")
        self.depth += 1
        step = self.expr(ty, 2)
        if ty == FIELD:
            self.emit(f"{acc.name} = {acc.name} + ({step}) + (i_{acc.name} as Field);")
        else:
            self.emit(f"{acc.name} = {acc.name} + ({step} % 8) + (i_{acc.name} as {ty});")
        self.depth -= 1
        self.emit("}")
        self.scope.append(acc)

    def stmt_hint(self) -> None:
        """A properly constrained unconstrained hint (division witness)."""
        name = f"div_hint_{self.counter}"
        self.helpers.append(
            textwrap.dedent(
                f"""
                unconstrained fn {name}(a: Field, b: Field) -> Field {{
                    if b == 0 {{ 0 }} else {{ a / b }}
                }}
                """
            ).strip()
        )
        num = self.expr(FIELD, 2)
        den = self.fresh(FIELD)
        out = self.fresh(FIELD)
        self.emit(f"let {den.name}: Field = ({self.expr(FIELD, 2)}) * ({self.expr(FIELD, 2)}) + 1;")
        self.emit(f"let n_{out.name}: Field = {num};")
        self.emit("// Safety: the quotient is constrained below.")
        self.emit(f"let {out.name}: Field = unsafe {{ {name}(n_{out.name}, {den.name}) }};")
        self.emit(f"assert({out.name} * {den.name} == n_{out.name});")
        self.scope.append(den)
        self.scope.append(out)

    def guarded_index(self, length: int, name: str) -> str:
        """An index guarded by a comparison rather than a modulo.

        `% length` can never go out of range, so it exercises none of the
        bounds-check machinery. A comparison guard is what real code writes and
        what an advisory about arrays being indexable out of bounds was about;
        it leaves the compiler responsible for proving the access safe.
        """
        raw = (
            self.rng.choice(self.index_params).name
            if self.index_params
            else f"({self.expr('u32', 2)})"
        )
        self.emit(f"let raw_{name}: u32 = {raw};")
        self.emit(f"let idx_{name}: u32 = if raw_{name} < {length} {{ raw_{name} }} else {{ 0 }};")
        return f"idx_{name}"

    def index_expr(self, length: int) -> str:
        """A dynamic index in `[0, length)`, built without a `Field` cast."""
        if self.index_params:
            base = self.rng.choice(self.index_params).name
            if self.rng.random() < 0.4 and len(self.index_params) > 1:
                other = self.rng.choice(self.index_params).name
                base = f"({base} + {other})"
            return f"({base} % {length})"
        index_type = "u32" if "u32" in self.numeric else FIELD
        raw = self.expr(index_type, 2)
        return f"(({raw} as u32) % {length})"

    def stmt_cast_chain(self) -> None:
        """A chain of narrowing and widening casts through `Field`."""
        source = self.rng.choice([FIELD] + UINTS)
        middle = self.rng.choice(UINTS)
        target = self.rng.choice([FIELD] + UINTS)
        out = self.fresh(target)
        value = self.expr(source, 2)
        if source in SINTS:
            value = f"({value} as u{BITS[source]})"
        chain = f"(({value} as {middle}) as {target})"
        self.emit(f"let {out.name}: {target} = {chain};")
        self.scope.append(out)

    def stmt_wide_cast(self) -> None:
        """A `Field` narrowed to the widest integer type and back.

        This is the exact shape of the forgery advisory: the cast lowers to a
        division by `2^128` whose quotient is bounded by a range check and a
        boundary gadget, and the whole question is whether that bound leaves
        the top of the field reachable.
        """
        out = self.fresh("u128")
        source = self.expr(FIELD, 2)
        self.emit(f"let {out.name}: u128 = ({source} as u128);")
        self.scope.append(out)

        back = self.fresh(FIELD)
        self.emit(f"let {back.name}: Field = ({out.name} as Field);")
        self.scope.append(back)

        flag = self.fresh("bool")
        self.emit(f"let {flag.name}: bool = ({out.name} == 0);")
        self.scope.append(flag)

    def stmt_as_witness(self) -> None:
        """Pin an intermediate as its own witness.

        `as_witness` exists to stop the optimiser folding a value away, and an
        advisory exists for it being eliminated anyway when the value looked
        unused but sat in the return data. Generating it exercises that path.
        """
        value = self.fresh(FIELD)
        self.emit(f"let {value.name}: Field = {self.expr(FIELD, 2)};")
        self.emit(f"std::as_witness({value.name});")
        self.scope.append(value)

    def stmt_signed_math(self) -> None:
        """Signed arithmetic, including the division whose overflow guard is
        the one place a published advisory found an off-by-one."""
        ty = self.rng.choice(SINTS)
        out = self.fresh(ty)
        lhs = self.expr(ty, 2)
        rhs = self.expr(ty, 2)
        op = self.rng.choice(["+", "-", "*"])
        self.emit(f"let {out.name}: {ty} = ({lhs} {op} ({rhs} % 8));")
        self.scope.append(out)

        guard = self.fresh(ty)
        divisor = self.expr(ty, 2)
        self.emit(f"let d_{guard.name}: {ty} = ({divisor} % 8);")
        self.emit(f"let {guard.name}: {ty} = if d_{guard.name} == 0 {{")
        self.depth += 1
        self.emit(f"{out.name}")
        self.depth -= 1
        self.emit("} else {")
        self.depth += 1
        self.emit(f"{out.name} / d_{guard.name}")
        self.depth -= 1
        self.emit("};")
        self.scope.append(guard)

    def stmt_shift(self) -> None:
        """A shift by a *variable* amount, which lowers to a different gadget
        than a constant shift and has its own advisory history."""
        ty = self.rng.choice(UINTS)
        out = self.fresh(ty)
        op = self.rng.choice(["<<", ">>"])
        # Noir requires both operands of a shift to have the same bit width.
        self.emit(f"let sh_{out.name}: {ty} = (({self.expr(ty, 2)}) % {BITS[ty]});")
        self.emit(f"let {out.name}: {ty} = ({self.expr(ty, 2)} {op} sh_{out.name});")
        self.scope.append(out)

    def stmt_division(self) -> None:
        """Unsigned division and modulo, guarded against a zero divisor."""
        ty = self.rng.choice(UINTS)
        out = self.fresh(ty)
        self.emit(f"let dv_{out.name}: {ty} = ({self.expr(ty, 2)} | 1);")
        op = self.rng.choice(["/", "%"])
        self.emit(f"let {out.name}: {ty} = ({self.expr(ty, 2)} {op} dv_{out.name});")
        self.scope.append(out)

    def stmt_conditional_array(self) -> None:
        """A dynamic array write guarded by a condition.

        The write has to be predicated in ACIR, and the array's memory block
        has to keep its old contents on the disabled branch. Several published
        advisories are exactly this going wrong.
        """
        length = self.rng.choice([2, 4, 8])
        array = self.fresh(FIELD)
        elements = ", ".join(self.expr(FIELD, 2) for _ in range(length))
        self.emit(f"let mut arr_{array.name}: [Field; {length}] = [{elements}];")
        # Half the time the index is proved in range by a comparison instead
        # of forced in range by a modulo.
        if self.rng.random() < 0.5:
            write_index = self.guarded_index(length, f"w{array.name}")
            read_index = self.guarded_index(length, f"r{array.name}")
        else:
            write_index = self.index_expr(length)
            read_index = self.index_expr(length)
        self.emit(f"let wi_{array.name}: u32 = {write_index};")
        self.emit(f"let ri_{array.name}: u32 = {read_index};")
        self.emit(f"if {self.bool_expr(0)} {{")
        self.depth += 1
        self.emit(f"arr_{array.name}[wi_{array.name}] = {self.expr(FIELD, 2)};")
        self.depth -= 1
        self.emit("}")
        self.emit(f"let {array.name}: Field = arr_{array.name}[ri_{array.name}];")
        self.scope.append(array)

    def stmt_nested_if(self) -> None:
        """Nested conditionals, so predicates have to compose."""
        result = self.fresh(FIELD)
        self.emit(f"let mut {result.name}: Field = {self.expr(FIELD, 2)};")
        self.emit(f"if {self.bool_expr(0)} {{")
        self.depth += 1
        self.emit(f"if {self.bool_expr(1)} {{")
        self.depth += 1
        self.emit(f"{result.name} = {self.expr(FIELD, 2)};")
        self.depth -= 1
        self.emit("} else {")
        self.depth += 1
        self.emit(f"{result.name} = {self.expr(FIELD, 2)};")
        self.depth -= 1
        self.emit("}")
        self.depth -= 1
        self.emit("} else {")
        self.depth += 1
        self.emit(f"{result.name} = {self.expr(FIELD, 2)};")
        self.depth -= 1
        self.emit("}")
        self.scope.append(result)

    def stmt_conditional_vector(self) -> None:
        """Vector push/pop under a condition.

        Several published advisories are exactly this: a vector operation on a
        disabled branch leaving the length and the backing storage out of step
        (`convert_slice_push_back` not updating the length,
        `convert_slice_pop_back` mis-indexing, `RemoveIfElse` mis-tracking
        sizes). Noir's own regression suite carries a
        `vector_pop_back_remove_if_else_bug` case for the same family.
        """
        vector = self.fresh(FIELD)
        name = f"vec_{vector.name}"
        self.emit(
            f"let mut {name}: [Field] = @[{self.expr(FIELD, 2)}, "
            f"{self.expr(FIELD, 2)}, {self.expr(FIELD, 2)}];"
        )
        self.emit(f"if {self.bool_expr(0)} {{")
        self.depth += 1
        self.emit(f"{name} = {name}.push_back({self.expr(FIELD, 2)});")
        self.depth -= 1
        self.emit("} else {")
        self.depth += 1
        self.emit(f"{name} = {name}.push_front({self.expr(FIELD, 2)});")
        self.depth -= 1
        self.emit("}")
        if self.rng.random() < 0.5:
            self.emit(f"if {self.bool_expr(0)} {{")
            self.depth += 1
            self.emit(f"let popped_{vector.name} = {name}.pop_back();")
            self.emit(f"{name} = popped_{vector.name}.0;")
            self.depth -= 1
            self.emit("}")
        self.emit(f"let {vector.name}: Field = {name}[1];")
        self.scope.append(vector)

    def stmt_assert(self) -> None:
        ty = self.rng.choice(self.numeric)
        lhs = self.expr(ty, 1)
        self.emit(f"assert(({lhs}) == ({lhs}));")

    def seed_scope(self, params_types: list[str]) -> None:
        """Bind one variable of every type to a parameter-derived value.

        Without this the expression grammar falls back to literals whenever a
        type has no in-scope variable, and the compiler folds the whole program
        to a constant before ACIR generation.
        """
        source = self.scope[0]
        for ty in ALL_TYPES:
            if any(v.ty == ty for v in self.scope):
                continue
            var = self.fresh(ty)
            self.emit(f"let {var.name}: {ty} = {self.coerce(source, ty)};")
            self.scope.append(var)

    def coerce(self, var: Var, ty: str) -> str:
        """Convert `var` to `ty` with a cast chain Noir accepts."""
        if var.ty == ty:
            return var.name
        if ty == "bool":
            if var.ty == "bool":
                return var.name
            return f"({var.name} != {self.literal(var.ty)})"
        if var.ty == "bool":
            return f"({var.name} as {ty})"
        if ty == FIELD:
            if var.ty in SINTS:
                return f"(({var.name} as u{BITS[var.ty]}) as Field)"
            return f"({var.name} as Field)"
        if var.ty == FIELD:
            return f"({var.name} as {ty})"
        return f"({var.name} as {ty})"

    # ------------------------------------------------------------------ main
    def generate(self) -> str:
        n_params = self.rng.randint(1, 4)
        params = []
        for _ in range(n_params):
            ty = self.rng.choice(self.types)
            var = self.fresh(ty)
            visibility = "pub " if self.rng.random() < 0.4 else ""
            params.append(f"{var.name}: {visibility}{ty}")
            self.scope.append(var)

        if self.mode == "control":
            for _ in range(2):
                index = self.fresh("u32")
                params.append(f"{index.name}: {index.name and ''}u32")
                self.index_params.append(index)

        self.seed_scope(params_types=[v.ty for v in self.scope])

        weights = [
            (self.stmt_let, 5),
            (self.stmt_if, 3),
            (self.stmt_array, 3),
            (self.stmt_loop, 2),
            (self.stmt_assert, 1),
        ]
        if self.mode == "hints":
            weights.append((self.stmt_hint, 3))
        if self.mode == "math":
            # Of the published Noir advisories that are genuinely about a
            # *missing* constraint rather than a wrong value, two are in this
            # area: the `Field as uN` cast that allowed proof forgery, and the
            # signed-overflow guard whose bound was off by one so it never
            # fired at `bit_size == 128`. Both only misbehave at the edges of
            # the representable range, which is why the input generator draws
            # boundary values and why this grammar concentrates on casts,
            # signed division and variable shifts.
            weights = [
                (self.stmt_cast_chain, 6),
                (self.stmt_wide_cast, 5),
                (self.stmt_signed_math, 5),
                (self.stmt_shift, 4),
                (self.stmt_division, 4),
                (self.stmt_as_witness, 2),
                (self.stmt_if, 2),
                (self.stmt_let, 2),
            ]
        if self.mode == "control":
            # Every published Noir soundness advisory about ACIR generation is
            # about a value crossing a disabled side-effects predicate: a
            # conditional array write, a slice operation under an `if`, a fold
            # across a branch. Weight the grammar towards exactly that.
            weights = [
                (self.stmt_conditional_array, 6),
                (self.stmt_if, 5),
                (self.stmt_nested_if, 4),
                (self.stmt_conditional_vector, 4),
                (self.stmt_array, 3),
                (self.stmt_let, 2),
                (self.stmt_loop, 2),
            ]
        population = [fn for fn, weight in weights for _ in range(weight)]

        for _ in range(self.size):
            self.rng.choice(population)()

        return_types = []
        return_exprs = []
        for _ in range(self.rng.randint(1, 3)):
            ty = self.rng.choice(self.numeric)
            return_types.append(ty)
            return_exprs.append(self.expr(ty, 1))

        if len(return_types) == 1:
            ret_ty = return_types[0]
            ret_expr = return_exprs[0]
        else:
            ret_ty = "(" + ", ".join(return_types) + ")"
            ret_expr = "(" + ", ".join(return_exprs) + ")"

        body = "\n".join(self.lines)
        helpers = "\n\n".join(self.helpers)
        header = f"// generated by tools/noir_gen.py --seed {self.seed} --mode {self.mode}"
        return (
            f"{header}\n\n"
            + (helpers + "\n\n" if helpers else "")
            + f"fn main({', '.join(params)}) -> pub {ret_ty} {{\n{body}\n    {ret_expr}\n}}\n"
        )


def write_package(out_dir: pathlib.Path, name: str, source: str) -> None:
    (out_dir / "src").mkdir(parents=True, exist_ok=True)
    (out_dir / "Nargo.toml").write_text(
        f'[package]\nname = "{name}"\ntype = "bin"\nauthors = [""]\n'
    )
    (out_dir / "src" / "main.nr").write_text(source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--mode",
        choices=["pure", "hints", "field", "control", "math"],
        default="pure",
    )
    parser.add_argument("--size", type=int, default=8, help="number of statements")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    source = Generator(args.seed, args.mode, args.size).generate()
    name = f"gen_{args.mode}_{args.seed}"
    write_package(args.out, name, source)
    print(args.out)


if __name__ == "__main__":
    main()

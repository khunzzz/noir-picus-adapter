# The SSA fuzzer's `Constant` mode compares a result against a leftover input

`tooling/ssa_fuzzer` ships five `FuzzerMode` variants. The fuzz target enables
one:

```rust
let modes = vec![FuzzerMode::NonConstant];
```

and the other four carry `#[allow(dead_code)]`. The README nevertheless tells
you to turn them on:

> Constant execution mode. In this mode fuzzer will create two more ACIR and
> Brillig builders, that will execute all instructions in constant mode […]
> This was done in order to catch bugs in constant_folding SSA pass.

Enabling `FuzzerMode::Constant` reports a disagreement on roughly **95% of
programs**. None of them is a compiler defect.

## What actually happens

For one saved program, the two modes compile to exactly what they should:

| mode | final ACIR |
| --- | --- |
| `NonConstant` | `main(v0: u8, v1: Field, v2: u1, v3: u1) { return v1 }` |
| `Constant` | `main() { return Field 0 }` |

Substituting the arguments folds the program to the constant `0`, and `v1`'s
value in that run *is* `0`. The two agree.

The harness reports otherwise:

```
NonConstant  -> [0]
Constant     -> [166]
```

`166` is not a result. The constant-folded program has **no parameters and no
opcodes**, so its witness map is still the initial witness the fuzzer supplied,
and `get_return_witnesses` indexes into it:

```rust
let return_witnesses = &program.functions[0].return_values.0;
let witness_vec = &self.witness_stack.peek().unwrap().witness;
return_witnesses.iter().map(|witness| witness_vec[witness]).collect()
```

The index lands on an input the fuzzer happened to place there. The comparison
is a computed value against a leftover argument.

## Why it matters

The mode exists to test the `constant_folding` SSA pass — a soundness-relevant
optimizer stage with no other differential aimed at it. As shipped it cannot be
used: anyone following the README gets a wall of false alarms and would
reasonably conclude the mode is worthless.

Fixing the extraction would turn it into a real oracle for a pass that currently
has none.

## Reproducing

`driver.rs` runs the fuzzer without libFuzzer, so no nightly toolchain and no
`cargo-fuzz` are needed. Drop it in `tooling/ssa_fuzzer/fuzzer/src/` and add:

```toml
[[bin]]
name = "driver"
path = "src/driver.rs"
```

```bash
cargo build --release --bin driver
driver 42 120 /tmp/out          # seed, rounds, output directory
driver replay <saved.json> Constant     # one program, with the SSA printed
```

`example_program.json` is one of the saved disagreements.

## The fix, and what it measures

The constant-folded program declares no parameters, so its witness numbering
starts at the return value. Handing it the initial witness puts an argument at
the index the return occupies. Giving it an empty witness map instead lets the
solver run:

```rust
let witness = if context.get_mode() == FuzzerMode::Constant {
    WitnessMap::new()
} else {
    initial_witness.clone()
};
```

(`fix.patch` in this directory.)

The same program, before and after:

| | `return_values` | witness map | reported |
| --- | --- | --- | --- |
| before | `{Witness(0)}` | `[(w0, 166), (w1, 0), (w2, 1), (w3, 0)]` | `[166]` |
| after | `{Witness(0)}` | `[(w0, 0)]` | `[0]` — matching every other mode |

Across 120 programs on one seed:

| | disagreements |
| --- | ---: |
| before the fix | **40** |
| after the fix | **4**, all of them `NonConstantWithoutSimplifying` failing to compile |

So the fix removes 36 false alarms and leaves no value mismatch at all.

## Running the repaired oracle

About 3000 programs in 45 seconds, all five modes:

* **no value mismatch in any mode** — `Constant`, `NonConstantWithoutDIE` and
  `NonConstantWithIdempotentMorphing` agreed with the standard mode everywhere;
* 85 disagreements, every one a compile failure rather than a differing value,
  80 of them in `NonConstantWithoutSimplifying`;
* a separate family of panics — `Expected NumericType, found Array([Numeric(U8)], 3)`
  — which come from the fuzzer's own `type.rs` and `typed_value.rs`, not the
  compiler. The message is the fuzzer's `Type` in `Debug` form; the compiler's
  own panic at `ssa/ir/types.rs:221` uses `Display`. A third defect in the
  harness, not an internal compiler error.

## What the other modes showed

Over 160 programs, with all five modes enabled:

| mode | agreed with `NonConstant` |
| --- | --- |
| `NonConstantWithoutDIE` | always |
| `NonConstantWithIdempotentMorphing` | always |
| `NonConstantWithoutSimplifying` | always, apart from two programs that failed to compile without simplification |
| `Constant` | 38 of 40 disagreements, all traced to the extraction above |

So disabling dead-instruction elimination and adding idempotent morphing never
changed a result — a small but genuine negative result for those passes.

## Version

1.0.0-beta.26+e088a9e.

# noir-picus-adapter Session Reference

Repository: https://github.com/khunzzz/noir-picus-adapter
Language: Rust, edition 2024, #![forbid(unsafe_code)]
Dependencies: acir (git rev), picus-smt (git rev)

## Quick Reference

```bash
cargo build                           # first build very slow (Picus compiles cvc5)
cargo test                            # 23 unit tests
cargo run -- scan <artifact> --targets returns --fixed all-params
```

## Project Layout

```
src/
  main.rs          # entry → lib::run()
  lib.rs           # CLI (clap), scan driver
  artifact.rs      # load/deserialize Noir artifact JSON
  targets.rs       # discover target witnesses (return values, BrilligCall outputs)
  translate.rs+    # ACIR→Picus IR translation (core)
    expr.rs        # AssertZero linear + nonlinear
    range.rs       # RANGE bit decomposition
    bitwise.rs     # AND/XOR bit decomposition
    memory.rs      # MemoryOp read/write (one-hot selectors)
    determinism.rs # blackbox determinism abstraction
    known.rs       # fixed-known propagation
    ir.rs          # wire mapping, var_name, coefficient helpers
    wires.rs       # wire enumeration
    tests.rs       # IR shape tests
    soundness_tests.rs  # solution-set differential tests
  solver.rs        # build UniquenessQuery, short circuits, run Picus
  report.rs        # ScanReport, TargetStatus, printers
  debug_info.rs    # debug symbol handling
```

## Key Internal Invariants

- **Witness→Picus wire mapping**: `picus_wire(w) = w.witness_index() + 1`. Wire 0 = constant signal.
- **Self-composition naming**: first copy = `x*` vars, second = `y*`. Fixed/input wires stay `x*` in both.
- **Constraint groups indivisible**: one ACIR opcode → multiple IR constraints; kept together so cone slicing never drops aux bits.
- **Cone-of-influence slicing**: cut at fixed-known signals. Full circuit IR still reported at circuit level.
- **Fixed-known propagation**: linear-only fixpoint. Nonlinear (mul_terms) intentionally skipped.
- **Dependency graph**: undirected → over-approximates influence. `BrilligCall` does NOT create edges (correct — Brillig outputs are nondeterministic).

## Soundness Margins

| Error type | Effect | Cost |
|-----------|--------|------|
| Translation loses solutions (IR stricter than ACIR) | `unsafe` → false `verified` | **Critical**: missed vulnerability |
| Translation adds solutions (IR weaker than ACIR) | `verified` → false `unsafe` | Noise, erodes trust |

## Fast Paths (verified without SMT call)

1. Target is a fixed input → by definition equal in both copies.
2. Linear fixed-known propagation: linear `AssertZero` with exactly one unknown wire uniquely determines it.

## Mutation Search (`mutate` subcommand)

A second, SMT-free search path. Takes an honest witness, mutates one hint,
and **repairs** the rest by walking ACIR opcodes in order. Requires `--witness`.

```bash
cargo run -- mutate <artifact> --witness <witness.gz> --attempts 8
```

Output: `mutation search: N attempt(s), M finding(s)` with witness-level detail.

**Key feature — memory repair** (2026-08-22): `MemOpKind::Write` with a soft
hint value now takes the value from the honest run immediately instead of
deferring. Without this, array writes through hint indices were structurally
unreachable. See `mutate.rs::solve_pass()`.

## Found Bugs To-Date

| Finding | Class | Status |
|---------|-------|--------|
| `regression_11490` | Lost constraint in ACIR | **Confirmed** |
| `non-pinning-constraint-silences-checker` | Broken checker heuristic | **Confirmed** |
| `predicated-constraint-silences-checker` | Broken checker heuristic | **Confirmed** |
| `array-output-length-threshold` | Documented trade-off | **Confirmed** |
| `ancestor-distance-false-positive` | Documented trade-off | **Confirmed** |
| `nightly-returndata-loop` | non-pinning-constraint variant | **Confirmed** |
| `two-hint-cross-constraint` | ❌ NOT a compiler bug | **False alarm** (see references/two-hint-cross-constraint.md) |

## Gadget Audit

`tools/gadget_audit.py` — enumerates 470+ minimal Noir programs, one per
compiler primitive (casts, arithmetic, memory, predicates, vectors, stdlib,
hashes, field_widths). Each is tested by `mutate` *and* boundary-input
rejection. Outcomes: `clean`, `finding`, `accepts_rejected`, `self_flagged`,
`vacuous`, `unjudged`.

```bash
python3 tools/gadget_audit.py \
  --adapter ./target/release/noir-picus-adapter \
  --nargo /path/to/nargo \
  --out /tmp/gadget_results \
  --work /tmp/gadget_work \
  --attempts 6
```

## Known Limitations

- **Memory**: one-hot encoding forces index in bounds. OOB semantics different from ACIR spec → treat with caution.
- **Bit width**: RANGE/AND/XOR with width ≥ field bits → no-op/unsupported.
- **External deps**: Picus/cvc5/z3/acir crate correctness taken on trust.
- **`unknown`**: solver timeout ≠ safe.

## CLI Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--fixed` | `public`, `all-params` | `all-params` | Which params held equal across copies |
| `--targets` | `returns`, `brillig-outputs`, `all` | `all` | Which witnesses to check |
| `--solver` | `cvc5`, `z3` | `cvc5` | SMT backend |
| `--theory` | `ff`, `nia` | `ff` | Finite-field / nonlinear int arith |
| `--timeout` | ms | `5000` | Per-target solver timeout |
| `--format` | `human`, `json` | `human` | Output format |
| `--dump-smt <dir>` | path | — | Write per-target .smt2 |
| `--verbose` | flag | — | Witness selection, IR sizes, mapping |
---
name: noir-compiler-testing
title: Noir Compiler Testing & ACIR Fuzzing
description: Use for Noir compiler, ACIR fuzzing, and bug detection.
version: 1.0.0
author: assistant
license: MIT OR Apache-2.0
metadata:
  hermes:
    tags: [noir, acir, fuzzing, compiler, zk, rust, smt]
    related_skills: [codebase-inspection, spike, systematic-debugging]
---

# Noir Compiler Testing & ACIR Fuzzing

Use when the user asks about **testing the Noir compiler**, **finding compiler bugs**,
**fuzzing ACIR circuits**, **generating ACIR test corpora**, **detecting under-constrained
witnesses**, or **building regression suites for Noir**.

## Available Tools (inside noir-lang/noir repo)

### 1. AST Fuzzer (`tooling/ast_fuzzer/`)

Generates **random monomorphized AST `Program` instances** and executes them under
different compilation strategies. Uses `cargo fuzz` (libFuzzer-based).

**Fuzz targets:**
- `acir_vs_brillig` — compare ACIR vs Brillig execution of same AST (differential)
- `comptime_vs_brillig` — comptime evaluator vs Brillig output
- `min_vs_full` — minimal SSA passes vs full SSA flow
- `orig_vs_morph` — original AST vs metamorphically transformed (should behave identically)

**Key commands:**
```bash
# Quick smoke test (10s, no ramp-up)
cargo test -p noir_ast_fuzzer_fuzz arbtest

# Full fuzz run with time limit
cargo +nightly fuzz run acir_vs_brillig -- -runs=1000 -max_total_time=60

# Reproduce from seed
NOIR_AST_FUZZER_SEED=0x6819c61400001000 cargo test -p noir_ast_fuzzer_fuzz

# Export failing AST as nargo project
NOIR_AST_FUZZER_EMIT_PROJECT=./repro \
  NOIR_AST_FUZZER_SEED=0x... \
  cargo test -p noir_ast_fuzzer_fuzz

# Reproduce via just recipe (from repo root)
just fuzz-repro 0x6819c61400001000
just fuzz-repro 0x6819c61400001000 acir_vs_brillig ./repro
```

**Env vars:** `NOIR_AST_FUZZER_SEED`, `NOIR_AST_FUZZER_EMIT_PROJECT`,
`NOIR_AST_FUZZER_SHOW_SSA`, `NOIR_AST_FUZZER_BUDGET_SECS`, `RUST_LOG=debug`.

**PITFALL:** `cargo fuzz` requires **nightly** Rust toolchain (cargo +nightly).

### 2. Greybox Fuzzer / `nargo fuzz` (`tooling/greybox_fuzzer/`)

Coverage-guided fuzzer built into `nargo`. Generates and mutates **inputs** for
user-written Noir programs (not compiler code). Detects discrepancies between
ACIR and Brillig execution modes.

**Usage in Noir source:**
```noir
#[fuzz]
fn fuzz_add(a: Field, b: Field) {
    assert(a!=(b+3));
}
```

**CLI:**
```bash
nargo fuzz [FUZZING_HARNESS_NAME]
nargo fuzz --corpus-dir ./corpus --num-threads 8
nargo fuzz --list-all
nargo fuzz --minimized-corpus-dir ./minimized
nargo fuzz --fuzzing-failure-dir ./failures
```

**Filtering failures by message:**
```noir
#[fuzz(only_fail_with = "This is the message")]
fn fuzz_add(a: u64, b: u64) {
    assert((a+b-15)!=(a-b+30), "This is the message");
}
```

## Under-Constraint Detection via noir-picus-adapter

### Architecture

```
Noir artifact JSON → acir::Circuit
  → select fixed witnesses + target witnesses
  → translate supported ACIR opcodes to Picus SMT IR
  → build self-composition uniqueness query
  → solver report (SAT=unsafe, UNSAT=verified, UNKNOWN)
```

**Self-composition query:**
```
exists W1, W2:
  SemACIR(W1) AND SemACIR(W2)      # both satisfy translated ACIR
  fixed witnesses agree             # same fixed inputs
  target witness differs            # W1[target] != W2[target]
```

### Supported Opcodes
- `AssertZero(Expression)` — linear + nonlinear
- `RANGE` — boolean for 1-bit, bit-decomposition for < field bits, no-op for ≥ field bits
- `AND`/`XOR` — bit decomposition for widths < field bits
- `MemoryOp` — read/write with one-hot selectors (forces index in bounds)
- `BrilligCall` outputs — treated as nondeterministic check targets
- **BlackBox** — determinism abstraction (Tier 1: fixed-known propagation; Tier 2: cross-copy equality-or-different-inputs constraint)

### CLI
```bash
cargo run -- scan examples/artifacts/unsafe_division_hint
  --fixed all-params|public
  --targets returns|brillig-outputs|all
  --solver cvc5|z3
  --theory ff|nia
  --timeout 5000
  --format human|json
  --verbose
  --dump-smt /tmp/smt
```

### Soundness Model
- **`verified`** = target uniquely determined by translated semantics (NOT = circuit is safe)
- **`unsafe`** = solver found two witness assignments diverging on target (may be false positive if translation is too weak)
- **`unsupported`** = unsupported opcode can influence the target
- **`unknown`** = solver timed out

### Key Optimizations
1. **Cone-of-influence slicing** — Picus only sees constraints reachable from the target
2. **Fixed-known propagation** — linear-only fixpoint marks witnesses known if a linear `AssertZero` has exactly one unknown
3. **Determinism abstraction** — blackbox outputs get cross-copy `out_x = out_y ∨ inputs_differ`

## Strategy: Building a Large ACIR Corpus to Find Real Compiler Bugs

### Phase 1: Leverage AST Fuzzer for ACIR Generation
1. Run AST Fuzzer `acir_vs_brillig` across many seeds
2. Save each generated `Program` as ACIR artifact (noir_version + bytecode only)
3. Feed artifacts into noir-picus-adapter scanner
4. Collect `unsafe` results with interesting witness patterns

**Minimal harness to extract ACIR from AST Fuzzer:**
- Modify or wrap the fuzzer loop to serialize `Program` between steps
- Run batch with `NOIR_AST_FUZZER_SEED=0x$(printf "%x" $seed)00001000`

### Phase 2: Direct ACIR Generation (bypass Noir frontend)
Generate random `acir::Circuit` instances in Rust:
- `AssertZero(Expression)` with varied linear/nonlinear combinations
- `RANGE` with different `num_bits`
- `AND`/`XOR` of various bit widths
- `MemoryOp` read/write with varied array sizes
- `BrilligCall` outputs
- **Not yet supported:** `Opcode::Call`, complex memory patterns with predicates

### Phase 3: Mutation-Based Fuzzing Over Existing Corpus
Take existing artifact → mutate:
- Add/remove constraints
- Shift witness indices
- Vary coefficients in `Expression`
- Change `num_bits` bounds
- Add `BrilligCall` with different output counts

### Phase 4: Targeted Fuzzing for Opcode Gaps
For each unsupported opcode, generate ACIR where that opcode is on the dependency
path to a target. Verify `unsupported` blocking is correct and not over-approximating.

### Phase 5: Compiler Regression Mining
- GitHub Security Advisories for Noir — turn each advisory PoC into a test case
- Closed issues labeled "bug" × "ACIR" × "under-constrained"
- Git blame on fixes in `noirc_evaluator` — check if original bug is detected

## Current Corpus (noir-picus-adapter repo)

| Tier | Count | Expectation |
|------|-------|-------------|
| Micro vulnerable | 40 | `unsafe` |
| Realistic vulnerable | 20 | `unsafe` |
| Realistic fixed | 20 | `verified` |
| Compiler regression | 6 | mixed (scan + execute + compile) |

**Run all gates:**
```bash
cargo test
bash corpus/check_corpus.sh              # micro: 40 unsafe
bash corpus/check_realistic_corpus.sh    # realistic: 20/20
bash corpus/check_compiler_regression.sh # compiler: 6 checks
```

**Artifact directory structure:**
```
corpus/
  artifacts/              # micro vulnerable (40 JSON files)
  realistic_artifacts/    # medium/large/stress (vulnerable + fixed variants)
  compiler_regression_artifacts/  # compiler PoCs
  vulnerable/             # source Noir packages
  realistic_common/       # shared helper library for realistic tier
  compiler_regression/    # source Noir packages for compiler PoCs
  *.tsv                   # manifests (source of truth for expected results)
  *.sh                    # runner scripts
  *.md                    # documentation (ANALYSIS, DIVERSITY, TRIAGE, …)
```

## Classification Pitfalls (critical) — not every `unsafe` is a compiler bug

The adapter finds **any** under-constrained witness. That includes witnesses the
programmer **deliberately left free** (or forgot to pin). Distinguish:

| Finding | Verdict |
|---------|---------|
| ACIR lost a constraint the source wrote | ✅ **Compiler bug** — e.g. `regression_11490` where `input` never enters any opcode |
| ACIR matches source, but the programmer's constraint is too weak | ❌ **Not a compiler bug** — the ACIR correctly represents weak source |
| Checker heuristic failed to flag something it *documentedly* doesn't guarantee | ⚠️ **Known limitation** — check if it's a documented trade-off (`max-array-output-length`, `max-ancestor-distance`, `is_against_const` rule) |

**Test each finding against three checks:**
1. **ACIR faithfulness** — does the ACIR have exactly the constraints the source writes, no fewer? (Compare `h1 + h2 == 0` vs `assert(h1 + h2 == 0)` in source — ACIR matches.)
2. **Certificate** — does the forged witness pass every ACIR opcode? If yes, the ACIR itself considers the value free.
3. **Control** — return the forged value to the honest one → rejected? If rejected, the certificate isn't vacuous.

**Known non-bug pattern: two-hint cross-constraint** (`assert(h1 * h2 == 0)`, `h1 + h2 == 0`).  
The ACIR correctly encodes two degrees of freedom; the programmer didn't write `assert(h1 == a)`.  
**Not a compiler bug.** See `references/two-hint-cross-constraint.md`.

## Memory Fix (2026-08-22)

In `src/mutate.rs`, `solve_pass()`, the `MemOpKind::Write` branch used to
`deferred = true` when the value to write was a soft hint. This caused:
the block to keep its stale init value, a subsequent `Read` to insert the
stale value, and the next pass to reject the attempt.

**Fix:** soft hints now take their value from the honest run immediately:

```rust
MemOpKind::Write => match assignment.get(&value_index) {
    Some(known) => cells[slot] = *known,
    None if soft.contains(&value_index) => {
        if let Some(honest_val) = honest.get(&value_index) {
            cells[slot] = *honest_val;
            assignment.insert(value_index, *honest_val);
            *derived += 1;
        } else { deferred = true; }
    }
    None => deferred = true,
},
```

**Regression test:** `conditional_array_write_with_hint_index` — proves that
mutating an index hint (1→0) correctly changes the public output (10→99).

1. **Noir version must match** — ACIR serialization changes between versions.
   Always use `nargo` from the same Noir commit as the `acir` dependency.
2. **`cargo fuzz` needs nightly** — use `cargo +nightly fuzz run` or
   `rustup default nightly`.
3. **First `cargo build` of noir-picus-adapter is slow** — Picus compiles cvc5
   if needed (C/C++ toolchain + libclang).
4. **SAT ≠ real bug** under determinism abstraction — `unsafe` via an abstracted
   blackbox may be a false positive. Check `abstracted:` annotations in output.
5. **Fixed variants must be manually written** — ensure they only add the
   missing binding, not over-constrain.
6. **Artifacts must be sanitized** — strip debug symbols, file maps, source
   text. Keep only `noir_version` + `bytecode`.
7. **`unsupported` is conservative** — witness-dependency graph is undirected,
   so it over-approximates influence.
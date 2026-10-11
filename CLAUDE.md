# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this project is

`noir-picus-adapter` is a Rust CLI that scans **Noir ACIR artifacts** (the JSON
that `nargo compile` produces) for **under-constrained witnesses**. It is an
*adapter*, not a fork: it does not re-implement Picus and does not lower ACIR to
R1CS. It translates supported ACIR opcodes into Picus SMT IR and asks Picus
whether a chosen target witness can take two different values under the same
fixed inputs.

For each target witness the tool builds a **self-composition / uniqueness
query**:

```
exists W1, W2:
  SemACIR(W1)               # both witness assignments satisfy the translated ACIR
  SemACIR(W2)
  fixed witnesses agree     # public/param inputs identical in both copies
  target witness differs    # W1[target] != W2[target]
```

Result interpretation:

- `SAT`  → `unsafe`     — target is under-constrained.
- `UNSAT` → `verified`  — target is uniquely determined by supported semantics.
- `UNKNOWN` → `unknown` — solver timed out or could not decide.
- `unsupported`          — a non-translated opcode can influence the target.

> Note: most prose docs (`README.md`, `docs/ARCHITECTURE.md`, `docs/SOUNDNESS.md`, `examples/README.md`)
> are written in **Russian**. The `corpus/*.md` docs are in English. Keep this
> bilingual convention when editing existing files; new top-level docs aimed at
> tooling/CI can be English.

## Build, test, run

```bash
cargo build                 # first build is SLOW unless CVC5_LIB_DIR points at a
                            # prebuilt cvc5 release (see README)
cargo test                  # unit tests live in src/translate/{tests,soundness_tests}.rs
cargo fmt                    # no custom rustfmt.toml; use defaults
cargo clippy

# Run a scan (artifact path works with or without .json):
cargo run -- scan examples/artifacts/unsafe_division_hint \
  --targets returns --fixed all-params
```

### Toolchain / dependencies

- Rust **1.89+**, **edition 2024**. `#![forbid(unsafe_code)]` in `src/lib.rs` —
  do not introduce `unsafe`.
- Requires `git`, `bash`, `make`, a C/C++ toolchain, and `libclang` (for
  `bindgen`, pulled in transitively by Picus).
- `acir` and `picus-smt` are pinned **by git revision** in `Cargo.toml`. You do
  NOT need a local Noir or Picus checkout to build or scan.
- ACIR serialization changes between Noir versions. If you regenerate artifacts,
  use a `nargo` built from the **same Noir revision** as the `acir` dep, or
  loading will fail with a version-mismatch error (see `src/artifact.rs`).

## CLI surface

Main subcommands: `scan` (SMT uniqueness) and `fuzz` (dynamic search for a
second accepting witness, no witness file needed); also `mutate`, `unpinned`,
`feasible`, `witness-inputs`, `check-witness` (all in `src/lib.rs`).

| Flag | Values | Default | Meaning |
| --- | --- | --- | --- |
| `--fixed` | `public`, `all-params` | `all-params` | which params are held equal across the two copies |
| `--targets` | `returns`, `brillig-outputs`, `all` | `all` | which witnesses to check |
| `--solver` | `cvc5`, `z3` | `cvc5` | Picus backend |
| `--theory` | `ff`, `nia` | `ff` | SMT theory (finite-field / nonlinear int arith) |
| `--format` | `human`, `json` | `human` | output format |
| `--timeout` | ms | `5000` | per-target solver timeout |
| `--dump-smt <dir>` | path | — | write per-target `.smt2` files, one per abstraction level |
| `--no-solve` | flag | — | propagate only; unresolved targets become `unknown` |
| `--max-range-bits` | u32 | `64` | widest `RANGE` still expanded into bits |
| `--exit-code-on-finding` | flag | — | exit 1 on `unsafe`, 2 on `error` |
| `--verbose` / `-v` | flag | — | witness selection, IR sizes, self-composition mapping |

## Source layout (`src/`)

| File | Responsibility |
| --- | --- |
| `main.rs` | Thin entry point; calls `lib::run()`. |
| `lib.rs` | Module tree and `run()` dispatch only. |
| `cli.rs` | clap argument types and CLI-enum ↔ internal-enum conversions. |
| `commands/` | One module per subcommand: `scan` (also the hidden `scan-target` / `refine-circuit` re-invocations used for hard timeouts), `fuzz`, `mutate`, `unpinned`, `witness` (`feasible`, `witness-inputs`, `check-witness`). Only entry points are `pub(crate)`. |
| `artifact.rs` | Load/deserialize Noir artifact JSON. Handles both `ProgramArtifact` (single program) and `ContractArtifact` (multiple functions → one `LoadedProgram` each). |
| `debug_info.rs` | ABI and debug-symbol parsing; witness → name / source location. |
| `targets.rs` | Discover target witnesses: return values and `BrilligCall` outputs (`Simple`/`Array`), tagged with `TargetOrigin`. |
| `translate.rs` + `translate/` | **Static path core.** ACIR→Picus IR translation. The root module owns `AcirPicusModel`, the `build_model` per-opcode driver, layered cone slicing (`target_constraints_at`) and unsupported-opcode tracking. Per-opcode emission lives in submodules: `expr` (AssertZero), `range`, `bitwise` (AND/XOR), `memory`, `determinism` (Tier-2 abstraction + the functional-blackbox allow-list), `uniqueness` (uniqueness-propagation lemmas), `known` (constant propagation), `ir` (wire mapping / `var_name` / coefficient helpers), `wires` (wire enumeration). Tests: `translate/tests.rs` (IR shape), `translate/uniqueness.rs` (lemma tests) and `translate/soundness_tests.rs` (differential, solution sets). |
| `refine.rs` | Decide/propagate loop: small local windows whose `UNSAT` proves a wire unique and feeds propagation (the QED²/DPVL idea, on ACIR). |
| `solver.rs` | Build the `UniquenessQuery`, short-circuit trivially-verified targets, run the Picus backend, optional SMT dump, map `SolverResult`→`TargetReport`. |
| `report.rs` | Serializable report types (`ScanReport` → `ProgramReport` → `CircuitReport` → `TargetReport`), `TargetStatus` enum, human + JSON printers. |
| `field.rs` | `FieldElement` ↔ `BigUint` / decimal conversions and black-box input resolution, shared by the dynamic path. Use these instead of re-deriving them. |
| `dynamic/` | **Dynamic path.** `concrete` (ACVM execution: black-box evaluation, input repair, Brillig-output override), `certify` (re-check a finding against ACIR opcodes), `candidates` (values to try, circuit structure), `repair` (forward re-derivation of a witness), `mutate` (mutation search), `fuzz` (input generation + hint-override search), `explain` (`unpinned` analysis and finding explanations). |

Docs: `docs/ARCHITECTURE.md` (pipelines and module map), `docs/SOUNDNESS.md`
(what each verdict means), `docs/research/` (research log, report, notes).

## Key conventions and invariants

These are easy to get wrong — respect them when editing `translate/`/`solver.rs`:

- **Witness → Picus wire mapping**: `picus_wire(w) = w.witness_index() + 1`.
  **Wire `0` is reserved** as the constant signal and is always an input. ACIR
  witness `wN` becomes Picus signal `N+1`. `target_signal == picus_wire`.
- **Self-composition naming**: the first copy uses `x*` variables, the second
  uses `y*`. **Fixed/input wires stay `x*` in both copies** (they are shared).
  `var_name()` in `translate/ir.rs` enforces this; counterexamples read `x{sig}` /
  `y{sig}` (see `solver.rs::counterexample`).
- **Constraint groups are indivisible.** One ACIR opcode may expand to several
  IR constraints (RANGE/AND/XOR allocate aux bit-wires). `push_constraint_group`
  keeps them together so cone-slicing can never keep a public wire while dropping
  its auxiliary bits.
- **Cone-of-influence slicing** (`target_constraints`): Picus only sees
  constraints reachable from the target, cut at `fixed_known_signals`. This is
  the main scaling guard. The full circuit IR is still reported at circuit level.
- **Conservative unsupported handling.** Unsupported opcodes are NOT silently
  ignored. A witness-dependency graph (`dependency_edges`) marks a target
  `unsupported` only if an unsupported opcode is in its non-fixed component;
  targets in unaffected components still get scanned.
- **Fixed-known propagation** (`infer_fixed_known_signals`): linear-only
  fixpoint — if an `AssertZero` linear equation has exactly one unknown wire,
  that wire becomes known. Nonlinear (`mul_terms`) constraints are intentionally
  skipped. Targets proven known this way are reported `verified` with no solver
  call.

### Supported vs unsupported opcodes

Supported (translated): `AssertZero(Expression)` (linear + nonlinear),
`RANGE` (boolean for `num_bits==1`, bit decomposition `x = Σ 2^i b_i` for widths
< field bits, no-op for widths ≥ field bits), `AND`/`XOR` (via input/output bit
decomposition, widths < field bits). `BrilligCall` outputs are treated as
nondeterministic and are valid check targets. There is partial `MemoryOp` /
`MemoryInit` handling (see `memory_*` functions).

Other blackbox calls (hashes, ECDSA, curve ops, ...) are **deterministic pure
functions** and are handled by the *determinism abstraction* rather than blocked:
if all inputs are fixed-known the outputs become known (`infer_fixed_known_signals`,
Tier 1); otherwise each output gets a cross-copy constraint
`out_x = out_y ∨ (some input differs)` (`determinism_constraint`, Tier 2). This
keeps `verified` sound but a resulting `unsafe` may be spurious, so affected
targets are flagged (`abstracted_reasons` / `abstraction_notes`). See
`docs/SOUNDNESS.md`. Only `Opcode::Call` and unsupported memory patterns still record
an `UnsupportedIssue` and may block affected targets.

## Examples (`examples/`)

Sanitized ACIR JSON lives in `examples/artifacts/` (only `noir_version` +
`bytecode`, no debug symbols/local paths) — runnable straight after clone. Noir
sources are in `examples/<name>/src/main.nr` with a `Nargo.toml`. Expected
results are tabulated in `examples/README.md` (e.g. `unsafe_division_hint` →
`unsafe`, `verified_division_hint` → `verified`).

## Corpus (`corpus/`)

A bank of realistic vulnerable-circuit miniports for bulk regression. Three
tiers, each with a TSV manifest (the source of truth for expected results) and a
runner script:

| Tier | Manifest | Runner | Expectation |
| --- | --- | --- | --- |
| Micro regression | `manifest.tsv` | `check_corpus.sh` | all rows `unsafe`; scan `--fixed public --targets returns` |
| Production-like | `realistic_manifest.tsv` | `check_realistic_corpus.sh` | vulnerable variants `unsafe`, fixed variants `verified`; records per-variant metrics |
| Compiler bugs | `compiler_regression_manifest.tsv` | `check_compiler_regression.sh` | Noir advisory PoCs; some scanned, some checked via `nargo execute` |

`provenance.tsv` files record the original DSL/project/source per miniport.
Markdown docs are navigation/analysis only — see `corpus/README.md` "Documentation
Map": `RESEARCH_REPORT.md` (publication), `ANALYSIS.md` (perf/engineering),
`DIVERSITY.md` (boundary-class taxonomy), `COMPILER_REGRESSION.md`, `TRIAGE.md`
(runbook for `unsafe`/`verified`/`unsupported`/`unknown` mismatches).

### Running corpus scripts

The runner scripts **recompile Noir packages**, so they need a `nargo` binary.
The default path is hardcoded to a developer machine — override it via env:

```bash
NARGO=/path/to/noir/target/debug/nargo bash corpus/check_corpus.sh
```

Useful env overrides: `NARGO`, `ADAPTER` (defaults to
`target/debug/noir-picus-adapter` — build first), `NOIR_PICUS_TIMEOUT_MS`,
`NOIR_PICUS_*_OUT` (diagnostics dirs under `/tmp`), `NOIR_PICUS_KEEP_TARGETS`.
Scripts are `set -euo pipefail` and assert manifest/provenance headers and case
sets stay in sync — keep TSVs aligned when adding cases.

## Working agreements

- **Git**: develop on the designated feature branch; commit with clear messages;
  push with `git push -u origin <branch>`. Do NOT open a PR unless explicitly
  asked. `.gitignore` excludes `target/` and `examples/smt/`.
- When changing translation semantics, **add/adjust the unit tests** in
  `src/translate/tests.rs` (and `soundness_tests.rs` for solution-set changes)
  and, if behavior is observable end-to-end, verify against
  the relevant `examples/` or `corpus/` expectations.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test --release` and the
  micro corpus. Keep all four green locally before pushing.
- Keep new artifacts **sanitized** (`noir_version` + `bytecode` only) to match
  the existing committed JSON.

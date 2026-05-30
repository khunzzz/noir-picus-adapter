# Vulnerable ZK Circuit Corpus

## Documentation Map

The corpus has several Markdown files because they serve different jobs. The
source of truth is still the TSV manifests, provenance files, Noir packages, and
runner scripts; Markdown files are navigation, analysis, or runbooks.

| File | Purpose | Read this when |
| --- | --- | --- |
| `README.md` | Entry point, tier layout, run commands, and where files live. | You want to run or inspect the corpus. |
| `RESEARCH_REPORT.md` | Publication-style report with research questions, tables, results, limitations, and reproducibility notes. | You need material for a paper, thesis, or presentation. |
| `ANALYSIS.md` | Engineering analysis of corpus behavior, performance, diagrams, and adapter acceleration. | You want to understand why scans are fast/slow and what changed in the tool. |
| `DIVERSITY.md` | Taxonomy of vulnerability boundary classes and duplicate-pattern cleanup notes. | You want to justify that the corpus is not one repeated toy pattern. |
| `COMPILER_REGRESSION.md` | Noir compiler bug tier, GitHub advisory PoCs, Trailmark snapshot, and `MemoryOp` support analysis. | You are studying compiler bugs rather than circuit-underconstraint bugs. |
| `TRIAGE.md` | Failure-analysis runbook for `unsafe`/`verified`/`unsupported`/`unknown` mismatches. | A corpus gate fails and you need to debug it systematically. |

Recommended reading paths:

| Task | Files |
| --- | --- |
| Run all checks | `README.md` only |
| Write up research results | `RESEARCH_REPORT.md`, then `ANALYSIS.md` for supporting details |
| Defend corpus diversity | `DIVERSITY.md` plus the provenance TSVs |
| Investigate Noir compiler bugs | `COMPILER_REGRESSION.md` |
| Debug a failing row | `TRIAGE.md` and the `/tmp/noir-picus-*` logs |

This corpus has three tiers.

The default `manifest.tsv` tier is a fast micro regression set. It contains Noir
miniports of real ZK bug patterns from Circom, Halo2, Cairo, Bellperson,
Arkworks, PIL, Gnark, Plonky3, Risc0, and zkEVM-style DSLs. The cases are
intentionally modeled as private witness chains under fixed public statements,
so scan them with `--fixed public --targets returns`.

The `realistic_manifest.tsv` tier is a production-like effectiveness set. It
keeps the same source-faithful vulnerable boundary, but wraps it in medium and
large constraint chains with vulnerable and fixed variants. Vulnerable variants
must scan `unsafe`; fixed variants must scan `verified`.

The `compiler_regression_manifest.tsv` tier is different: it tracks Noir
compiler/security PoCs from GitHub advisories and issues. Some rows are Picus
scans, while Brillig/runtime semantic bugs are checked by `nargo execute`.

```bash
cargo build

./target/debug/noir-picus-adapter scan corpus/artifacts/vuln_binary_merkle_selector \
  --fixed public \
  --targets returns
```

Run every case:

```bash
bash corpus/check_corpus.sh
bash corpus/check_realistic_corpus.sh
bash corpus/check_compiler_regression.sh
```

The artifacts in `corpus/artifacts` are sanitized `nargo compile` outputs:
`noir_version` plus `bytecode`, with debug paths removed.

`manifest.tsv` and `realistic_manifest.tsv` are the runner-facing lists of
expected results. `provenance.tsv` and `realistic_provenance.tsv` record the
original DSL/project/source and the translation note for each miniport.

`check_corpus.sh` compiles all packages with the canonical Noir checkout,
regenerates sanitized artifacts, scans every manifest row, and writes failure
diagnostics to `/tmp/noir-picus-corpus`. See `TRIAGE.md` for the required
analysis flow when a case is not reported as `unsafe`.

`check_realistic_corpus.sh` does the same for `corpus/realistic`, writes
diagnostics to `/tmp/noir-picus-realistic-corpus`, and records per-variant
metrics: status, wire count, original constraint count, target count, elapsed
scan time, and reason.

See [ANALYSIS.md](ANALYSIS.md) for the comparative analysis, diagrams, current
performance snapshot, and the adapter acceleration notes from the realistic
corpus loop. See [DIVERSITY.md](DIVERSITY.md) for the boundary-class audit and
the duplicate-pattern cleanup notes. See
[COMPILER_REGRESSION.md](COMPILER_REGRESSION.md) for the Noir compiler bug
regression layer and Trailmark snapshot. See
[RESEARCH_REPORT.md](RESEARCH_REPORT.md) for the publication-oriented summary
with research questions, tables, results, limitations, and reproducibility
commands.

## Case Map

| Case | Pattern |
| --- | --- |
| `vuln_binary_merkle_selector` | Missing boolean constraints on Merkle path selectors, inspired by ZK-Kit `BinaryMerkleRoot`/`MultiMux1`. |
| `vuln_maci_state_index_bypass` | State-index equality guarded behind an invalid-message flag, inspired by MACI 1.0. |
| `vuln_aztec_nullifier_index_alias` | Membership checks a truncated index while nullifier derivation uses a wider index, inspired by Aztec 2.0. |
| `vuln_bigint_remainder_overflow` | Big integer division equation without remainder limb bounds, inspired by `circom-bigint`. |
| `vuln_evm_div_mod_remainder` | Division/modulo equation without `remainder < divisor`, inspired by zkEVM arithmetic gadgets. |
| `vuln_polygon_smt_rkey_bit` | Sparse Merkle key reconstruction without a boolean constraint on the next key bit. |
| `vuln_scroll_shift_byte_binding` | Shift helper byte drives the result but is not bound to the stack word byte. |
| `vuln_circom_decoder_onehot` | Decoder/one-hot constraints omit booleanity on output wires. |
| `vuln_mimc_assigned_not_constrained` | Internal hash is checked, but the exposed output is not constrained to it. |
| `vuln_r1cs_inverse_result` | Inverse witness is checked, but the quotient/result is not tied to it. |
| `vuln_montgomery_degenerate_point` | Coordinate conversion equations miss exceptional-denominator exclusions. |
| `vuln_bits2point_free_output` | Point decompression exposes a coordinate without curve/sign constraints. |

The full list is in `manifest.tsv`; all rows are expected to report `unsafe`.

## Provenance

- 0xPARC `zk-bug-tracker`: Dark Forest, Aztec 2.0, MACI, MiMC, zkEVM
  division/modulo, Polygon zkEVM SMT.
- PSE ZK-Kit disclosure: `BinaryMerkleRoot` selector booleanity.
- RustSec `RUSTSEC-2021-0075`: `ark-r1cs-std::FieldVar::mul_by_inverse`.
- Veridise EF/0xPARC Circom audit: circomlib Decoder, Montgomery conversions,
  Window/point conversion outputs, and `circom-bigint` assumptions.

# Corpus Failure Triage

`check_corpus.sh` is the acceptance gate for the micro corpus.
`check_realistic_corpus.sh` is the acceptance gate for the medium/large
realistic corpus. A failing case should be analyzed as an
instrument-or-fixture mismatch, not papered over.

Diagnostic files are written under `/tmp/noir-picus-corpus` by default:

- `compile/<case>.log`
- `scan/<case>.json`
- `verbose/<case>.txt`
- `smt/<case>/*.smt2`
- `summary.tsv`

The realistic gate writes the same shape under
`/tmp/noir-picus-realistic-corpus`. Its summary also includes wire count,
original constraint count, target count, and elapsed scan time.

## Status Guide

`verified`: the Noir miniport probably overconstrains the returned witness.
Compare `src/main.nr` with `provenance.tsv`, identify the assertion or fixed
input that makes the return unique, then either remove that accidental binding
or document why the source bug is no longer represented.

`unsupported`: inspect `verbose/<case>.txt` for unsupported ACIR opcodes on the
target dependency component. If the opcode is central to the source bug, improve
the adapter translator and add focused Rust tests. If it is incidental heavy
machinery, replace it with a lightweight Noir substitute and update
`provenance.tsv`.

`unknown`: inspect SMT size and shape in `smt/<case>`. Prefer reducing heavy
hash/lookup/permutation substitutes while preserving the vulnerable boundary. If
the query is small, investigate solver/theory handling in the adapter.

`unsafe on fixed`: this is a false positive in the scanner or in fixed-witness
treatment. Compare the vulnerable/fixed Noir delta, confirm the missing
constraint is present, then inspect translated constraints and target discovery.
Adapter fixes need focused Rust tests before rerunning the corpus gates.

`no targets`: ensure the vulnerable witness is returned from `main` and that the
manifest row uses `targets=returns`. If the target should be a Brillig output,
add explicit scanner support and tests before changing corpus policy.

`compile_failed`: fix Noir syntax/type errors first. Rebuild with the canonical
compiler `/home/said/noir/target/debug/nargo` because the adapter pins the same
Noir/ACIR commit.

`artifact mismatch`: regenerate the artifact from the matching source package
and keep only `{ "noir_version", "bytecode" }`. Artifacts must not include local
paths, debug symbols, file maps, or source text.

## Policy

Do not weaken a fixture only to make the scanner pass. The original vulnerable
constraint/witness chain must remain recognizable in `src/main.nr` and
`provenance.tsv`.

If a miniport needs an unsupported ACIR opcode, prefer improving the adapter when
that opcode is semantically central. For adapter changes, add focused Rust tests
before re-running the full corpus gate.

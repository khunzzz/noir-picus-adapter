//! Dynamic search for a second witness, by mutation and repair.
//!
//! The SMT path proves things, but a finite-field solver gives up long before
//! a realistic circuit does. This path proves nothing in the negative direction
//! and everything in the positive one: it looks for a *concrete* second witness,
//! and when it finds one there is nothing left to argue about — two assignments,
//! same inputs, different output, both accepted by every ACIR opcode.
//!
//! The method:
//!
//! 1. Start from an honest witness produced by `nargo execute`.
//! 2. Pick a witness that a `BrilligCall` produced. Those are hints — the
//!    proving system does not compute them, it only checks whatever the prover
//!    supplies — so they are the only places a malicious prover has freedom.
//! 3. Change it, then *repair* the assignment: walk the opcodes in order and
//!    re-solve every constraint that has exactly one stale witness left in it.
//!    ACIR is largely a chain of definitions, so this recovers most of the
//!    downstream values without any search.
//! 4. Check every opcode against the repaired assignment. If they all hold and
//!    a return value moved, the circuit accepts two different outputs for the
//!    same inputs.
//!
//! Nothing here is complete: a failed repair means only that this mutation did
//! not work out. But each success is a finished, self-contained proof, and the
//! whole pass costs no solver time at all, which is what makes it usable on the
//! circuits the SMT path cannot reach.

use std::collections::{BTreeMap, BTreeSet};

use acir::{AcirField, FieldElement, circuit::Circuit};
use serde::Serialize;

use crate::dynamic::candidates::{
    candidate_values, hint_witnesses, index_candidates, input_candidates, public_outputs,
    range_widths, wrap_candidates,
};
use crate::dynamic::certify::WitnessValues;
use crate::dynamic::repair::{RepairOutcome, repair};
use crate::field::to_decimal;

/// An input assignment the constraint system accepts.
///
/// Whether that is a bug depends on something this crate cannot see: what the
/// program does on those inputs. The caller runs the program on them, and a
/// circuit that accepts what the program rejects is a soundness break — the
/// verifier would take a proof of a statement the source says is false. That
/// is the shape of every advisory where a check failed to survive compilation.
#[derive(Debug, Serialize)]
pub(crate) struct AcceptedInputs {
    /// The input witness that was moved, and to what.
    pub(crate) witness: u32,
    pub(crate) original: String,
    pub(crate) alternative: String,
    /// Every circuit parameter, in witness order, for the accepting assignment.
    pub(crate) inputs: BTreeMap<u32, String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Mutation {
    /// The hint witness that was changed.
    pub(crate) witness: u32,
    pub(crate) original: String,
    pub(crate) alternative: String,
    /// Return witnesses whose value moved as a result.
    pub(crate) diverging_returns: BTreeMap<u32, String>,
    /// Every witness that had to be repaired.
    pub(crate) repaired: usize,
    /// The full assignment, for re-checking the finding elsewhere.
    #[serde(skip)]
    pub(crate) assignment: Option<BTreeMap<u32, String>>,
}

/// Where the search loses mutations. Without this the only visible number is
/// "no findings", which says nothing about whether the search explored anything
/// at all.
impl MutationFunnel {
    /// Record what one attempt produced. Every call site goes through here so
    /// that a loop cannot quietly stop reporting and make a program look
    /// unsearched.
    fn record(&mut self, outcome: &RepairOutcome) {
        if outcome.solved {
            self.repaired += 1;
        }
        if outcome.refuted {
            self.refuted += 1;
        }
        if outcome.unjudged {
            self.unjudged += 1;
            if let Some(reason) = &outcome.unjudged_reason {
                *self
                    .unjudged_reasons
                    .entry(normalise_reason(reason))
                    .or_insert(0) += 1;
            }
        }
    }
}

/// Collapse a reason to its kind, so the histogram has a handful of buckets
/// rather than one entry per opcode index. "opcode 12 not evaluated: black box
/// SHA256" and the same at opcode 340 are one problem, not two.
fn normalise_reason(reason: &str) -> String {
    let tail = match reason.split_once(" not evaluated: ") {
        Some((_, rest)) => rest,
        None => reason,
    };
    let mut out = String::with_capacity(tail.len());
    let mut chars = tail.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'w' && chars.peek().is_some_and(char::is_ascii_digit) {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push_str("wN");
        } else if c.is_ascii_digit() {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push('N');
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct MutationFunnel {
    /// Hint witnesses considered.
    pub(crate) hints: usize,
    /// Mutations where every broken constraint could be re-solved.
    pub(crate) repaired: usize,
    /// Repairs that then satisfied every ACIR opcode.
    pub(crate) accepted: usize,
    /// Accepted repairs that left every return value unchanged, so the
    /// divergence stayed internal and is not exploitable.
    pub(crate) internal_only: usize,
    /// Input assignments the constraint system accepted.
    pub(crate) accepted_inputs: usize,
    /// Attempts a constraint refuted outright. These are real results: the
    /// circuit rejected the alternative, which is the answer being looked for
    /// when the circuit is correct.
    pub(crate) refuted: usize,
    /// Attempts that produced a full assignment the ACIR evaluator could not
    /// judge — a hash or a curve operation on the path, whose semantics this
    /// crate does not implement. Also not a search result.
    pub(crate) unjudged: usize,
    /// What stopped each of those, by kind. Reported so a zero-finding run can
    /// be read for what it did not cover, not just for its verdict.
    pub(crate) unjudged_reasons: BTreeMap<String, usize>,
}

impl MutationReport {
    /// Fold another circuit's result into this one.
    pub(crate) fn merge(&mut self, other: Self) {
        self.attempted += other.attempted;
        self.funnel.hints += other.funnel.hints;
        self.funnel.repaired += other.funnel.repaired;
        self.funnel.accepted += other.funnel.accepted;
        self.funnel.internal_only += other.funnel.internal_only;
        self.funnel.accepted_inputs += other.funnel.accepted_inputs;
        self.funnel.refuted += other.funnel.refuted;
        self.funnel.unjudged += other.funnel.unjudged;
        for (reason, count) in other.funnel.unjudged_reasons {
            *self.funnel.unjudged_reasons.entry(reason).or_insert(0) += count;
        }
        self.findings.extend(other.findings);
        self.accepted_inputs.extend(other.accepted_inputs);
    }
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct MutationReport {
    pub(crate) attempted: usize,
    pub(crate) funnel: MutationFunnel,
    pub(crate) findings: Vec<Mutation>,
    /// Input assignments the constraint system accepts, for the caller to
    /// re-run against the program itself.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) accepted_inputs: Vec<AcceptedInputs>,
}

/// Knobs for one search.
#[derive(Clone, Debug)]
pub(crate) struct SearchOptions {
    pub(crate) attempts_per_witness: usize,
    /// Mutate only Brillig outputs, not every witness. The fuzzer runs the
    /// search once per generated input, and on a circuit with thousands of
    /// witnesses the full surface costs minutes per run.
    pub(crate) hints_only: bool,
    /// Skip the input-moving oracle, whose results need the program to judge.
    pub(crate) skip_input_oracle: bool,
    pub(crate) deadline: Option<std::time::Instant>,
}

/// Try to build a second accepting witness by perturbing hint outputs.
pub(crate) fn search(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    attempts_per_witness: usize,
) -> MutationReport {
    search_with(
        circuit,
        honest,
        &SearchOptions {
            attempts_per_witness,
            hints_only: false,
            skip_input_oracle: false,
            deadline: None,
        },
    )
}

pub(crate) fn search_with(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    options: &SearchOptions,
) -> MutationReport {
    let attempts_per_witness = options.attempts_per_witness;
    let out_of_time = || {
        options
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    };
    let mut report = MutationReport::default();
    let returns = public_outputs(circuit);
    let inputs = circuit
        .private_parameters
        .iter()
        .chain(circuit.public_parameters.0.iter())
        .map(|witness| witness.witness_index())
        .collect::<BTreeSet<_>>();

    let wraps = wrap_candidates(circuit);
    let hints = hint_witnesses(circuit)
        .into_iter()
        .filter(|hint| !inputs.contains(hint))
        .collect::<BTreeSet<_>>();

    // Output-directed search first. Perturbing a hint and seeing where the
    // change lands is undirected, and on real Noir output it almost always
    // lands nowhere: the free hints are the inverse witnesses inside `IsZero`
    // gadgets, which are genuinely unconstrained when their input is zero and
    // feed nothing. Starting from the answer instead — move a return value,
    // then try to pay for it out of the hints, which are the prover's to choose
    // — asks the question that actually matters.
    for &output in &returns {
        if inputs.contains(&output) {
            continue;
        }
        let Some(original) = honest.get(&output).copied() else {
            continue;
        };
        for alternative in candidate_values(original, attempts_per_witness) {
            report.attempted += 1;
            let outcome = repair(circuit, honest, &inputs, &hints, output, alternative);
            report.funnel.record(&outcome);
            let Some((candidate, repaired)) = outcome.accepted else {
                continue;
            };
            report.funnel.accepted += 1;
            report.findings.push(Mutation {
                witness: output,
                original: original.to_string(),
                alternative: alternative.to_string(),
                diverging_returns: BTreeMap::from([(output, alternative.to_string())]),
                repaired,
                assignment: Some(canonical(&candidate)),
            });
            break;
        }
    }

    // Second oracle: move an *input* rather than a hint. The constraint system
    // accepting the result is not itself a bug — the program may well accept
    // those inputs too. It becomes one when the program does not, which the
    // caller checks by running it, so every accepting assignment is reported
    // for that comparison rather than judged here.
    let widths = range_widths(circuit);
    for &input in inputs.iter().filter(|_| !options.skip_input_oracle) {
        if out_of_time() {
            break;
        }
        let Some(original) = honest.get(&input).copied() else {
            continue;
        };
        for alternative in
            input_candidates(original, widths.get(&input).copied(), attempts_per_witness)
        {
            report.attempted += 1;
            let outcome = repair(circuit, honest, &inputs, &hints, input, alternative);
            report.funnel.record(&outcome);
            let Some((candidate, _)) = outcome.accepted else {
                continue;
            };
            report.funnel.accepted_inputs += 1;
            report.accepted_inputs.push(AcceptedInputs {
                witness: input,
                original: original.to_string(),
                alternative: alternative.to_string(),
                inputs: inputs
                    .iter()
                    .filter_map(|witness| Some((*witness, candidate.get(witness)?.to_string())))
                    .collect(),
            });
            break;
        }
    }

    // Every witness is a candidate, not only the hints.
    //
    // A hint is where a prover *obviously* has freedom, but it is not the only
    // place it can have freedom: any witness a pass left unpinned is fair game,
    // and those do not announce themselves. Restricting the search to hints
    // also made it structurally blind to whole gadgets — `assert_max_bit_size`
    // and the `from_*_bytes` family contain no hint at all, so the search saw
    // nothing to try and the audit had to mark them vacuous.
    //
    // Mutating a witness that *is* pinned costs one rejected forward solve, so
    // the extra candidates are cheap; mutating one that is not is exactly the
    // finding being looked for.
    let indexed = index_candidates(circuit);
    let surface = attack_surface(circuit, honest, &inputs);
    for hint in surface
        .into_iter()
        .filter(|witness| !options.hints_only || hints.contains(witness))
    {
        if out_of_time() {
            break;
        }
        let Some(original) = honest.get(&hint).copied() else {
            continue;
        };
        report.funnel.hints += 1;

        let mut values = candidate_values(original, attempts_per_witness);
        values.extend(
            wraps
                .get(&hint)
                .into_iter()
                .flatten()
                .map(|step| original + *step),
        );
        // A hint that picks a position — the offset of a match, the index of
        // a list element — is wrong in the interesting way only at another
        // *valid* position, which is never a neighbour of the honest one.
        // Those positions are read off the memory blocks the hint indexes.
        if hints.contains(&hint) {
            values.extend((2u128..=8).map(FieldElement::from));
            // Only for a hint that holds a position now; see `index_candidates`.
            if let Some(slots) = indexed.get(&hint)
                && widths
                    .get(&hint)
                    .is_some_and(|bits| (2..=64).contains(bits))
                && original.num_bits() <= 32
                && (original.to_u128() as usize) < slots.len()
            {
                values.extend(slots.iter().copied());
            }
        }
        let mut seen = BTreeSet::new();
        values.retain(|value| *value != original && seen.insert(value.to_be_bytes()));
        for alternative in values {
            report.attempted += 1;
            let outcome = repair(circuit, honest, &inputs, &hints, hint, alternative);
            report.funnel.record(&outcome);
            let Some((candidate, repaired)) = outcome.accepted else {
                continue;
            };
            report.funnel.accepted += 1;

            let diverging = returns
                .iter()
                .filter_map(|witness| {
                    let before = honest.get(witness)?;
                    let after = candidate.get(witness)?;
                    (before != after).then(|| (*witness, after.to_string()))
                })
                .collect::<BTreeMap<_, _>>();
            if diverging.is_empty() {
                report.funnel.internal_only += 1;
                continue;
            }

            report.findings.push(Mutation {
                witness: hint,
                original: original.to_string(),
                alternative: alternative.to_string(),
                diverging_returns: diverging,
                repaired,
                assignment: Some(canonical(&candidate)),
            });
            break;
        }
    }

    report
}

/// The assignment as canonical residues.
///
/// A field element prints signed, so a value just below the modulus comes out
/// as `-1`. That is fine to read and useless to feed to anything else, and the
/// point of emitting an assignment is for something else to re-check it.
fn canonical(assignment: &WitnessValues) -> BTreeMap<u32, String> {
    assignment
        .iter()
        .map(|(witness, value)| (*witness, to_decimal(*value)))
        .collect()
}

/// Witnesses worth trying to move, hints first.
///
/// Hints lead because they are where an attack usually starts and a finding
/// there is immediately meaningful. The rest follow so that a witness left
/// unpinned by a compiler pass is still reachable, which is the case a
/// hint-only search cannot see at all.
fn attack_surface(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    inputs: &BTreeSet<u32>,
) -> Vec<u32> {
    let hints = hint_witnesses(circuit)
        .into_iter()
        .filter(|witness| !inputs.contains(witness))
        .collect::<BTreeSet<_>>();

    let mut surface = hints.iter().copied().collect::<Vec<_>>();
    surface.extend(
        honest
            .keys()
            .copied()
            .filter(|witness| !inputs.contains(witness) && !hints.contains(witness)),
    );
    surface
}

#[cfg(test)]
mod tests {
    use acir::{
        circuit::{
            Circuit, Opcode, PublicInputs,
            brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
            opcodes::{BlackBoxFuncCall, BlockType, FunctionInput, MemOpKind},
        },
        native_types::{Expression, Witness},
    };

    use super::*;

    fn hint(outputs: &[u32]) -> Opcode<FieldElement> {
        Opcode::BrilligCall {
            id: BrilligFunctionId::new(0),
            inputs: vec![BrilligInputs::Single(Expression::default())],
            outputs: outputs
                .iter()
                .map(|witness| BrilligOutputs::Simple(Witness(*witness)))
                .collect(),
            predicate: Expression::one(),
        }
    }

    fn range(witness: u32, num_bits: u32) -> Opcode<FieldElement> {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(Witness(witness)),
            num_bits,
        })
    }

    fn field(value: &str) -> FieldElement {
        FieldElement::try_from_str(value).expect("a decimal field element")
    }

    /// The `Field as u128` cast gadget, in the shape Noir emitted before
    /// `1.0.0-beta.16`, and the forgery it allows (GHSA-cp84-xrj5-49vg).
    ///
    /// ```text
    /// hint      -> (quotient w1, remainder w2)
    /// RANGE w1 126,  RANGE w2 129
    /// w2 = w0 - 2^128 * w1          // the split
    /// hint      -> inverse w3
    /// w4 = 1 - w2*w3                // IsZero(w2)
    /// 0  = w2*w4
    /// w5 = 2 - w4                   // the output: 1 when w2 == 0, else 2
    /// ```
    ///
    /// With `w0 = 0` the honest witness has `w1 = w2 = 0` and returns `1`. The
    /// attack takes `w1 = p / 2^128`, which makes `w2 = p mod 2^128` — non-zero,
    /// inside both ranges, and still satisfying the split over the field — so
    /// the same input returns `2`.
    ///
    /// Three separate things have to work for the search to reach it: the
    /// wrap-around candidate must be derived from the `2^128` coefficient, the
    /// inverse hint must be left open rather than pinned to its honest value,
    /// and the two `IsZero` equations have to be solved across two walks. This
    /// test fails if any of them regresses.
    // A read inside a loop is `idx = hint * predicate`, not `idx = hint + c`.
    // The hint must still get every slot of the block as a candidate: that is
    // how the second match of a non-strict substring search is reached.
    #[test]
    fn index_candidates_follow_a_predicated_index() {
        let mut define = Expression::default();
        define.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        define.push_addition_term(-FieldElement::one(), Witness(3));
        let circuit = Circuit {
            opcodes: vec![
                hint(&[1]),
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId::new(0),
                    init: (10..15).map(Witness).collect(),
                    block_type: BlockType::Memory,
                },
                Opcode::AssertZero(define),
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId::new(0),
                    op: acir::circuit::opcodes::MemOp::read_at_mem_index(Witness(3), Witness(4)),
                },
            ],
            ..Circuit::<FieldElement>::default()
        };
        let found = index_candidates(&circuit);
        let slots = found.get(&1).expect("hint 1 reaches the index");
        assert_eq!(slots.len(), 5);
        assert!(slots.contains(&FieldElement::from(4u128)));
    }

    #[test]
    fn finds_the_field_to_u128_cast_forgery() {
        let two_128 = field("340282366920938463463374607431768211456");

        // w2 = w0 - 2^128 * w1
        let mut split = Expression::default();
        split.push_addition_term(FieldElement::one(), Witness(2));
        split.push_addition_term(-FieldElement::one(), Witness(0));
        split.push_addition_term(two_128, Witness(1));

        // w4 = 1 - w2*w3
        let mut flag = Expression::default();
        flag.push_multiplication_term(FieldElement::one(), Witness(2), Witness(3));
        flag.push_addition_term(FieldElement::one(), Witness(4));
        flag.q_c = -FieldElement::one();

        // 0 = w2*w4
        let mut guard = Expression::default();
        guard.push_multiplication_term(FieldElement::one(), Witness(2), Witness(4));

        // w5 = 2 - w4
        let mut output = Expression::default();
        output.push_addition_term(FieldElement::one(), Witness(5));
        output.push_addition_term(FieldElement::one(), Witness(4));
        output.q_c = -FieldElement::from(2u128);

        let circuit = Circuit {
            private_parameters: [Witness(0)].into_iter().collect(),
            return_values: PublicInputs([Witness(5)].into_iter().collect()),
            opcodes: vec![
                hint(&[1, 2]),
                range(1, 126),
                range(2, 129),
                Opcode::AssertZero(split),
                hint(&[3]),
                Opcode::AssertZero(flag),
                Opcode::AssertZero(guard),
                Opcode::AssertZero(output),
            ],
            ..Circuit::<FieldElement>::default()
        };

        // The honest run: input 0, so both halves of the split are 0, the
        // IsZero flag is 1, and the output is 1.
        let honest = [
            (0, FieldElement::zero()),
            (1, FieldElement::zero()),
            (2, FieldElement::zero()),
            (3, FieldElement::zero()),
            (4, FieldElement::one()),
            (5, FieldElement::one()),
        ]
        .into_iter()
        .collect::<WitnessValues>();

        let report = search(&circuit, &honest, 8);
        let forgery = report
            .findings
            .iter()
            .find(|finding| finding.diverging_returns.contains_key(&5))
            .expect("the cast forgery is reachable");

        assert_eq!(
            forgery.alternative, "64323764613183177041862057485226039389",
            "the forged quotient is the field modulus divided by 2^128"
        );
        assert_eq!(
            forgery.diverging_returns.get(&5).map(String::as_str),
            Some("2")
        );
    }

    /// A memory block written through a soft (hint) value and then read.
    ///
    /// The honest run has `idx_hint = 1`, so the write goes to slot 1 and the
    /// read at slot 0 gets the original init value. After mutating `idx_hint`
    /// to 0, the write targets slot 0 and the read at slot 0 now picks up the
    /// written value — a genuine divergence in the public output.
    ///
    /// Before the memory-repair fix, the forward walk deferred the write
    /// when the value was a soft hint (even though the prover could freely
    /// choose it), the read got the stale init value from the block, and the
    /// assignment was poisoned so subsequent walks rejected the attempt.
    #[test]
    fn conditional_array_write_with_hint_index() {
        // w0 = param (private)
        // w1 = hint (soft)  -> idx
        // w2 = hint (soft)  -> value to write
        // w5 = 0            -> constant index for read (slot 0)
        // w3 = read result  -> public output
        // MemoryInit block0 = [10, 20, 30, 40]
        // MemoryOp block0[w1] = Write(w2)     write value at hinted index
        // MemoryOp block0[w5] = Read(w3)       read from slot 0
        // Return w3

        let block_id = acir::circuit::opcodes::BlockId::new(0);

        let circuit = Circuit {
            private_parameters: [Witness(0)].into_iter().collect(),
            return_values: PublicInputs([Witness(3)].into_iter().collect()),
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id,
                    init: vec![Witness(10), Witness(11), Witness(12), Witness(13)],
                    block_type: BlockType::Memory,
                },
                hint(&[1]),
                hint(&[2]),
                Opcode::MemoryOp {
                    block_id,
                    op: acir::circuit::opcodes::MemOp {
                        operation: MemOpKind::Write,
                        index: Witness(1),
                        value: Witness(2),
                    },
                },
                Opcode::MemoryOp {
                    block_id,
                    op: acir::circuit::opcodes::MemOp {
                        operation: MemOpKind::Read,
                        index: Witness(5),
                        value: Witness(3),
                    },
                },
                // Init witnesses: w10..w13 = 10, 20, 30, 40
                Opcode::AssertZero({
                    let mut e = Expression::default();
                    e.push_addition_term(FieldElement::one(), Witness(10));
                    e.q_c = -FieldElement::from(10u128);
                    e
                }),
                Opcode::AssertZero({
                    let mut e = Expression::default();
                    e.push_addition_term(FieldElement::one(), Witness(11));
                    e.q_c = -FieldElement::from(20u128);
                    e
                }),
                Opcode::AssertZero({
                    let mut e = Expression::default();
                    e.push_addition_term(FieldElement::one(), Witness(12));
                    e.q_c = -FieldElement::from(30u128);
                    e
                }),
                Opcode::AssertZero({
                    let mut e = Expression::default();
                    e.push_addition_term(FieldElement::one(), Witness(13));
                    e.q_c = -FieldElement::from(40u128);
                    e
                }),
                // Read index = 0
                Opcode::AssertZero({
                    let mut e = Expression::default();
                    e.push_addition_term(FieldElement::one(), Witness(5));
                    e
                }),
            ],
            ..Circuit::<FieldElement>::default()
        };

        // Honest run: idx=1, write=99 to slot 1, read from slot 0 -> output 10
        let honest = [
            (0, FieldElement::from(5u128)),   // param
            (1, FieldElement::from(1u128)),   // idx_hint = 1
            (2, FieldElement::from(99u128)),  // value hint
            (3, FieldElement::from(10u128)),  // output = block[0] = 10
            (5, FieldElement::zero()),        // read index = 0
            (10, FieldElement::from(10u128)), // block init
            (11, FieldElement::from(20u128)),
            (12, FieldElement::from(30u128)),
            (13, FieldElement::from(40u128)),
        ]
        .into_iter()
        .collect::<WitnessValues>();

        // Mutate idx_hint from 1 to 0.
        // Expected: write 99 to slot 0, read from slot 0 -> output 99
        let report = search(&circuit, &honest, 8);
        let finding = report
            .findings
            .iter()
            .find(|f| f.diverging_returns.contains_key(&3))
            .expect("conditional array write with hint index should be reachable");

        assert_eq!(
            finding.witness, 1,
            "the mutated witness should be the idx hint"
        );
        assert_eq!(
            finding.diverging_returns.get(&3).map(String::as_str),
            Some("99"),
            "the public output should change from 10 to 99"
        );
    }
}

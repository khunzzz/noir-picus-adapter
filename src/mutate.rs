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

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        brillig::BrilligOutputs,
        opcodes::{BlackBoxFuncCall, BlockType, FunctionInput, MemOpKind},
    },
    native_types::{Expression, Witness},
};
use num_bigint::BigUint;
use serde::Serialize;

use crate::certify::{self, WitnessValues};

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
            if let Some(slots) = indexed.get(&hint) {
                if widths
                    .get(&hint)
                    .is_some_and(|bits| (2..=64).contains(bits))
                    && original.num_bits() <= 32
                    && (original.to_u128() as usize) < slots.len()
                {
                    values.extend(slots.iter().copied());
                }
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

/// Every value that makes a hint land on a valid position of a memory block it
/// indexes.
///
/// ACIR reads `block[idx]` with `idx` a witness; when the source wrote
/// `haystack[i + offset]`, `idx` is defined by `idx - offset - i = 0`. For such
/// a pair the hint can only matter at `k - i` for `k` in the block, so those
/// are exactly the values worth trying. Capped, so a huge block does not turn
/// one hint into thousands of repair passes.
pub(crate) fn index_candidates(
    circuit: &Circuit<FieldElement>,
) -> BTreeMap<u32, Vec<FieldElement>> {
    const CAP: usize = 1024;
    let mut block_len = std::collections::HashMap::new();
    let mut index_len: BTreeMap<u32, usize> = BTreeMap::new();
    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::MemoryInit { block_id, init, .. } => {
                block_len.insert(*block_id, init.len());
            }
            Opcode::MemoryOp { block_id, op } => {
                if let Some(len) = block_len.get(block_id) {
                    let entry = index_len.entry(op.index.witness_index()).or_insert(0);
                    *entry = (*entry).max(*len);
                }
            }
            _ => {}
        }
    }
    let mut found: BTreeMap<u32, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut add = |hint: u32, shift: FieldElement, len: usize| {
        let entry = found.entry(hint).or_default();
        for k in 0..len.min(CAP) {
            if entry.len() >= CAP {
                break;
            }
            entry.insert((FieldElement::from(k as u128) - shift).to_be_bytes());
        }
    };
    for (&index, &len) in &index_len {
        add(index, FieldElement::zero(), len);
    }
    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else {
            continue;
        };
        if !expression.mul_terms.is_empty() || expression.linear_combinations.len() != 2 {
            continue;
        }
        let [(a, x), (b, y)] = [
            expression.linear_combinations[0],
            expression.linear_combinations[1],
        ];
        // a*x + b*y + q = 0. If x is an index and y = x - c, then y's valid
        // values are k - c. Same with the roles swapped.
        for ((ci, idx), (ch, hint)) in [((a, x), (b, y)), ((b, y), (a, x))] {
            let Some(&len) = index_len.get(&idx.witness_index()) else {
                continue;
            };
            if ci.is_zero() || -(ch / ci) != FieldElement::one() {
                continue;
            }
            // idx = hint + c with c = -q / ci.
            let c = -(expression.q_c / ci);
            add(hint.witness_index(), c, len);
        }
    }
    // Indices are rarely the hint itself. A read inside a loop compiles to
    // `idx = hint * predicate` (or `(hint + i) * predicate`), which the exact
    // rule above cannot see. Walk the constraints that define each index back
    // to the hints they mention, a few steps deep, and give every hint found
    // the whole block as candidates: a wider net, still bounded by the block.
    let hints = hint_witnesses(circuit).into_iter().collect::<BTreeSet<_>>();
    let mut mentions: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (position, opcode) in circuit.opcodes.iter().enumerate() {
        if let Opcode::AssertZero(expression) = opcode {
            for witness in witnesses_of(expression) {
                mentions.entry(witness).or_default().push(position);
            }
        }
    }
    for (&index, &len) in &index_len {
        let mut frontier = vec![index];
        let mut visited = BTreeSet::from([index]);
        for _depth in 0..3 {
            let mut next = Vec::new();
            for witness in frontier {
                let Some(positions) = mentions.get(&witness) else {
                    continue;
                };
                // A witness in many constraints is a hub (a loop predicate);
                // following it would connect everything to everything.
                if positions.len() > 24 {
                    continue;
                }
                for &position in positions {
                    let Opcode::AssertZero(expression) = &circuit.opcodes[position] else {
                        continue;
                    };
                    for other in witnesses_of(expression) {
                        if !visited.insert(other) {
                            continue;
                        }
                        if hints.contains(&other) {
                            add(other, FieldElement::zero(), len);
                        } else {
                            next.push(other);
                        }
                    }
                }
            }
            frontier = next;
        }
    }

    found
        .into_iter()
        .map(|(hint, values)| {
            (
                hint,
                values
                    .into_iter()
                    .map(|bytes| FieldElement::from_be_bytes_reduce(&bytes))
                    .collect(),
            )
        })
        .collect()
}

/// The assignment as canonical residues.
///
/// A field element prints signed, so a value just below the modulus comes out
/// as `-1`. That is fine to read and useless to feed to anything else, and the
/// point of emitting an assignment is for something else to re-check it.
fn canonical(assignment: &WitnessValues) -> BTreeMap<u32, String> {
    assignment
        .iter()
        .map(|(witness, value)| (*witness, to_biguint(*value).to_string()))
        .collect()
}

/// Steps that make a hint wrap around the field modulus.
///
/// Neighbouring values find a hint that is simply free. They never find the
/// other shape, where a hint is pinned by an equation like `input = 2^k * q + r`
/// and the second solution lies a whole modulus away: `q` moves by `p / 2^k`
/// and `r` absorbs the difference, so the equation still holds over the field
/// while the integers it was meant to represent are completely different. That
/// is the arithmetic behind the `Field as uN` cast forgery, and a search that
/// only tries `original + 1` cannot reach it no matter how long it runs.
///
/// The step is derived from the coefficients the hint actually appears with,
/// so no guessing is involved: for a hint multiplied by `c`, moving it by
/// `p / c` shifts the term by very nearly the modulus.
pub(crate) fn wrap_candidates(circuit: &Circuit<FieldElement>) -> BTreeMap<u32, Vec<FieldElement>> {
    let modulus = biguint_modulus();
    let mut steps: BTreeMap<u32, BTreeSet<Vec<u8>>> = BTreeMap::new();

    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else {
            continue;
        };
        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = to_biguint(*coefficient);
            // Take the signed magnitude. A coefficient of `-2^128` is stored as
            // `p - 2^128`, and dividing the modulus by that gives 1, which is
            // no step at all — the whole point is to move by `p / 2^128`.
            let magnitude = std::cmp::min(coeff.clone(), &modulus - &coeff);
            if magnitude <= BigUint::from(1u32) {
                continue;
            }
            let quotient = &modulus / &magnitude;
            if quotient == BigUint::ZERO {
                continue;
            }
            let entry = steps.entry(witness.witness_index()).or_default();
            for step in [
                quotient.clone(),
                &quotient + BigUint::from(1u32),
                &modulus - &quotient,
            ] {
                entry.insert(step.to_bytes_be());
            }
        }
    }

    steps
        .into_iter()
        .map(|(witness, values)| {
            (
                witness,
                values
                    .into_iter()
                    .map(|bytes| FieldElement::from_be_bytes_reduce(&bytes))
                    .collect(),
            )
        })
        .collect()
}

/// The field modulus as a `num-bigint` value of the version this crate uses.
/// `acir` is on a different major version, so it crosses the boundary as bytes.
fn biguint_modulus() -> BigUint {
    BigUint::from_bytes_be(&FieldElement::modulus().to_bytes_be())
}

/// Alternative values to try for a hint.
///
/// The order matters more than the count. A hint that is genuinely free
/// usually accepts anything, so a neighbouring value finds it immediately; a
/// hint that is pinned by a range check or a boolean constraint only breaks at
/// the edges, which is what `0`, `1` and `-1` are for. Trying a wide spread
/// first would waste attempts on values that any range check rejects outright.
pub(crate) fn candidate_values(original: FieldElement, attempts: usize) -> Vec<FieldElement> {
    let one = FieldElement::one();
    let mut values = vec![
        original + one,
        original - one,
        FieldElement::zero(),
        one,
        -one,
        original + original,
        original + FieldElement::from(256u128),
    ];
    values.retain(|value| *value != original);
    values.dedup();
    values.truncate(attempts.max(1));
    values
}

/// Values to try for an input.
///
/// An input is not free the way a hint is — the circuit range-checks it — so
/// the interesting values are the ones at the edge of that range. Overflow and
/// truncation checks only misbehave there, and both advisories in this class
/// were off-by-one guards: one that used `u128::MAX - 1` where it needed
/// `u128::MAX`, and one where a cast's quotient bound left the top of the
/// field reachable. A uniform draw would essentially never land on them.
fn input_candidates(
    original: FieldElement,
    width: Option<u32>,
    attempts: usize,
) -> Vec<FieldElement> {
    let mut values = candidate_values(original, attempts);
    if let Some(width) = width.filter(|width| *width <= 128) {
        let top = (BigUint::from(1u32) << width) - BigUint::from(1u32);
        for edge in [
            top.clone(),
            &top - BigUint::from(1u32),
            BigUint::from(1u32) << (width - 1),
        ] {
            values.push(FieldElement::from_be_bytes_reduce(&edge.to_bytes_be()));
        }
    }
    values.retain(|value| *value != original);
    values.dedup();
    values
}

/// The tightest `RANGE` width each witness carries, which is how wide the type
/// behind it is.
pub(crate) fn range_widths(circuit: &Circuit<FieldElement>) -> BTreeMap<u32, u32> {
    let mut widths = BTreeMap::new();
    for opcode in &circuit.opcodes {
        if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(witness),
            num_bits,
        }) = opcode
        {
            widths
                .entry(witness.witness_index())
                .and_modify(|known: &mut u32| *known = (*known).min(*num_bits))
                .or_insert(*num_bits);
        }
    }
    widths
}

/// The circuit's public outputs.
///
/// `return_values` is not the whole story. When a program is written
/// `-> return_data T`, Noir routes its outputs through a memory block of type
/// `ReturnData` and leaves `return_values` empty, so a search that only looked
/// there would compare nothing and call every divergence internal. Noir's own
/// AST fuzzer emits that form for roughly one program in eight, which is a
/// large blind spot to leave open.
pub(crate) fn public_outputs(circuit: &Circuit<FieldElement>) -> BTreeSet<u32> {
    let mut outputs = circuit
        .return_values
        .0
        .iter()
        .map(|witness| witness.witness_index())
        .collect::<BTreeSet<_>>();

    for opcode in &circuit.opcodes {
        if let Opcode::MemoryInit {
            init,
            block_type: BlockType::ReturnData,
            ..
        } = opcode
        {
            outputs.extend(init.iter().map(Witness::witness_index));
        }
    }

    outputs
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

/// Witnesses a `BrilligCall` produces. These are the prover's free choices.
pub(crate) fn hint_witnesses(circuit: &Circuit<FieldElement>) -> Vec<u32> {
    let mut found = Vec::new();
    for opcode in &circuit.opcodes {
        let Opcode::BrilligCall { outputs, .. } = opcode else {
            continue;
        };
        for output in outputs {
            match output {
                BrilligOutputs::Simple(witness) => found.push(witness.witness_index()),
                BrilligOutputs::Array(witnesses) => {
                    found.extend(witnesses.iter().map(Witness::witness_index));
                }
            }
        }
    }
    found
}

/// What one mutation attempt produced.
struct RepairOutcome {
    /// The forward solve ran to completion.
    solved: bool,
    /// A constraint refuted the attempt: the circuit doing its job. Counting
    /// this as "nothing was checked" reported well-constrained gadgets as
    /// unsearched, which is how the coverage signal went wrong once already.
    refuted: bool,
    /// The evaluator could not judge the result: an opcode on the path has no
    /// implementation here, so neither acceptance nor rejection was proved.
    unjudged: bool,
    /// Why it could not be judged. A bare count says how often the search came
    /// back empty-handed but not what would fix it, and the answer decides
    /// where the next work goes: an unmodelled black box needs an evaluator,
    /// an exhausted choice budget needs a bigger budget, and an unassigned
    /// witness needs better propagation. Those are three different tasks.
    unjudged_reason: Option<String>,
    /// ...and the resulting assignment satisfies every ACIR opcode.
    accepted: Option<(WitnessValues, usize)>,
}

/// Re-derive the whole witness with the hints held at chosen values.
///
/// This models what a prover actually does, and what it is actually free to
/// choose. Every `BrilligCall` output is supplied — the proving system does not
/// recompute them, it only checks the constraints — while everything else is
/// *derived* by walking the opcodes in order and solving each one for the value
/// it defines.
///
/// That is a stronger move than patching whichever constraints a change happened
/// to break. An array write under a mutated index changes the whole memory
/// block, and only a forward pass gets the reads after it right. Memory is where
/// most of Noir's published soundness advisories live, so a search that cannot
/// follow a value through a block cannot reach them at all.
/// How many different choices to try at a constraint that several still-open
/// hints could absorb. A comparison on integers produces two such hints — the
/// quotient and the remainder — so bailing out at the first ambiguity made the
/// search structurally blind to every branch predicated on `<` or `>`.
const MAX_PREFERENCES_DEFAULT: usize = 4;

/// How deep to search at an ambiguous constraint.
///
/// Measured, not guessed: the reason histogram added alongside this showed that
/// on a generated circuit all 134 unjudged attempts came from one cause — this
/// budget running out — and none from an unmodelled opcode. So the coverage of
/// a zero-finding run is set by this number, and a run that wants a stronger
/// negative result has to be able to raise it. Kept an environment variable
/// rather than a flag because it has to reach a function nested four levels
/// below the CLI, and the default stays what every earlier campaign used.
fn max_preferences() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("NOIR_PICUS_MAX_PREFERENCES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(MAX_PREFERENCES_DEFAULT)
    })
}

/// Try each choice at an ambiguous constraint in turn and keep the first that
/// yields an accepted witness.
///
/// The certificate is what keeps this sound: a wrong choice produces an
/// assignment that the independent opcode walk rejects, so widening the search
/// can only add findings that were already checkable, never fabricate one.
fn repair(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    inputs: &BTreeSet<u32>,
    hints: &BTreeSet<u32>,
    mutated: u32,
    value: FieldElement,
) -> RepairOutcome {
    let mut fallback: Option<RepairOutcome> = None;
    // Размер пространства выбора становится известен только после прохода, и
    // на разных попытках путь может отличаться, поэтому берётся наибольший
    // виденный.
    let mut widest_space = 1usize;
    let budget = max_preferences();
    let mut preference = 0usize;
    while preference < budget {
        let mut choice_points = 0usize;
        let mut space = 1usize;
        let outcome = repair_with(
            circuit,
            honest,
            inputs,
            hints,
            mutated,
            value,
            preference,
            &mut choice_points,
            &mut space,
        );
        if outcome.accepted.is_some() {
            return outcome;
        }
        if choice_points == 0 {
            // No ambiguity arose, so further preferences would repeat this run.
            return outcome;
        }
        widest_space = widest_space.max(space);
        fallback = Some(outcome);
        preference += 1;
        if preference >= widest_space {
            // Пространство сочетаний пройдено целиком: отказ здесь — настоящее
            // опровержение, а не нехватка сведений.
            break;
        }
    }
    let truncated = widest_space > budget;
    // Every choice tried failed, but the choices were capped, so this is a lack
    // of information rather than a proof that no second witness exists.
    let mut outcome = fallback.unwrap_or(RepairOutcome {
        solved: false,
        refuted: false,
        unjudged: true,
        unjudged_reason: Some("search exhausted its choice budget".to_owned()),
        accepted: None,
    });
    if truncated && outcome.refuted {
        outcome.refuted = false;
        outcome.unjudged = true;
        outcome.unjudged_reason = Some("search exhausted its choice budget".to_owned());
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn repair_with(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    inputs: &BTreeSet<u32>,
    hints: &BTreeSet<u32>,
    mutated: u32,
    value: FieldElement,
    preference: usize,
    choice_points: &mut usize,
    space: &mut usize,
) -> RepairOutcome {
    let trace = std::env::var_os("NOIR_PICUS_TRACE_MUTATE").is_some();
    if trace {
        eprintln!("mutate w{mutated} -> {value}");
    }
    // Every exit from here is a verdict. A walk that cannot finish does not
    // bail out: it falls through to the certificate with the honest values
    // filling whatever the constraints never pinned, and the evaluator decides.
    // So there is no "gave up without an answer" outcome to account for.
    let refuted = RepairOutcome {
        solved: false,
        refuted: true,
        unjudged: false,
        unjudged_reason: None,
        accepted: None,
    };

    // The prover controls exactly two things: the inputs it claims, and the
    // hints it supplies. It has to keep the inputs, so those are copied over
    // unchanged; the hints start from the honest run and one of them moves.
    // Only the prover's actual commitments start out fixed: the inputs, which
    // it must keep, and the one hint being moved. Every other hint is left
    // *open* rather than copied from the honest run, because a prover picks
    // all of its hints together and will pick whatever keeps the constraints
    // satisfied.
    //
    // Copying them instead was the bug that hid the `Field as u128` forgery.
    // The attack needs the inverse hint of an `IsZero` gadget to move along
    // with the value it tests; with the honest inverse pinned in place, the
    // gadget's own equation forced the flag to the honest branch and the
    // attempt was rejected one constraint later. Left open, the same two
    // equations determine both, and the attack falls out.
    let mut assignment = WitnessValues::new();
    for witness in inputs {
        if let Some(known) = honest.get(witness) {
            assignment.insert(*witness, *known);
        }
    }
    assignment.insert(mutated, value);

    let soft = hints
        .iter()
        .copied()
        .filter(|witness| *witness != mutated)
        .collect::<BTreeSet<_>>();
    let mut pinned = assignment;

    // ACIR is mostly, but not entirely, in definition order: a constraint can
    // mention two values that only later opcodes pin down. One pass would give
    // up there, so passes are repeated while any of them learns something, the
    // way a witness solver does. Memory state is rebuilt from scratch each
    // pass, because reads and writes are order-dependent and only a full walk
    // gets the block contents right.
    // Two nested fixpoints, and they are not the same thing.
    //
    // The inner one carries derived values forward and simply re-walks the
    // opcodes: a constraint with two unknowns is skipped on one walk and
    // solvable on the next, once another constraint has pinned one of them.
    // The `IsZero` gadget needs exactly this — `flag = 1 - x*inv` has two
    // unknowns until `x*flag = 0` fixes the flag, and only then does the
    // inverse follow.
    //
    // The outer one restarts from scratch whenever a *hint* had to be
    // corrected, because everything derived before that correction was derived
    // from the wrong value.
    const MAX_ROUNDS: usize = 6;
    const MAX_WALKS: usize = 12;

    let mut derived = 0;
    let mut assignment = pinned.clone();
    'rounds: for _ in 0..MAX_ROUNDS {
        assignment = pinned.clone();
        derived = 0;
        for _ in 0..MAX_WALKS {
            let before = assignment.len();
            let mut corrected = BTreeMap::new();
            let outcome = solve_pass(
                circuit,
                honest,
                &soft,
                &mut assignment,
                &mut derived,
                &mut corrected,
                preference,
                choice_points,
                space,
            );
            if matches!(outcome, PassOutcome::Rejected) {
                return refuted;
            }
            if !corrected.is_empty() {
                pinned.extend(corrected);
                continue 'rounds;
            }
            if matches!(outcome, PassOutcome::Complete) {
                break 'rounds;
            }
            if assignment.len() == before {
                // Nothing left to derive, so the rest is the prover's free
                // choice; fall back to the honest values for those and check.
                break 'rounds;
            }
        }
    }

    // A hint the constraints never pinned down is genuinely the prover's to
    // choose; the honest value is as good as any and keeps the reported
    // witness close to the original.
    for witness in &soft {
        if let (false, Some(known)) = (assignment.contains_key(witness), honest.get(witness)) {
            assignment.insert(*witness, *known);
        }
    }
    for _ in 0..MAX_WALKS {
        let before = assignment.len();
        let mut ignored = BTreeMap::new();
        let outcome = solve_pass(
            circuit,
            honest,
            &soft,
            &mut assignment,
            &mut derived,
            &mut ignored,
            preference,
            choice_points,
            space,
        );
        if matches!(outcome, PassOutcome::Rejected) {
            return refuted;
        }
        if matches!(outcome, PassOutcome::Complete) || assignment.len() == before {
            break;
        }
    }

    let component = (1..=max_witness(circuit) + 1).collect::<BTreeSet<_>>();
    // Both halves of the pair are the same assignment: this only asks whether
    // the derived witness satisfies ACIR at all. The divergence itself is
    // established by the caller, which compares the derived return values
    // against the honest ones.
    let certificate = certify::certify(
        circuit,
        &component,
        &BTreeSet::new(),
        None,
        &assignment,
        &assignment,
    );
    let unjudged = matches!(certificate.status, certify::CertificateStatus::Incomplete);
    let accepted = matches!(certificate.status, certify::CertificateStatus::Certified)
        .then_some((assignment, derived));
    RepairOutcome {
        solved: true,
        refuted: accepted.is_none() && !unjudged,
        unjudged,
        unjudged_reason: unjudged.then(|| {
            certificate
                .detail
                .clone()
                .unwrap_or_else(|| "unstated".to_owned())
        }),
        accepted,
    }
}

/// How far one solving pass got.
#[derive(Debug)]
enum PassOutcome {
    /// Every opcode was derived or checked.
    Complete,
    /// Some opcode could not be handled yet; another pass may help.
    Deferred,
    /// Some opcode is violated outright, so this choice of hints is dead.
    Rejected,
}

#[allow(clippy::too_many_arguments)]
fn solve_pass(
    circuit: &Circuit<FieldElement>,
    honest: &WitnessValues,
    soft: &BTreeSet<u32>,
    assignment: &mut WitnessValues,
    derived: &mut usize,
    corrected: &mut BTreeMap<u32, FieldElement>,
    preference: usize,
    choice_points: &mut usize,
    space: &mut usize,
) -> PassOutcome {
    let mut blocks: BTreeMap<u32, Vec<FieldElement>> = BTreeMap::new();
    let mut deferred = false;
    let mut hardened = BTreeSet::new();

    for (index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            // Hint outputs are already in place, and a Brillig call constrains
            // nothing, so there is nothing to derive or check here.
            Opcode::BrilligCall { .. } => {}
            Opcode::AssertZero(expression) => {
                let unknown = unknowns_of(expression, assignment);
                match unknown.as_slice() {
                    [] => match certify::evaluate(expression, assignment) {
                        Some(residue) if residue.is_zero() => {}
                        // Violated. Before rejecting, see whether a single
                        // still-soft hint in this constraint can absorb it:
                        // that is the prover adjusting its other hints to keep
                        // the witness consistent.
                        _ => {
                            if std::env::var_os("NOIR_PICUS_TRACE_MUTATE").is_some() {
                                eprintln!("    violated: opcode {index}");
                            }
                            let adjustable = witnesses_of(expression)
                                .into_iter()
                                .filter(|witness| {
                                    soft.contains(witness) && !hardened.contains(witness)
                                })
                                .collect::<BTreeSet<_>>();
                            match adjustable.iter().copied().collect::<Vec<_>>().as_slice() {
                                [only] => match solve_for(expression, assignment, *only) {
                                    Some(solved) => {
                                        assignment.insert(*only, solved);
                                        corrected.insert(*only, solved);
                                        hardened.insert(*only);
                                        *derived += 1;
                                    }
                                    None => return PassOutcome::Rejected,
                                },
                                // Several open hints appear in this constraint,
                                // so which one absorbs the violation is a real
                                // choice. Record that a choice was made — a
                                // later refutation is then only a refutation of
                                // the choices tried — and take the one this
                                // preference selects.
                                [] => return PassOutcome::Rejected,
                                many => {
                                    // Разряд смешанной системы счисления, а не общий
                                    // индекс. Прежний `preference % many.len()`
                                    // подставлял ОДИН И ТОТ ЖЕ номер во все точки
                                    // выбора сразу, то есть шёл по диагонали
                                    // декартова произведения: при двух точках по два
                                    // варианта он посещал 2 сочетания из 4, и рост
                                    // бюджета ничего не менял. Здесь номер попытки
                                    // раскладывается по разрядам, поэтому перебор
                                    // действительно проходит произведение целиком.
                                    *choice_points += 1;
                                    let pick = many[(preference / *space) % many.len()];
                                    *space = space.saturating_mul(many.len());
                                    match solve_for(expression, assignment, pick) {
                                        Some(solved) => {
                                            assignment.insert(pick, solved);
                                            corrected.insert(pick, solved);
                                            hardened.insert(pick);
                                            *derived += 1;
                                        }
                                        None => return PassOutcome::Rejected,
                                    }
                                }
                            }
                        }
                    },
                    [only] => match solve_for(expression, assignment, *only) {
                        Some(solved) => {
                            assignment.insert(*only, solved);
                            *derived += 1;
                        }
                        // The unknown occurs only quadratically, or its
                        // coefficient vanished; a later pass may pin it.
                        None => deferred = true,
                    },
                    _ => deferred = true,
                }
            }
            Opcode::MemoryInit { block_id, init, .. } => {
                let mut cells = Vec::with_capacity(init.len());
                for witness in init {
                    match assignment.get(&witness.witness_index()) {
                        Some(known) => cells.push(*known),
                        None => {
                            deferred = true;
                            break;
                        }
                    }
                }
                if cells.len() == init.len() {
                    blocks.insert(block_id.as_u32(), cells);
                }
            }
            Opcode::MemoryOp { block_id, op } => {
                let Some(cells) = blocks.get_mut(&block_id.as_u32()) else {
                    deferred = true;
                    continue;
                };
                let Some(index) = assignment.get(&op.index.witness_index()).copied() else {
                    deferred = true;
                    continue;
                };
                // An index outside the block is a violation, not a deferral:
                // ACIR requires it to be in range.
                let Some(slot) = to_usize(index).filter(|slot| *slot < cells.len()) else {
                    return PassOutcome::Rejected;
                };
                let value_index = op.value.witness_index();
                match op.operation {
                    MemOpKind::Read => match assignment.get(&value_index) {
                        Some(known) if *known == cells[slot] => {}
                        Some(_) => return PassOutcome::Rejected,
                        None => {
                            assignment.insert(value_index, cells[slot]);
                            *derived += 1;
                        }
                    },
                    MemOpKind::Write => match assignment.get(&value_index) {
                        Some(known) => cells[slot] = *known,
                        None if soft.contains(&value_index) => {
                            // The prover can freely choose this hint's value.
                            // Using the honest value keeps the block state
                            // consistent so that subsequent reads don't get
                            // stale values that poison the assignment.
                            if let Some(honest_val) = honest.get(&value_index) {
                                cells[slot] = *honest_val;
                                assignment.insert(value_index, *honest_val);
                                *derived += 1;
                            } else {
                                deferred = true;
                            }
                        }
                        None => deferred = true,
                    },
                }
            }
            Opcode::BlackBoxFuncCall(black_box) => {
                match derive_black_box(black_box, honest, assignment, derived) {
                    BlackBoxOutcome::Done => {}
                    BlackBoxOutcome::Deferred => deferred = true,
                    BlackBoxOutcome::Rejected => {
                        if std::env::var_os("NOIR_PICUS_TRACE_MUTATE").is_some() {
                            eprintln!("    black box rejects: opcode {index}");
                        }
                        return PassOutcome::Rejected;
                    }
                }
            }
            Opcode::Call { .. } => return PassOutcome::Rejected,
        }
    }

    if deferred {
        PassOutcome::Deferred
    } else {
        PassOutcome::Complete
    }
}

/// Fill in a black box's outputs, or report that this pass cannot.
///
/// `AND`, `XOR` and `RANGE` are computed or checked directly. Anything else —
/// hashes, curve operations, signature checks — is reused from the honest run
/// when its inputs did not move, and gives up otherwise: producing a hash
/// preimage is not a move a prover can make either.
enum BlackBoxOutcome {
    Done,
    Deferred,
    Rejected,
}

fn derive_black_box(
    black_box: &BlackBoxFuncCall<FieldElement>,
    honest: &WitnessValues,
    assignment: &mut WitnessValues,
    derived: &mut usize,
) -> BlackBoxOutcome {
    match black_box {
        BlackBoxFuncCall::RANGE { input, num_bits } => match resolve(input, assignment) {
            Some(value) if value.num_bits() <= *num_bits => BlackBoxOutcome::Done,
            Some(_) => BlackBoxOutcome::Rejected,
            None => BlackBoxOutcome::Deferred,
        },
        BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        } => derive_bitwise(lhs, rhs, *num_bits, *output, assignment, derived, |a, b| {
            a & b
        }),
        BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        } => derive_bitwise(lhs, rhs, *num_bits, *output, assignment, derived, |a, b| {
            a ^ b
        }),
        other => {
            // Fast path: inputs unchanged from the honest run, so the honest
            // outputs are the answer and no evaluation is needed.
            let mut all_present = true;
            let mut unchanged = true;
            for witness in other.get_input_witnesses() {
                let index = witness.witness_index();
                match (assignment.get(&index), honest.get(&index)) {
                    (Some(now), Some(before)) if now == before => {}
                    (Some(_), _) => unchanged = false,
                    (None, _) => all_present = false,
                }
            }
            if !all_present {
                return BlackBoxOutcome::Deferred;
            }
            let outputs: Vec<(u32, FieldElement)> = if unchanged
                && other
                    .get_outputs_vec()
                    .iter()
                    .all(|witness| honest.contains_key(&witness.witness_index()))
            {
                other
                    .get_outputs_vec()
                    .iter()
                    .map(|witness| (witness.witness_index(), honest[&witness.witness_index()]))
                    .collect()
            } else {
                // A moved input: run the black box for real. Rejecting here,
                // as this used to, made every value that flows into a hash
                // unreachable — on a circuit that ends in a commitment, that is
                // every return value.
                match crate::concrete::eval_black_box(other, assignment) {
                    crate::concrete::BlackBoxEval::Outputs(outputs) => outputs,
                    crate::concrete::BlackBoxEval::Missing => return BlackBoxOutcome::Deferred,
                    crate::concrete::BlackBoxEval::Failed(_)
                    | crate::concrete::BlackBoxEval::Unverifiable => {
                        return BlackBoxOutcome::Rejected;
                    }
                }
            };
            for (index, value) in outputs {
                match assignment.get(&index) {
                    Some(existing) if *existing != value => return BlackBoxOutcome::Rejected,
                    Some(_) => {}
                    None => {
                        assignment.insert(index, value);
                        *derived += 1;
                    }
                }
            }
            BlackBoxOutcome::Done
        }
    }
}

fn derive_bitwise(
    lhs: &FunctionInput<FieldElement>,
    rhs: &FunctionInput<FieldElement>,
    num_bits: u32,
    output: Witness,
    assignment: &mut WitnessValues,
    derived: &mut usize,
    combine: fn(BigUint, BigUint) -> BigUint,
) -> BlackBoxOutcome {
    let (Some(lhs), Some(rhs)) = (resolve(lhs, assignment), resolve(rhs, assignment)) else {
        return BlackBoxOutcome::Deferred;
    };
    if lhs.num_bits() > num_bits || rhs.num_bits() > num_bits {
        return BlackBoxOutcome::Rejected;
    }
    let expected = FieldElement::from_be_bytes_reduce(
        &combine(to_biguint(lhs), to_biguint(rhs)).to_bytes_be(),
    );
    let index = output.witness_index();
    match assignment.get(&index) {
        Some(known) if *known == expected => BlackBoxOutcome::Done,
        Some(_) => BlackBoxOutcome::Rejected,
        None => {
            assignment.insert(index, expected);
            *derived += 1;
            BlackBoxOutcome::Done
        }
    }
}

fn resolve(
    input: &FunctionInput<FieldElement>,
    assignment: &WitnessValues,
) -> Option<FieldElement> {
    match input {
        FunctionInput::Constant(value) => Some(*value),
        FunctionInput::Witness(witness) => assignment.get(&witness.witness_index()).copied(),
    }
}

fn unknowns_of(expression: &Expression<FieldElement>, assignment: &WitnessValues) -> Vec<u32> {
    let mut unknown = witnesses_of(expression)
        .into_iter()
        .filter(|witness| !assignment.contains_key(witness))
        .collect::<Vec<_>>();
    unknown.sort_unstable();
    unknown.dedup();
    unknown
}

fn to_biguint(value: FieldElement) -> BigUint {
    BigUint::from_bytes_be(&value.to_be_bytes())
}

fn to_usize(value: FieldElement) -> Option<usize> {
    usize::try_from(to_biguint(value)).ok()
}

/// Solve `expression = 0` for `unknown`, treating every other witness as fixed.
///
/// Only linear occurrences are solvable: the coefficient is collected from the
/// linear terms plus every product where the other factor is known, and the
/// result exists exactly when that coefficient is non-zero, since a non-zero
/// field element is invertible.
fn solve_for(
    expression: &Expression<FieldElement>,
    assignment: &WitnessValues,
    unknown: u32,
) -> Option<FieldElement> {
    let mut coefficient = FieldElement::zero();
    let mut constant = expression.q_c;

    for (factor, lhs, rhs) in &expression.mul_terms {
        let (lhs_index, rhs_index) = (lhs.witness_index(), rhs.witness_index());
        match (lhs_index == unknown, rhs_index == unknown) {
            // `unknown * unknown` is quadratic; not solved here.
            (true, true) => return None,
            (true, false) => coefficient += *factor * *assignment.get(&rhs_index)?,
            (false, true) => coefficient += *factor * *assignment.get(&lhs_index)?,
            (false, false) => {
                constant += *factor * *assignment.get(&lhs_index)? * *assignment.get(&rhs_index)?;
            }
        }
    }

    for (factor, witness) in &expression.linear_combinations {
        let index = witness.witness_index();
        if index == unknown {
            coefficient += *factor;
        } else {
            constant += *factor * *assignment.get(&index)?;
        }
    }

    if coefficient.is_zero() {
        return None;
    }
    Some(-constant / coefficient)
}

fn witnesses_of(expression: &Expression<FieldElement>) -> Vec<u32> {
    let mut found = Vec::new();
    for (_, lhs, rhs) in &expression.mul_terms {
        found.push(lhs.witness_index());
        found.push(rhs.witness_index());
    }
    for (_, witness) in &expression.linear_combinations {
        found.push(witness.witness_index());
    }
    found
}

fn max_witness(circuit: &Circuit<FieldElement>) -> usize {
    circuit
        .opcodes
        .iter()
        .flat_map(crate::translate::opcode_wires)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use acir::circuit::{
        PublicInputs,
        brillig::{BrilligFunctionId, BrilligInputs},
        opcodes::BlackBoxFuncCall,
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

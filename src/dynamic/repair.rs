//! Re-deriving a whole witness after one value was changed: the forward
//! solve that `mutate` uses to turn "move this hint" into a full assignment,
//! and the certificate check that decides whether the result is accepted.

use std::collections::{BTreeMap, BTreeSet};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, FunctionInput, MemOpKind},
    },
    native_types::{Expression, Witness},
};
use num_bigint::BigUint;

use crate::dynamic::certify::{self, WitnessValues};
use crate::field::{resolve, to_biguint, to_usize};

/// What one mutation attempt produced.
pub(crate) struct RepairOutcome {
    /// The forward solve ran to completion.
    pub(crate) solved: bool,
    /// A constraint refuted the attempt: the circuit doing its job. Counting
    /// this as "nothing was checked" reported well-constrained gadgets as
    /// unsearched, which is how the coverage signal went wrong once already.
    pub(crate) refuted: bool,
    /// The evaluator could not judge the result: an opcode on the path has no
    /// implementation here, so neither acceptance nor rejection was proved.
    pub(crate) unjudged: bool,
    /// Why it could not be judged. A bare count says how often the search came
    /// back empty-handed but not what would fix it, and the answer decides
    /// where the next work goes: an unmodelled black box needs an evaluator,
    /// an exhausted choice budget needs a bigger budget, and an unassigned
    /// witness needs better propagation. Those are three different tasks.
    pub(crate) unjudged_reason: Option<String>,
    /// ...and the resulting assignment satisfies every ACIR opcode.
    pub(crate) accepted: Option<(WitnessValues, usize)>,
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
pub(crate) const MAX_PREFERENCES_DEFAULT: usize = 4;

/// How deep to search at an ambiguous constraint.
///
/// Measured, not guessed: the reason histogram added alongside this showed that
/// on a generated circuit all 134 unjudged attempts came from one cause — this
/// budget running out — and none from an unmodelled opcode. So the coverage of
/// a zero-finding run is set by this number, and a run that wants a stronger
/// negative result has to be able to raise it. Kept an environment variable
/// rather than a flag because it has to reach a function nested four levels
/// below the CLI, and the default stays what every earlier campaign used.
pub(crate) fn max_preferences() -> usize {
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
pub(crate) fn repair(
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
pub(crate) fn repair_with(
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
pub(crate) enum PassOutcome {
    /// Every opcode was derived or checked.
    Complete,
    /// Some opcode could not be handled yet; another pass may help.
    Deferred,
    /// Some opcode is violated outright, so this choice of hints is dead.
    Rejected,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn solve_pass(
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
pub(crate) enum BlackBoxOutcome {
    Done,
    Deferred,
    Rejected,
}

pub(crate) fn derive_black_box(
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
                match crate::dynamic::concrete::eval_black_box(other, assignment) {
                    crate::dynamic::concrete::BlackBoxEval::Outputs(outputs) => outputs,
                    crate::dynamic::concrete::BlackBoxEval::Missing => {
                        return BlackBoxOutcome::Deferred;
                    }
                    crate::dynamic::concrete::BlackBoxEval::Failed(_)
                    | crate::dynamic::concrete::BlackBoxEval::Unverifiable => {
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

pub(crate) fn derive_bitwise(
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

pub(crate) fn unknowns_of(
    expression: &Expression<FieldElement>,
    assignment: &WitnessValues,
) -> Vec<u32> {
    let mut unknown = witnesses_of(expression)
        .into_iter()
        .filter(|witness| !assignment.contains_key(witness))
        .collect::<Vec<_>>();
    unknown.sort_unstable();
    unknown.dedup();
    unknown
}

/// Solve `expression = 0` for `unknown`, treating every other witness as fixed.
///
/// Only linear occurrences are solvable: the coefficient is collected from the
/// linear terms plus every product where the other factor is known, and the
/// result exists exactly when that coefficient is non-zero, since a non-zero
/// field element is invertible.
pub(crate) fn solve_for(
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

pub(crate) fn witnesses_of(expression: &Expression<FieldElement>) -> Vec<u32> {
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

pub(crate) fn max_witness(circuit: &Circuit<FieldElement>) -> usize {
    circuit
        .opcodes
        .iter()
        .flat_map(crate::translate::opcode_wires)
        .max()
        .unwrap_or(0)
}

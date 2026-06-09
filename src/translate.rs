use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, BlockId, FunctionInput, MemOp, MemOpKind},
    },
    native_types::{Expression, Witness},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

#[derive(Clone, Debug)]
pub(crate) struct AcirPicusModel {
    pub(crate) n_wires: usize,
    pub(crate) input_indices: HashSet<usize>,
    pub(crate) orig_constraints: Vec<IRConstraint>,
    pub(crate) alt_constraints: Vec<IRConstraint>,
    pub(crate) unsupported_reasons: Vec<String>,
    pub(crate) abstracted_reasons: Vec<String>,
    pub(crate) fixed_known_signals: HashSet<usize>,
    constraint_groups: Vec<ConstraintGroup>,
    unsupported_issues: Vec<UnsupportedIssue>,
    abstracted_issues: Vec<AbstractionIssue>,
    dependency_edges: Vec<Vec<usize>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FixedMode {
    Public,
    AllParams,
}

#[derive(Clone, Debug)]
struct UnsupportedIssue {
    reason: String,
    wires: Vec<usize>,
}

// A deterministic black box that we do not translate exactly, but model with a
// determinism (uninterpreted-function) abstraction instead of blocking the
// target. Tracked separately from unsupported issues so we can annotate any
// target whose verdict depended on the abstraction. See SOUNDNESS.md.
#[derive(Clone, Debug)]
struct AbstractionIssue {
    reason: String,
    wires: Vec<usize>,
}

#[derive(Clone, Debug)]
struct ConstraintGroup {
    // All IR constraints emitted for one ACIR opcode. Keeping the wire set and
    // ranges lets us later slice a per-target query without losing aux wires.
    wires: Vec<usize>,
    orig_range: Range<usize>,
    alt_range: Range<usize>,
}

#[derive(Clone, Copy, Debug)]
enum BitwiseOp {
    And,
    Xor,
}

#[derive(Clone, Debug)]
struct BitwiseAuxWires {
    lhs: Vec<usize>,
    rhs: Vec<usize>,
    output: Vec<usize>,
}

#[derive(Clone, Copy, Debug)]
enum BitRef {
    Constant(bool),
    Wire(usize),
}

pub(crate) fn build_model(
    circuit: &Circuit<FieldElement>,
    fixed_mode: FixedMode,
) -> AcirPicusModel {
    let mut input_indices = HashSet::new();
    input_indices.insert(0);

    if matches!(fixed_mode, FixedMode::AllParams) {
        for witness in &circuit.private_parameters {
            input_indices.insert(picus_wire(*witness));
        }
    }

    for witness in &circuit.public_parameters.0 {
        input_indices.insert(picus_wire(*witness));
    }

    let mut orig_constraints = Vec::new();
    let mut alt_constraints = Vec::new();
    let mut unsupported_issues = Vec::new();
    let mut abstracted_issues = Vec::new();
    let mut dependency_edges = Vec::new();
    let mut constraint_groups = Vec::new();
    let mut next_aux_wire = max_witness_index(circuit).map_or(1, |index| index as usize + 2);
    let mut memory_blocks = HashMap::<BlockId, Vec<usize>>::new();

    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                let wires = expression_wires(expression);
                push_dependency_edge(&mut dependency_edges, wires.clone());
                let orig = expression_to_ir(expression, false, &input_indices)
                    .into_iter()
                    .collect();
                let alt = expression_to_ir(expression, true, &input_indices)
                    .into_iter()
                    .collect();
                push_constraint_group(
                    &mut orig_constraints,
                    &mut alt_constraints,
                    &mut constraint_groups,
                    wires,
                    orig,
                    alt,
                );
            }
            Opcode::BlackBoxFuncCall(black_box) => match black_box {
                BlackBoxFuncCall::AND {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                } => {
                    match bitwise_constraint_group(
                        BitwiseOp::And,
                        *lhs,
                        *rhs,
                        *output,
                        *num_bits,
                        &mut next_aux_wire,
                        &input_indices,
                    ) {
                        Ok((wires, orig, alt)) => {
                            push_dependency_edge(&mut dependency_edges, wires.clone());
                            push_constraint_group(
                                &mut orig_constraints,
                                &mut alt_constraints,
                                &mut constraint_groups,
                                wires,
                                orig,
                                alt,
                            );
                        }
                        Err(reason) => push_unsupported_issue(
                            &mut unsupported_issues,
                            &mut dependency_edges,
                            opcode_index,
                            reason,
                            opcode_wires(opcode),
                        ),
                    }
                }
                BlackBoxFuncCall::XOR {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                } => {
                    match bitwise_constraint_group(
                        BitwiseOp::Xor,
                        *lhs,
                        *rhs,
                        *output,
                        *num_bits,
                        &mut next_aux_wire,
                        &input_indices,
                    ) {
                        Ok((wires, orig, alt)) => {
                            push_dependency_edge(&mut dependency_edges, wires.clone());
                            push_constraint_group(
                                &mut orig_constraints,
                                &mut alt_constraints,
                                &mut constraint_groups,
                                wires,
                                orig,
                                alt,
                            );
                        }
                        Err(reason) => push_unsupported_issue(
                            &mut unsupported_issues,
                            &mut dependency_edges,
                            opcode_index,
                            reason,
                            opcode_wires(opcode),
                        ),
                    }
                }
                BlackBoxFuncCall::RANGE { input, num_bits } => {
                    let aux_wires =
                        match allocate_range_aux_wires(*input, *num_bits, &mut next_aux_wire) {
                            Ok(aux_wires) => aux_wires,
                            Err(reason) => {
                                push_unsupported_issue(
                                    &mut unsupported_issues,
                                    &mut dependency_edges,
                                    opcode_index,
                                    reason,
                                    opcode_wires(opcode),
                                );
                                continue;
                            }
                        };
                    let mut wires = function_input_wires(input);
                    wires.extend(aux_wires.iter().copied());
                    push_dependency_edge(&mut dependency_edges, wires.clone());

                    let orig = match range_constraints(
                        *input,
                        *num_bits,
                        &aux_wires,
                        false,
                        &input_indices,
                    ) {
                        Ok(constraints) => constraints,
                        Err(reason) => {
                            push_unsupported_issue(
                                &mut unsupported_issues,
                                &mut dependency_edges,
                                opcode_index,
                                reason,
                                opcode_wires(opcode),
                            );
                            continue;
                        }
                    };
                    let alt = match range_constraints(
                        *input,
                        *num_bits,
                        &aux_wires,
                        true,
                        &input_indices,
                    ) {
                        Ok(constraints) => constraints,
                        Err(reason) => {
                            push_unsupported_issue(
                                &mut unsupported_issues,
                                &mut dependency_edges,
                                opcode_index,
                                reason,
                                opcode_wires(opcode),
                            );
                            continue;
                        }
                    };
                    push_constraint_group(
                        &mut orig_constraints,
                        &mut alt_constraints,
                        &mut constraint_groups,
                        wires,
                        orig,
                        alt,
                    );
                }
                // Every remaining black box is a deterministic pure function of
                // its inputs (hashes, ECDSA, curve ops, ...). Rather than
                // blocking the target as unsupported, abstract it: forget the
                // function, keep only that equal inputs force equal outputs.
                _ => match determinism_constraint_group(black_box, &input_indices) {
                    Some((wires, orig)) => {
                        push_dependency_edge(&mut dependency_edges, wires.clone());
                        abstracted_issues.push(AbstractionIssue {
                            reason: format!(
                                "opcode {opcode_index}: deterministic black box {} modeled by \
                                 determinism abstraction (output is a pure function of its inputs)",
                                black_box.name()
                            ),
                            wires: wires.clone(),
                        });
                        push_constraint_group(
                            &mut orig_constraints,
                            &mut alt_constraints,
                            &mut constraint_groups,
                            wires,
                            orig,
                            Vec::new(),
                        );
                    }
                    None => push_unsupported_issue(
                        &mut unsupported_issues,
                        &mut dependency_edges,
                        opcode_index,
                        format!(
                            "unsupported black box {} (no outputs to abstract)",
                            black_box.name()
                        ),
                        opcode_wires(opcode),
                    ),
                },
            },
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryOp { block_id, op } => match memory_constraint_group(
                *block_id,
                op,
                &mut memory_blocks,
                &mut next_aux_wire,
                &input_indices,
            ) {
                Ok((wires, orig, alt)) => {
                    push_dependency_edge(&mut dependency_edges, wires.clone());
                    push_constraint_group(
                        &mut orig_constraints,
                        &mut alt_constraints,
                        &mut constraint_groups,
                        wires,
                        orig,
                        alt,
                    );
                }
                Err(reason) => push_unsupported_issue(
                    &mut unsupported_issues,
                    &mut dependency_edges,
                    opcode_index,
                    reason,
                    opcode_wires(opcode),
                ),
            },
            Opcode::MemoryInit { block_id, init, .. } => {
                memory_blocks.insert(
                    *block_id,
                    init.iter().copied().map(picus_wire).collect::<Vec<_>>(),
                );
            }
            Opcode::Call { .. } => push_unsupported_issue(
                &mut unsupported_issues,
                &mut dependency_edges,
                opcode_index,
                "unsupported Call".to_owned(),
                opcode_wires(opcode),
            ),
        }
    }
    let unsupported_reasons = unsupported_issues
        .iter()
        .map(|issue| issue.reason.clone())
        .collect();
    let abstracted_reasons = abstracted_issues
        .iter()
        .map(|issue| issue.reason.clone())
        .collect();
    let fixed_known_signals = infer_fixed_known_signals(circuit, &input_indices);

    AcirPicusModel {
        n_wires: next_aux_wire,
        input_indices,
        orig_constraints,
        alt_constraints,
        unsupported_reasons,
        abstracted_reasons,
        fixed_known_signals,
        constraint_groups,
        unsupported_issues,
        abstracted_issues,
        dependency_edges,
    }
}

impl AcirPicusModel {
    pub(crate) fn is_fixed_known_signal(&self, signal: usize) -> bool {
        self.fixed_known_signals.contains(&signal)
    }

    pub(crate) fn unsupported_reasons_for_target(&self, target: Witness) -> Vec<String> {
        let component = self.dependency_component(target_signal(target));

        self.unsupported_issues
            .iter()
            .filter(|issue| {
                issue.wires.is_empty() || issue.wires.iter().any(|wire| component.contains(wire))
            })
            .map(|issue| issue.reason.clone())
            .collect()
    }

    /// Determinism-abstraction issues that lie in this target's cone. A verdict
    /// for such a target is computed under the abstraction: `verified` stays
    /// sound, but `unsafe` may be spurious (see SOUNDNESS.md). The caller
    /// surfaces these as caveats rather than blocking the scan.
    pub(crate) fn abstraction_reasons_for_target(&self, target: Witness) -> Vec<String> {
        let component = self.dependency_component(target_signal(target));

        self.abstracted_issues
            .iter()
            .filter(|issue| issue.wires.iter().any(|wire| component.contains(wire)))
            .map(|issue| issue.reason.clone())
            .collect()
    }

    pub(crate) fn target_constraints(
        &self,
        target: Witness,
    ) -> (Vec<IRConstraint>, Vec<IRConstraint>) {
        // Build a cone-of-influence for this exact target and stop at values
        // already determined by fixed/public inputs. This is the main scaling
        // guard: Picus sees the vulnerable boundary, not the whole circuit.
        //
        // Soundness (see SOUNDNESS.md): cutting at `fixed_known_signals` is safe
        // because a fixed-known signal takes the same value in both
        // self-composition copies (it is uniquely determined by the shared
        // inputs), so constraints reachable only *through* it cannot create a
        // divergence in the target. Dropping them never hides an `unsafe`. The
        // cone itself over-approximates influence (edges are undirected and
        // constraint groups are kept whole), so it never drops a constraint
        // that could matter.
        let component =
            self.dependency_component_cut(target_signal(target), &self.fixed_known_signals);
        let mut orig = Vec::new();
        let mut alt = Vec::new();

        for group in &self.constraint_groups {
            if !group.wires.iter().any(|wire| component.contains(wire)) {
                continue;
            }
            orig.extend(
                self.orig_constraints[group.orig_range.clone()]
                    .iter()
                    .cloned(),
            );
            alt.extend(
                self.alt_constraints[group.alt_range.clone()]
                    .iter()
                    .cloned(),
            );
        }

        (orig, alt)
    }

    fn dependency_component(&self, target: usize) -> HashSet<usize> {
        self.dependency_component_cut(target, &self.input_indices)
    }

    fn dependency_component_cut(&self, target: usize, cut_set: &HashSet<usize>) -> HashSet<usize> {
        let mut component = HashSet::new();
        if cut_set.contains(&target) {
            return component;
        }

        component.insert(target);
        let mut changed = true;
        while changed {
            changed = false;
            for edge in &self.dependency_edges {
                if !edge.iter().any(|wire| component.contains(wire)) {
                    continue;
                }
                for wire in edge {
                    if !cut_set.contains(wire) && component.insert(*wire) {
                        changed = true;
                    }
                }
            }
        }

        component
    }
}

fn push_constraint_group(
    orig_constraints: &mut Vec<IRConstraint>,
    alt_constraints: &mut Vec<IRConstraint>,
    constraint_groups: &mut Vec<ConstraintGroup>,
    mut wires: Vec<usize>,
    orig: Vec<IRConstraint>,
    alt: Vec<IRConstraint>,
) {
    // ACIR opcodes can expand to several Picus constraints, especially
    // RANGE/AND/XOR with decomposition wires. We keep them as an indivisible
    // group so slicing cannot keep the public-facing wire and drop its aux bits.
    let orig_start = orig_constraints.len();
    let alt_start = alt_constraints.len();
    orig_constraints.extend(orig);
    alt_constraints.extend(alt);

    wires.sort_unstable();
    wires.dedup();
    if !wires.is_empty()
        && (orig_constraints.len() > orig_start || alt_constraints.len() > alt_start)
    {
        constraint_groups.push(ConstraintGroup {
            wires,
            orig_range: orig_start..orig_constraints.len(),
            alt_range: alt_start..alt_constraints.len(),
        });
    }
}

fn infer_fixed_known_signals(
    circuit: &Circuit<FieldElement>,
    input_indices: &HashSet<usize>,
) -> HashSet<usize> {
    // Conservative propagation: if a linear equation has exactly one unknown,
    // that unknown is uniquely determined by the current fixed/public set.
    // Nonlinear constraints are intentionally ignored here.
    //
    // Soundness (see SOUNDNESS.md): over a prime field every nonzero
    // coefficient is invertible, so a linear `AssertZero` with exactly one
    // unknown wire `w` pins `w` to a single value once the other wires are
    // fixed. Marking `w` known therefore cannot drop a genuine second solution,
    // so a target proven known this way is truly uniquely determined and the
    // `verified` short-circuit in `solver.rs` is sound. Nonlinear constraints
    // can have multiple roots and are deliberately excluded.
    let mut known = input_indices.clone();
    let mut changed = true;

    while changed {
        changed = false;
        for opcode in &circuit.opcodes {
            match opcode {
                Opcode::AssertZero(expression) => {
                    if let Some(wire) = single_unknown_linear_wire(expression, &known)
                        && known.insert(wire)
                    {
                        changed = true;
                    }
                }
                Opcode::BlackBoxFuncCall(black_box) => {
                    // Determinism (Tier 1): a black box output is a pure function
                    // of its inputs, so once every input (and the predicate, if
                    // any) is known, every output is uniquely determined and
                    // becomes known too. This is unconditionally sound: it never
                    // marks a genuinely free witness as determined.
                    let inputs_known = black_box
                        .get_input_witnesses()
                        .into_iter()
                        .all(|witness| known.contains(&picus_wire(witness)))
                        && black_box
                            .get_predicate()
                            .is_none_or(|witness| known.contains(&picus_wire(witness)));
                    if inputs_known {
                        for witness in black_box.get_outputs_vec() {
                            if known.insert(picus_wire(witness)) {
                                changed = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    known
}

fn single_unknown_linear_wire(
    expression: &Expression<FieldElement>,
    known: &HashSet<usize>,
) -> Option<usize> {
    if !expression.mul_terms.is_empty() {
        return None;
    }

    let modulus = FieldElement::modulus();
    let mut coefficients = HashMap::<usize, BigUint>::new();
    for (coefficient, witness) in &expression.linear_combinations {
        let coeff = field_to_biguint(*coefficient);
        if coeff.is_zero() {
            continue;
        }
        let entry = coefficients
            .entry(picus_wire(*witness))
            .or_insert_with(BigUint::zero);
        *entry += coeff;
        *entry %= &modulus;
    }
    coefficients.retain(|_, coeff| !coeff.is_zero());

    let mut unknowns = coefficients
        .keys()
        .copied()
        .filter(|wire| !known.contains(wire));
    let unknown = unknowns.next()?;
    unknowns.next().is_none().then_some(unknown)
}

pub(crate) fn picus_wire(witness: Witness) -> usize {
    witness.witness_index() as usize + 1
}

pub(crate) fn target_signal(witness: Witness) -> usize {
    picus_wire(witness)
}

fn expression_to_ir(
    expression: &Expression<FieldElement>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Option<IRConstraint> {
    if expression.mul_terms.is_empty() {
        let terms = expression_linear_terms(expression, is_alt, input_indices, false);
        return (!terms.is_empty()).then_some(IRConstraint::Linear(terms));
    }

    let lhs_terms = expression
        .mul_terms
        .iter()
        .filter_map(|(coefficient, lhs, rhs)| {
            let coeff = field_to_biguint(*coefficient);
            (!coeff.is_zero()).then(|| IRProductTerm {
                coeff,
                var_a: var_name(picus_wire(*lhs), is_alt, input_indices),
                var_b: var_name(picus_wire(*rhs), is_alt, input_indices),
            })
        })
        .collect::<Vec<_>>();

    if lhs_terms.is_empty() {
        let terms = expression_linear_terms(expression, is_alt, input_indices, false);
        return (!terms.is_empty()).then_some(IRConstraint::Linear(terms));
    }

    let rhs_terms = expression_linear_terms(expression, is_alt, input_indices, true);
    Some(IRConstraint::NonLinear {
        lhs_terms,
        rhs_terms,
    })
}

fn expression_linear_terms(
    expression: &Expression<FieldElement>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
    negate: bool,
) -> Vec<IRTerm> {
    let mut terms = Vec::new();
    for (coefficient, witness) in &expression.linear_combinations {
        push_linear_term(
            &mut terms,
            *coefficient,
            picus_wire(*witness),
            is_alt,
            input_indices,
            negate,
        );
    }
    push_linear_term(&mut terms, expression.q_c, 0, is_alt, input_indices, negate);
    terms
}

fn push_linear_term(
    terms: &mut Vec<IRTerm>,
    coefficient: FieldElement,
    wire: usize,
    is_alt: bool,
    input_indices: &HashSet<usize>,
    negate: bool,
) {
    let coefficient = if negate { -coefficient } else { coefficient };
    let coeff = field_to_biguint(coefficient);
    if coeff.is_zero() {
        return;
    }
    terms.push(IRTerm {
        coeff,
        var: var_name(wire, is_alt, input_indices),
    });
}

fn bitwise_constraint_group(
    op: BitwiseOp,
    lhs: FunctionInput<FieldElement>,
    rhs: FunctionInput<FieldElement>,
    output: Witness,
    num_bits: u32,
    next_aux_wire: &mut usize,
    input_indices: &HashSet<usize>,
) -> Result<(Vec<usize>, Vec<IRConstraint>, Vec<IRConstraint>), String> {
    let aux_wires = allocate_bitwise_aux_wires(op, lhs, rhs, output, num_bits, next_aux_wire)?;
    let orig = bitwise_constraints(
        op,
        lhs,
        rhs,
        output,
        num_bits,
        &aux_wires,
        false,
        input_indices,
    )?;
    let alt = bitwise_constraints(
        op,
        lhs,
        rhs,
        output,
        num_bits,
        &aux_wires,
        true,
        input_indices,
    )?;
    let mut wires = function_input_wires(&lhs);
    wires.extend(function_input_wires(&rhs));
    wires.push(picus_wire(output));
    wires.extend(aux_wires.lhs.iter().copied());
    wires.extend(aux_wires.rhs.iter().copied());
    wires.extend(aux_wires.output.iter().copied());

    Ok((wires, orig, alt))
}

fn allocate_bitwise_aux_wires(
    op: BitwiseOp,
    lhs: FunctionInput<FieldElement>,
    rhs: FunctionInput<FieldElement>,
    output: Witness,
    num_bits: u32,
    next_aux_wire: &mut usize,
) -> Result<BitwiseAuxWires, String> {
    if num_bits >= FieldElement::max_num_bits() {
        return Err(format!(
            "unsupported {} width {num_bits}: bitwise opcodes require explicit bit decomposition",
            bitwise_op_name(op)
        ));
    }

    let mut local_next_aux_wire = *next_aux_wire;
    let aux_wires = BitwiseAuxWires {
        lhs: allocate_range_aux_wires(lhs, num_bits, &mut local_next_aux_wire)?,
        rhs: allocate_range_aux_wires(rhs, num_bits, &mut local_next_aux_wire)?,
        output: allocate_range_aux_wires(
            FunctionInput::Witness(output),
            num_bits,
            &mut local_next_aux_wire,
        )?,
    };
    *next_aux_wire = local_next_aux_wire;
    Ok(aux_wires)
}

fn bitwise_constraints(
    op: BitwiseOp,
    lhs: FunctionInput<FieldElement>,
    rhs: FunctionInput<FieldElement>,
    output: Witness,
    num_bits: u32,
    aux_wires: &BitwiseAuxWires,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Result<Vec<IRConstraint>, String> {
    let mut constraints = Vec::new();
    constraints.extend(range_constraints(
        lhs,
        num_bits,
        &aux_wires.lhs,
        is_alt,
        input_indices,
    )?);
    constraints.extend(range_constraints(
        rhs,
        num_bits,
        &aux_wires.rhs,
        is_alt,
        input_indices,
    )?);
    constraints.extend(range_constraints(
        FunctionInput::Witness(output),
        num_bits,
        &aux_wires.output,
        is_alt,
        input_indices,
    )?);

    let lhs_bits = input_bit_refs(lhs, num_bits, &aux_wires.lhs)?;
    let rhs_bits = input_bit_refs(rhs, num_bits, &aux_wires.rhs)?;
    let output_bits = input_bit_refs(FunctionInput::Witness(output), num_bits, &aux_wires.output)?;

    for ((lhs_bit, rhs_bit), output_bit) in lhs_bits.into_iter().zip(rhs_bits).zip(output_bits) {
        constraints.push(bitwise_bit_constraint(
            op,
            lhs_bit,
            rhs_bit,
            output_bit,
            is_alt,
            input_indices,
        ));
    }

    Ok(constraints)
}

fn input_bit_refs(
    input: FunctionInput<FieldElement>,
    num_bits: u32,
    aux_wires: &[usize],
) -> Result<Vec<BitRef>, String> {
    let num_bits = usize::try_from(num_bits)
        .map_err(|_| format!("RANGE width {num_bits} does not fit usize"))?;
    match input {
        FunctionInput::Constant(value) => constant_bit_refs(value, num_bits),
        FunctionInput::Witness(_) if num_bits == 0 => Ok(Vec::new()),
        FunctionInput::Witness(witness) if num_bits == 1 => {
            Ok(vec![BitRef::Wire(picus_wire(witness))])
        }
        FunctionInput::Witness(_) => {
            if aux_wires.len() != num_bits {
                return Err(format!(
                    "bit decomposition internal error: expected {num_bits} aux wires, got {}",
                    aux_wires.len()
                ));
            }
            Ok(aux_wires.iter().copied().map(BitRef::Wire).collect())
        }
    }
}

fn constant_bit_refs(value: FieldElement, num_bits: usize) -> Result<Vec<BitRef>, String> {
    let mut value = field_to_biguint(value);
    let one = BigUint::one();
    let mut bits = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        bits.push(BitRef::Constant((&value & &one) == one));
        value >>= 1usize;
    }
    if value.is_zero() {
        Ok(bits)
    } else {
        Err("constant does not fit requested bit width".to_owned())
    }
}

fn bitwise_bit_constraint(
    op: BitwiseOp,
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match op {
        BitwiseOp::And => and_bit_constraint(lhs, rhs, output, is_alt, input_indices),
        BitwiseOp::Xor => xor_bit_constraint(lhs, rhs, output, is_alt, input_indices),
    }
}

fn and_bit_constraint(
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match (lhs, rhs) {
        (BitRef::Constant(false), _) | (_, BitRef::Constant(false)) => {
            bit_linear_constraint(vec![(BigUint::one(), output)], is_alt, input_indices)
        }
        (BitRef::Constant(true), bit) | (bit, BitRef::Constant(true)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (neg_mod_coeff(&BigUint::one()), bit),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Wire(lhs), BitRef::Wire(rhs)) => IRConstraint::NonLinear {
            lhs_terms: vec![IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(lhs, is_alt, input_indices),
                var_b: var_name(rhs, is_alt, input_indices),
            }],
            rhs_terms: bit_linear_terms(vec![(BigUint::one(), output)], is_alt, input_indices),
        },
    }
}

fn xor_bit_constraint(
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match (lhs, rhs) {
        (BitRef::Constant(false), bit) | (bit, BitRef::Constant(false)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (neg_mod_coeff(&BigUint::one()), bit),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Constant(true), bit) | (bit, BitRef::Constant(true)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (BigUint::one(), bit),
                (neg_mod_coeff(&BigUint::one()), BitRef::Constant(true)),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Wire(lhs), BitRef::Wire(rhs)) => IRConstraint::NonLinear {
            lhs_terms: vec![IRProductTerm {
                coeff: BigUint::from(2u32),
                var_a: var_name(lhs, is_alt, input_indices),
                var_b: var_name(rhs, is_alt, input_indices),
            }],
            rhs_terms: bit_linear_terms(
                vec![
                    (BigUint::one(), BitRef::Wire(lhs)),
                    (BigUint::one(), BitRef::Wire(rhs)),
                    (neg_mod_coeff(&BigUint::one()), output),
                ],
                is_alt,
                input_indices,
            ),
        },
    }
}

fn bit_linear_constraint(
    terms: Vec<(BigUint, BitRef)>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::Linear(bit_linear_terms(terms, is_alt, input_indices))
}

fn bit_linear_terms(
    terms: Vec<(BigUint, BitRef)>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRTerm> {
    let mut ir_terms = Vec::new();
    for (coeff, bit) in terms {
        if coeff.is_zero() {
            continue;
        }
        match bit {
            BitRef::Constant(false) => {}
            BitRef::Constant(true) => ir_terms.push(IRTerm {
                coeff,
                var: var_name(0, is_alt, input_indices),
            }),
            BitRef::Wire(wire) => ir_terms.push(IRTerm {
                coeff,
                var: var_name(wire, is_alt, input_indices),
            }),
        }
    }
    ir_terms
}

fn bitwise_op_name(op: BitwiseOp) -> &'static str {
    match op {
        BitwiseOp::And => "AND",
        BitwiseOp::Xor => "XOR",
    }
}

fn allocate_range_aux_wires(
    input: FunctionInput<FieldElement>,
    num_bits: u32,
    next_aux_wire: &mut usize,
) -> Result<Vec<usize>, String> {
    match input {
        FunctionInput::Constant(value) => {
            if constant_fits_in_bits(value, num_bits) {
                Ok(Vec::new())
            } else {
                Err(format!(
                    "RANGE({num_bits}) constant input does not fit: {value}"
                ))
            }
        }
        FunctionInput::Witness(_) if num_bits <= 1 || num_bits >= FieldElement::max_num_bits() => {
            Ok(Vec::new())
        }
        FunctionInput::Witness(_) => {
            let num_bits = usize::try_from(num_bits)
                .map_err(|_| format!("RANGE width {num_bits} does not fit usize"))?;
            let start = *next_aux_wire;
            *next_aux_wire += num_bits;
            Ok((start..start + num_bits).collect())
        }
    }
}

fn range_constraints(
    input: FunctionInput<FieldElement>,
    num_bits: u32,
    aux_wires: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Result<Vec<IRConstraint>, String> {
    match input {
        FunctionInput::Constant(value) => {
            if constant_fits_in_bits(value, num_bits) {
                Ok(Vec::new())
            } else {
                Err(format!(
                    "RANGE({num_bits}) constant input does not fit: {value}"
                ))
            }
        }
        FunctionInput::Witness(_) if num_bits >= FieldElement::max_num_bits() => Ok(Vec::new()),
        FunctionInput::Witness(witness) if num_bits == 0 => {
            Ok(vec![IRConstraint::Linear(vec![IRTerm {
                coeff: BigUint::one(),
                var: var_name(picus_wire(witness), is_alt, input_indices),
            }])])
        }
        FunctionInput::Witness(witness) if num_bits == 1 => Ok(vec![boolean_wire_constraint(
            picus_wire(witness),
            is_alt,
            input_indices,
        )]),
        FunctionInput::Witness(witness) => {
            let expected_len = usize::try_from(num_bits)
                .map_err(|_| format!("RANGE width {num_bits} does not fit usize"))?;
            if aux_wires.len() != expected_len {
                return Err(format!(
                    "RANGE({num_bits}) internal error: expected {expected_len} aux wires, got {}",
                    aux_wires.len()
                ));
            }

            let mut constraints = Vec::with_capacity(aux_wires.len() + 1);
            for &wire in aux_wires {
                constraints.push(boolean_wire_constraint(wire, is_alt, input_indices));
            }

            let mut linear_terms = vec![IRTerm {
                coeff: BigUint::one(),
                var: var_name(picus_wire(witness), is_alt, input_indices),
            }];
            let mut power_of_two = BigUint::one();
            for &wire in aux_wires {
                linear_terms.push(IRTerm {
                    coeff: neg_mod_coeff(&power_of_two),
                    var: var_name(wire, is_alt, input_indices),
                });
                power_of_two <<= 1usize;
            }
            constraints.push(IRConstraint::Linear(linear_terms));

            Ok(constraints)
        }
    }
}

fn memory_constraint_group(
    block_id: BlockId,
    op: &MemOp<FieldElement>,
    memory_blocks: &mut HashMap<BlockId, Vec<usize>>,
    next_aux_wire: &mut usize,
    input_indices: &HashSet<usize>,
) -> Result<(Vec<usize>, Vec<IRConstraint>, Vec<IRConstraint>), String> {
    let cells = memory_blocks
        .get(&block_id)
        .cloned()
        .ok_or_else(|| format!("MemoryOp references uninitialized block {block_id}"))?;
    if cells.is_empty() {
        return Err(format!("MemoryOp references empty block {block_id}"));
    }

    let selectors = allocate_memory_aux_wires(cells.len(), next_aux_wire);
    let new_cells = if matches!(op.operation, MemOpKind::Write) {
        allocate_memory_aux_wires(cells.len(), next_aux_wire)
    } else {
        Vec::new()
    };

    let orig = memory_op_constraints(op, &cells, &selectors, &new_cells, false, input_indices);
    let alt = memory_op_constraints(op, &cells, &selectors, &new_cells, true, input_indices);

    let mut wires = vec![picus_wire(op.index), picus_wire(op.value)];
    wires.extend(cells.iter().copied());
    wires.extend(selectors.iter().copied());
    wires.extend(new_cells.iter().copied());

    if matches!(op.operation, MemOpKind::Write) {
        memory_blocks.insert(block_id, new_cells);
    }

    Ok((wires, orig, alt))
}

fn allocate_memory_aux_wires(len: usize, next_aux_wire: &mut usize) -> Vec<usize> {
    let start = *next_aux_wire;
    *next_aux_wire += len;
    (start..start + len).collect()
}

fn memory_op_constraints(
    op: &MemOp<FieldElement>,
    cells: &[usize],
    selectors: &[usize],
    new_cells: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRConstraint> {
    let mut constraints = memory_selector_constraints(op.index, selectors, is_alt, input_indices);
    match op.operation {
        MemOpKind::Read => {
            constraints.push(memory_read_constraint(
                picus_wire(op.value),
                cells,
                selectors,
                is_alt,
                input_indices,
            ));
        }
        MemOpKind::Write => {
            for ((&old_cell, &new_cell), &selector) in cells.iter().zip(new_cells).zip(selectors) {
                constraints.push(memory_write_constraint(
                    old_cell,
                    new_cell,
                    picus_wire(op.value),
                    selector,
                    is_alt,
                    input_indices,
                ));
            }
        }
    }
    constraints
}

fn memory_selector_constraints(
    index: Witness,
    selectors: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRConstraint> {
    let mut constraints = Vec::with_capacity(selectors.len() + 2);
    for &selector in selectors {
        constraints.push(boolean_wire_constraint(selector, is_alt, input_indices));
    }

    let mut one_hot_terms = selectors
        .iter()
        .map(|&selector| IRTerm {
            coeff: BigUint::one(),
            var: var_name(selector, is_alt, input_indices),
        })
        .collect::<Vec<_>>();
    one_hot_terms.push(IRTerm {
        coeff: neg_mod_coeff(&BigUint::one()),
        var: var_name(0, is_alt, input_indices),
    });
    constraints.push(IRConstraint::Linear(one_hot_terms));

    let mut index_terms = vec![IRTerm {
        coeff: BigUint::one(),
        var: var_name(picus_wire(index), is_alt, input_indices),
    }];
    for (cell_index, &selector) in selectors.iter().enumerate() {
        let coeff = neg_mod_coeff(&BigUint::from(cell_index));
        if coeff.is_zero() {
            continue;
        }
        index_terms.push(IRTerm {
            coeff,
            var: var_name(selector, is_alt, input_indices),
        });
    }
    constraints.push(IRConstraint::Linear(index_terms));

    constraints
}

fn memory_read_constraint(
    value: usize,
    cells: &[usize],
    selectors: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::NonLinear {
        lhs_terms: cells
            .iter()
            .zip(selectors)
            .map(|(&cell, &selector)| IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(cell, is_alt, input_indices),
                var_b: var_name(selector, is_alt, input_indices),
            })
            .collect(),
        rhs_terms: vec![IRTerm {
            coeff: BigUint::one(),
            var: var_name(value, is_alt, input_indices),
        }],
    }
}

fn memory_write_constraint(
    old_cell: usize,
    new_cell: usize,
    value: usize,
    selector: usize,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::NonLinear {
        lhs_terms: vec![
            IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(selector, is_alt, input_indices),
                var_b: var_name(value, is_alt, input_indices),
            },
            IRProductTerm {
                coeff: neg_mod_coeff(&BigUint::one()),
                var_a: var_name(selector, is_alt, input_indices),
                var_b: var_name(old_cell, is_alt, input_indices),
            },
        ],
        rhs_terms: vec![
            IRTerm {
                coeff: BigUint::one(),
                var: var_name(new_cell, is_alt, input_indices),
            },
            IRTerm {
                coeff: neg_mod_coeff(&BigUint::one()),
                var: var_name(old_cell, is_alt, input_indices),
            },
        ],
    }
}

// Build the determinism abstraction (Tier 2) for a deterministic black box
// `outputs = F(inputs)` we do not translate exactly. Returns the wire set and
// one cross-copy constraint per output. `None` when there is nothing to
// abstract (no outputs), leaving the caller to fall back to `unsupported`.
fn determinism_constraint_group(
    black_box: &BlackBoxFuncCall<FieldElement>,
    input_indices: &HashSet<usize>,
) -> Option<(Vec<usize>, Vec<IRConstraint>)> {
    let output_wires = black_box
        .get_outputs_vec()
        .into_iter()
        .map(picus_wire)
        .collect::<Vec<_>>();
    if output_wires.is_empty() {
        return None;
    }

    let mut input_wires = black_box
        .get_input_witnesses()
        .into_iter()
        .map(picus_wire)
        .collect::<Vec<_>>();
    if let Some(predicate) = black_box.get_predicate() {
        input_wires.push(picus_wire(predicate));
    }

    let constraints = output_wires
        .iter()
        .map(|&output| determinism_constraint(output, &input_wires, input_indices))
        .collect::<Vec<_>>();

    let mut wires = input_wires;
    wires.extend(output_wires);
    Some((wires, constraints))
}

// Encode `inputs agree across the two copies => this output agrees`, i.e. the
// determinism of `F`, without modeling `F` itself:
//
//   out_x = out_y  OR  in_1^x != in_1^y  OR  ...  OR  in_n^x != in_n^y
//
// The solution set is a superset of the real one (we keep determinism, forget
// the value), so UNSAT / `verified` stays sound. Inputs fixed across both
// copies share a single `x` variable, so their disjunct is dropped here and the
// output is forced equal whenever it depends only on fixed inputs.
fn determinism_constraint(
    output: usize,
    inputs: &[usize],
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    let mut disjuncts = vec![IRConstraint::Linear(vec![
        IRTerm {
            coeff: BigUint::one(),
            var: var_name(output, false, input_indices),
        },
        IRTerm {
            coeff: neg_mod_coeff(&BigUint::one()),
            var: var_name(output, true, input_indices),
        },
    ])];

    for &input in inputs {
        let original = var_name(input, false, input_indices);
        let alternative = var_name(input, true, input_indices);
        if original != alternative {
            disjuncts.push(IRConstraint::VarNeq(original, alternative));
        }
    }

    IRConstraint::Or(disjuncts)
}

fn boolean_wire_constraint(
    wire: usize,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    let var = var_name(wire, is_alt, input_indices);
    IRConstraint::NonLinear {
        lhs_terms: vec![IRProductTerm {
            coeff: BigUint::one(),
            var_a: var.clone(),
            var_b: var.clone(),
        }],
        rhs_terms: vec![IRTerm {
            coeff: BigUint::one(),
            var,
        }],
    }
}

fn constant_fits_in_bits(value: FieldElement, num_bits: u32) -> bool {
    num_bits >= FieldElement::max_num_bits() || value.num_bits() <= num_bits
}

fn neg_mod_coeff(value: &BigUint) -> BigUint {
    let modulus = FieldElement::modulus();
    let reduced = value % &modulus;
    if reduced.is_zero() {
        BigUint::zero()
    } else {
        modulus - reduced
    }
}

fn var_name(wire: usize, is_alt: bool, input_indices: &HashSet<usize>) -> String {
    if is_alt && !input_indices.contains(&wire) {
        format!("y{wire}")
    } else {
        format!("x{wire}")
    }
}

fn field_to_biguint(field: FieldElement) -> BigUint {
    BigUint::from_bytes_be(&field.to_be_bytes()) % FieldElement::modulus()
}

fn push_unsupported_issue(
    unsupported_issues: &mut Vec<UnsupportedIssue>,
    dependency_edges: &mut Vec<Vec<usize>>,
    opcode_index: usize,
    reason: String,
    wires: Vec<usize>,
) {
    push_dependency_edge(dependency_edges, wires.clone());
    unsupported_issues.push(UnsupportedIssue {
        reason: format!("opcode {opcode_index}: {reason}"),
        wires,
    });
}

fn push_dependency_edge(dependency_edges: &mut Vec<Vec<usize>>, mut wires: Vec<usize>) {
    wires.sort_unstable();
    wires.dedup();
    if !wires.is_empty() {
        dependency_edges.push(wires);
    }
}

pub(crate) fn opcode_wires(opcode: &Opcode<FieldElement>) -> Vec<usize> {
    let mut wires = Vec::new();
    match opcode {
        Opcode::AssertZero(expression) => wires.extend(expression_wires(expression)),
        Opcode::BlackBoxFuncCall(black_box) => {
            for witness in black_box.get_input_witnesses() {
                wires.push(picus_wire(witness));
            }
            for witness in black_box.get_outputs_vec() {
                wires.push(picus_wire(witness));
            }
            if let Some(predicate) = black_box.get_predicate() {
                wires.push(picus_wire(predicate));
            }
        }
        Opcode::MemoryOp { op, .. } => {
            wires.push(picus_wire(op.index));
            wires.push(picus_wire(op.value));
        }
        Opcode::MemoryInit { init, .. } => {
            for witness in init {
                wires.push(picus_wire(*witness));
            }
        }
        Opcode::BrilligCall { .. } => {}
        Opcode::Call {
            inputs,
            outputs,
            predicate,
            ..
        } => {
            for witness in inputs {
                wires.push(picus_wire(*witness));
            }
            for witness in outputs {
                wires.push(picus_wire(*witness));
            }
            wires.extend(expression_wires(predicate));
        }
    }
    wires
}

fn expression_wires(expression: &Expression<FieldElement>) -> Vec<usize> {
    let mut wires = Vec::new();
    for (_, lhs, rhs) in &expression.mul_terms {
        wires.push(picus_wire(*lhs));
        wires.push(picus_wire(*rhs));
    }
    for (_, witness) in &expression.linear_combinations {
        wires.push(picus_wire(*witness));
    }
    wires
}

fn function_input_wires(input: &FunctionInput<FieldElement>) -> Vec<usize> {
    match input {
        FunctionInput::Witness(witness) => vec![picus_wire(*witness)],
        FunctionInput::Constant(_) => Vec::new(),
    }
}

fn max_witness_index(circuit: &Circuit<FieldElement>) -> Option<u32> {
    let mut max = None;

    for witness in &circuit.private_parameters {
        observe_witness(&mut max, *witness);
    }
    for witness in &circuit.public_parameters.0 {
        observe_witness(&mut max, *witness);
    }
    for witness in &circuit.return_values.0 {
        observe_witness(&mut max, *witness);
    }

    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expression) => observe_expression(&mut max, expression),
            Opcode::BlackBoxFuncCall(black_box) => {
                for witness in black_box.get_input_witnesses() {
                    observe_witness(&mut max, witness);
                }
                for witness in black_box.get_outputs_vec() {
                    observe_witness(&mut max, witness);
                }
                if let Some(predicate) = black_box.get_predicate() {
                    observe_witness(&mut max, predicate);
                }
            }
            Opcode::MemoryOp { op, .. } => {
                observe_witness(&mut max, op.index);
                observe_witness(&mut max, op.value);
            }
            Opcode::MemoryInit { init, .. } => {
                for witness in init {
                    observe_witness(&mut max, *witness);
                }
            }
            Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                for input in inputs {
                    match input {
                        acir::circuit::brillig::BrilligInputs::Single(expression) => {
                            observe_expression(&mut max, expression);
                        }
                        acir::circuit::brillig::BrilligInputs::Array(expressions) => {
                            for expression in expressions {
                                observe_expression(&mut max, expression);
                            }
                        }
                        acir::circuit::brillig::BrilligInputs::MemoryArray(_) => {}
                    }
                }
                for output in outputs {
                    match output {
                        acir::circuit::brillig::BrilligOutputs::Simple(witness) => {
                            observe_witness(&mut max, *witness);
                        }
                        acir::circuit::brillig::BrilligOutputs::Array(witnesses) => {
                            for witness in witnesses {
                                observe_witness(&mut max, *witness);
                            }
                        }
                    }
                }
                observe_expression(&mut max, predicate);
            }
            Opcode::Call {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                for witness in inputs {
                    observe_witness(&mut max, *witness);
                }
                for witness in outputs {
                    observe_witness(&mut max, *witness);
                }
                observe_expression(&mut max, predicate);
            }
        }
    }

    max
}

fn observe_expression(max: &mut Option<u32>, expression: &Expression<FieldElement>) {
    for (_, lhs, rhs) in &expression.mul_terms {
        observe_witness(max, *lhs);
        observe_witness(max, *rhs);
    }
    for (_, witness) in &expression.linear_combinations {
        observe_witness(max, *witness);
    }
}

fn observe_witness(max: &mut Option<u32>, witness: Witness) {
    *max = Some(max.map_or(witness.witness_index(), |current| {
        current.max(witness.witness_index())
    }));
}

#[cfg(test)]
mod tests {
    use acir::{
        AcirField, FieldElement,
        circuit::{
            Circuit, Opcode, PublicInputs,
            opcodes::{AcirFunctionId, BlackBoxFuncCall, BlockId, BlockType, FunctionInput, MemOp},
        },
        native_types::{Expression, Witness},
    };
    use num_bigint::BigUint;
    use picus_smt::query::IRConstraint;

    use super::{FixedMode, build_model, expression_to_ir, picus_wire};

    // A genuinely unsupported opcode (a call to a separate ACIR circuit), used
    // to exercise the unsupported-blocking path now that deterministic black
    // boxes are abstracted rather than blocked.
    fn unsupported_call_opcode(input: Witness) -> Opcode<FieldElement> {
        Opcode::Call {
            id: AcirFunctionId(0),
            inputs: vec![input],
            outputs: vec![Witness(50)],
            predicate: Expression::default(),
        }
    }

    #[test]
    fn linear_assert_zero_encodes_constant_on_synthetic_wire() {
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(1));
        expression.q_c = FieldElement::from(5u32);

        let input_indices = [0].into_iter().collect();
        let constraint = expression_to_ir(&expression, false, &input_indices).unwrap();

        let IRConstraint::Linear(terms) = constraint else {
            panic!("expected linear constraint");
        };
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].coeff, BigUint::from(1u32));
        assert_eq!(terms[0].var, "x2");
        assert_eq!(terms[1].coeff, BigUint::from(5u32));
        assert_eq!(terms[1].var, "x0");
    }

    #[test]
    fn nonlinear_assert_zero_moves_linear_terms_to_rhs() {
        let mut expression = Expression::default();
        expression.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        expression.push_addition_term(-FieldElement::one(), Witness(3));

        let input_indices = [0].into_iter().collect();
        let constraint = expression_to_ir(&expression, false, &input_indices).unwrap();

        let IRConstraint::NonLinear {
            lhs_terms,
            rhs_terms,
        } = constraint
        else {
            panic!("expected nonlinear constraint");
        };
        assert_eq!(lhs_terms.len(), 1);
        assert_eq!(lhs_terms[0].coeff, BigUint::from(1u32));
        assert_eq!(lhs_terms[0].var_a, "x2");
        assert_eq!(lhs_terms[0].var_b, "x3");
        assert_eq!(rhs_terms.len(), 1);
        assert_eq!(rhs_terms[0].coeff, BigUint::from(1u32));
        assert_eq!(rhs_terms[0].var, "x4");
    }

    #[test]
    fn witness_zero_shifts_to_picus_wire_one() {
        assert_eq!(picus_wire(Witness(0)), 1);
    }

    #[test]
    fn model_includes_synthetic_wire_and_shifted_input() {
        let circuit = Circuit {
            private_parameters: [Witness(0)].into_iter().collect(),
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::AllParams);

        assert_eq!(model.n_wires, 2);
        assert!(model.input_indices.contains(&0));
        assert!(model.input_indices.contains(&1));
    }

    #[test]
    fn public_fixed_mode_does_not_fix_private_parameters() {
        let circuit = Circuit {
            private_parameters: [Witness(0)].into_iter().collect(),
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.input_indices.contains(&0));
        assert!(!model.input_indices.contains(&1));
    }

    #[test]
    fn linear_assertion_marks_target_known_from_public_input() {
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(1));
        expression.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(expression)],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert!(!model.input_indices.contains(&picus_wire(Witness(1))));
        assert!(model.is_fixed_known_signal(picus_wire(Witness(1))));
    }

    #[test]
    fn linear_knownness_propagates_through_supported_chain() {
        let mut first = Expression::default();
        first.push_addition_term(FieldElement::one(), Witness(1));
        first.push_addition_term(-FieldElement::one(), Witness(0));

        let mut second = Expression::default();
        second.push_addition_term(FieldElement::one(), Witness(2));
        second.push_addition_term(-FieldElement::from(3u32), Witness(1));
        second.q_c = -FieldElement::from(5u32);

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(first), Opcode::AssertZero(second)],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.is_fixed_known_signal(picus_wire(Witness(1))));
        assert!(model.is_fixed_known_signal(picus_wire(Witness(2))));
    }

    #[test]
    fn nonlinear_assertion_does_not_mark_target_known() {
        let mut expression = Expression::default();
        expression.push_multiplication_term(FieldElement::one(), Witness(1), Witness(1));
        expression.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(expression)],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert!(!model.is_fixed_known_signal(picus_wire(Witness(1))));
    }

    #[test]
    fn target_constraints_slice_at_fixed_known_boundary() {
        let mut first = Expression::default();
        first.push_addition_term(FieldElement::one(), Witness(1));
        first.push_addition_term(-FieldElement::one(), Witness(0));

        let mut second = Expression::default();
        second.push_addition_term(FieldElement::one(), Witness(2));
        second.push_addition_term(-FieldElement::one(), Witness(1));

        let mut boundary = Expression::default();
        boundary.push_multiplication_term(FieldElement::one(), Witness(4), Witness(3));
        boundary.push_multiplication_term(-FieldElement::one(), Witness(4), Witness(2));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![
                Opcode::AssertZero(first),
                Opcode::AssertZero(second),
                Opcode::AssertZero(boundary),
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);
        let (orig, alt) = model.target_constraints(Witness(3));

        assert_eq!(model.orig_constraints.len(), 3);
        assert_eq!(orig.len(), 1);
        assert_eq!(alt.len(), 1);
    }

    #[test]
    fn target_constraints_keep_range_auxiliary_group() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(1)),
                num_bits: 3,
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);
        let (orig, alt) = model.target_constraints(Witness(1));

        assert_eq!(orig.len(), 4);
        assert_eq!(alt.len(), 4);
    }

    #[test]
    fn range_allocates_bit_decomposition_constraints() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: 3,
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.n_wires, 5);
        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.orig_constraints.len(), 4);
        assert_eq!(model.alt_constraints.len(), 4);

        for (index, constraint) in model.orig_constraints.iter().take(3).enumerate() {
            let IRConstraint::NonLinear {
                lhs_terms,
                rhs_terms,
            } = constraint
            else {
                panic!("expected boolean constraint");
            };
            let bit_var = format!("x{}", index + 2);
            assert_eq!(lhs_terms[0].var_a, bit_var);
            assert_eq!(lhs_terms[0].var_b, bit_var);
            assert_eq!(rhs_terms[0].var, bit_var);
        }

        let IRConstraint::Linear(terms) = &model.orig_constraints[3] else {
            panic!("expected range sum constraint");
        };
        let modulus = FieldElement::modulus();
        assert_eq!(terms.len(), 4);
        assert_eq!(terms[0].coeff, BigUint::from(1u32));
        assert_eq!(terms[0].var, "x1");
        assert_eq!(terms[1].coeff, &modulus - BigUint::from(1u32));
        assert_eq!(terms[1].var, "x2");
        assert_eq!(terms[2].coeff, &modulus - BigUint::from(2u32));
        assert_eq!(terms[2].var, "x3");
        assert_eq!(terms[3].coeff, &modulus - BigUint::from(4u32));
        assert_eq!(terms[3].var, "x4");
    }

    #[test]
    fn range_zero_constrains_witness_to_zero() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: 0,
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.n_wires, 2);
        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.orig_constraints.len(), 1);

        let IRConstraint::Linear(terms) = &model.orig_constraints[0] else {
            panic!("expected zero constraint");
        };
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].coeff, BigUint::from(1u32));
        assert_eq!(terms[0].var, "x1");
    }

    #[test]
    fn memory_read_with_dynamic_index_is_supported() {
        let block_id = BlockId(0);
        let mut read_matches_public = Expression::default();
        read_matches_public.push_addition_term(FieldElement::one(), Witness(4));
        read_matches_public.push_addition_term(-FieldElement::one(), Witness(0));

        let mut return_matches_brillig = Expression::default();
        return_matches_brillig.push_addition_term(FieldElement::one(), Witness(2));
        return_matches_brillig.push_addition_term(-FieldElement::one(), Witness(3));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0), Witness(1)].into_iter().collect()),
            return_values: PublicInputs([Witness(2)].into_iter().collect()),
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id,
                    init: vec![Witness(3), Witness(0), Witness(0), Witness(0)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id,
                    op: MemOp::read_at_mem_index(Witness(1), Witness(4)),
                },
                Opcode::AssertZero(read_matches_public),
                Opcode::AssertZero(return_matches_brillig),
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);
        let (orig, alt) = model.target_constraints(Witness(2));

        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.n_wires, 10);
        assert_eq!(model.orig_constraints.len(), 9);
        assert_eq!(orig.len(), 8);
        assert_eq!(alt.len(), 8);
    }

    #[test]
    fn memory_write_updates_state_for_later_reads() {
        let block_id = BlockId(0);
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id,
                    init: vec![Witness(0), Witness(1)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id,
                    op: MemOp::write_to_mem_index(Witness(2), Witness(3)),
                },
                Opcode::MemoryOp {
                    block_id,
                    op: MemOp::read_at_mem_index(Witness(2), Witness(4)),
                },
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.n_wires, 12);
        assert_eq!(model.orig_constraints.len(), 11);
        assert_eq!(model.alt_constraints.len(), 11);
    }

    #[test]
    fn range_at_field_width_is_noop() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: FieldElement::max_num_bits(),
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.n_wires, 2);
        assert!(model.unsupported_reasons.is_empty());
        assert!(model.orig_constraints.is_empty());
        assert!(model.alt_constraints.is_empty());
    }

    #[test]
    fn out_of_range_constant_is_unsupported() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Constant(FieldElement::from(4u32)),
                num_bits: 2,
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.unsupported_reasons.len(), 1);
        assert!(model.unsupported_reasons[0].contains("RANGE(2) constant input does not fit"));
    }

    #[test]
    fn bitwise_and_allocates_bit_decomposition_constraints() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Witness(Witness(1)),
                num_bits: 2,
                output: Witness(2),
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.n_wires, 10);
        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.orig_constraints.len(), 11);
        assert_eq!(model.alt_constraints.len(), 11);

        let IRConstraint::NonLinear {
            lhs_terms,
            rhs_terms,
        } = &model.orig_constraints[9]
        else {
            panic!("expected first AND bit constraint");
        };
        assert_eq!(lhs_terms[0].coeff, BigUint::from(1u32));
        assert_eq!(lhs_terms[0].var_a, "x4");
        assert_eq!(lhs_terms[0].var_b, "x6");
        assert_eq!(rhs_terms[0].coeff, BigUint::from(1u32));
        assert_eq!(rhs_terms[0].var, "x8");

        let IRConstraint::NonLinear {
            lhs_terms,
            rhs_terms,
        } = &model.orig_constraints[10]
        else {
            panic!("expected second AND bit constraint");
        };
        assert_eq!(lhs_terms[0].var_a, "x5");
        assert_eq!(lhs_terms[0].var_b, "x7");
        assert_eq!(rhs_terms[0].var, "x9");
    }

    #[test]
    fn bitwise_xor_with_constant_uses_linear_bit_relations() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Constant(FieldElement::from(1u32)),
                num_bits: 2,
                output: Witness(1),
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.n_wires, 7);
        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.orig_constraints.len(), 8);
        assert_eq!(model.alt_constraints.len(), 8);

        let modulus = FieldElement::modulus();
        let IRConstraint::Linear(terms) = &model.orig_constraints[6] else {
            panic!("expected first XOR bit relation");
        };
        assert_eq!(terms.len(), 3);
        assert_eq!(terms[0].coeff, BigUint::from(1u32));
        assert_eq!(terms[0].var, "x5");
        assert_eq!(terms[1].coeff, BigUint::from(1u32));
        assert_eq!(terms[1].var, "x3");
        assert_eq!(terms[2].coeff, &modulus - BigUint::from(1u32));
        assert_eq!(terms[2].var, "x0");

        let IRConstraint::Linear(terms) = &model.orig_constraints[7] else {
            panic!("expected second XOR bit relation");
        };
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].coeff, BigUint::from(1u32));
        assert_eq!(terms[0].var, "x6");
        assert_eq!(terms[1].coeff, &modulus - BigUint::from(1u32));
        assert_eq!(terms[1].var, "x4");
    }

    #[test]
    fn bitwise_width_at_field_width_is_unsupported() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Witness(Witness(1)),
                num_bits: FieldElement::max_num_bits(),
                output: Witness(2),
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.unsupported_reasons.len(), 1);
        assert!(model.unsupported_reasons[0].contains("unsupported AND width"));
    }

    #[test]
    fn bitwise_out_of_range_constant_is_unsupported() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Constant(FieldElement::from(4u32)),
                num_bits: 2,
                output: Witness(1),
            })],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::Public);

        assert_eq!(model.unsupported_reasons.len(), 1);
        assert!(model.unsupported_reasons[0].contains("RANGE(2) constant input does not fit"));
    }

    #[test]
    fn unrelated_unsupported_opcode_does_not_block_target() {
        let circuit = Circuit {
            opcodes: vec![unsupported_call_opcode(Witness(9))],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::AllParams);

        assert_eq!(model.unsupported_reasons.len(), 1);
        assert!(model.unsupported_reasons_for_target(Witness(1)).is_empty());
    }

    #[test]
    fn related_unsupported_opcode_blocks_target() {
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(1));
        expression.push_addition_term(-FieldElement::one(), Witness(9));

        let circuit = Circuit {
            opcodes: vec![
                Opcode::AssertZero(expression),
                unsupported_call_opcode(Witness(9)),
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::AllParams);

        assert_eq!(model.unsupported_reasons_for_target(Witness(1)).len(), 1);
    }

    #[test]
    fn unsupported_opcode_sharing_only_fixed_input_does_not_block_target() {
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(1));
        expression.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            private_parameters: [Witness(0)].into_iter().collect(),
            opcodes: vec![
                Opcode::AssertZero(expression),
                unsupported_call_opcode(Witness(0)),
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::AllParams);

        assert!(model.unsupported_reasons_for_target(Witness(1)).is_empty());
    }
}

#[cfg(test)]
mod soundness_tests {
    //! Differential / metamorphic tests for the ACIR -> Picus IR translation.
    //!
    //! The unit tests in `mod tests` assert the *shape* of the emitted IR
    //! (constraint kind, wires, coefficients). These tests instead validate the
    //! *solution set*: they evaluate the generated constraints against concrete
    //! assignments and assert that the set of assignments the Picus IR accepts
    //! matches the semantics of the original ACIR opcode, exhaustively over a
    //! small domain.
    //!
    //! This is the empirical backstop for the soundness claim documented in
    //! `SOUNDNESS.md`: a `verified` verdict is only trustworthy if the
    //! translation of each supported opcode neither *adds* nor *drops*
    //! solutions. A bug that drops solutions can turn an under-constrained
    //! (`unsafe`) witness into a false `verified` (a missed vulnerability);
    //! a bug that adds solutions can turn a sound circuit into a false
    //! `unsafe`. Both are caught here by comparing against ground truth.

    use std::collections::HashMap;

    use acir::{
        AcirField, FieldElement,
        circuit::{
            Circuit, Opcode, PublicInputs,
            brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
            opcodes::{AcirFunctionId, BlackBoxFuncCall, BlockId, BlockType, FunctionInput, MemOp},
        },
        native_types::{Expression, Witness},
    };
    use num_bigint::BigUint;
    use num_traits::Zero;
    use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

    use super::{FixedMode, build_model, picus_wire};

    type Assignment = HashMap<String, BigUint>;

    fn modulus() -> BigUint {
        FieldElement::modulus()
    }

    /// Build an assignment over the first ("x") self-composition copy. Wire 0 is
    /// the reserved constant signal and is always fixed to 1.
    fn base_assignment() -> Assignment {
        let mut map = Assignment::new();
        map.insert("x0".to_owned(), BigUint::from(1u32));
        map
    }

    fn set_wire(map: &mut Assignment, wire: usize, value: u64) {
        map.insert(format!("x{wire}"), BigUint::from(value));
    }

    /// Set an arbitrary SMT variable (e.g. a `y*` second-copy wire) directly.
    fn set_var(map: &mut Assignment, name: &str, value: u64) {
        map.insert(name.to_owned(), BigUint::from(value));
    }

    /// Set `n` consecutive aux wires starting at `start` to the LSB-first bit
    /// decomposition of `value`, matching `allocate_range_aux_wires` ordering.
    fn set_bits(map: &mut Assignment, start: usize, value: u64, n: usize) {
        for i in 0..n {
            set_wire(map, start + i, (value >> i) & 1);
        }
    }

    fn var<'a>(assignment: &'a Assignment, name: &str) -> &'a BigUint {
        assignment
            .get(name)
            .unwrap_or_else(|| panic!("assignment is missing variable {name}"))
    }

    fn linear_sum(terms: &[IRTerm], assignment: &Assignment, modulus: &BigUint) -> BigUint {
        let mut acc = BigUint::zero();
        for term in terms {
            acc = (acc + &term.coeff * var(assignment, &term.var)) % modulus;
        }
        acc
    }

    fn product_sum(terms: &[IRProductTerm], assignment: &Assignment, modulus: &BigUint) -> BigUint {
        let mut acc = BigUint::zero();
        for term in terms {
            let contribution =
                &term.coeff * var(assignment, &term.var_a) * var(assignment, &term.var_b);
            acc = (acc + contribution) % modulus;
        }
        acc
    }

    /// Evaluate a single IR constraint against an assignment.
    /// `Linear(t)` means `sum(t) == 0`; `NonLinear{lhs, rhs}` means
    /// `sum(lhs products) == sum(rhs linear)` (i.e. `A*B = C`). `Or` holds if any
    /// disjunct holds; `VarNeq(a, b)` holds iff the two variables differ;
    /// `VarEq(v, c)` iff `v == c`. The determinism abstraction emits `Or` /
    /// `VarNeq`; the other variants round out the evaluator.
    fn constraint_holds(
        constraint: &IRConstraint,
        assignment: &Assignment,
        modulus: &BigUint,
    ) -> bool {
        match constraint {
            IRConstraint::Linear(terms) => linear_sum(terms, assignment, modulus).is_zero(),
            IRConstraint::NonLinear {
                lhs_terms,
                rhs_terms,
            } => {
                product_sum(lhs_terms, assignment, modulus)
                    == linear_sum(rhs_terms, assignment, modulus)
            }
            IRConstraint::Or(subs) => subs
                .iter()
                .any(|sub| constraint_holds(sub, assignment, modulus)),
            IRConstraint::VarNeq(a, b) => var(assignment, a) != var(assignment, b),
            IRConstraint::VarEq(name, value) => var(assignment, name) == value,
        }
    }

    /// True iff every constraint in the first ("x") copy holds for `assignment`.
    fn orig_holds(
        constraints: &[IRConstraint],
        assignment: &Assignment,
        modulus: &BigUint,
    ) -> bool {
        constraints
            .iter()
            .all(|constraint| constraint_holds(constraint, assignment, modulus))
    }

    // A deterministic black box (Blake2s) used to exercise the determinism
    // abstraction. `first_output` controls where its 32 output witnesses start.
    fn blake2s_opcode(input: Witness, first_output: u32) -> Opcode<FieldElement> {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
            inputs: vec![FunctionInput::Witness(input)],
            outputs: Box::new(std::array::from_fn(|index| {
                Witness(first_output + index as u32)
            })),
        })
    }

    // A genuinely unsupported opcode (call to a separate ACIR circuit) for the
    // unsupported-blocking boundary tests.
    fn unsupported_call_opcode(input: Witness) -> Opcode<FieldElement> {
        Opcode::Call {
            id: AcirFunctionId(0),
            inputs: vec![input],
            outputs: vec![Witness(60)],
            predicate: Expression::default(),
        }
    }

    #[test]
    fn linear_assert_zero_solution_set_matches_acir() {
        // ACIR: w1 - w2 = 0  (Witness(1) -> x2, Witness(2) -> x3).
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(1));
        expression.push_addition_term(-FieldElement::one(), Witness(2));

        let circuit = Circuit {
            opcodes: vec![Opcode::AssertZero(expression)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();

        for v1 in 0..6u64 {
            for v2 in 0..6u64 {
                let mut assignment = base_assignment();
                set_wire(&mut assignment, 2, v1);
                set_wire(&mut assignment, 3, v2);
                let ground_truth = v1 == v2;
                assert_eq!(
                    orig_holds(&model.orig_constraints, &assignment, &modulus),
                    ground_truth,
                    "linear AssertZero w1-w2=0 disagrees at v1={v1}, v2={v2}"
                );
            }
        }
    }

    #[test]
    fn nonlinear_assert_zero_solution_set_matches_acir() {
        // ACIR: w1*w2 - w3 = 0  (Witness(1) -> x2, Witness(2) -> x3, Witness(3) -> x4).
        let mut expression = Expression::default();
        expression.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        expression.push_addition_term(-FieldElement::one(), Witness(3));

        let circuit = Circuit {
            opcodes: vec![Opcode::AssertZero(expression)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();

        for v1 in 0..4u64 {
            for v2 in 0..4u64 {
                for v3 in 0..16u64 {
                    let mut assignment = base_assignment();
                    set_wire(&mut assignment, 2, v1);
                    set_wire(&mut assignment, 3, v2);
                    set_wire(&mut assignment, 4, v3);
                    let ground_truth = v1 * v2 == v3;
                    assert_eq!(
                        orig_holds(&model.orig_constraints, &assignment, &modulus),
                        ground_truth,
                        "nonlinear AssertZero w1*w2-w3=0 disagrees at v1={v1}, v2={v2}, v3={v3}"
                    );
                }
            }
        }
    }

    #[test]
    fn range_solution_set_matches_acir() {
        // ACIR: RANGE(Witness(0), 3 bits). Witness(0) -> x1, aux bits x2..x4.
        // A value is in range iff there EXISTS a boolean bit assignment that
        // satisfies all emitted constraints. We check satisfiability
        // exhaustively over both the value and the candidate bit assignment.
        let num_bits = 3usize;
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: num_bits as u32,
            })],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();

        for value in 0..(1u64 << (num_bits + 1)) {
            let mut satisfiable = false;
            for candidate_bits in 0..(1u64 << num_bits) {
                let mut assignment = base_assignment();
                set_wire(&mut assignment, 1, value);
                set_bits(&mut assignment, 2, candidate_bits, num_bits);
                if orig_holds(&model.orig_constraints, &assignment, &modulus) {
                    satisfiable = true;
                    break;
                }
            }
            let ground_truth = value < (1u64 << num_bits);
            assert_eq!(
                satisfiable, ground_truth,
                "RANGE({num_bits}) satisfiability disagrees at value={value}"
            );
        }
    }

    #[test]
    fn bitwise_and_solution_set_matches_acir() {
        bitwise_solution_set_matches_acir(true);
    }

    #[test]
    fn bitwise_xor_solution_set_matches_acir() {
        bitwise_solution_set_matches_acir(false);
    }

    fn bitwise_solution_set_matches_acir(is_and: bool) {
        // lhs=Witness(0)->x1, rhs=Witness(1)->x2, output=Witness(2)->x3.
        // aux bit wires (LSB first): lhs x4,x5  rhs x6,x7  output x8,x9.
        let num_bits = 2usize;
        let black_box = if is_and {
            BlackBoxFuncCall::AND {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Witness(Witness(1)),
                num_bits: num_bits as u32,
                output: Witness(2),
            }
        } else {
            BlackBoxFuncCall::XOR {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Witness(Witness(1)),
                num_bits: num_bits as u32,
                output: Witness(2),
            }
        };
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(black_box)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();
        let limit = 1u64 << num_bits;

        for lhs in 0..limit {
            for rhs in 0..limit {
                for output in 0..limit {
                    let mut assignment = base_assignment();
                    set_wire(&mut assignment, 1, lhs);
                    set_wire(&mut assignment, 2, rhs);
                    set_wire(&mut assignment, 3, output);
                    set_bits(&mut assignment, 4, lhs, num_bits);
                    set_bits(&mut assignment, 6, rhs, num_bits);
                    set_bits(&mut assignment, 8, output, num_bits);

                    let expected_output = if is_and { lhs & rhs } else { lhs ^ rhs };
                    let ground_truth = output == expected_output;
                    let op = if is_and { "AND" } else { "XOR" };
                    assert_eq!(
                        orig_holds(&model.orig_constraints, &assignment, &modulus),
                        ground_truth,
                        "{op}({num_bits}) disagrees at lhs={lhs}, rhs={rhs}, output={output}"
                    );
                }
            }
        }
    }

    #[test]
    fn memory_read_solution_set_matches_acir_and_forces_index_in_bounds() {
        // Array [c0, c1] in block 0; read at dynamic index Witness(2)->x3 into
        // value Witness(3)->x4. cells: x1, x2; selectors: x5, x6.
        let block_id = BlockId(0);
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id,
                    init: vec![Witness(0), Witness(1)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id,
                    op: MemOp::read_at_mem_index(Witness(2), Witness(3)),
                },
            ],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();
        let cells = [7u64, 9u64];

        // In-bounds reads return the indexed cell; a wrong value is rejected.
        for index in 0..cells.len() {
            let mut assignment = base_assignment();
            set_wire(&mut assignment, 1, cells[0]);
            set_wire(&mut assignment, 2, cells[1]);
            set_wire(&mut assignment, 3, index as u64);
            set_wire(&mut assignment, 4, cells[index]);
            set_wire(&mut assignment, 5, u64::from(index == 0));
            set_wire(&mut assignment, 6, u64::from(index == 1));
            assert!(
                orig_holds(&model.orig_constraints, &assignment, &modulus),
                "memory read at index {index} should return cell value {}",
                cells[index]
            );

            let mut wrong = assignment.clone();
            set_wire(&mut wrong, 4, cells[index] + 1);
            assert!(
                !orig_holds(&model.orig_constraints, &wrong, &modulus),
                "memory read at index {index} must reject a wrong value"
            );
        }

        // Soundness boundary (see SOUNDNESS.md): the one-hot selector encoding
        // forces the index in-bounds. No boolean selector assignment can model
        // an out-of-bounds index, so we document that exhaustively.
        let mut out_of_bounds_satisfiable = false;
        for selector0 in 0..2u64 {
            for selector1 in 0..2u64 {
                for value in 0..12u64 {
                    let mut assignment = base_assignment();
                    set_wire(&mut assignment, 1, cells[0]);
                    set_wire(&mut assignment, 2, cells[1]);
                    set_wire(&mut assignment, 3, 2); // out-of-bounds index
                    set_wire(&mut assignment, 4, value);
                    set_wire(&mut assignment, 5, selector0);
                    set_wire(&mut assignment, 6, selector1);
                    if orig_holds(&model.orig_constraints, &assignment, &modulus) {
                        out_of_bounds_satisfiable = true;
                    }
                }
            }
        }
        assert!(
            !out_of_bounds_satisfiable,
            "the memory model must force the index in-bounds via the one-hot encoding"
        );
    }

    #[test]
    fn memory_write_solution_set_matches_acir() {
        // Array [c0, c1] in block 0; write value Witness(3)->x4 at index
        // Witness(2)->x3. cells: x1, x2; selectors: x5, x6; new cells: x7, x8.
        let block_id = BlockId(0);
        let circuit = Circuit {
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id,
                    init: vec![Witness(0), Witness(1)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id,
                    op: MemOp::write_to_mem_index(Witness(2), Witness(3)),
                },
            ],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();
        let cells = [7u64, 9u64];
        let write_value = 3u64;

        for index in 0..cells.len() {
            let new_cells = [
                if index == 0 { write_value } else { cells[0] },
                if index == 1 { write_value } else { cells[1] },
            ];
            let mut assignment = base_assignment();
            set_wire(&mut assignment, 1, cells[0]);
            set_wire(&mut assignment, 2, cells[1]);
            set_wire(&mut assignment, 3, index as u64);
            set_wire(&mut assignment, 4, write_value);
            set_wire(&mut assignment, 5, u64::from(index == 0));
            set_wire(&mut assignment, 6, u64::from(index == 1));
            set_wire(&mut assignment, 7, new_cells[0]);
            set_wire(&mut assignment, 8, new_cells[1]);
            assert!(
                orig_holds(&model.orig_constraints, &assignment, &modulus),
                "memory write at index {index} should update only the indexed cell"
            );

            // The non-indexed cell must be preserved: perturbing it is rejected.
            let untouched = 1 - index;
            let mut wrong = assignment.clone();
            set_wire(&mut wrong, 7 + untouched, new_cells[untouched] + 1);
            assert!(
                !orig_holds(&model.orig_constraints, &wrong, &modulus),
                "memory write at index {index} must preserve the non-indexed cell"
            );
        }
    }

    #[test]
    fn unsupported_opcode_feeding_only_brillig_hint_does_not_block_target() {
        // An unsupported opcode constrains Witness(9). A Brillig hint reads
        // Witness(9) as an input and produces the target (Witness(1)) as a
        // nondeterministic output. Brillig outputs are unconstrained by ACIR
        // and create no dependency edge, so Witness(9) cannot affect the
        // target's degrees of freedom: the target must NOT be blocked.
        let target = Witness(1);
        let mut hint_input = Expression::default();
        hint_input.push_addition_term(FieldElement::one(), Witness(9));

        let circuit = Circuit {
            opcodes: vec![
                Opcode::BrilligCall {
                    id: BrilligFunctionId(0),
                    inputs: vec![BrilligInputs::Single(hint_input)],
                    outputs: vec![BrilligOutputs::Simple(target)],
                    predicate: Expression::default(),
                },
                unsupported_call_opcode(Witness(9)),
            ],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::AllParams);

        assert_eq!(model.unsupported_reasons.len(), 1);
        assert!(
            model.unsupported_reasons_for_target(target).is_empty(),
            "an unsupported opcode feeding only a Brillig hint input must not block the target"
        );
    }

    #[test]
    fn unsupported_opcode_linked_through_assert_zero_blocks_target() {
        // Same unsupported opcode, but now a *translated* constraint links the
        // target to Witness(9). The dependency graph must connect them and the
        // target must be blocked, since the unsupported opcode can now
        // influence its value.
        let target = Witness(1);
        let mut link = Expression::default();
        link.push_addition_term(FieldElement::one(), target);
        link.push_addition_term(-FieldElement::one(), Witness(9));

        let circuit = Circuit {
            opcodes: vec![
                Opcode::AssertZero(link),
                unsupported_call_opcode(Witness(9)),
            ],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::AllParams);

        assert_eq!(
            model.unsupported_reasons_for_target(target).len(),
            1,
            "an unsupported opcode linked to the target via AssertZero must block it"
        );
    }

    #[test]
    fn deterministic_blackbox_with_fixed_inputs_marks_outputs_known() {
        // Tier 1: Blake2s of a public (fixed) input. Determinism makes every
        // output a known signal, so a downstream target is verified without a
        // solver call. The black box is abstracted, not blocked as unsupported.
        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![blake2s_opcode(Witness(0), 100)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.is_fixed_known_signal(picus_wire(Witness(100))));
        assert!(model.is_fixed_known_signal(picus_wire(Witness(131))));
        assert!(model.unsupported_reasons.is_empty());
        assert_eq!(model.abstracted_reasons.len(), 1);
    }

    #[test]
    fn deterministic_blackbox_with_free_input_does_not_mark_outputs_known() {
        // Tier 1 must not over-claim: if the input is a free witness (not fixed),
        // the output is genuinely undetermined and must NOT be marked known.
        let circuit = Circuit {
            opcodes: vec![blake2s_opcode(Witness(0), 100)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);

        assert!(!model.is_fixed_known_signal(picus_wire(Witness(100))));
    }

    #[test]
    fn determinism_constraint_solution_set_matches_determinism() {
        // Tier 2: the emitted cross-copy constraint for a black box output must
        // accept a self-composition assignment iff `inputs agree => output
        // agrees`. Blake2s(W0)->W100.. with W0 free, so the first emitted
        // constraint is Or(x101 = y101, x1 != y1) over input wire 1, output 101.
        let circuit = Circuit {
            opcodes: vec![blake2s_opcode(Witness(0), 100)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);
        let modulus = modulus();
        let determinism = &model.orig_constraints[0];

        for input_x in 0..3u64 {
            for input_y in 0..3u64 {
                for output_x in 0..3u64 {
                    for output_y in 0..3u64 {
                        let mut assignment = Assignment::new();
                        set_var(&mut assignment, "x1", input_x);
                        set_var(&mut assignment, "y1", input_y);
                        set_var(&mut assignment, "x101", output_x);
                        set_var(&mut assignment, "y101", output_y);

                        let ground_truth = input_x != input_y || output_x == output_y;
                        assert_eq!(
                            constraint_holds(determinism, &assignment, &modulus),
                            ground_truth,
                            "determinism disagrees at in=({input_x},{input_y}), \
                             out=({output_x},{output_y})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn deterministic_blackbox_annotates_but_does_not_block_target() {
        // A target linked to a black box output is scanned (not blocked) but
        // flagged as computed under the determinism abstraction.
        let mut link = Expression::default();
        link.push_addition_term(FieldElement::one(), Witness(1));
        link.push_addition_term(-FieldElement::one(), Witness(100));

        let circuit = Circuit {
            opcodes: vec![blake2s_opcode(Witness(0), 100), Opcode::AssertZero(link)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.unsupported_reasons_for_target(Witness(1)).is_empty());
        assert_eq!(model.abstraction_reasons_for_target(Witness(1)).len(), 1);
    }

    #[test]
    fn unrelated_deterministic_blackbox_does_not_annotate_target() {
        // The abstraction caveat is scoped to the cone: an unrelated black box
        // must not flag a target it cannot influence.
        let circuit = Circuit {
            opcodes: vec![blake2s_opcode(Witness(9), 100)],
            ..Circuit::<FieldElement>::default()
        };
        let model = build_model(&circuit, FixedMode::Public);

        assert!(model.abstraction_reasons_for_target(Witness(1)).is_empty());
    }
}

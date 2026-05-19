use std::collections::HashSet;

use acir::{
    AcirField, FieldElement,
    circuit::{Circuit, Opcode, opcodes::BlackBoxFuncCall, opcodes::FunctionInput},
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
    unsupported_issues: Vec<UnsupportedIssue>,
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
    let mut dependency_edges = Vec::new();
    let mut next_aux_wire = max_witness_index(circuit).map_or(1, |index| index as usize + 2);

    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                push_dependency_edge(&mut dependency_edges, expression_wires(expression));
                if let Some(constraint) = expression_to_ir(expression, false, &input_indices) {
                    orig_constraints.push(constraint);
                }
                if let Some(constraint) = expression_to_ir(expression, true, &input_indices) {
                    alt_constraints.push(constraint);
                }
            }
            Opcode::BlackBoxFuncCall(black_box) => match black_box {
                BlackBoxFuncCall::RANGE { input, num_bits } => {
                    push_dependency_edge(&mut dependency_edges, function_input_wires(input));

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

                    match range_constraints(*input, *num_bits, &aux_wires, false, &input_indices) {
                        Ok(constraints) => orig_constraints.extend(constraints),
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
                    }
                    match range_constraints(*input, *num_bits, &aux_wires, true, &input_indices) {
                        Ok(constraints) => alt_constraints.extend(constraints),
                        Err(reason) => {
                            push_unsupported_issue(
                                &mut unsupported_issues,
                                &mut dependency_edges,
                                opcode_index,
                                reason,
                                opcode_wires(opcode),
                            );
                        }
                    }
                }
                _ => push_unsupported_issue(
                    &mut unsupported_issues,
                    &mut dependency_edges,
                    opcode_index,
                    format!("unsupported black box {}", black_box.name()),
                    opcode_wires(opcode),
                ),
            },
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryOp { .. } => push_unsupported_issue(
                &mut unsupported_issues,
                &mut dependency_edges,
                opcode_index,
                "unsupported MemoryOp".to_owned(),
                opcode_wires(opcode),
            ),
            Opcode::MemoryInit { .. } => push_unsupported_issue(
                &mut unsupported_issues,
                &mut dependency_edges,
                opcode_index,
                "unsupported MemoryInit".to_owned(),
                opcode_wires(opcode),
            ),
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

    AcirPicusModel {
        n_wires: next_aux_wire,
        input_indices,
        orig_constraints,
        alt_constraints,
        unsupported_reasons,
        unsupported_issues,
        dependency_edges,
    }
}

impl AcirPicusModel {
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

    fn dependency_component(&self, target: usize) -> HashSet<usize> {
        let mut component = HashSet::new();
        if self.input_indices.contains(&target) {
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
                    if !self.input_indices.contains(wire) && component.insert(*wire) {
                        changed = true;
                    }
                }
            }
        }

        component
    }
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

fn opcode_wires(opcode: &Opcode<FieldElement>) -> Vec<usize> {
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
            Circuit, Opcode,
            opcodes::{BlackBoxFuncCall, FunctionInput},
        },
        native_types::{Expression, Witness},
    };
    use num_bigint::BigUint;
    use picus_smt::query::IRConstraint;

    use super::{FixedMode, build_model, expression_to_ir, picus_wire};

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
    fn unrelated_unsupported_opcode_does_not_block_target() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                lhs: FunctionInput::Witness(Witness(9)),
                rhs: FunctionInput::Constant(FieldElement::from(1u32)),
                num_bits: 8,
                output: Witness(10),
            })],
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
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                    lhs: FunctionInput::Witness(Witness(9)),
                    rhs: FunctionInput::Constant(FieldElement::from(1u32)),
                    num_bits: 8,
                    output: Witness(10),
                }),
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
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                    lhs: FunctionInput::Witness(Witness(0)),
                    rhs: FunctionInput::Constant(FieldElement::from(1u32)),
                    num_bits: 8,
                    output: Witness(10),
                }),
            ],
            ..Circuit::<FieldElement>::default()
        };

        let model = build_model(&circuit, FixedMode::AllParams);

        assert!(model.unsupported_reasons_for_target(Witness(1)).is_empty());
    }
}

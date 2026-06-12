//! Shape-level unit tests: assert the kind, wires and coefficients of the IR
//! emitted for each supported opcode, plus the fixed-known and
//! unsupported-blocking model queries.

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

use super::{FixedMode, build_model, expr::expression_to_ir, picus_wire};

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

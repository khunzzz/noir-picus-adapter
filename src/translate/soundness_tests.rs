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
fn constraint_holds(constraint: &IRConstraint, assignment: &Assignment, modulus: &BigUint) -> bool {
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
fn orig_holds(constraints: &[IRConstraint], assignment: &Assignment, modulus: &BigUint) -> bool {
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

//! Fixed-known-signal propagation: which wires are uniquely determined by the
//! fixed/public inputs through linear constraints and deterministic black
//! boxes (Tier 1).

use std::collections::{HashMap, HashSet};

use acir::{
    AcirField, FieldElement,
    circuit::{Circuit, Opcode},
    native_types::Expression,
};
use num_bigint::BigUint;
use num_traits::Zero;

use super::ir::{field_to_biguint, picus_wire};

pub(super) fn infer_fixed_known_signals(
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

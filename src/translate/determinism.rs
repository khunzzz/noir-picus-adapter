//! The determinism (uninterpreted-function) abstraction for deterministic
//! black boxes that are not translated exactly (Tier 2, see SOUNDNESS.md).

use std::collections::HashSet;

use acir::{FieldElement, circuit::opcodes::BlackBoxFuncCall};
use num_bigint::BigUint;
use num_traits::One;
use picus_smt::query::{IRConstraint, IRTerm};

use super::ir::{neg_mod_coeff, picus_wire, var_name};

// Build the determinism abstraction (Tier 2) for a deterministic black box
// `outputs = F(inputs)` we do not translate exactly. Returns the wire set and
// one cross-copy constraint per output. `None` when there is nothing to
// abstract (no outputs), leaving the caller to fall back to `unsupported`.
pub(super) fn determinism_constraint_group(
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

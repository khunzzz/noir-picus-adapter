//! Translation of the `RANGE` black box: boolean constraint for 1-bit widths,
//! bit decomposition `x = sum(2^i * b_i)` for widths below the field width,
//! no-op at or above it.

use std::collections::HashSet;

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use num_bigint::BigUint;
use num_traits::One;
use picus_smt::query::{IRConstraint, IRTerm};

use super::ir::{
    boolean_wire_constraint, constant_fits_in_bits, neg_mod_coeff, picus_wire, var_name,
};

pub(super) fn allocate_range_aux_wires(
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

pub(super) fn range_constraints(
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

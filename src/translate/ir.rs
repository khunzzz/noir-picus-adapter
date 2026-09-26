//! Shared IR-emission helpers: the witness -> Picus wire mapping, the
//! self-composition variable naming scheme and modular coefficient utilities.

use std::collections::BTreeSet;

use acir::{AcirField, FieldElement, native_types::Witness};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

/// The field modulus, as a `num-bigint` value of the version `picus-smt` uses.
///
/// `acir` and `picus-smt` depend on different major versions of `num-bigint`,
/// and two `BigUint`s from different versions are different types even though
/// they look identical. The modulus therefore crosses the boundary as bytes.
/// Every `FieldElement::modulus()` call in this crate goes through here.
pub(crate) fn field_modulus() -> BigUint {
    BigUint::from_bytes_be(&FieldElement::modulus().to_bytes_be())
}

pub(crate) fn picus_wire(witness: Witness) -> usize {
    witness.witness_index() as usize + 1
}

pub(crate) fn target_signal(witness: Witness) -> usize {
    picus_wire(witness)
}

pub(super) fn var_name(wire: usize, is_alt: bool, input_indices: &BTreeSet<usize>) -> String {
    if is_alt && !input_indices.contains(&wire) {
        format!("y{wire}")
    } else {
        format!("x{wire}")
    }
}

pub(super) fn field_to_biguint(field: FieldElement) -> BigUint {
    BigUint::from_bytes_be(&field.to_be_bytes()) % field_modulus()
}

pub(super) fn neg_mod_coeff(value: &BigUint) -> BigUint {
    let modulus = field_modulus();
    let reduced = value % &modulus;
    if reduced.is_zero() {
        BigUint::zero()
    } else {
        modulus - reduced
    }
}

pub(super) fn constant_fits_in_bits(value: FieldElement, num_bits: u32) -> bool {
    num_bits >= FieldElement::max_num_bits() || value.num_bits() <= num_bits
}

pub(super) fn boolean_wire_constraint(
    wire: usize,
    is_alt: bool,
    input_indices: &BTreeSet<usize>,
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

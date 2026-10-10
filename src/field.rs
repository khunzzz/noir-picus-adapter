//! Small conversions between `acir`'s `FieldElement` and the rest of the
//! crate. `acir` and this crate depend on different `num-bigint` majors, so
//! values cross the boundary as bytes, and only here.

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use num_bigint::BigUint;

use crate::dynamic::certify::WitnessValues;

/// The canonical residue in `[0, p)` as an integer.
pub(crate) fn to_biguint(value: FieldElement) -> BigUint {
    BigUint::from_bytes_be(&value.to_be_bytes())
}

/// The canonical residue, if it fits a `usize` (an index or a length).
pub(crate) fn to_usize(value: FieldElement) -> Option<usize> {
    usize::try_from(to_biguint(value)).ok()
}

/// The canonical residue in decimal. `FieldElement` prints signed, so a value
/// just below the modulus would come out as `-1` — fine to read, useless to
/// feed back into anything.
pub(crate) fn to_decimal(value: FieldElement) -> String {
    to_biguint(value).to_string()
}

/// Parse a decimal residue; anything unparsable becomes zero.
pub(crate) fn parse_decimal(value: &str) -> FieldElement {
    BigUint::parse_bytes(value.trim().as_bytes(), 10)
        .map(|big| FieldElement::from_be_bytes_reduce(&big.to_bytes_be()))
        .unwrap_or_default()
}

/// The value of a black-box input under `values`, if assigned.
pub(crate) fn resolve(
    input: &FunctionInput<FieldElement>,
    values: &WitnessValues,
) -> Option<FieldElement> {
    match input {
        FunctionInput::Constant(value) => Some(*value),
        FunctionInput::Witness(witness) => values.get(&witness.witness_index()).copied(),
    }
}

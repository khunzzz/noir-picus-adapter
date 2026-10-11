//! The dynamic path: concrete execution, mutation and fuzzing, and the
//! certificate that re-checks a finding against the ACIR opcodes.
//!
//! Where `translate` + `solver` prove uniqueness symbolically, this side looks
//! for a concrete second witness. A finding here is two full assignments that
//! both satisfy every opcode, so it does not depend on the translation.

pub(crate) mod candidates;
pub(crate) mod certify;
pub(crate) mod concrete;
pub(crate) mod explain;
pub(crate) mod fuzz;
pub(crate) mod mutate;
pub(crate) mod repair;

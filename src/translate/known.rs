//! Constant propagation: wires *provably equal to a concrete field element*.
//!
//! These are strictly stronger than the merely *determined* wires that
//! `uniqueness` finds. A constant wire can be pinned with `x_s = c`, so its
//! defining constraints may then be sliced away without changing the solution
//! set. Cutting the cone at a merely determined wire keeps only `x_s = y_s`,
//! which lets the solver choose any value for `s` — including values the
//! circuit forbids — and produces spurious `unsafe` verdicts.

use std::collections::BTreeMap;

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, FunctionInput},
    },
    native_types::Expression,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::ir::{field_modulus, field_to_biguint, picus_wire};

/// Wires whose value is a concrete field element, derived by exact constant
/// folding over `AssertZero`. Wire 0 (the constant-one wire) seeds the fixpoint.
///
/// Only equality-preserving steps are taken: an expression is folded when every
/// wire in it except one linear occurrence already has a constant value, and the
/// remaining wire is then solved for by multiplying with the modular inverse of
/// its coefficient. The result is exact, so pinning these wires with `VarEq`
/// and slicing their defining constraints away preserves the solution set.
pub(super) fn infer_constant_signals(circuit: &Circuit<FieldElement>) -> BTreeMap<usize, BigUint> {
    infer_constant_signals_from(circuit, &BTreeMap::new())
}

/// Constant propagation seeded with wires whose value is already known.
///
/// Pinning the circuit's inputs turns this from a minor simplification into
/// the main lever: with every parameter concrete, the linear part of a circuit
/// collapses almost entirely, and a satisfiability question that would
/// otherwise go to the solver whole is left with only its nonlinear residue.
pub(super) fn infer_constant_signals_from(
    circuit: &Circuit<FieldElement>,
    seed: &BTreeMap<usize, BigUint>,
) -> BTreeMap<usize, BigUint> {
    let modulus = field_modulus();
    let mut constants = BTreeMap::new();
    constants.insert(0usize, BigUint::one());
    for (wire, value) in seed {
        constants.insert(*wire, value.clone() % &modulus);
    }

    let mut changed = true;
    while changed {
        changed = false;
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else {
                continue;
            };
            if let Some((wire, value)) = solve_single_unknown(expression, &constants, &modulus)
                && constants.insert(wire, value).is_none()
            {
                changed = true;
            }
        }
    }

    constants.remove(&0);
    constants
}

/// Solve `expression = 0` for its single non-constant wire, if there is exactly
/// one and it occurs only linearly.
/// The first opcode these constant values violate outright, if any.
///
/// Only opcodes whose every wire is known are judged; anything still open is
/// left to the solver. `RANGE` is included because an overflow check is a
/// range check, and catching it here is what makes the common case free.
/// How many constraint-bearing opcodes could actually be evaluated, and how
/// many there are.
///
/// Without this, an assignment that pins too few witnesses to evaluate anything
/// reports the same "no violation" as a complete one that genuinely satisfies
/// the circuit. That reading nearly produced a false finding: `a / b` with
/// `b = 0` looked accepted, when in truth the guard `b * b_inv = 1` simply
/// could not be evaluated because the inverse was unknown. The circuit does
/// reject it.
pub(super) fn constraint_coverage(
    circuit: &Circuit<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
) -> (usize, usize) {
    let modulus = field_modulus();
    let mut evaluated = 0;
    let mut total = 0;

    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expression) => {
                total += 1;
                if evaluate_constant(expression, constants, &modulus).is_some() {
                    evaluated += 1;
                }
            }
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(witness),
                ..
            }) => {
                total += 1;
                if constants.contains_key(&picus_wire(*witness)) {
                    evaluated += 1;
                }
            }
            Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::AND {
                    lhs, rhs, output, ..
                }
                | BlackBoxFuncCall::XOR {
                    lhs, rhs, output, ..
                },
            ) => {
                total += 1;
                if bitwise_operand(lhs, constants).is_some()
                    && bitwise_operand(rhs, constants).is_some()
                    && constants.contains_key(&picus_wire(*output))
                {
                    evaluated += 1;
                }
            }
            // Anything else this pass cannot evaluate still counts against the
            // total, so a circuit full of unchecked opcodes cannot report a
            // clean bill of health.
            Opcode::BlackBoxFuncCall(_) | Opcode::MemoryOp { .. } => total += 1,
            _ => {}
        }
    }
    (evaluated, total)
}

pub(super) fn first_violated_constraint(
    circuit: &Circuit<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
) -> Option<String> {
    let modulus = field_modulus();

    for (index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                // An opcode with an open wire is not a verdict, so it is
                // skipped rather than ending the scan.
                let Some(total) = evaluate_constant(expression, constants, &modulus) else {
                    continue;
                };
                if !total.is_zero() {
                    return Some(format!("opcode {index}: AssertZero evaluates to {total}"));
                }
            }
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(witness),
                num_bits,
            }) => {
                let Some(value) = constants.get(&picus_wire(*witness)) else {
                    continue;
                };
                if value.bits() > u64::from(*num_bits) {
                    return Some(format!("opcode {index}: RANGE({num_bits}) rejects {value}"));
                }
            }
            // `AND` and `XOR` carry a width obligation as well as a functional
            // one: ACVM's own solver calls `check_bit_size` on both operands
            // before computing the result. Noir's `redundant_range` pass relies
            // on exactly that and drops the explicit `RANGE` opcodes, so a
            // checker that skips these two sees a `u8` with no bound anywhere.
            Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::AND {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                }
                | BlackBoxFuncCall::XOR {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                },
            ) => {
                let exclusive = matches!(
                    opcode,
                    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR { .. })
                );
                let (Some(left), Some(right), Some(actual)) = (
                    bitwise_operand(lhs, constants),
                    bitwise_operand(rhs, constants),
                    constants.get(&picus_wire(*output)).cloned(),
                ) else {
                    continue;
                };
                let name = if exclusive { "XOR" } else { "AND" };
                for value in [&left, &right] {
                    if value.bits() > u64::from(*num_bits) {
                        return Some(format!(
                            "opcode {index}: {name} operand {value} exceeds {num_bits} bits"
                        ));
                    }
                }
                let expected = if exclusive {
                    &left ^ &right
                } else {
                    &left & &right
                };
                if actual != expected {
                    return Some(format!(
                        "opcode {index}: {name} output {actual} does not match {expected}"
                    ));
                }
            }
            _ => {}
        }
    }

    None
}

/// Resolve a bitwise operand, which may be a constant or an assigned witness.
fn bitwise_operand(
    input: &FunctionInput<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
) -> Option<BigUint> {
    match input {
        FunctionInput::Constant(value) => Some(BigUint::from_bytes_be(&value.to_be_bytes())),
        FunctionInput::Witness(witness) => constants.get(&picus_wire(*witness)).cloned(),
    }
}

/// Evaluate an expression when every wire it mentions is already constant.
fn evaluate_constant(
    expression: &Expression<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
    modulus: &BigUint,
) -> Option<BigUint> {
    let mut total = field_to_biguint(expression.q_c);
    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let lhs = constants.get(&picus_wire(*lhs))?;
        let rhs = constants.get(&picus_wire(*rhs))?;
        total = (total + field_to_biguint(*coefficient) * lhs * rhs) % modulus;
    }
    for (coefficient, witness) in &expression.linear_combinations {
        let value = constants.get(&picus_wire(*witness))?;
        total = (total + field_to_biguint(*coefficient) * value) % modulus;
    }
    Some(total)
}

fn solve_single_unknown(
    expression: &Expression<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
    modulus: &BigUint,
) -> Option<(usize, BigUint)> {
    let mut constant_part = field_to_biguint(expression.q_c);
    let mut unknown: Option<(usize, BigUint)> = None;

    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let coeff = field_to_biguint(*coefficient);
        if coeff.is_zero() {
            continue;
        }
        // A product contributes a constant only when both operands are known.
        // Anything else leaves a nonlinear unknown, which this pass never
        // attempts to solve.
        let lhs_value = constants.get(&picus_wire(*lhs))?;
        let rhs_value = constants.get(&picus_wire(*rhs))?;
        constant_part = (constant_part + coeff * lhs_value * rhs_value) % modulus;
    }

    for (coefficient, witness) in &expression.linear_combinations {
        let coeff = field_to_biguint(*coefficient);
        if coeff.is_zero() {
            continue;
        }
        let wire = picus_wire(*witness);
        match constants.get(&wire) {
            Some(value) => constant_part = (constant_part + &coeff * value) % modulus,
            None => match &mut unknown {
                // The same unknown wire may appear more than once; accumulate
                // its coefficients instead of giving up.
                Some((known_wire, accumulated)) if *known_wire == wire => {
                    *accumulated = (&*accumulated + coeff) % modulus;
                }
                Some(_) => return None,
                None => unknown = Some((wire, coeff % modulus)),
            },
        }
    }

    let (wire, coeff) = unknown?;
    if coeff.is_zero() {
        return None;
    }
    // coeff * wire + constant_part = 0  =>  wire = -constant_part / coeff
    let negated = (modulus - constant_part % modulus) % modulus;
    let inverse = modular_inverse(&coeff, modulus)?;
    Some((wire, (negated * inverse) % modulus))
}

/// Modular inverse over a prime modulus via Fermat's little theorem.
fn modular_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return None;
    }
    Some(value.modpow(&(modulus - BigUint::from(2u32)), modulus))
}

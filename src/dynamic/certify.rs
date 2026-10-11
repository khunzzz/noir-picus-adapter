//! Independent validation of a reported divergence against ACIR semantics.
//!
//! Everything the solver sees has been through this crate's translation, so an
//! `unsafe` verdict is only as trustworthy as that translation. A certificate
//! closes the loop: take the two witness assignments the solver produced and
//! re-check them directly against the ACIR opcodes, without going through the
//! Picus IR at all.
//!
//! What a passing certificate establishes:
//!
//! 1. both assignments satisfy every ACIR opcode that can reach the target,
//! 2. they agree on every fixed input,
//! 3. they disagree on the target.
//!
//! Which is exactly the definition of an under-constrained target — so a
//! certified finding cannot be an artefact of a translation bug. A failing
//! certificate is equally informative in the other direction: it means the
//! translation admitted an assignment ACIR rejects, i.e. it found a bug in
//! *this* tool, and the case belongs in the regression tests.
//!
//! Opcodes outside the target's component are deliberately not checked. Their
//! witnesses are disjoint from the component's, so any assignment of them that
//! works for an honest run still works here; they cannot affect the divergence.
//!
//! Black boxes (hashes, curve operations, signature checks) are evaluated
//! through the ACVM's own solver (`concrete.rs`). Only recursive verification,
//! which the ACVM itself does not check, and unassigned inputs make the
//! certificate `Incomplete` rather than
//! failed: the divergence may well be real, but this module did not prove it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, BlockId, FunctionInput, MemOp, MemOpKind},
    },
    native_types::{Expression, Witness},
};
use num_bigint::BigUint;

use crate::field::{resolve, to_biguint, to_usize};
use serde::{Deserialize, Serialize};

/// One assignment of ACIR witnesses, as produced by the solver.
pub(crate) type WitnessValues = BTreeMap<u32, FieldElement>;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateStatus {
    /// Both assignments satisfy every reachable opcode: the finding is real
    /// regardless of whether the translation is faithful.
    Certified,
    /// At least one opcode rejects one of the assignments. The finding is an
    /// artefact of this tool's translation, not a property of the circuit.
    Refuted,
    /// An opcode on the path has no evaluator here, so nothing was proven.
    Incomplete,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Certificate {
    pub(crate) status: CertificateStatus,
    /// Opcodes checked under both assignments.
    pub(crate) checked_opcodes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}

/// Re-check a reported divergence against the ACIR opcodes themselves.
///
/// `fixed_inputs` are the witnesses both assignments must agree on, and
/// `target` the one they must disagree on; `target` is `None` when the caller
/// only wants to know whether a single assignment satisfies ACIR, which is how
/// the mutation search uses this.
pub(crate) fn certify(
    circuit: &Circuit<FieldElement>,
    component: &BTreeSet<usize>,
    fixed_inputs: &BTreeSet<u32>,
    target: Option<u32>,
    original: &WitnessValues,
    alternative: &WitnessValues,
) -> Certificate {
    // Check the two halves of the claim that do not depend on any opcode
    // first. They are what makes the verdict mean "under-constrained" rather
    // than merely "two assignments exist": without them, a pair that simply
    // uses different inputs, or that agrees on the target, would sail through.
    for input in fixed_inputs {
        match (original.get(input), alternative.get(input)) {
            (Some(left), Some(right)) if left == right => {}
            (Some(left), Some(right)) => {
                return Certificate {
                    status: CertificateStatus::Refuted,
                    checked_opcodes: 0,
                    detail: Some(format!(
                        "the two assignments disagree on fixed input w{input}: {left} vs {right}"
                    )),
                };
            }
            _ => {
                return Certificate {
                    status: CertificateStatus::Incomplete,
                    checked_opcodes: 0,
                    detail: Some(format!("fixed input w{input} is unassigned")),
                };
            }
        }
    }

    if let Some(target) = target {
        match (original.get(&target), alternative.get(&target)) {
            (Some(left), Some(right)) if left != right => {}
            (Some(_), Some(_)) => {
                return Certificate {
                    status: CertificateStatus::Refuted,
                    checked_opcodes: 0,
                    detail: Some(format!("the two assignments agree on the target w{target}")),
                };
            }
            _ => {
                return Certificate {
                    status: CertificateStatus::Incomplete,
                    checked_opcodes: 0,
                    detail: Some(format!("target w{target} is unassigned")),
                };
            }
        }
    }

    let mut checked = 0;
    let mut memory_original = MemoryState::default();
    let mut memory_alternative = MemoryState::default();

    for (index, opcode) in circuit.opcodes.iter().enumerate() {
        if !touches_component(opcode, component) {
            continue;
        }
        for (values, memory, copy) in [
            (original, &mut memory_original, "original"),
            (alternative, &mut memory_alternative, "alternative"),
        ] {
            match check_opcode(opcode, values, memory) {
                Check::Satisfied => {}
                Check::Violated(reason) => {
                    return Certificate {
                        status: CertificateStatus::Refuted,
                        checked_opcodes: checked,
                        detail: Some(format!(
                            "opcode {index} rejects the {copy} assignment: {reason}"
                        )),
                    };
                }
                Check::Unsupported(reason) => {
                    return Certificate {
                        status: CertificateStatus::Incomplete,
                        checked_opcodes: checked,
                        detail: Some(format!("opcode {index} not evaluated: {reason}")),
                    };
                }
            }
        }
        checked += 1;
    }

    if checked == 0 {
        // Nothing was checked, so nothing was proved. This is not a corner
        // case: an `unconstrained fn main` compiles to a circuit with no
        // constraints at all, every output of it is trivially non-unique, and
        // calling that "certified" would dress up a vacuous verdict as a
        // finding.
        return Certificate {
            status: CertificateStatus::Incomplete,
            checked_opcodes: 0,
            detail: Some(
                "no ACIR opcode constrains this target, so the divergence is vacuous".to_owned(),
            ),
        };
    }

    Certificate {
        status: CertificateStatus::Certified,
        checked_opcodes: checked,
        detail: None,
    }
}

#[derive(Default)]
struct MemoryState {
    // `BlockId` is not `Ord` in this ACIR revision.
    blocks: HashMap<BlockId, Vec<FieldElement>>,
}

enum Check {
    Satisfied,
    Violated(String),
    Unsupported(String),
}

fn touches_component(opcode: &Opcode<FieldElement>, component: &BTreeSet<usize>) -> bool {
    crate::translate::opcode_wires(opcode)
        .iter()
        .any(|wire| component.contains(wire))
}

fn check_opcode(
    opcode: &Opcode<FieldElement>,
    values: &WitnessValues,
    memory: &mut MemoryState,
) -> Check {
    match opcode {
        Opcode::AssertZero(expression) => match evaluate(expression, values) {
            Some(value) if value.is_zero() => Check::Satisfied,
            Some(value) => Check::Violated(format!("AssertZero evaluates to {value}")),
            None => Check::Unsupported("expression mentions an unassigned witness".to_owned()),
        },
        // A Brillig call constrains nothing: its outputs are hints, and it is
        // precisely the absence of constraints on them that this tool looks
        // for. Nothing to check.
        Opcode::BrilligCall { .. } => Check::Satisfied,
        Opcode::BlackBoxFuncCall(black_box) => check_black_box(black_box, values),
        Opcode::MemoryInit { block_id, init, .. } => {
            let mut cells = Vec::with_capacity(init.len());
            for witness in init {
                match values.get(&witness.witness_index()) {
                    Some(value) => cells.push(*value),
                    None => {
                        return Check::Unsupported(
                            "memory block initialised from an unassigned witness".to_owned(),
                        );
                    }
                }
            }
            memory.blocks.insert(*block_id, cells);
            Check::Satisfied
        }
        Opcode::MemoryOp { block_id, op } => check_memory_op(*block_id, op, values, memory),
        Opcode::Call { .. } => Check::Unsupported("ACIR call to another circuit".to_owned()),
    }
}

fn check_memory_op(
    block_id: BlockId,
    op: &MemOp,
    values: &WitnessValues,
    memory: &mut MemoryState,
) -> Check {
    let Some(cells) = memory.blocks.get_mut(&block_id) else {
        return Check::Unsupported(format!("memory block {block_id} was never initialised"));
    };
    let (Some(index), Some(value)) = (
        values.get(&op.index.witness_index()).copied(),
        values.get(&op.value.witness_index()).copied(),
    ) else {
        return Check::Unsupported("memory operand is unassigned".to_owned());
    };

    let Some(slot) = to_usize(index) else {
        return Check::Violated(format!("memory index {index} is out of range"));
    };
    let Some(cell) = cells.get_mut(slot) else {
        return Check::Violated(format!(
            "memory index {slot} is past the end of block {block_id}"
        ));
    };

    match op.operation {
        MemOpKind::Read => {
            if *cell == value {
                Check::Satisfied
            } else {
                Check::Violated(format!("read {value} where the block holds {cell}"))
            }
        }
        MemOpKind::Write => {
            *cell = value;
            Check::Satisfied
        }
    }
}

fn check_black_box(black_box: &BlackBoxFuncCall<FieldElement>, values: &WitnessValues) -> Check {
    match black_box {
        BlackBoxFuncCall::RANGE { input, num_bits } => match resolve(input, values) {
            Some(value) => {
                if value.num_bits() <= *num_bits {
                    Check::Satisfied
                } else {
                    Check::Violated(format!("{value} does not fit in {num_bits} bits"))
                }
            }
            None => Check::Unsupported("RANGE input is unassigned".to_owned()),
        },
        BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        } => check_bitwise(lhs, rhs, *num_bits, *output, values, |a, b| a & b, "AND"),
        BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        } => check_bitwise(lhs, rhs, *num_bits, *output, values, |a, b| a ^ b, "XOR"),
        other => match crate::dynamic::concrete::eval_black_box(other, values) {
            crate::dynamic::concrete::BlackBoxEval::Outputs(outputs) => {
                for (index, expected) in outputs {
                    match values.get(&index) {
                        Some(actual) if *actual == expected => {}
                        Some(actual) => {
                            return Check::Violated(format!(
                                "{} output w{index} is {actual}, the function gives {expected}",
                                other.name()
                            ));
                        }
                        None => {
                            return Check::Unsupported(format!(
                                "{} output w{index} is unassigned",
                                other.name()
                            ));
                        }
                    }
                }
                Check::Satisfied
            }
            crate::dynamic::concrete::BlackBoxEval::Missing => {
                Check::Unsupported(format!("black box {} input is unassigned", other.name()))
            }
            crate::dynamic::concrete::BlackBoxEval::Failed(reason) => {
                Check::Violated(format!("black box {} fails: {reason}", other.name()))
            }
            crate::dynamic::concrete::BlackBoxEval::Unverifiable => Check::Unsupported(format!(
                "black box {} cannot be checked from witness values",
                other.name()
            )),
        },
    }
}

fn check_bitwise(
    lhs: &FunctionInput<FieldElement>,
    rhs: &FunctionInput<FieldElement>,
    num_bits: u32,
    output: Witness,
    values: &WitnessValues,
    combine: fn(BigUint, BigUint) -> BigUint,
    name: &str,
) -> Check {
    let (Some(lhs), Some(rhs), Some(actual)) = (
        resolve(lhs, values),
        resolve(rhs, values),
        values.get(&output.witness_index()).copied(),
    ) else {
        return Check::Unsupported(format!("{name} operand is unassigned"));
    };
    if lhs.num_bits() > num_bits || rhs.num_bits() > num_bits {
        return Check::Violated(format!("{name} operand exceeds {num_bits} bits"));
    }
    let expected = combine(to_biguint(lhs), to_biguint(rhs));
    if to_biguint(actual) == expected {
        Check::Satisfied
    } else {
        Check::Violated(format!("{name} output {actual} does not match {expected}"))
    }
}

pub(crate) fn evaluate(
    expression: &Expression<FieldElement>,
    values: &WitnessValues,
) -> Option<FieldElement> {
    let mut total = expression.q_c;
    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let lhs = values.get(&lhs.witness_index())?;
        let rhs = values.get(&rhs.witness_index())?;
        total += *coefficient * *lhs * *rhs;
    }
    for (coefficient, witness) in &expression.linear_combinations {
        let value = values.get(&witness.witness_index())?;
        total += *coefficient * *value;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use acir::circuit::PublicInputs;

    use super::*;

    fn values(pairs: &[(u32, u32)]) -> WitnessValues {
        pairs
            .iter()
            .map(|(witness, value)| (*witness, FieldElement::from(*value as u128)))
            .collect()
    }

    // `w1 * w2 = w0` leaves `w1` free when `w2` is free: a genuine divergence,
    // and both assignments really do satisfy the opcode.
    #[test]
    fn a_real_divergence_is_certified() {
        let mut product = Expression::default();
        product.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        product.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(product)],
            ..Circuit::<FieldElement>::default()
        };
        let component = BTreeSet::from([1, 2, 3]);

        let certificate = certify(
            &circuit,
            &component,
            &BTreeSet::from([0]),
            Some(1),
            &values(&[(0, 12), (1, 3), (2, 4)]),
            &values(&[(0, 12), (1, 6), (2, 2)]),
        );
        assert_eq!(certificate.status, CertificateStatus::Certified);
        assert_eq!(certificate.checked_opcodes, 1);
    }

    // An assignment ACIR rejects must be refuted, whatever the translation
    // thought. This is the case that would expose a bug in this crate.
    #[test]
    fn an_assignment_acir_rejects_is_refuted() {
        let mut product = Expression::default();
        product.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        product.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(product)],
            ..Circuit::<FieldElement>::default()
        };

        let certificate = certify(
            &circuit,
            &BTreeSet::from([1, 2, 3]),
            &BTreeSet::from([0]),
            Some(1),
            &values(&[(0, 12), (1, 3), (2, 4)]),
            &values(&[(0, 12), (1, 5), (2, 5)]),
        );
        assert_eq!(certificate.status, CertificateStatus::Refuted);
    }

    // A range check the assignment violates is caught too.
    #[test]
    fn a_range_violation_is_refuted() {
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: 4,
            })],
            ..Circuit::<FieldElement>::default()
        };

        let certificate = certify(
            &circuit,
            &BTreeSet::from([1]),
            &BTreeSet::new(),
            Some(0),
            &values(&[(0, 15)]),
            &values(&[(0, 16)]),
        );
        assert_eq!(certificate.status, CertificateStatus::Refuted);
    }

    // Two assignments that simply use different inputs are not evidence of
    // anything. This is the check that separates "under-constrained" from
    // "the output depends on a private input", which is what a scan with only
    // the public parameters fixed would otherwise report on every circuit.
    #[test]
    fn disagreeing_on_a_fixed_input_is_refuted() {
        let mut product = Expression::default();
        product.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        product.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(product)],
            ..Circuit::<FieldElement>::default()
        };

        let certificate = certify(
            &circuit,
            &BTreeSet::from([1, 2, 3]),
            &BTreeSet::from([0]),
            Some(1),
            &values(&[(0, 12), (1, 3), (2, 4)]),
            &values(&[(0, 20), (1, 4), (2, 5)]),
        );
        assert_eq!(certificate.status, CertificateStatus::Refuted);
    }

    // A pair that agrees on the target proves nothing either.
    #[test]
    fn agreeing_on_the_target_is_refuted() {
        let mut product = Expression::default();
        product.push_multiplication_term(FieldElement::one(), Witness(1), Witness(2));
        product.push_addition_term(-FieldElement::one(), Witness(0));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(product)],
            ..Circuit::<FieldElement>::default()
        };

        let certificate = certify(
            &circuit,
            &BTreeSet::from([1, 2, 3]),
            &BTreeSet::from([0]),
            Some(1),
            &values(&[(0, 12), (1, 3), (2, 4)]),
            &values(&[(0, 12), (1, 3), (2, 4)]),
        );
        assert_eq!(certificate.status, CertificateStatus::Refuted);
    }

    // Black boxes are evaluated through the ACVM, so a certificate on a
    // circuit with a hash means something: the right digest passes, a wrong
    // one is rejected. Before, both came back `Incomplete`, which is what made
    // every circuit ending in a commitment unreachable for the mutation search.
    #[test]
    fn a_black_box_is_evaluated_concretely() {
        let outputs: [Witness; 32] = std::array::from_fn(|i| Witness(1 + i as u32));
        let call = BlackBoxFuncCall::Blake2s {
            inputs: vec![FunctionInput::Witness(Witness(0))],
            outputs: Box::new(outputs),
        };
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(call.clone())],
            ..Circuit::<FieldElement>::default()
        };
        let component = (1..=33).collect::<BTreeSet<usize>>();

        let mut honest = values(&[(0, 7)]);
        let crate::dynamic::concrete::BlackBoxEval::Outputs(digest) =
            crate::dynamic::concrete::eval_black_box(&call, &honest)
        else {
            panic!("blake2s should evaluate");
        };
        honest.extend(digest);
        let accepted = certify(
            &circuit,
            &component,
            &BTreeSet::new(),
            None,
            &honest,
            &honest,
        );
        assert_eq!(accepted.status, CertificateStatus::Certified);

        let mut forged = honest.clone();
        let byte = forged[&5];
        forged.insert(5, byte + FieldElement::one());
        let rejected = certify(
            &circuit,
            &component,
            &BTreeSet::new(),
            None,
            &forged,
            &forged,
        );
        assert_eq!(rejected.status, CertificateStatus::Refuted);
    }

    // An input that is not assigned still leaves the verdict unproven.
    #[test]
    fn a_black_box_with_an_unassigned_input_is_incomplete() {
        let outputs: [Witness; 32] = std::array::from_fn(|i| Witness(1 + i as u32));
        let circuit = Circuit {
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
                inputs: vec![FunctionInput::Witness(Witness(0))],
                outputs: Box::new(outputs),
            })],
            ..Circuit::<FieldElement>::default()
        };
        let component = (1..=33).collect::<BTreeSet<usize>>();
        let assignment = values(&[(1, 2)]);
        let certificate = certify(
            &circuit,
            &component,
            &BTreeSet::new(),
            None,
            &assignment,
            &assignment,
        );
        assert_eq!(certificate.status, CertificateStatus::Incomplete);
    }
}

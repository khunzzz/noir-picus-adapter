//! Circuit mutants: known under-constraint bugs injected into compiled ACIR.
//!
//! The corpora measure the tool on bugs someone wrote by hand, which says
//! little about what it misses. Mutants give ground truth at scale: take a
//! correct circuit, weaken one constraint the way real bugs weaken them, and
//! ask every detector whether it notices. A mutant that has a certified pair of
//! witnesses is a real bug, so a `verified` on it is a soundness bug in the
//! detector, and the fraction of real bugs each detector finds is its recall.
//!
//! Every operator only *removes* or *relaxes* a check, and only one the ACVM
//! does not need to compute anything: the honest witness of the original
//! circuit still satisfies the mutant and the mutant still executes, so the
//! dynamic path can always start from it.
//!
//! Operators, by the bug class they model:
//!
//! - `drop-check`: delete an `AssertZero` whose witnesses are all computed by
//!   earlier opcodes, so it constrains rather than defines. Subclassed by what
//!   it checked: a Brillig hint (`hint-binding`), a product that must vanish
//!   (`zero-product`, the second half of an is-zero gadget), a boolean
//!   (`boolean`), or anything else (`assert`).
//! - `drop-range`: delete a `RANGE` (`bool-range` for one bit, else `range`).
//! - `widen-range`: let a `RANGE` admit one more bit (`range-off-by-one`), the
//!   shape of a remainder bound written `<=` instead of `<`.

use std::collections::{BTreeSet, HashSet};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode, OpcodeLocation, Program,
        brillig::BrilligOutputs,
        opcodes::{BlackBoxFuncCall, FunctionInput, MemOp, MemOpKind},
    },
    native_types::{Expression, Witness},
};

pub(crate) struct Mutant {
    /// Operator name, one of the three above.
    pub(crate) operator: &'static str,
    /// Bug class, finer than the operator.
    pub(crate) class: &'static str,
    /// Index of the mutated opcode in the original `main`.
    pub(crate) opcode_index: usize,
    /// The opcode before mutation, as ACIR text.
    pub(crate) before: String,
    /// `None` removes the opcode; `Some` replaces it.
    replacement: Option<Opcode<FieldElement>>,
}

impl Mutant {
    /// The mutated program. Built on demand: a 50 000-opcode circuit has
    /// thousands of candidates and only a sample of them is ever written.
    pub(crate) fn apply(&self, program: &Program<FieldElement>) -> Program<FieldElement> {
        let main = &program.functions[0];
        let mutated = match &self.replacement {
            None => remove_opcode(main, self.opcode_index),
            Some(opcode) => {
                let mut replaced = main.clone();
                replaced.opcodes[self.opcode_index] = opcode.clone();
                replaced
            }
        };
        with_main(program, mutated)
    }
}

/// Every mutant of the program's `main` (function 0), in opcode order.
pub(crate) fn mutants(program: &Program<FieldElement>) -> Vec<Mutant> {
    let Some(main) = program.functions.first() else {
        return Vec::new();
    };
    let hints = hint_outputs(main);
    let checks = pure_checks(main);
    let mut found = Vec::new();

    for (index, opcode) in main.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) if checks.contains(&index) => {
                found.push(Mutant {
                    operator: "drop-check",
                    class: check_class(expression, &hints),
                    opcode_index: index,
                    before: opcode.to_string(),
                    replacement: None,
                });
            }
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(witness),
                num_bits,
            }) => {
                found.push(Mutant {
                    operator: "drop-range",
                    class: if *num_bits == 1 {
                        "bool-range"
                    } else {
                        "range"
                    },
                    opcode_index: index,
                    before: opcode.to_string(),
                    replacement: None,
                });
                // Past the field width a wider range is no range at all; those
                // are already covered by `drop-range`.
                if *num_bits < FieldElement::max_num_bits() - 1 {
                    found.push(Mutant {
                        operator: "widen-range",
                        class: "range-off-by-one",
                        opcode_index: index,
                        before: opcode.to_string(),
                        replacement: Some(Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                            input: FunctionInput::Witness(*witness),
                            num_bits: num_bits + 1,
                        })),
                    });
                }
            }
            _ => {}
        }
    }
    found
}

/// `AssertZero` opcodes that only check: every witness in them is already
/// assigned when the ACVM reaches them, so removing one leaves execution
/// untouched. An `AssertZero` with exactly one unassigned witness is how ACIR
/// *defines* that witness, and removing it would make the ACVM stall.
fn pure_checks(circuit: &Circuit<FieldElement>) -> HashSet<usize> {
    let mut assigned: HashSet<Witness> = circuit
        .private_parameters
        .iter()
        .chain(&circuit.public_parameters.0)
        .copied()
        .collect();
    let mut checks = HashSet::new();
    for (index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                let unassigned: BTreeSet<Witness> = expression_witnesses(expression)
                    .filter(|witness| !assigned.contains(witness))
                    .collect();
                if unassigned.is_empty() {
                    checks.insert(index);
                }
                assigned.extend(unassigned);
            }
            Opcode::BlackBoxFuncCall(call) => assigned.extend(call.get_outputs_vec()),
            Opcode::BrilligCall { outputs, .. } => {
                for output in outputs {
                    match output {
                        BrilligOutputs::Simple(witness) => {
                            assigned.insert(*witness);
                        }
                        BrilligOutputs::Array(witnesses) => assigned.extend(witnesses),
                    }
                }
            }
            Opcode::MemoryOp {
                op:
                    MemOp {
                        operation: MemOpKind::Read,
                        value,
                        ..
                    },
                ..
            } => {
                assigned.insert(*value);
            }
            Opcode::Call { outputs, .. } => assigned.extend(outputs),
            Opcode::MemoryOp { .. } | Opcode::MemoryInit { .. } => {}
        }
    }
    checks
}

fn hint_outputs(circuit: &Circuit<FieldElement>) -> HashSet<Witness> {
    crate::dynamic::candidates::hint_witnesses(circuit)
        .into_iter()
        .map(Witness)
        .collect()
}

fn check_class(expression: &Expression<FieldElement>, hints: &HashSet<Witness>) -> &'static str {
    if expression_witnesses(expression).any(|witness| hints.contains(&witness)) {
        return "hint-binding";
    }
    let one_product = expression.mul_terms.len() == 1;
    if one_product && expression.linear_combinations.is_empty() && expression.q_c.is_zero() {
        return "zero-product";
    }
    if one_product && expression.linear_combinations.len() == 1 && expression.q_c.is_zero() {
        let (_, a, b) = expression.mul_terms[0];
        let (_, w) = expression.linear_combinations[0];
        if a == b && a == w {
            return "boolean";
        }
    }
    "assert"
}

fn expression_witnesses(
    expression: &Expression<FieldElement>,
) -> impl Iterator<Item = Witness> + '_ {
    expression
        .mul_terms
        .iter()
        .flat_map(|(_, a, b)| [*a, *b])
        .chain(expression.linear_combinations.iter().map(|(_, w)| *w))
}

/// `circuit` without opcode `index`, with assertion messages re-pointed at the
/// shifted opcodes.
fn remove_opcode(circuit: &Circuit<FieldElement>, index: usize) -> Circuit<FieldElement> {
    let mut mutated = circuit.clone();
    mutated.opcodes.remove(index);
    mutated.assert_messages = circuit
        .assert_messages
        .iter()
        .filter_map(|(location, payload)| {
            let location = match *location {
                OpcodeLocation::Acir(at) if at == index => return None,
                OpcodeLocation::Acir(at) => OpcodeLocation::Acir(shift(at, index)),
                OpcodeLocation::Brillig { acir_index, .. } if acir_index == index => return None,
                OpcodeLocation::Brillig {
                    acir_index,
                    brillig_index,
                } => OpcodeLocation::Brillig {
                    acir_index: shift(acir_index, index),
                    brillig_index,
                },
            };
            Some((location, payload.clone()))
        })
        .collect();
    mutated
}

fn shift(at: usize, removed: usize) -> usize {
    if at > removed { at - 1 } else { at }
}

fn with_main(
    program: &Program<FieldElement>,
    main: Circuit<FieldElement>,
) -> Program<FieldElement> {
    let mut mutated = program.clone();
    mutated.functions[0] = main;
    mutated
}

#[cfg(test)]
mod tests {
    use acir::{FieldElement, circuit::Program};

    use crate::dynamic::concrete::execute;

    // The property every operator promises: the mutant still executes on the
    // original's honest inputs and solves exactly the same witness, so the
    // original's honest witness satisfies it. Checked on every mutant of every
    // example that has an executable input among a few simple guesses, and
    // through a serialization round trip, since mutants are used as files.
    #[test]
    fn every_mutant_accepts_the_honest_witness_unchanged() {
        let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/artifacts");
        let (mut circuits, mut checked) = (0, 0);
        for entry in std::fs::read_dir(examples).unwrap() {
            let loaded = crate::artifact::load_programs(&entry.unwrap().path()).unwrap();
            let program = &loaded.programs[0].program;
            let main = &program.functions[0];
            let parameters: Vec<u32> = main
                .private_parameters
                .iter()
                .chain(&main.public_parameters.0)
                .map(|witness| witness.witness_index())
                .collect();
            let honest = [2u128, 3, 7, 11].iter().find_map(|base| {
                let inputs = parameters
                    .iter()
                    .enumerate()
                    .map(|(position, index)| {
                        (
                            *index,
                            FieldElement::from(base * (position as u128 + 1) + 1),
                        )
                    })
                    .collect();
                execute(program, &inputs)
                    .ok()
                    .map(|solved| (inputs, solved))
            });
            let Some((inputs, solved)) = honest else {
                continue;
            };
            circuits += 1;
            for mutant in super::mutants(program) {
                let bytes = Program::serialize_program(&mutant.apply(program));
                let mutated = Program::<FieldElement>::deserialize_program(&bytes).unwrap();
                let resolved = execute(&mutated, &inputs).unwrap_or_else(|failure| {
                    panic!(
                        "{} at {}: {}",
                        mutant.operator, mutant.opcode_index, failure.message
                    )
                });
                assert_eq!(
                    resolved, solved,
                    "{} at {}",
                    mutant.operator, mutant.opcode_index
                );
                checked += 1;
            }
        }
        assert!(
            circuits >= 3 && checked >= 3,
            "{circuits} circuit(s), {checked} mutant(s)"
        );
    }
}

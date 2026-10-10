//! Concrete evaluation through the ACVM.
//!
//! Two things in this crate need to *run* ACIR rather than translate it:
//!
//! * the dynamic path (`mutate`, `fuzz`) has to follow a changed value through
//!   a hash. Before this module every black box other than `RANGE`/`AND`/`XOR`
//!   was copied from the honest run, so any mutation that moved a hash input was
//!   rejected outright, and the final certificate marked every circuit with a
//!   hash as `Incomplete`. Every ZKPassport circuit ends in a Poseidon2
//!   commitment, so the search could not accept a single finding on any of
//!   them, whatever the bug;
//! * the fuzzer needs an honest witness for inputs it made up itself, which
//!   means executing Brillig hints, not just checking constraints.
//!
//! Black boxes are evaluated by giving a one-opcode circuit to the ACVM with
//! the Bn254 solver — the very code `nargo execute` uses — so no hash is
//! re-implemented here.

use std::collections::BTreeMap;

use acvm::{
    AcirField, FieldElement,
    acir::{
        brillig::ForeignCallResult,
        circuit::{Opcode, OpcodeLocation, Program, opcodes::BlackBoxFuncCall},
        native_types::{Expression, Witness, WitnessMap},
    },
    pwg::{ACVM, ACVMStatus, ErrorLocation, OpcodeResolutionError},
};
use bn254_blackbox_solver::Bn254BlackBoxSolver;

use crate::dynamic::certify::WitnessValues;

/// What evaluating one black box against a partial assignment gave.
pub(crate) enum BlackBoxEval {
    /// Every output, in the order `get_outputs_vec` lists them.
    Outputs(Vec<(u32, FieldElement)>),
    /// An input is not assigned yet; another pass may supply it.
    Missing,
    /// The function itself refused the inputs (e.g. a malformed curve point).
    Failed(String),
    /// The black box has no meaning that can be checked from witness values
    /// alone. Recursive verification is the case: the ACVM treats it as a
    /// no-op and only the proving system checks it, so accepting it here would
    /// let a certificate vouch for a proof nobody verified.
    Unverifiable,
}

/// Evaluate `black_box` on the values `assignment` gives its inputs.
pub(crate) fn eval_black_box(
    black_box: &BlackBoxFuncCall<FieldElement>,
    assignment: &WitnessValues,
) -> BlackBoxEval {
    if matches!(black_box, BlackBoxFuncCall::RecursiveAggregation { .. }) {
        return BlackBoxEval::Unverifiable;
    }
    let mut initial = WitnessMap::new();
    for witness in black_box.get_input_witnesses() {
        match assignment.get(&witness.witness_index()) {
            Some(value) => {
                initial.insert(witness, *value);
            }
            None => return BlackBoxEval::Missing,
        }
    }
    let opcodes = [Opcode::BlackBoxFuncCall(black_box.clone())];
    let solver = Bn254BlackBoxSolver;
    let mut acvm = ACVM::new(&solver, &opcodes, initial, &[], &[]);
    match acvm.solve() {
        ACVMStatus::Solved => {}
        ACVMStatus::Failure(OpcodeResolutionError::OpcodeNotSolvable(_)) => {
            return BlackBoxEval::Missing;
        }
        ACVMStatus::Failure(error) => return BlackBoxEval::Failed(error.to_string()),
        other => return BlackBoxEval::Failed(format!("unexpected ACVM status: {other}")),
    }
    let solved = acvm.finalize();
    let mut outputs = Vec::new();
    for witness in black_box.get_outputs_vec() {
        match solved.get(&witness) {
            Some(value) => outputs.push((witness.witness_index(), *value)),
            None => {
                return BlackBoxEval::Failed(format!(
                    "output w{} not produced",
                    witness.witness_index()
                ));
            }
        }
    }
    BlackBoxEval::Outputs(outputs)
}

/// Why a run did not produce a witness.
#[derive(Debug)]
pub(crate) struct ExecFailure {
    /// The ACIR opcode that failed, when the ACVM could say.
    pub(crate) opcode: Option<usize>,
    pub(crate) message: String,
    /// What was solved before the failure. Input repair reads the failing
    /// constraint against it.
    pub(crate) partial: WitnessValues,
}

/// Execute the entry circuit of `program` on `inputs`, Brillig hints included.
///
/// Programs that split into several ACIR functions (`#[fold]`) are refused:
/// the dynamic search works on one circuit at a time.
pub(crate) fn execute(
    program: &Program<FieldElement>,
    inputs: &WitnessValues,
) -> Result<WitnessValues, ExecFailure> {
    let circuit = &program.functions[0];
    let initial: WitnessMap<FieldElement> = inputs
        .iter()
        .map(|(index, value)| (Witness(*index), *value))
        .collect::<BTreeMap<_, _>>()
        .into();
    let solver = Bn254BlackBoxSolver;
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        initial,
        &program.unconstrained_functions,
        &circuit.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::InProgress => continue,
            // `print`/`println` and other oracles: nothing the circuit depends
            // on, answered with no values.
            ACVMStatus::RequiresForeignCall(_) => {
                acvm.resolve_pending_foreign_call(ForeignCallResult::default());
            }
            ACVMStatus::RequiresAcirCall(_) => {
                return Err(ExecFailure {
                    opcode: None,
                    message: "program calls another ACIR function (#[fold]); not supported".into(),
                    partial: to_values(acvm.witness_map()),
                });
            }
            ACVMStatus::Failure(error) => {
                return Err(ExecFailure {
                    opcode: failing_opcode(&error),
                    message: describe(&error),
                    partial: to_values(acvm.witness_map()),
                });
            }
        }
    }
    Ok(to_values(&acvm.finalize()))
}

/// The error with its assertion message, when the program gave one: "Cannot
/// satisfy constraint" alone does not say which of a circuit's checks a
/// generated input keeps failing, and that is what decides how to fix the
/// generator.
fn describe(error: &OpcodeResolutionError<FieldElement>) -> String {
    use acvm::pwg::ResolvedAssertionPayload;
    let payload = match error {
        OpcodeResolutionError::UnsatisfiedConstrain { payload, .. }
        | OpcodeResolutionError::BrilligFunctionFailed { payload, .. } => payload.as_ref(),
        _ => None,
    };
    let at = failing_opcode(error)
        .map(|index| format!(" at opcode {index}"))
        .unwrap_or_default();
    match payload {
        Some(ResolvedAssertionPayload::String(message)) => format!("{error}{at}: {message}"),
        _ => format!("{error}{at}"),
    }
}

fn to_values(map: &WitnessMap<FieldElement>) -> WitnessValues {
    map.clone()
        .into_iter()
        .map(|(witness, value)| (witness.witness_index(), value))
        .collect()
}

fn failing_opcode(error: &OpcodeResolutionError<FieldElement>) -> Option<usize> {
    let location = match error {
        OpcodeResolutionError::UnsatisfiedConstrain {
            opcode_location, ..
        }
        | OpcodeResolutionError::IndexOutOfBounds {
            opcode_location, ..
        }
        | OpcodeResolutionError::InvalidInputBitSize {
            opcode_location, ..
        } => opcode_location,
        _ => return None,
    };
    match location {
        ErrorLocation::Resolved(OpcodeLocation::Acir(index)) => Some(*index),
        ErrorLocation::Resolved(OpcodeLocation::Brillig { acir_index, .. }) => Some(*acir_index),
        ErrorLocation::Unresolved => None,
    }
}

/// A window of parameters that, in the seed, held exactly the values some
/// computed witnesses held: the signed attributes carry `sha256(eContent)`,
/// the eContent carries `sha256(DG1)`. When a mutation changes what is hashed,
/// copying the recomputed values back keeps the input well-formed.
#[derive(Clone, Debug)]
pub(crate) struct InputLink {
    pub(crate) params: Vec<u32>,
    pub(crate) sources: Vec<u32>,
    /// The parameters' RANGE width: a value that does not fit is not copied,
    /// since the circuit's own type check would reject the run at once.
    pub(crate) bits: Option<u32>,
}

/// Execute, repairing inputs that are pinned by a linear equation.
///
/// Real circuits open with checks a random input never passes: a public
/// commitment `comm_in` must equal the Poseidon2 hash of the private inputs,
/// a claimed length must equal a computed one. Each of those compiles to an
/// `AssertZero` that is linear in exactly one parameter, so the parameter that
/// would satisfy it can be read straight off the failure — solve for it and run
/// again. Nothing here changes what the circuit checks: the repaired inputs are
/// re-executed from scratch, so the witness returned is an honest one.
///
/// Learned links are re-established the same way: copying recomputed digests
/// back into the input. That is sound for the same reason — whatever inputs
/// come out are executed from scratch — and a wrong link costs a failed run,
/// never a wrong result.
pub(crate) fn execute_with_repairs(
    program: &Program<FieldElement>,
    inputs: &mut WitnessValues,
    max_repairs: usize,
    links: &[InputLink],
) -> Result<WitnessValues, ExecFailure> {
    let circuit = &program.functions[0];
    let params = circuit
        .private_parameters
        .iter()
        .chain(circuit.public_parameters.0.iter())
        .map(|witness| witness.witness_index())
        .collect::<std::collections::BTreeSet<_>>();
    let mut last = None;
    for _ in 0..=max_repairs {
        match execute(program, inputs) {
            Ok(values) => return Ok(values),
            Err(failure) => {
                let linear = failure
                    .opcode
                    .and_then(|index| match circuit.opcodes.get(index) {
                        Some(Opcode::AssertZero(expression)) => {
                            solve_param(expression, &params, &failure.partial)
                        }
                        _ => None,
                    });
                if let Some((witness, value)) = linear
                    && inputs.get(&witness) != Some(&value)
                {
                    inputs.insert(witness, value);
                    last = Some(failure);
                    continue;
                }
                let mut changed = false;
                for link in links {
                    // Copy whatever the failed run already computed. A digest
                    // is produced before the check that compares it, so its
                    // bytes are all there when that check fails.
                    for (param, source) in link.params.iter().zip(&link.sources) {
                        let Some(value) = failure.partial.get(source).copied() else {
                            continue;
                        };
                        if link.bits.is_some_and(|bits| value.num_bits() > bits) {
                            continue;
                        }
                        if inputs.get(param) != Some(&value) {
                            inputs.insert(*param, value);
                            changed = true;
                        }
                    }
                }
                if !changed {
                    return Err(failure);
                }
                last = Some(failure);
            }
        }
    }
    Err(last.unwrap_or(ExecFailure {
        opcode: None,
        message: "input repair budget exhausted".into(),
        partial: WitnessValues::new(),
    }))
}

/// The single parameter that makes `expression` vanish, if there is exactly
/// one parameter in it, it appears only linearly, and every other witness in
/// it is known.
fn solve_param(
    expression: &Expression<FieldElement>,
    params: &std::collections::BTreeSet<u32>,
    values: &WitnessValues,
) -> Option<(u32, FieldElement)> {
    let in_products = expression
        .mul_terms
        .iter()
        .flat_map(|(_, a, b)| [a.witness_index(), b.witness_index()])
        .collect::<std::collections::BTreeSet<_>>();
    let mut chosen: Option<(u32, FieldElement)> = None;
    let mut rest = expression.q_c;
    for (coefficient, witness) in &expression.linear_combinations {
        let index = witness.witness_index();
        if params.contains(&index) && !in_products.contains(&index) && chosen.is_none() {
            chosen = Some((index, *coefficient));
            continue;
        }
        rest += *coefficient * *values.get(&index)?;
    }
    for (coefficient, a, b) in &expression.mul_terms {
        rest +=
            *coefficient * *values.get(&a.witness_index())? * *values.get(&b.witness_index())?;
    }
    let (witness, coefficient) = chosen?;
    if coefficient.is_zero() {
        return None;
    }
    Some((witness, -rest / coefficient))
}

/// Execute with one Brillig output replaced: the prover runs the program
/// honestly, except that it answers one hint with a value of its choosing.
///
/// This is the cheapest attack there is and the one constraint-level repair
/// handles worst. Changing a length hint moves every comparison against it,
/// and each comparison carries its own quotient/remainder hints; re-deriving
/// those from the constraints is a search, while re-running the Brillig code
/// that produces them is a function call. If the ACVM reaches the end, every
/// opcode held — it checks each one as it goes.
pub(crate) fn execute_with_override(
    program: &Program<FieldElement>,
    inputs: &WitnessValues,
    hint: u32,
    value: FieldElement,
) -> Result<WitnessValues, ExecFailure> {
    let circuit = &program.functions[0];
    let producer = circuit.opcodes.iter().position(|opcode| match opcode {
        Opcode::BrilligCall { outputs, .. } => outputs.iter().any(|output| match output {
            acvm::acir::circuit::brillig::BrilligOutputs::Simple(witness) => {
                witness.witness_index() == hint
            }
            acvm::acir::circuit::brillig::BrilligOutputs::Array(witnesses) => witnesses
                .iter()
                .any(|witness| witness.witness_index() == hint),
        }),
        _ => false,
    });
    let Some(producer) = producer else {
        return Err(ExecFailure {
            opcode: None,
            message: format!("w{hint} is not a Brillig output"),
            partial: WitnessValues::new(),
        });
    };
    let initial: WitnessMap<FieldElement> = inputs
        .iter()
        .map(|(index, value)| (Witness(*index), *value))
        .collect::<BTreeMap<_, _>>()
        .into();
    let solver = Bn254BlackBoxSolver;
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        initial,
        &program.unconstrained_functions,
        &circuit.assert_messages,
    );
    let fail = |acvm: &ACVM<FieldElement, Bn254BlackBoxSolver>,
                error: Option<&OpcodeResolutionError<FieldElement>>,
                message: String| ExecFailure {
        opcode: error.and_then(failing_opcode),
        message,
        partial: to_values(acvm.witness_map()),
    };
    // Run up to and including the producing call.
    while acvm.instruction_pointer() <= producer {
        match acvm.solve_opcode() {
            ACVMStatus::Solved => break,
            ACVMStatus::InProgress => {}
            ACVMStatus::RequiresForeignCall(_) => {
                acvm.resolve_pending_foreign_call(ForeignCallResult::default());
            }
            ACVMStatus::RequiresAcirCall(_) => {
                return Err(fail(&acvm, None, "ACIR call not supported".into()));
            }
            ACVMStatus::Failure(error) => {
                let message = error.to_string();
                return Err(fail(&acvm, Some(&error), message));
            }
        }
    }
    acvm.overwrite_witness(Witness(hint), value);
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::InProgress => continue,
            ACVMStatus::RequiresForeignCall(_) => {
                acvm.resolve_pending_foreign_call(ForeignCallResult::default());
            }
            ACVMStatus::RequiresAcirCall(_) => {
                return Err(fail(&acvm, None, "ACIR call not supported".into()));
            }
            ACVMStatus::Failure(error) => {
                let message = error.to_string();
                return Err(fail(&acvm, Some(&error), message));
            }
        }
    }
    Ok(to_values(&acvm.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acvm::acir::native_types::Expression;

    // `comm_in == hash(...)` compiles to `comm_in - h = 0`: one parameter,
    // linear, everything else known. That is the shape input repair solves.
    #[test]
    fn solves_a_linearly_pinned_parameter() {
        let mut expression = Expression::default();
        expression.push_addition_term(FieldElement::one(), Witness(0));
        expression.push_addition_term(-FieldElement::one(), Witness(5));
        let params = std::collections::BTreeSet::from([0u32, 1]);
        let values = WitnessValues::from([
            (0, FieldElement::from(3u128)),
            (5, FieldElement::from(42u128)),
        ]);
        assert_eq!(
            solve_param(&expression, &params, &values),
            Some((0, FieldElement::from(42u128)))
        );
    }

    // A parameter inside a product is not solvable this way, and must not be
    // "repaired" by pretending it is linear.
    #[test]
    fn refuses_a_parameter_inside_a_product() {
        let mut expression = Expression::default();
        expression.push_multiplication_term(FieldElement::one(), Witness(0), Witness(5));
        expression.push_addition_term(FieldElement::one(), Witness(0));
        let params = std::collections::BTreeSet::from([0u32]);
        let values = WitnessValues::from([
            (0, FieldElement::from(3u128)),
            (5, FieldElement::from(2u128)),
        ]);
        assert_eq!(solve_param(&expression, &params, &values), None);
    }
}

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use acir::{AcirField, FieldElement, circuit::Circuit, native_types::Witness};
use color_eyre::eyre::{Context, Result, eyre};
use num_bigint::BigUint;
use picus_smt::{
    SolverKind, Theory, backends::SolverResult, create_backend, query::UniquenessQuery,
};

use crate::{
    certify::{self, Certificate, CertificateStatus, WitnessValues},
    report::{Counterexample, DecidedBy, SolverOutcome, TargetReport, TargetStatus, WitnessPair},
    targets::Target,
    translate::{AcirPicusModel, field_modulus, target_signal},
};

#[derive(Debug)]
pub(crate) struct SolverOptions {
    pub(crate) timeout_ms: u64,
    pub(crate) dump_smt_dir: Option<PathBuf>,
    pub(crate) solver: SolverKind,
    pub(crate) theory: Theory,
    /// Re-check every reported divergence against ACIR semantics.
    pub(crate) certify: bool,
}

pub(crate) fn solve_target(
    model: &AcirPicusModel,
    circuit: &Circuit<FieldElement>,
    target: &Target,
    options: &SolverOptions,
    label: &str,
) -> Result<TargetReport> {
    let target_signal = target_signal(target.witness);
    if model.input_indices.contains(&target_signal) {
        // No solver call is needed if the target itself is fixed in both
        // self-composition copies.
        return Ok(TargetReport::from_solver(
            target.clone(),
            SolverOutcome {
                status: TargetStatus::Verified,
                decided_by: DecidedBy::FixedInput,
                query_orig_constraint_count: Some(0),
                query_alt_constraint_count: Some(0),
                reason: Some("target is a fixed circuit input".to_owned()),
                counterexample: None,
                certificate: None,
            },
        ));
    }
    if model.is_fixed_known_signal(target_signal) {
        // The target is not an input, but linear propagation proved it is
        // uniquely determined by fixed/public inputs. Treat it as verified
        // before constructing a large SMT query.
        return Ok(TargetReport::from_solver(
            target.clone(),
            SolverOutcome {
                status: TargetStatus::Verified,
                decided_by: DecidedBy::LinearPropagation,
                query_orig_constraint_count: Some(0),
                query_alt_constraint_count: Some(0),
                reason: Some(
                    "target is determined by fixed inputs through linear constraints".to_owned(),
                ),
                counterexample: None,
                certificate: None,
            },
        ));
    }

    // Counterexample-guided refinement. Level 0 hands the solver only the
    // constraints that survive cutting at every determined wire; each level
    // pulls one more layer of defining constraints back in. Every level
    // over-approximates, so the first `UNSAT` already proves the target unique
    // and the loop stops there — which is what keeps large circuits tractable.
    // A `SAT` is only reported once the slice is exact.
    let mut refinements = 0;
    let mut depth = 0;
    let outcome = loop {
        let run = run_query(model, target_signal, options, label, depth)?;
        match run.result {
            SolverResult::Unsat => {
                break SolverOutcome {
                    status: TargetStatus::Verified,
                    decided_by: DecidedBy::Solver,
                    query_orig_constraint_count: Some(run.orig_count),
                    query_alt_constraint_count: Some(run.alt_count),
                    reason: (!run.is_exact)
                        .then(|| "unique already on the relaxed over-approximation".to_owned()),
                    counterexample: None,
                    certificate: None,
                };
            }
            SolverResult::Sat(model_values) if run.is_exact => {
                let certificate = options
                    .certify
                    .then(|| certificate(model, circuit, target.witness, &model_values));
                // A divergence the ACIR opcodes themselves reject is not a
                // finding. It means the translation admitted an assignment the
                // circuit does not, which is exactly what a relaxation such as
                // a reduced range budget is expected to do — so the verdict is
                // downgraded rather than reported. The certificate stays in the
                // report: if the translation was supposed to be exact here, a
                // refutation is a bug in this tool and belongs in the tests.
                let refuted = matches!(
                    certificate.as_ref().map(|certificate| certificate.status),
                    Some(CertificateStatus::Refuted)
                );
                let (status, reason) = if refuted {
                    (
                        TargetStatus::Unknown,
                        "the solver's counterexample is rejected by ACIR itself".to_owned(),
                    )
                } else {
                    (
                        TargetStatus::Unsafe,
                        "found two satisfying assignments with different target values".to_owned(),
                    )
                };
                break SolverOutcome {
                    status,
                    decided_by: DecidedBy::Solver,
                    query_orig_constraint_count: Some(run.orig_count),
                    query_alt_constraint_count: Some(run.alt_count),
                    reason: Some(reason),
                    counterexample: Some(counterexample(model, target_signal, &model_values)),
                    certificate,
                };
            }
            SolverResult::Unknown if run.is_exact => {
                break SolverOutcome {
                    status: TargetStatus::Unknown,
                    decided_by: DecidedBy::Solver,
                    query_orig_constraint_count: Some(run.orig_count),
                    query_alt_constraint_count: Some(run.alt_count),
                    reason: Some("solver returned unknown or timed out".to_owned()),
                    counterexample: None,
                    certificate: None,
                };
            }
            // The abstraction was too coarse. Refining one layer at a time
            // only pays off when the extra layer decides the target; measured
            // on the realistic corpus it mostly added a whole extra solver call
            // before the exact query ran anyway, so escalate straight to exact.
            _ => {
                refinements += 1;
                depth = usize::MAX;
            }
        }
    };
    let _ = refinements;

    Ok(TargetReport::from_solver(target.clone(), outcome))
}

struct QueryRun {
    result: SolverResult,
    orig_count: usize,
    alt_count: usize,
    is_exact: bool,
}

fn run_query(
    model: &AcirPicusModel,
    target_signal: usize,
    options: &SolverOptions,
    label: &str,
    depth: usize,
) -> Result<QueryRun> {
    let sliced = model.target_constraints_at(Witness((target_signal - 1) as u32), depth);
    let is_exact = sliced.is_exact;
    let query = UniquenessQuery {
        prime: field_modulus(),
        n_wires: model.n_wires,
        input_indices: model.input_indices.iter().copied().collect(),
        orig_constraints: sliced.orig,
        alt_constraints: sliced.alt,
        constants: Vec::new(),
        known_signals: model.fixed_known_signals.iter().copied().collect(),
        target_signal,
    };
    let orig_count = query.orig_constraints.len();
    let alt_count = query.alt_constraints.len();

    let mut backend = create_backend(options.solver, options.theory)
        .map_err(|message| eyre!("failed to create Picus backend: {message}"))?
        .ok_or_else(|| eyre!("Picus backend creation returned no solver"))?;

    if let Some(dump_smt_dir) = &options.dump_smt_dir {
        let file_name = format!("{}_depth{depth}.smt2", sanitize_file_name(label));
        let smt_path = dump_smt_dir.join(file_name);
        std::fs::write(&smt_path, backend.dump_smt(&query))
            .wrap_err_with(|| format!("failed to write SMT dump {}", smt_path.display()))?;
    }

    let result = backend
        .solve(&query, options.timeout_ms)
        .map_err(|error| eyre!("Picus solver failed: {error}"))?;

    Ok(QueryRun {
        result,
        orig_count,
        alt_count,
        is_exact,
    })
}

/// Re-check the divergence against ACIR itself. See `certify` for what a
/// passing certificate does and does not establish.
fn certificate(
    model: &AcirPicusModel,
    circuit: &Circuit<FieldElement>,
    target: Witness,
    model_values: &HashMap<String, BigUint>,
) -> Certificate {
    let component = model.exact_component(target);
    let read = |alternative: bool| -> WitnessValues {
        let mut assignment = WitnessValues::new();
        for wire in 1..model.witness_wire_limit {
            // Fixed inputs are a single shared variable, so both copies read
            // the same `x` value for them.
            let name = if alternative && !model.input_indices.contains(&wire) {
                format!("y{wire}")
            } else {
                format!("x{wire}")
            };
            if let Some(value) = model_values.get(&name) {
                assignment.insert(
                    (wire - 1) as u32,
                    FieldElement::from_be_bytes_reduce(&value.to_bytes_be()),
                );
            }
        }
        assignment
    };

    let fixed_inputs = model
        .input_indices
        .iter()
        .filter(|wire| **wire != 0)
        .map(|wire| (wire - 1) as u32)
        .collect::<std::collections::BTreeSet<_>>();

    certify::certify(
        circuit,
        &component,
        &fixed_inputs,
        Some(target.witness_index()),
        &read(false),
        &read(true),
    )
}

/// Project the SAT model back onto ACIR witnesses.
///
/// The solver returns an assignment for every variable in the query. Keeping
/// only the target's two values throws away exactly what a reader needs in
/// order to reproduce and triage the finding, so the full divergence is
/// recorded: the shared input assignment, and every witness where the two
/// copies differ. Wires this crate invented for bit decomposition, one-hot
/// selectors and memory state are dropped — they are not ACIR witnesses.
fn counterexample(
    model: &AcirPicusModel,
    target_signal: usize,
    model_values: &HashMap<String, BigUint>,
) -> Counterexample {
    let mut fixed_inputs = BTreeMap::new();
    let mut diverging = BTreeMap::new();

    for wire in 1..model.witness_wire_limit {
        let Some(original) = model_values.get(&format!("x{wire}")) else {
            continue;
        };
        let witness_index = (wire - 1) as u32;
        if model.input_indices.contains(&wire) {
            fixed_inputs.insert(witness_index, original.to_string());
            continue;
        }
        match model_values.get(&format!("y{wire}")) {
            Some(alternative) if alternative != original => {
                diverging.insert(
                    witness_index,
                    WitnessPair {
                        original: original.to_string(),
                        alternative: alternative.to_string(),
                    },
                );
            }
            _ => {}
        }
    }

    Counterexample {
        original: model_values
            .get(&format!("x{target_signal}"))
            .map(ToString::to_string),
        alternative: model_values
            .get(&format!("y{target_signal}"))
            .map(ToString::to_string),
        fixed_inputs,
        diverging_witnesses: diverging,
    }
}

fn sanitize_file_name(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

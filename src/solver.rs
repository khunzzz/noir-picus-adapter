use std::path::PathBuf;

use acir::AcirField;
use color_eyre::eyre::{Context, Result, eyre};
use num_bigint::BigUint;
use picus_smt::{
    SolverKind, Theory, backends::SolverResult, create_backend, query::UniquenessQuery,
};

use crate::{
    report::{Counterexample, SolverOutcome, TargetReport, TargetStatus},
    targets::Target,
    translate::{AcirPicusModel, target_signal},
};

#[derive(Debug)]
pub(crate) struct SolverOptions {
    pub(crate) timeout_ms: u64,
    pub(crate) dump_smt_dir: Option<PathBuf>,
    pub(crate) solver: SolverKind,
    pub(crate) theory: Theory,
}

pub(crate) fn solve_target(
    model: &AcirPicusModel,
    target: &Target,
    options: &SolverOptions,
    label: &str,
) -> Result<TargetReport> {
    let target_signal = target_signal(target.witness);
    if model.input_indices.contains(&target_signal) {
        return Ok(TargetReport::from_solver(
            target.clone(),
            SolverOutcome {
                status: TargetStatus::Verified,
                reason: Some("target is a fixed circuit input".to_owned()),
                counterexample: None,
            },
        ));
    }

    let query = UniquenessQuery {
        prime: acir::FieldElement::modulus(),
        n_wires: model.n_wires,
        input_indices: model.input_indices.clone(),
        orig_constraints: model.orig_constraints.clone(),
        alt_constraints: model.alt_constraints.clone(),
        constants: Vec::new(),
        known_signals: model.input_indices.clone(),
        target_signal,
    };

    let mut backend = create_backend(options.solver, options.theory)
        .map_err(|message| eyre!("failed to create Picus backend: {message}"))?
        .ok_or_else(|| eyre!("Picus backend creation returned no solver"))?;

    if let Some(dump_smt_dir) = &options.dump_smt_dir {
        let file_name = format!("{}.smt2", sanitize_file_name(label));
        let smt_path = dump_smt_dir.join(file_name);
        std::fs::write(&smt_path, backend.dump_smt(&query))
            .wrap_err_with(|| format!("failed to write SMT dump {}", smt_path.display()))?;
    }

    let result = backend
        .solve(&query, options.timeout_ms)
        .map_err(|error| eyre!("Picus solver failed: {error}"))?;

    let outcome = match result {
        SolverResult::Unsat => SolverOutcome {
            status: TargetStatus::Verified,
            reason: None,
            counterexample: None,
        },
        SolverResult::Sat(model_values) => SolverOutcome {
            status: TargetStatus::Unsafe,
            reason: Some(
                "found two satisfying assignments with different target values".to_owned(),
            ),
            counterexample: Some(counterexample(target_signal, &model_values)),
        },
        SolverResult::Unknown => SolverOutcome {
            status: TargetStatus::Unknown,
            reason: Some("solver returned unknown or timed out".to_owned()),
            counterexample: None,
        },
    };

    Ok(TargetReport::from_solver(target.clone(), outcome))
}

fn counterexample(
    target_signal: usize,
    model_values: &std::collections::HashMap<String, BigUint>,
) -> Counterexample {
    let original_var = format!("x{target_signal}");
    let alternative_var = format!("y{target_signal}");
    Counterexample {
        original: model_values.get(&original_var).map(ToString::to_string),
        alternative: model_values.get(&alternative_var).map(ToString::to_string),
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

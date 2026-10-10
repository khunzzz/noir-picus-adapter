//! `feasible`, `witness-inputs`, `check-witness`: checks of a given input
//! assignment or witness file against the circuit.

use acir::{AcirField, FieldElement, circuit::Circuit};
use color_eyre::eyre::{Context, Result, eyre};

use crate::artifact;
use crate::cli::*;
use crate::dynamic::certify;
use crate::translate::{self, FixedMode, ModelOptions};

/// Check whether a witness file satisfies the circuit, and print it.
///
/// Useful on its own — it answers "would a verifier accept this?" for any
/// witness, including one someone else claims is a forgery — and it is how a
/// published attack witness gets checked against this crate's own evaluator.
pub(crate) fn check_witness(args: WitnessInputsArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;
    let circuit = program
        .program
        .functions
        .first()
        .ok_or_else(|| eyre!("program contains no circuit"))?;

    let raw = std::fs::read(&args.witness)
        .wrap_err_with(|| format!("failed to read witness {}", args.witness.display()))?;
    let stack = acir::native_types::WitnessStack::<FieldElement>::deserialize(&raw)
        .map_err(|error| eyre!("failed to parse witness file: {error}"))?;
    let item = stack
        .peek()
        .ok_or_else(|| eyre!("witness file carries no witness map"))?;

    let assignment: certify::WitnessValues = item
        .witness
        .clone()
        .into_iter()
        .map(|(witness, value)| (witness.witness_index(), value))
        .collect();

    let component = assignment
        .keys()
        .map(|witness| *witness as usize + 1)
        .collect::<std::collections::BTreeSet<_>>();
    let certificate = certify::certify(
        circuit,
        &component,
        &std::collections::BTreeSet::new(),
        None,
        &assignment,
        &assignment,
    );

    println!(
        "{:?} after {} opcode(s)",
        certificate.status, certificate.checked_opcodes
    );
    if let Some(detail) = &certificate.detail {
        println!("  {detail}");
    }
    println!(
        "returns: {}",
        circuit
            .return_values
            .0
            .iter()
            .map(|witness| format!(
                "w{}={}",
                witness.witness_index(),
                assignment
                    .get(&witness.witness_index())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "?".to_owned())
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (witness, value) in &assignment {
        println!("  w{witness} = {value}");
    }
    Ok(())
}

/// Print the parameter witnesses of a circuit and the values an honest run
/// gave them.
///
/// Which witness a parameter lands on is a layout convention, not something
/// the artifact states, and a feasibility answer computed under the wrong
/// layout is worse than no answer. Callers compare this against their own
/// encoding on a run that succeeded, and only trust the layout when it agrees.
pub(crate) fn witness_inputs(args: WitnessInputsArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;
    let circuit = program
        .program
        .functions
        .first()
        .ok_or_else(|| eyre!("program contains no circuit"))?;

    let raw = std::fs::read(&args.witness)
        .wrap_err_with(|| format!("failed to read witness {}", args.witness.display()))?;
    let stack = acir::native_types::WitnessStack::<FieldElement>::deserialize(&raw)
        .map_err(|error| eyre!("failed to parse witness file: {error}"))?;
    let item = stack
        .peek()
        .ok_or_else(|| eyre!("witness file carries no witness map"))?;

    let mut inputs = std::collections::BTreeMap::new();
    for witness in circuit
        .private_parameters
        .iter()
        .chain(circuit.public_parameters.0.iter())
    {
        if let Some(value) = item.witness.get(witness) {
            inputs.insert(witness.witness_index().to_string(), value.to_string());
        }
    }

    serde_json::to_writer(std::io::stdout(), &inputs)?;
    println!();
    Ok(())
}

/// Decide whether the constraint system accepts a fixed input assignment.
///
/// This is the other half of a soundness question the uniqueness check cannot
/// ask. A program rejects some inputs — an assertion fails, an addition
/// overflows, an index runs past the end of an array — and every one of those
/// rejections is supposed to survive compilation as a constraint. If the
/// circuit still accepts a witness for those inputs, a verifier would take a
/// proof of a statement the source says is false, which is exactly the shape
/// of the advisories where a check was dropped or its guard was off by one.
///
/// Asked as a satisfiability query rather than a uniqueness one: pin the
/// inputs, give the second copy no constraints at all, and point the target at
/// a wire nothing mentions, so the query is satisfiable precisely when the
/// constraints are. A satisfying model is then re-checked against the ACIR
/// opcodes, so a relaxation such as a reduced range budget cannot turn into a
/// false answer.
pub(crate) fn feasible(args: FeasibleArgs) -> Result<()> {
    use picus_smt::{backends::SolverResult, create_backend, query::IRConstraint};

    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;
    let circuit = program
        .program
        .functions
        .first()
        .ok_or_else(|| eyre!("program contains no circuit"))?;

    let values = serde_json::from_str::<std::collections::BTreeMap<String, String>>(&args.inputs)?;

    // Propagate the inputs first. With every parameter concrete, most of the
    // circuit follows by plain arithmetic, and any opcode that comes out
    // violated settles the question on the spot — which is the common case
    // here, since these inputs come from a run the program itself rejected.
    // Only what survives propagation is worth a solver call.
    let mut seed = std::collections::BTreeMap::new();
    for (witness, value) in &values {
        let index = witness.parse::<usize>()?;
        let parsed = value
            .parse::<num_bigint::BigUint>()
            .map_err(|error| eyre!("bad value for w{index}: {error}"))?;
        seed.insert(index + 1, parsed);
    }
    let (constants, violation) = translate::evaluate_with_inputs(circuit, &seed);
    if let Some(reason) = &violation {
        println!("rejected");
        eprintln!("{reason}");
        return Ok(());
    }
    if args.propagate_only {
        // "Nothing was violated" is only an answer when there was something to
        // violate. An assignment that pins too few witnesses evaluates nothing
        // and would otherwise read exactly like a satisfied circuit.
        let (evaluated, total) = translate::constraint_coverage(circuit, &constants);
        if evaluated < total {
            println!("undecided: {evaluated} of {total} constraint(s) could be evaluated");
            return Ok(());
        }
        println!("no-violation ({total} constraint(s) evaluated)");
        return Ok(());
    }

    let model = translate::build_model(
        circuit,
        ModelOptions {
            fixed_mode: FixedMode::AllParams,
            max_range_bits: args.max_range_bits,
        },
    );

    let mut orig = model.orig_constraints.clone();
    for (wire, value) in &constants {
        if *wire != 0 {
            orig.push(IRConstraint::VarEq(format!("x{wire}"), value.clone()));
        }
    }

    let query = picus_smt::query::UniquenessQuery {
        prime: translate::field_modulus(),
        // One wire past the end, mentioned by nothing, so the inequality the
        // query always asserts is free and does not affect the answer.
        n_wires: model.n_wires + 1,
        input_indices: model.input_indices.iter().copied().collect(),
        orig_constraints: orig,
        alt_constraints: Vec::new(),
        constants: Vec::new(),
        known_signals: std::collections::HashSet::new(),
        target_signal: model.n_wires,
    };

    let mut backend = create_backend(args.solver.into(), args.theory.into())
        .map_err(|message| eyre!("failed to create Picus backend: {message}"))?
        .ok_or_else(|| eyre!("Picus backend creation returned no solver"))?;

    let verdict = match backend.solve(&query, args.timeout)? {
        SolverResult::Unsat => "rejected",
        // A relaxation is dangerous in this direction: the range checks that
        // were dropped to keep the solver tractable are exactly the overflow
        // checks the question is about, so a dropped range would make every
        // overflowing input look accepted. The model is therefore re-checked
        // against the ACIR opcodes, which restores exactness — and anything
        // that fails the re-check is reported as unknown rather than as an
        // acceptance.
        SolverResult::Sat(model_values) => {
            if accepts_exactly(circuit, &model, &values, &model_values)? {
                "accepted"
            } else {
                "unknown"
            }
        }
        SolverResult::Unknown => "unknown",
    };
    println!("{verdict}");
    Ok(())
}

/// Re-check a satisfying model against ACIR, and against the inputs asked about.
fn accepts_exactly(
    circuit: &Circuit<FieldElement>,
    model: &translate::AcirPicusModel,
    requested: &std::collections::BTreeMap<String, String>,
    model_values: &std::collections::HashMap<String, num_bigint::BigUint>,
) -> Result<bool> {
    let mut assignment = certify::WitnessValues::new();
    for wire in 1..model.witness_wire_limit {
        if let Some(value) = model_values.get(&format!("x{wire}")) {
            assignment.insert(
                (wire - 1) as u32,
                FieldElement::from_be_bytes_reduce(&value.to_bytes_be()),
            );
        }
    }

    // The solver was asked to pin these; make sure it did.
    for (witness, value) in requested {
        let index = witness.parse::<u32>()?;
        let expected = FieldElement::from_be_bytes_reduce(
            &value.parse::<num_bigint::BigUint>()?.to_bytes_be(),
        );
        if assignment.get(&index) != Some(&expected) {
            return Ok(false);
        }
    }

    let component = (1..=model.witness_wire_limit).collect::<std::collections::BTreeSet<_>>();
    let certificate = certify::certify(
        circuit,
        &component,
        &std::collections::BTreeSet::new(),
        None,
        &assignment,
        &assignment,
    );
    Ok(matches!(
        certificate.status,
        certify::CertificateStatus::Certified
    ))
}

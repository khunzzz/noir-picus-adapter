#![forbid(unsafe_code)]

mod artifact;
mod certify;
mod debug_info;
mod explain;
mod mutate;
mod refine;
mod report;
mod solver;
mod targets;
mod translate;

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use acir::{AcirField, FieldElement, circuit::Circuit, circuit::Opcode};
use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Context, Result, eyre};
use debug_info::{AbiNaming, ProgramDebugData};
use picus_smt::{SolverKind, Theory};
use report::{
    CircuitReport, OutputFormat, ProgramReport, REPORT_SCHEMA_VERSION, ScanReport, ScanSummary,
    TargetReport, TargetSourceLocation,
};
use solver::SolverOptions;
use targets::{Target, TargetMode, TargetOrigin};
use translate::{FixedMode, ModelOptions};

#[derive(Debug, Parser)]
#[command(name = "noir-picus-adapter")]
#[command(about = "Picus adapter for scanning Noir ACIR artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan(ScanArgs),
    /// Search for a second accepting witness by mutating hint outputs.
    Mutate(MutateArgs),

    /// List hint outputs that nothing in the circuit appears able to pin.
    ///
    /// Needs neither a witness nor an execution, so it reaches programs the
    /// mutation search cannot start on at all — in campaign runs about one in
    /// seven generated programs never produces an honest witness.
    Unpinned(UnpinnedArgs),

    /// Ask whether the constraint system accepts a given input assignment.
    Feasible(FeasibleArgs),

    /// Print the circuit's parameter witnesses and their values in a witness
    /// file, so a caller can check its own idea of the input layout.
    WitnessInputs(WitnessInputsArgs),

    /// Check a witness file against the ACIR opcodes and print what it holds.
    CheckWitness(WitnessInputsArgs),

    /// Run the refinement pass for one circuit and stream the wires it proves
    /// unique, one per line.
    ///
    /// Not meant to be run by hand: `scan` re-invokes the binary through this
    /// so the pass can be killed on a hard wall clock without losing what it
    /// already proved.
    #[command(hide = true)]
    RefineCircuit(RefineCircuitArgs),

    /// Solve exactly one target and print its report as JSON.
    ///
    /// Not meant to be run by hand: `scan --target-timeout` re-invokes the
    /// binary through this to put a hard wall clock around each solver call.
    #[command(hide = true)]
    ScanTarget(ScanTargetArgs),
}

#[derive(Debug, Args)]
struct WitnessInputsArgs {
    artifact: PathBuf,

    #[arg(long)]
    witness: PathBuf,
}

#[derive(Debug, Args)]
struct UnpinnedArgs {
    /// The compiled artifact.
    artifact: PathBuf,

    /// Fix only the public parameters, leaving private ones free.
    ///
    /// The default fixes every parameter, because that is the soundness
    /// question: a prover commits to all of its inputs and then looks for a
    /// second witness agreeing with them. Fixing only the public ones asks a
    /// different and weaker question, and on Noir's own corpus it reported two
    /// programs whose hints are in fact pinned once the private inputs are
    /// held.
    #[arg(long)]
    public_inputs_only: bool,

    /// Keep single-bit witnesses that look like digits of a decomposition.
    ///
    /// They are skipped by default because a decomposition pins its digits
    /// jointly rather than one assertion at a time, so every digit of a
    /// `to_le_bits` looks free to a per-witness rule.
    #[arg(long)]
    include_bits: bool,
}

#[derive(Debug, Args)]
struct FeasibleArgs {
    /// The compiled artifact.
    artifact: PathBuf,

    /// JSON object mapping ACIR witness index to a decimal value, for every
    /// circuit parameter.
    #[arg(long)]
    inputs: String,

    #[arg(long, default_value_t = 20000)]
    timeout: u64,

    #[arg(long, default_value_t = 16)]
    max_range_bits: u32,

    /// Stop after constant propagation instead of falling through to the
    /// solver.
    ///
    /// With a full assignment pinned there is nothing to search for: every
    /// opcode either evaluates or it does not, and propagation settles that in
    /// milliseconds. The solver stage only exists for partial assignments, and
    /// on a large circuit it will not finish — so re-checking a complete
    /// witness needs a way to say "just evaluate it".
    #[arg(long)]
    propagate_only: bool,

    #[arg(long, value_enum, default_value = "cvc5")]
    solver: CliSolverKind,

    #[arg(long, value_enum, default_value = "ff")]
    theory: CliTheory,
}

#[derive(Debug, Args)]
struct MutateArgs {
    /// The compiled artifact.
    artifact: PathBuf,

    /// Witness file produced by `nargo execute` (the `.gz` next to the
    /// artifact). Supplies the honest assignment the search starts from.
    #[arg(long)]
    witness: PathBuf,

    /// How many alternative values to try per hint witness.
    #[arg(long, default_value_t = 3)]
    attempts: usize,

    /// Write the full witness assignment of the first finding to this path, as
    /// a witness-index -> value JSON map.
    ///
    /// A finding is only as good as the evaluator that accepted it, so the
    /// assignment has to be checkable by something else. Feeding this to
    /// `feasible` re-checks it through constant propagation instead of the
    /// certificate's opcode walk — a different code path reaching the same
    /// question.
    #[arg(long)]
    emit_witness: Option<PathBuf>,

    /// For each finding, list every opcode that mentions the moved witness.
    ///
    /// Isolating why a constraint system let a witness move meant dumping the
    /// ACIR and grepping for the index by hand. That is mechanical, and doing
    /// it here also states the one thing the list proves on its own: a witness
    /// whose only opcodes are its definition and a range check cannot be
    /// pinned by anything.
    #[arg(long)]
    explain: bool,

    #[arg(long, value_enum, default_value = "human")]
    format: CliOutputFormat,
}

#[derive(Debug, Args)]
struct RefineCircuitArgs {
    #[command(flatten)]
    scan: ScanArgs,

    #[arg(long)]
    program_index: usize,

    #[arg(long)]
    circuit_index: usize,
}

#[derive(Debug, Args)]
struct ScanTargetArgs {
    #[command(flatten)]
    scan: ScanArgs,

    /// Index into the artifact's programs.
    #[arg(long)]
    program_index: usize,

    /// Index into the program's circuits.
    #[arg(long)]
    circuit_index: usize,

    /// ACIR witness index of the target.
    #[arg(long)]
    witness: u32,
}

#[derive(Debug, Args)]
struct ScanArgs {
    artifact: PathBuf,

    #[arg(long, value_enum, default_value = "human")]
    format: CliOutputFormat,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    dump_smt: Option<PathBuf>,

    #[arg(long, default_value_t = 5000)]
    timeout: u64,

    #[arg(long, value_enum, default_value = "all-params")]
    fixed: CliFixedMode,

    #[arg(long, value_enum, default_value = "all")]
    targets: CliTargetMode,

    #[arg(long, value_enum, default_value = "cvc5")]
    solver: CliSolverKind,

    #[arg(long, value_enum, default_value = "ff")]
    theory: CliTheory,

    /// Exit with status 1 when any target is `unsafe`, 2 when any target
    /// errored. Off by default so existing scripts keep working.
    #[arg(long)]
    exit_code_on_finding: bool,

    /// Skip the uniqueness-refinement pass (small local SMT queries that grow
    /// the determined set before any target is solved). On by default: it is
    /// what keeps the per-target queries small on real circuits.
    #[arg(long)]
    no_refine: bool,

    /// Per-query budget for the refinement pass, in milliseconds. Deliberately
    /// short — a local window that does not settle quickly is not worth
    /// waiting for, since failing to prove uniqueness costs nothing but a
    /// larger query later.
    #[arg(long, default_value_t = 300)]
    refine_timeout: u64,

    /// Total wall-clock budget for the refinement pass, in milliseconds.
    #[arg(long, default_value_t = 15000)]
    refine_budget: u64,

    /// Largest neighbourhood radius the refinement pass will try.
    #[arg(long, default_value_t = 2)]
    refine_radius: usize,

    /// Hard wall-clock budget per target, in milliseconds. When set, each
    /// target is solved in a child process and killed if it overruns, and the
    /// target is reported `unknown`.
    ///
    /// cvc5's own `tlimit` is checked between search steps and a finite-field
    /// Groebner basis computation can run far past it, so an in-process
    /// timeout cannot be relied on for batch runs.
    #[arg(long)]
    target_timeout: Option<u64>,

    /// Skip the ACIR re-check of reported divergences. On by default: a
    /// finding that survives it cannot be an artefact of a translation bug.
    #[arg(long)]
    no_certify: bool,

    /// Translate and propagate, but never call the solver. Every target that
    /// propagation cannot settle is reported `unknown`. Useful for measuring
    /// how much work the propagation layer removes, and for triaging a circuit
    /// that makes the solver blow up.
    #[arg(long)]
    no_solve: bool,

    /// Widest `RANGE` still expanded into an exact bit decomposition.
    ///
    /// Wider ranges are dropped, which is a relaxation: `verified` stays sound
    /// because the query only gains solutions, and a spurious `unsafe` is
    /// caught by the ACIR re-check and downgraded. That pairing is what makes
    /// a low budget the right default rather than a compromise — the bit
    /// decomposition is the single biggest source of solver blow-up, and with
    /// `RANGE(32)` expanded the known compiler bug in
    /// `compiler_symbolic_array_index_brillig_output` times out, while at a
    /// lower budget it is found and certified in milliseconds.
    #[arg(long, default_value_t = 16)]
    max_range_bits: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliOutputFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliFixedMode {
    Public,
    AllParams,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTargetMode {
    Returns,
    BrilligOutputs,
    All,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliSolverKind {
    Cvc5,
    Z3,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTheory {
    Ff,
    Nia,
}

pub fn run() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::ScanTarget(args) => scan_one_target(args),
        Command::RefineCircuit(args) => refine_one_circuit(args),
        Command::Mutate(args) => mutate(args),
        Command::Unpinned(args) => unpinned(args),
        Command::Feasible(args) => feasible(args),
        Command::WitnessInputs(args) => witness_inputs(args),
        Command::CheckWitness(args) => check_witness(args),
    }
}

fn scan(args: ScanArgs) -> Result<()> {
    if let Some(dump_smt) = &args.dump_smt {
        std::fs::create_dir_all(dump_smt)?;
    }

    let loaded = artifact::load_programs(&args.artifact)?;
    let noir_version = loaded.noir_version;
    let loaded_programs = loaded.programs;
    let solver_name = args.solver.as_str().to_owned();
    let theory_name = args.theory.as_str().to_owned();
    let solver_options = SolverOptions {
        timeout_ms: args.timeout,
        dump_smt_dir: args.dump_smt.clone(),
        solver: args.solver.into(),
        theory: args.theory.into(),
        certify: !args.no_certify,
    };
    picus_smt::validate_combination(solver_options.solver, solver_options.theory)
        .map_err(|message| eyre!("invalid Picus solver/theory combination: {message}"))?;
    let model_options = ModelOptions {
        fixed_mode: args.fixed.into(),
        max_range_bits: args.max_range_bits,
    };
    let target_mode = args.targets.into();

    let mut program_reports = Vec::new();
    let mut summary = ScanSummary::default();
    for (program_index, loaded) in loaded_programs.into_iter().enumerate() {
        let mut circuit_reports = Vec::new();

        // Схемы разбираются от ВЫЗЫВАЕМЫХ к вызывающим. `Opcode::Call` в схеме с
        // меньшим номером ссылается на схему с бо́льшим, поэтому обратный порядок
        // гарантирует, что к моменту разбора вызывающей схемы про вызываемую уже
        // известно, детерминирована ли она. Отчёты потом возвращаются в прямой
        // порядок, чтобы вывод не зависел от порядка разбора.
        let mut deterministic_calls: BTreeSet<u32> = BTreeSet::new();
        for (circuit_index, circuit) in loaded.program.functions.iter().enumerate().rev() {
            let discovered_targets =
                targets::discover_targets(&loaded.program, circuit, target_mode);
            let mut model =
                translate::build_model_with_calls(circuit, model_options, &deterministic_calls);
            let mut refinement = refine::RefinementStats::default();
            if !args.no_solve && !args.no_refine {
                for wire in refine_out_of_process(&args, program_index, circuit_index) {
                    model.mark_determined(wire);
                    refinement.proved += 1;
                }
            }
            let circuit_name = if circuit.function_name.is_empty() {
                format!("circuit_{circuit_index}")
            } else {
                circuit.function_name.clone()
            };
            // The artifact ABI describes `main` only, i.e. the entry circuit.
            let abi_naming = (circuit_index == 0)
                .then_some(loaded.abi.as_ref())
                .flatten()
                .map(|abi| {
                    let n_param_witnesses =
                        circuit.private_parameters.len() + circuit.public_parameters.0.len();
                    AbiNaming::new(abi, n_param_witnesses, circuit.return_values.0.len())
                });

            let mut target_reports = Vec::new();
            for target in discovered_targets {
                let witness = target.witness;
                let annotations = annotate_target(
                    &target,
                    circuit,
                    circuit_index,
                    abi_naming.as_ref(),
                    loaded.debug.as_ref(),
                );
                let label = format!("{}_{}_{}", loaded.name, circuit_name, witness);
                // The two trivial-verified short-circuits are checked first: a
                // target that is itself a fixed input needs no analysis, and
                // reporting it as `unsupported` because something unrelated in
                // its component is untranslated is pure noise.
                let target_unsupported_reasons = model.unsupported_reasons_for_target(witness);
                let mut target_report = if args.no_solve && !model.is_trivially_determined(witness)
                {
                    TargetReport::not_solved(target)
                } else if model.is_trivially_determined(witness)
                    || target_unsupported_reasons.is_empty()
                {
                    // A solver failure is confined to its own target: a batch
                    // scan must not lose every other verdict because one query
                    // blew up. With `--target-timeout` the isolation is a real
                    // process boundary, so a solver that overruns its own time
                    // limit cannot hang the run either.
                    let solved = match args.target_timeout {
                        Some(budget_ms) if !model.is_trivially_determined(witness) => {
                            solve_target_out_of_process(
                                &args,
                                program_index,
                                circuit_index,
                                &target,
                                budget_ms,
                            )
                        }
                        _ => None,
                    };
                    match solved.unwrap_or_else(|| {
                        solver::solve_target(&model, circuit, &target, &solver_options, &label)
                    }) {
                        Ok(report) => report,
                        Err(error) => TargetReport::failed(target, format!("{error:#}")),
                    }
                } else {
                    TargetReport::unsupported(target, target_unsupported_reasons.join("; "))
                };
                summary.record(target_report.status);
                target_report.abstraction_notes = model.abstraction_reasons_for_target(witness);
                target_report.abi_name = annotations.abi_name;
                target_report.source_locations = annotations.source_locations;
                target_reports.push(target_report);
            }

            // Схема считается детерминированной, только если КАЖДОЕ её
            // возвращаемое значение доказано однозначным при её параметрах.
            // Именно это свойство и утверждает абстракция вызова, поэтому более
            // слабого условия здесь быть не может: одного недоказанного возврата
            // достаточно, чтобы вызов остался неподдерживаемым.
            let return_witnesses: BTreeSet<u32> = circuit
                .return_values
                .0
                .iter()
                .map(|witness| witness.witness_index())
                .collect();
            let returns_all_verified = !return_witnesses.is_empty()
                && return_witnesses.iter().all(|index| {
                    target_reports.iter().any(|report| {
                        report.witness_index == *index
                            && matches!(report.status, report::TargetStatus::Verified)
                    })
                });
            if returns_all_verified {
                deterministic_calls.insert(circuit_index as u32);
            }

            circuit_reports.push(CircuitReport {
                name: circuit_name,
                index: circuit_index,
                private_parameters: circuit
                    .private_parameters
                    .iter()
                    .map(|witness| witness.witness_index())
                    .collect(),
                public_parameters: circuit.public_parameters.indices(),
                return_values: circuit.return_values.indices(),
                fixed_witnesses: fixed_witness_indices(&model),
                witness_wires: model.witness_wire_limit.saturating_sub(1),
                // Wire 0 is the constant-one wire, not an ACIR witness.
                refined_wires: refinement.proved,
                refinement_queries: refinement.queries,
                determined_wires: model
                    .fixed_known_signals
                    .iter()
                    .filter(|wire| **wire != 0 && **wire < model.witness_wire_limit)
                    .count(),
                undetermined_witnesses: undetermined_witnesses(&model),
                constant_wires: model.constant_signals.len(),
                n_wires: model.n_wires,
                orig_constraint_count: model.orig_constraints.len(),
                alt_constraint_count: model.alt_constraints.len(),
                unsupported_reasons: model.unsupported_reasons,
                abstracted_reasons: model.abstracted_reasons,
                targets: target_reports,
            });
        }

        // обратно в прямой порядок номеров схем
        circuit_reports.sort_by_key(|report| report.index);
        program_reports.push(ProgramReport {
            name: loaded.name,
            circuits: circuit_reports,
        });
    }

    let report = ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        artifact: args.artifact.display().to_string(),
        noir_version,
        summary,
        solver: solver_name,
        theory: theory_name,
        timeout_ms: solver_options.timeout_ms,
        fixed_mode: args.fixed.as_str().to_owned(),
        target_mode: args.targets.as_str().to_owned(),
        dump_smt_dir: solver_options
            .dump_smt_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        programs: program_reports,
    };
    match args.format {
        CliOutputFormat::Human => report.print_human(args.verbose),
        CliOutputFormat::Json => report.print(OutputFormat::Json)?,
    }

    let exit_code = report.exit_code();
    if exit_code != 0 && args.exit_code_on_finding {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Check whether a witness file satisfies the circuit, and print it.
///
/// Useful on its own — it answers "would a verifier accept this?" for any
/// witness, including one someone else claims is a forgery — and it is how a
/// published attack witness gets checked against this crate's own evaluator.
fn check_witness(args: WitnessInputsArgs) -> Result<()> {
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
fn witness_inputs(args: WitnessInputsArgs) -> Result<()> {
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
fn feasible(args: FeasibleArgs) -> Result<()> {
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

/// Report hint outputs that no constraint appears able to pin.
///
/// This is a triage pass, and it is careful about what it claims. Propagation
/// gives the witnesses that provably *are* determined by the inputs; the rest
/// are merely not known to be. A hint output among those, where every
/// assertion touching it also touches another undetermined witness, has the
/// exact shape of the class documented in
/// `findings/non-pinning-constraint-silences-checker`. That is a candidate,
/// not a proof: two assertions could still pin such a pair jointly. Confirming
/// one means running `mutate` or `scan` on it.
///
/// What it buys is reach. It needs no honest witness, so it applies to
/// artifacts that cannot be executed at all.
fn unpinned(args: UnpinnedArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;

    let mut candidates = 0usize;
    for (index, circuit) in program.program.functions.iter().enumerate() {
        let options = translate::ModelOptions {
            fixed_mode: if args.public_inputs_only {
                translate::FixedMode::Public
            } else {
                translate::FixedMode::AllParams
            },
            ..Default::default()
        };
        let model = translate::build_model(circuit, options);
        let mut determined = (1..model.witness_wire_limit)
            .filter(|wire| model.fixed_known_signals.contains(wire))
            .map(|wire| (wire - 1) as u32)
            .collect::<std::collections::BTreeSet<_>>();
        explain::refine_determined(circuit, &mut determined);
        let undetermined = (1..model.witness_wire_limit)
            .map(|wire| (wire - 1) as u32)
            .filter(|witness| !determined.contains(witness))
            .collect::<std::collections::BTreeSet<_>>();

        // A circuit with no assertions at all comes from an `unconstrained fn
        // main`: the whole program is the prover's to compute, by declaration.
        // Every hint in it is free, correctly so, and reporting them buries the
        // cases that matter — one such program in Noir's own corpus accounted
        // for 32 of the candidates.
        if !circuit
            .opcodes
            .iter()
            .any(|opcode| matches!(opcode, acir::circuit::Opcode::AssertZero(_)))
        {
            continue;
        }

        let reaching_output = explain::reachable_from_outputs(circuit, &undetermined);
        let bounds = explain::value_bounds(circuit);
        for witness in mutate::hint_witnesses(circuit) {
            if !undetermined.contains(&witness) {
                continue;
            }
            // A hint that never reaches what the circuit hands back cannot
            // change what a verifier sees, however free it is.
            if !reaching_output.contains(&witness) {
                continue;
            }
            let explanation =
                explain::explain_with_bounds(circuit, witness, &undetermined, &bounds);
            if !args.include_bits && explanation.looks_like_a_decomposition_digit() {
                continue;
            }
            if matches!(
                explanation.verdict,
                explain::Verdict::BoundedNeverPinned
                    | explain::Verdict::Unconstrained
                    | explain::Verdict::OnlyVanishingConstraints
                    | explain::Verdict::PropagatesFreedom
            ) {
                candidates += 1;
                println!("circuit {index}: {}", explanation.headline());
                for touch in &explanation.touches {
                    println!("    opcode {:>4}  {}", touch.index, touch.description);
                }
            }
        }
    }
    println!("{candidates} candidate(s)");
    if candidates == 0 { Ok(()) } else { std::process::exit(1) }
}

/// Подобрать из стека свидетель, который действительно удовлетворяет схеме.
///
/// Возвращает `None`, если ни один не подходит: тогда честной отправной точки
/// для поиска нет, и молча брать чужую нельзя — это порождает находки на пустом
/// месте.
fn pick_matching_witness(
    circuit: &acir::circuit::Circuit<FieldElement>,
    witnesses: &[acir::native_types::WitnessMap<FieldElement>],
) -> Option<std::collections::BTreeMap<u32, FieldElement>> {
    for witness in witnesses {
        let values: std::collections::BTreeMap<u32, FieldElement> = witness
            .clone()
            .into_iter()
            .map(|(index, value)| (index.witness_index(), value))
            .collect();
        // Проверка — тем же вычислителем ACIR, что выносит вердикты о находках.
        // Оба «экземпляра» одинаковы, цели нет: вопрос ровно один — удовлетворяет
        // ли этот свидетель данной схеме.
        // Область покрывает все сигналы свидетеля: проверять надо схему целиком.
        let last_wire = values.keys().copied().max().unwrap_or(0) as usize;
        let component = (1..=last_wire + 1).collect::<std::collections::BTreeSet<_>>();
        let certificate = certify::certify(
            circuit,
            &component,
            &std::collections::BTreeSet::new(),
            None,
            &values,
            &values,
        );
        if matches!(certificate.status, certify::CertificateStatus::Certified) {
            return Some(values);
        }
    }
    None
}

/// Search for a second accepting witness by mutation and repair.
fn mutate(args: MutateArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;

    let raw = std::fs::read(&args.witness)
        .wrap_err_with(|| format!("failed to read witness {}", args.witness.display()))?;
    let stack = acir::native_types::WitnessStack::<FieldElement>::deserialize(&raw)
        .map_err(|error| eyre!("failed to parse witness file: {error}"))?;

    // Every circuit in the program is searched, not only the entry one.
    // A `#[fold]` function is not inlined: the program compiles to several
    // circuits joined by `Opcode::Call`, and *all* of the hints live in the
    // callees. Looking only at the entry circuit reported those programs clean
    // having explored nothing at all — the funnel showed zero hints — which is
    // worse than reporting nothing.
    // The witness stack holds one map per circuit invocation, with the entry
    // circuit on top, so popping walks outermost to innermost.
    let mut witnesses = Vec::new();
    let mut stack = stack;
    while let Some(item) = stack.pop() {
        witnesses.push(item.witness);
    }

    let mut report = mutate::MutationReport::default();
    let mut explanations = Vec::new();
    let mut unpaired = 0usize;
    for (circuit_index, circuit) in program.program.functions.iter().enumerate() {
        // Схема сопоставляется со свидетелем ПРОВЕРКОЙ, а не по порядку.
        //
        // Прежний код брал `functions.iter().zip(&witnesses)`. Порядок схем —
        // это порядок ОБЪЯВЛЕНИЯ, а порядок в стеке свидетелей — порядок
        // ВЫЗОВА, и совпадают они не всегда. На программе
        // `fold_out_of_order_calls` из набора Noir (две функции с `#[fold]`,
        // вызванные в обратном порядке) подсхеме доставался чужой свидетель,
        // и поиск сообщал о находке там, где схема тривиально корректна:
        // сигнал был закреплён `ASSERT w2 = w0 + w1`, но проверялся против
        // значений другой подсхемы.
        //
        // Показательно, что этот тест написан Noir против такой же ошибки
        // сопоставления в их собственном компиляторе — и поймал её у нас.
        let honest = match pick_matching_witness(circuit, &witnesses) {
            Some(values) => values,
            None => {
                unpaired += 1;
                continue;
            }
        };
        let _ = circuit_index;
        let found = mutate::search(circuit, &honest, args.attempts);
        if args.explain {
            // Explained against the circuit that produced the finding, so the
            // opcode indices are the ones a reader would see in that circuit.
            explanations.extend(found.findings.iter().map(|finding| {
                // Which witnesses actually moved is read off the finding, by
                // comparing its assignment against the honest one.
                let moved = finding
                    .assignment
                    .as_ref()
                    .map(|assignment| {
                        assignment
                            .iter()
                            .filter(|(index, value)| {
                                honest.get(*index).map(|known| known.to_string().as_str() != value.as_str()).unwrap_or(true)
                            })
                            .map(|(index, _)| *index)
                            .collect::<std::collections::BTreeSet<_>>()
                    })
                    .unwrap_or_default();
                explain::explain(circuit, finding.witness, &moved)
            }));
        }
        report.merge(found);
    }

    if let Some(path) = &args.emit_witness {
        match report
            .findings
            .first()
            .and_then(|finding| finding.assignment.as_ref())
        {
            Some(assignment) => std::fs::write(path, serde_json::to_string(assignment)?)?,
            None => eprintln!("warning: no finding to write to {}", path.display()),
        }
    }
    match args.format {
        CliOutputFormat::Json => {
            serde_json::to_writer_pretty(std::io::stdout(), &report)?;
            println!();
        }
        CliOutputFormat::Human => {
            println!(
                "mutation search: {} attempt(s), {} finding(s)",
                report.attempted,
                report.findings.len()
            );
            for finding in &report.findings {
                println!(
                    "  w{} {} -> {} ({} witness(es) repaired) changes returns: {}",
                    finding.witness,
                    finding.original,
                    finding.alternative,
                    finding.repaired,
                    finding
                        .diverging_returns
                        .iter()
                        .map(|(witness, value)| format!("w{witness}={value}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for explanation in &explanations {
                println!("\n  {}", explanation.headline());
                for touch in &explanation.touches {
                    let together = if touch.moved_with.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "   [moved with {}]",
                            touch
                                .moved_with
                                .iter()
                                .map(|index| format!("w{index}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    };
                    println!(
                        "    opcode {:>4}  {}{}",
                        touch.index, touch.description, together
                    );
                }
            }
        }
    }
    if report.findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

/// Run refinement for one circuit, streaming each proven wire. The
/// `refine-circuit` subcommand.
fn refine_one_circuit(args: RefineCircuitArgs) -> Result<()> {
    use std::io::Write;

    let loaded = artifact::load_programs(&args.scan.artifact)?;
    let program = loaded
        .programs
        .get(args.program_index)
        .ok_or_else(|| eyre!("program index {} is out of range", args.program_index))?;
    let circuit = program
        .program
        .functions
        .get(args.circuit_index)
        .ok_or_else(|| eyre!("circuit index {} is out of range", args.circuit_index))?;

    let mut model = translate::build_model(
        circuit,
        ModelOptions {
            fixed_mode: args.scan.fixed.into(),
            max_range_bits: args.scan.max_range_bits,
        },
    );
    let options = SolverOptions {
        timeout_ms: args.scan.refine_timeout,
        dump_smt_dir: None,
        solver: args.scan.solver.into(),
        theory: args.scan.theory.into(),
        certify: false,
    };
    let radii = (1..=args.scan.refine_radius).collect::<Vec<_>>();
    // Each result is flushed as it is found, so a parent that kills this
    // process on a deadline still keeps every wire proved before the cut.
    refine::refine(
        &mut model,
        &options,
        &radii,
        args.scan.refine_timeout,
        args.scan.refine_budget,
        &mut |wire| {
            let mut stdout = std::io::stdout();
            let _ = writeln!(stdout, "{wire}");
            let _ = stdout.flush();
        },
    );
    Ok(())
}

/// Run the refinement pass for one circuit in a child process, killed on a
/// hard wall clock. Returns the wires it managed to prove unique.
fn refine_out_of_process(
    args: &ScanArgs,
    program_index: usize,
    circuit_index: usize,
) -> Vec<usize> {
    use std::process::{Command, Stdio};

    let Ok(output_file) = tempfile() else {
        return Vec::new();
    };
    let Ok(handle) = output_file.try_clone() else {
        return Vec::new();
    };
    let Ok(executable) = std::env::current_exe() else {
        return Vec::new();
    };
    let Ok(mut child) = Command::new(executable)
        .arg("refine-circuit")
        .arg(&args.artifact)
        .args(["--program-index", &program_index.to_string()])
        .args(["--circuit-index", &circuit_index.to_string()])
        .args(["--fixed", args.fixed.as_str()])
        .args(["--targets", args.targets.as_str()])
        .args(["--solver", args.solver.as_str()])
        .args(["--theory", args.theory.as_str()])
        .args(["--max-range-bits", &args.max_range_bits.to_string()])
        .args(["--refine-timeout", &args.refine_timeout.to_string()])
        .args(["--refine-radius", &args.refine_radius.to_string()])
        .args(["--refine-budget", &args.refine_budget.to_string()])
        .stdout(Stdio::from(handle))
        .stderr(Stdio::null())
        .spawn()
    else {
        return Vec::new();
    };

    // A little slack over the child's own budget: cvc5 can overrun the time
    // limit it was given, and this is the brake that actually holds.
    let grace = std::time::Duration::from_millis(args.refine_budget / 2 + 2000);
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(args.refine_budget) + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => break,
        }
    }

    read_wire_list(output_file)
}

fn tempfile() -> std::io::Result<std::fs::File> {
    let path = std::env::temp_dir().join(format!(
        "noir-picus-refine-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    ));
    let file = std::fs::File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    // Unlink immediately: the handle keeps it alive, and nothing is left behind
    // however the process exits.
    let _ = std::fs::remove_file(&path);
    Ok(file)
}

fn read_wire_list(mut file: std::fs::File) -> Vec<usize> {
    use std::io::{Read, Seek};

    let mut contents = String::new();
    if file.rewind().is_err() || file.read_to_string(&mut contents).is_err() {
        return Vec::new();
    }
    contents
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// Solve one target, in this process. The `scan-target` subcommand.
fn scan_one_target(args: ScanTargetArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.scan.artifact)?;
    let program = loaded
        .programs
        .get(args.program_index)
        .ok_or_else(|| eyre!("program index {} is out of range", args.program_index))?;
    let circuit = program
        .program
        .functions
        .get(args.circuit_index)
        .ok_or_else(|| eyre!("circuit index {} is out of range", args.circuit_index))?;

    let target = targets::discover_targets(&program.program, circuit, args.scan.targets.into())
        .into_iter()
        .find(|target| target.witness.witness_index() == args.witness)
        .ok_or_else(|| eyre!("witness {} is not a target of this circuit", args.witness))?;

    let model = translate::build_model(
        circuit,
        ModelOptions {
            fixed_mode: args.scan.fixed.into(),
            max_range_bits: args.scan.max_range_bits,
        },
    );
    let options = SolverOptions {
        timeout_ms: args.scan.timeout,
        dump_smt_dir: args.scan.dump_smt.clone(),
        solver: args.scan.solver.into(),
        theory: args.scan.theory.into(),
        certify: !args.scan.no_certify,
    };
    let label = format!("{}_{}", program.name, args.witness);
    let report = solver::solve_target(&model, circuit, &target, &options, &label)?;
    serde_json::to_writer(std::io::stdout(), &report)?;
    Ok(())
}

/// Solve one target in a child process, killed if it overruns `budget_ms`.
///
/// Returns `None` when the child could not be launched at all, so the caller
/// can fall back to solving in-process.
fn solve_target_out_of_process(
    args: &ScanArgs,
    program_index: usize,
    circuit_index: usize,
    target: &Target,
    budget_ms: u64,
) -> Option<Result<TargetReport>> {
    use std::process::{Command, Stdio};

    let witness = target.witness.witness_index();
    let mut child = Command::new(std::env::current_exe().ok()?)
        .arg("scan-target")
        .arg(&args.artifact)
        .args(["--program-index", &program_index.to_string()])
        .args(["--circuit-index", &circuit_index.to_string()])
        .args(["--witness", &witness.to_string()])
        .args(["--fixed", args.fixed.as_str()])
        .args(["--targets", args.targets.as_str()])
        .args(["--solver", args.solver.as_str()])
        .args(["--theory", args.theory.as_str()])
        .args(["--timeout", &args.timeout.to_string()])
        .args(["--max-range-bits", &args.max_range_bits.to_string()])
        .args(args.no_certify.then_some("--no-certify"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(Ok(TargetReport::timed_out(target.clone(), budget_ms)));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => return Some(Err(error.into())),
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => return Some(Err(error.into())),
    };
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Some(Ok(TargetReport::failed(
            target.clone(),
            if message.is_empty() {
                "target subprocess failed".to_owned()
            } else {
                message
            },
        )));
    }
    Some(serde_json::from_slice(&output.stdout).map_err(Into::into))
}

struct TargetAnnotations {
    abi_name: Option<String>,
    source_locations: Vec<TargetSourceLocation>,
}

/// Best-effort source-level context for a target: its ABI name (return slot or
/// parameter path) and the source positions where the witness is produced
/// (Brillig call sites) and constrained (opcodes referencing it). All of it
/// degrades to nothing on sanitized artifacts.
fn annotate_target(
    target: &Target,
    circuit: &Circuit<FieldElement>,
    circuit_index: usize,
    abi_naming: Option<&AbiNaming>,
    debug: Option<&ProgramDebugData>,
) -> TargetAnnotations {
    const MAX_CONSTRAINT_SITES: usize = 4;

    let abi_name = abi_naming.and_then(|naming| {
        target
            .origins
            .iter()
            .find_map(|origin| match origin {
                TargetOrigin::ReturnValue { return_index } => {
                    naming.return_name(*return_index).map(str::to_owned)
                }
                _ => None,
            })
            .or_else(|| {
                naming
                    .parameter_name(target.witness.witness_index())
                    .map(str::to_owned)
            })
    });

    let mut source_locations = Vec::new();
    let Some(debug) = debug else {
        return TargetAnnotations {
            abi_name,
            source_locations,
        };
    };

    let mut seen = HashSet::new();
    for origin in &target.origins {
        let (opcode_index, role) = match origin {
            TargetOrigin::BrilligSimpleOutput {
                opcode_index,
                function_name,
                ..
            }
            | TargetOrigin::BrilligArrayOutput {
                opcode_index,
                function_name,
                ..
            } => (
                *opcode_index,
                match function_name {
                    Some(name) => format!("unconstrained hint `{name}` called at"),
                    None => "unconstrained hint called at".to_owned(),
                },
            ),
            TargetOrigin::ReturnValue { .. } => continue,
        };
        if let Some(location) = debug.opcode_location(circuit_index, opcode_index)
            && seen.insert((location.file.clone(), location.line, location.column))
        {
            source_locations.push(TargetSourceLocation { role, location });
        }
    }

    // Opcodes that mention the target witness show where (or whether!) it is
    // constrained. Brillig calls are skipped: they never constrain anything.
    let wire = translate::picus_wire(target.witness);
    let mut constraint_sites = 0;
    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        if matches!(opcode, Opcode::BrilligCall { .. }) {
            continue;
        }
        if !translate::opcode_wires(opcode).contains(&wire) {
            continue;
        }
        if let Some(location) = debug.opcode_location(circuit_index, opcode_index)
            && seen.insert((location.file.clone(), location.line, location.column))
        {
            source_locations.push(TargetSourceLocation {
                role: "constrained at".to_owned(),
                location,
            });
            constraint_sites += 1;
            if constraint_sites == MAX_CONSTRAINT_SITES {
                break;
            }
        }
    }

    TargetAnnotations {
        abi_name,
        source_locations,
    }
}

/// Witnesses propagation left open, capped so a large circuit cannot flood the
/// report.
fn undetermined_witnesses(model: &translate::AcirPicusModel) -> Vec<u32> {
    const MAX_LISTED: usize = 64;

    (1..model.witness_wire_limit)
        .filter(|wire| !model.fixed_known_signals.contains(wire))
        .map(|wire| (wire - 1) as u32)
        .take(MAX_LISTED)
        .collect()
}

fn fixed_witness_indices(model: &translate::AcirPicusModel) -> Vec<u32> {
    let mut witnesses = model
        .input_indices
        .iter()
        .filter_map(|wire| wire.checked_sub(1).map(|witness| witness as u32))
        .collect::<Vec<_>>();
    witnesses.sort_unstable();
    witnesses
}

impl From<CliFixedMode> for FixedMode {
    fn from(value: CliFixedMode) -> Self {
        match value {
            CliFixedMode::Public => FixedMode::Public,
            CliFixedMode::AllParams => FixedMode::AllParams,
        }
    }
}

impl CliFixedMode {
    fn as_str(self) -> &'static str {
        match self {
            CliFixedMode::Public => "public",
            CliFixedMode::AllParams => "all-params",
        }
    }
}

impl From<CliTargetMode> for TargetMode {
    fn from(value: CliTargetMode) -> Self {
        match value {
            CliTargetMode::Returns => TargetMode::Returns,
            CliTargetMode::BrilligOutputs => TargetMode::BrilligOutputs,
            CliTargetMode::All => TargetMode::All,
        }
    }
}

impl CliTargetMode {
    fn as_str(self) -> &'static str {
        match self {
            CliTargetMode::Returns => "returns",
            CliTargetMode::BrilligOutputs => "brillig-outputs",
            CliTargetMode::All => "all",
        }
    }
}

impl From<CliSolverKind> for SolverKind {
    fn from(value: CliSolverKind) -> Self {
        match value {
            CliSolverKind::Cvc5 => SolverKind::Cvc5,
            CliSolverKind::Z3 => SolverKind::Z3,
        }
    }
}

impl CliSolverKind {
    fn as_str(self) -> &'static str {
        match self {
            CliSolverKind::Cvc5 => "cvc5",
            CliSolverKind::Z3 => "z3",
        }
    }
}

impl From<CliTheory> for Theory {
    fn from(value: CliTheory) -> Self {
        match value {
            CliTheory::Ff => Theory::Ff,
            CliTheory::Nia => Theory::Nia,
        }
    }
}

impl CliTheory {
    fn as_str(self) -> &'static str {
        match self {
            CliTheory::Ff => "ff",
            CliTheory::Nia => "nia",
        }
    }
}

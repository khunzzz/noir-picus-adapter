#![forbid(unsafe_code)]

mod artifact;
mod debug_info;
mod report;
mod solver;
mod targets;
mod translate;

use std::collections::HashSet;
use std::path::PathBuf;

use acir::{FieldElement, circuit::Circuit, circuit::Opcode};
use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Result, eyre};
use debug_info::{AbiNaming, ProgramDebugData};
use picus_smt::{SolverKind, Theory};
use report::{
    CircuitReport, OutputFormat, ProgramReport, ScanReport, TargetReport, TargetSourceLocation,
};
use solver::SolverOptions;
use targets::{Target, TargetMode, TargetOrigin};
use translate::FixedMode;

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
    }
}

fn scan(args: ScanArgs) -> Result<()> {
    if let Some(dump_smt) = &args.dump_smt {
        std::fs::create_dir_all(dump_smt)?;
    }

    let loaded_programs = artifact::load_programs(&args.artifact)?;
    let solver_name = args.solver.as_str().to_owned();
    let theory_name = args.theory.as_str().to_owned();
    let solver_options = SolverOptions {
        timeout_ms: args.timeout,
        dump_smt_dir: args.dump_smt,
        solver: args.solver.into(),
        theory: args.theory.into(),
    };
    picus_smt::validate_combination(solver_options.solver, solver_options.theory)
        .map_err(|message| eyre!("invalid Picus solver/theory combination: {message}"))?;
    let fixed_mode = args.fixed.into();
    let target_mode = args.targets.into();

    let mut program_reports = Vec::new();
    for loaded in loaded_programs {
        let mut circuit_reports = Vec::new();

        for (circuit_index, circuit) in loaded.program.functions.iter().enumerate() {
            let discovered_targets =
                targets::discover_targets(&loaded.program, circuit, target_mode);
            let model = translate::build_model(circuit, fixed_mode);
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
                let target_unsupported_reasons = model.unsupported_reasons_for_target(witness);
                let mut target_report = if target_unsupported_reasons.is_empty() {
                    let label = format!("{}_{}_{}", loaded.name, circuit_name, witness);
                    solver::solve_target(&model, &target, &solver_options, &label)?
                } else {
                    TargetReport::unsupported(target, target_unsupported_reasons.join("; "))
                };
                target_report.abstraction_notes = model.abstraction_reasons_for_target(witness);
                target_report.abi_name = annotations.abi_name;
                target_report.source_locations = annotations.source_locations;
                target_reports.push(target_report);
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
                n_wires: model.n_wires,
                orig_constraint_count: model.orig_constraints.len(),
                alt_constraint_count: model.alt_constraints.len(),
                unsupported_reasons: model.unsupported_reasons,
                abstracted_reasons: model.abstracted_reasons,
                targets: target_reports,
            });
        }

        program_reports.push(ProgramReport {
            name: loaded.name,
            circuits: circuit_reports,
        });
    }

    let report = ScanReport {
        artifact: args.artifact.display().to_string(),
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

    Ok(())
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

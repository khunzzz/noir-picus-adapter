#![forbid(unsafe_code)]

mod artifact;
mod report;
mod solver;
mod targets;
mod translate;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Result, eyre};
use picus_smt::{SolverKind, Theory};
use report::{CircuitReport, OutputFormat, ProgramReport, ScanReport, TargetReport};
use solver::SolverOptions;
use targets::TargetMode;
use translate::FixedMode;

#[derive(Debug, Parser)]
#[command(name = "noir-picus-acir")]
#[command(about = "Picus-backed ACIR underconstraint scanner for Noir artifacts")]
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

            let mut target_reports = Vec::new();
            for target in discovered_targets {
                let target_unsupported_reasons =
                    model.unsupported_reasons_for_target(target.witness);
                let target_report = if target_unsupported_reasons.is_empty() {
                    let label = format!("{}_{}_{}", loaded.name, circuit_name, target.witness);
                    solver::solve_target(&model, &target, &solver_options, &label)?
                } else {
                    TargetReport::unsupported(target, target_unsupported_reasons.join("; "))
                };
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

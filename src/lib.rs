#![forbid(unsafe_code)]

//! `noir-picus-adapter`: under-constrained witness detection for Noir ACIR.
//!
//! - `translate` + `solver` + `refine`: the static path. ACIR is translated to
//!   Picus IR and a self-composition query decides whether a target can take
//!   two values (see `docs/SOUNDNESS.md`).
//! - `dynamic`: the concrete path — execution, mutation, fuzzing, certificates.
//! - `commands`: one module per subcommand; `cli`: argument parsing.

mod artifact;
mod cli;
mod commands;
mod debug_info;
mod dynamic;
mod field;
mod refine;
mod report;
mod solver;
mod targets;
mod translate;

use clap::Parser;
use color_eyre::eyre::Result;

use cli::{Cli, Command};

pub fn run() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => commands::scan::scan(args),
        Command::ScanTarget(args) => commands::scan::scan_one_target(args),
        Command::RefineCircuit(args) => commands::scan::refine_one_circuit(args),
        Command::Mutate(args) => commands::mutate::mutate(args),
        Command::Fuzz(args) => commands::fuzz::fuzz(args),
        Command::Unpinned(args) => commands::unpinned::unpinned(args),
        Command::Feasible(args) => commands::witness::feasible(args),
        Command::WitnessInputs(args) => commands::witness::witness_inputs(args),
        Command::CheckWitness(args) => commands::witness::check_witness(args),
    }
}

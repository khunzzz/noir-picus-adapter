//! Command-line surface: clap argument types and their conversions to the
//! internal option enums.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use picus_smt::{SolverKind, Theory};

use crate::targets::TargetMode;
use crate::translate::FixedMode;

#[derive(Debug, Parser)]
#[command(name = "noir-picus-adapter")]
#[command(about = "Picus adapter for scanning Noir ACIR artifacts")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Prove targets uniquely determined, or find two witnesses that differ
    /// (SMT self-composition after propagation and local refinement).
    Scan(ScanArgs),
    /// Search for a second accepting witness by mutating hint outputs.
    Mutate(MutateArgs),

    /// Generate inputs, execute in-process, and search the hints of every
    /// honest run for a second accepting witness with a different output.
    ///
    /// Needs no witness file: inputs are generated (biased toward the circuit's
    /// own constants and repeated windows) and parameters pinned by a linear
    /// check, such as a public commitment, are solved for. Every finding is
    /// certified against the ACIR opcodes, black boxes included.
    Fuzz(FuzzArgs),

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
pub(crate) struct WitnessInputsArgs {
    pub(crate) artifact: PathBuf,

    #[arg(long)]
    pub(crate) witness: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct UnpinnedArgs {
    /// The compiled artifact.
    pub(crate) artifact: PathBuf,

    /// Fix only the public parameters, leaving private ones free.
    ///
    /// The default fixes every parameter, because that is the soundness
    /// question: a prover commits to all of its inputs and then looks for a
    /// second witness agreeing with them. Fixing only the public ones asks a
    /// different and weaker question, and on Noir's own corpus it reported two
    /// programs whose hints are in fact pinned once the private inputs are
    /// held.
    #[arg(long)]
    pub(crate) public_inputs_only: bool,

    /// Keep single-bit witnesses that look like digits of a decomposition.
    ///
    /// They are skipped by default because a decomposition pins its digits
    /// jointly rather than one assertion at a time, so every digit of a
    /// `to_le_bits` looks free to a per-witness rule.
    #[arg(long)]
    pub(crate) include_bits: bool,
}

#[derive(Debug, Args)]
pub(crate) struct FeasibleArgs {
    /// The compiled artifact.
    pub(crate) artifact: PathBuf,

    /// JSON object mapping ACIR witness index to a decimal value, for every
    /// circuit parameter.
    #[arg(long)]
    pub(crate) inputs: String,

    #[arg(long, default_value_t = 20000)]
    pub(crate) timeout: u64,

    #[arg(long, default_value_t = 16)]
    pub(crate) max_range_bits: u32,

    /// Stop after constant propagation instead of falling through to the
    /// solver.
    ///
    /// With a full assignment pinned there is nothing to search for: every
    /// opcode either evaluates or it does not, and propagation settles that in
    /// milliseconds. The solver stage only exists for partial assignments, and
    /// on a large circuit it will not finish — so re-checking a complete
    /// witness needs a way to say "just evaluate it".
    #[arg(long)]
    pub(crate) propagate_only: bool,

    #[arg(long, value_enum, default_value = "cvc5")]
    pub(crate) solver: CliSolverKind,

    #[arg(long, value_enum, default_value = "ff")]
    pub(crate) theory: CliTheory,
}

#[derive(Debug, Args)]
pub(crate) struct FuzzArgs {
    /// The compiled artifact.
    pub(crate) artifact: PathBuf,

    /// How many generated inputs to try.
    #[arg(long, default_value_t = 300)]
    pub(crate) rounds: usize,

    /// Wall-clock budget in seconds.
    #[arg(long, default_value_t = 120)]
    pub(crate) budget_secs: u64,

    /// Seed for the input generator.
    #[arg(long, default_value_t = 1)]
    pub(crate) seed: u64,

    /// Optional JSON object mapping parameter witness index to a decimal
    /// value. Round 0 runs it as given and later rounds mutate it, which is
    /// how a structured input (a well-formed eContent) reaches deep checks.
    #[arg(long)]
    pub(crate) inputs: Option<PathBuf>,

    /// Alternative values per hint beyond the position-derived ones.
    #[arg(long, default_value_t = 7)]
    pub(crate) attempts: usize,

    /// Keep fuzzing after the first finding.
    #[arg(long)]
    pub(crate) all: bool,

    /// How many linearly pinned parameters to solve for per run.
    #[arg(long, default_value_t = 64)]
    pub(crate) max_input_repairs: usize,

    #[arg(long, value_enum, default_value_t = CliOutputFormat::Human)]
    pub(crate) format: CliOutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct MutateArgs {
    /// The compiled artifact.
    pub(crate) artifact: PathBuf,

    /// Witness file produced by `nargo execute` (the `.gz` next to the
    /// artifact). Supplies the honest assignment the search starts from.
    #[arg(long)]
    pub(crate) witness: PathBuf,

    /// How many alternative values to try per hint witness.
    #[arg(long, default_value_t = 3)]
    pub(crate) attempts: usize,

    /// Write the full witness assignment of the first finding to this path, as
    /// a witness-index -> value JSON map.
    ///
    /// A finding is only as good as the evaluator that accepted it, so the
    /// assignment has to be checkable by something else. Feeding this to
    /// `feasible` re-checks it through constant propagation instead of the
    /// certificate's opcode walk — a different code path reaching the same
    /// question.
    #[arg(long)]
    pub(crate) emit_witness: Option<PathBuf>,

    /// For each finding, list every opcode that mentions the moved witness.
    ///
    /// Isolating why a constraint system let a witness move meant dumping the
    /// ACIR and grepping for the index by hand. That is mechanical, and doing
    /// it here also states the one thing the list proves on its own: a witness
    /// whose only opcodes are its definition and a range check cannot be
    /// pinned by anything.
    #[arg(long)]
    pub(crate) explain: bool,

    #[arg(long, value_enum, default_value = "human")]
    pub(crate) format: CliOutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct RefineCircuitArgs {
    #[command(flatten)]
    pub(crate) scan: ScanArgs,

    #[arg(long)]
    pub(crate) program_index: usize,

    #[arg(long)]
    pub(crate) circuit_index: usize,
}

#[derive(Debug, Args)]
pub(crate) struct ScanTargetArgs {
    #[command(flatten)]
    pub(crate) scan: ScanArgs,

    /// Index into the artifact's programs.
    #[arg(long)]
    pub(crate) program_index: usize,

    /// Index into the program's circuits.
    #[arg(long)]
    pub(crate) circuit_index: usize,

    /// ACIR witness index of the target.
    #[arg(long)]
    pub(crate) witness: u32,
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    pub(crate) artifact: PathBuf,

    #[arg(long, value_enum, default_value = "human")]
    pub(crate) format: CliOutputFormat,

    #[arg(short, long)]
    pub(crate) verbose: bool,

    #[arg(long)]
    pub(crate) dump_smt: Option<PathBuf>,

    #[arg(long, default_value_t = 5000)]
    pub(crate) timeout: u64,

    #[arg(long, value_enum, default_value = "all-params")]
    pub(crate) fixed: CliFixedMode,

    #[arg(long, value_enum, default_value = "all")]
    pub(crate) targets: CliTargetMode,

    #[arg(long, value_enum, default_value = "cvc5")]
    pub(crate) solver: CliSolverKind,

    #[arg(long, value_enum, default_value = "ff")]
    pub(crate) theory: CliTheory,

    /// Exit with status 1 when any target is `unsafe`, 2 when any target
    /// errored. Off by default so existing scripts keep working.
    #[arg(long)]
    pub(crate) exit_code_on_finding: bool,

    /// Skip the uniqueness-refinement pass (small local SMT queries that grow
    /// the determined set before any target is solved). On by default: it is
    /// what keeps the per-target queries small on real circuits.
    #[arg(long)]
    pub(crate) no_refine: bool,

    /// Per-query budget for the refinement pass, in milliseconds. Deliberately
    /// short — a local window that does not settle quickly is not worth
    /// waiting for, since failing to prove uniqueness costs nothing but a
    /// larger query later.
    #[arg(long, default_value_t = 300)]
    pub(crate) refine_timeout: u64,

    /// Total wall-clock budget for the refinement pass, in milliseconds.
    #[arg(long, default_value_t = 15000)]
    pub(crate) refine_budget: u64,

    /// Largest neighbourhood radius the refinement pass will try.
    #[arg(long, default_value_t = 2)]
    pub(crate) refine_radius: usize,

    /// Hard wall-clock budget per target, in milliseconds. When set, each
    /// target is solved in a child process and killed if it overruns, and the
    /// target is reported `unknown`.
    ///
    /// cvc5's own `tlimit` is checked between search steps and a finite-field
    /// Groebner basis computation can run far past it, so an in-process
    /// timeout cannot be relied on for batch runs.
    #[arg(long)]
    pub(crate) target_timeout: Option<u64>,

    /// Skip the ACIR re-check of reported divergences. On by default: a
    /// finding that survives it cannot be an artefact of a translation bug.
    #[arg(long)]
    pub(crate) no_certify: bool,

    /// Translate and propagate, but never call the solver. Every target that
    /// propagation cannot settle is reported `unknown`. Useful for measuring
    /// how much work the propagation layer removes, and for triaging a circuit
    /// that makes the solver blow up.
    #[arg(long)]
    pub(crate) no_solve: bool,

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
    pub(crate) max_range_bits: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliOutputFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliFixedMode {
    Public,
    AllParams,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliTargetMode {
    Returns,
    BrilligOutputs,
    All,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliSolverKind {
    Cvc5,
    Z3,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliTheory {
    Ff,
    Nia,
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
    pub(crate) fn as_str(self) -> &'static str {
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
    pub(crate) fn as_str(self) -> &'static str {
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
    pub(crate) fn as_str(self) -> &'static str {
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CliTheory::Ff => "ff",
            CliTheory::Nia => "nia",
        }
    }
}

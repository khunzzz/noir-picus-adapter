use std::collections::BTreeMap;

use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};

use crate::certify::Certificate;
use crate::debug_info::SourceLocation;
use crate::targets::{Target, TargetOrigin};

/// Bumped whenever the JSON shape changes incompatibly, so downstream
/// tooling can refuse a report it does not understand.
pub(crate) const REPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Serialize)]
pub(crate) struct ScanReport {
    pub(crate) schema_version: u32,
    pub(crate) tool_version: &'static str,
    pub(crate) artifact: String,
    /// `noir_version` recorded in the artifact, when it carries one. The single
    /// most useful provenance field for reproducing a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) noir_version: Option<String>,
    pub(crate) summary: ScanSummary,
    pub(crate) solver: String,
    pub(crate) theory: String,
    pub(crate) timeout_ms: u64,
    pub(crate) fixed_mode: String,
    pub(crate) target_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dump_smt_dir: Option<String>,
    pub(crate) programs: Vec<ProgramReport>,
}

/// Target counts across the whole scan. Without this every consumer has to
/// re-walk the report, and the corpus runners had to shell out to `jq`.
#[derive(Debug, Default, Serialize)]
pub(crate) struct ScanSummary {
    pub(crate) targets: usize,
    pub(crate) verified: usize,
    #[serde(rename = "unsafe")]
    pub(crate) unsafe_: usize,
    pub(crate) unknown: usize,
    pub(crate) unsupported: usize,
    pub(crate) error: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProgramReport {
    pub(crate) name: String,
    pub(crate) circuits: Vec<CircuitReport>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CircuitReport {
    pub(crate) name: String,
    pub(crate) index: usize,
    pub(crate) private_parameters: Vec<u32>,
    pub(crate) public_parameters: Vec<u32>,
    pub(crate) return_values: Vec<u32>,
    pub(crate) fixed_witnesses: Vec<u32>,
    /// ACIR witnesses in this circuit. `n_wires` also counts the bit,
    /// selector and memory wires this crate invents, which can outnumber the
    /// witnesses by an order of magnitude, so coverage ratios belong against
    /// this number.
    pub(crate) witness_wires: usize,
    /// Wires the refinement pass proved unique with a small local query, and
    /// how many queries that took.
    pub(crate) refined_wires: usize,
    pub(crate) refinement_queries: usize,
    /// How many wires uniqueness propagation settled without a solver call.
    /// The ratio against `n_wires` is the headline number for the propagation
    /// layer: everything it settles never reaches the SMT.
    pub(crate) determined_wires: usize,
    pub(crate) constant_wires: usize,
    /// Witnesses propagation could not settle. These are what the solver has
    /// to reason about, so this list is where to look when a scan is slow.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) undetermined_witnesses: Vec<u32>,
    pub(crate) n_wires: usize,
    pub(crate) orig_constraint_count: usize,
    pub(crate) alt_constraint_count: usize,
    pub(crate) unsupported_reasons: Vec<String>,
    pub(crate) abstracted_reasons: Vec<String>,
    pub(crate) targets: Vec<TargetReport>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TargetReport {
    pub(crate) witness: String,
    pub(crate) witness_index: u32,
    pub(crate) target_signal: usize,
    pub(crate) original_var: String,
    pub(crate) alternative_var: String,
    pub(crate) origins: Vec<TargetOrigin>,
    pub(crate) status: TargetStatus,
    /// Which stage produced the verdict. `verified` from the solver and
    /// `verified` from a propagation short-circuit are very different claims,
    /// and benchmarks must not mix them.
    pub(crate) decided_by: DecidedBy,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Number of constraints sent to the per-target SMT query after slicing.
    // Compare with CircuitReport::*_constraint_count to see how much was cut.
    pub(crate) query_orig_constraint_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) query_alt_constraint_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) counterexample: Option<Counterexample>,
    /// Independent re-check of the counterexample against ACIR semantics.
    /// `certified` means the finding holds even if the translation is wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) certificate: Option<Certificate>,
    // Determinism-abstraction issues in this target's cone. When non-empty the
    // verdict was computed under the abstraction: `verified` is sound, `unsafe`
    // may be spurious. Empty for fully-translated targets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) abstraction_notes: Vec<String>,
    // ABI-derived name of this witness (parameter path or return slot), when
    // the artifact carries an ABI. Best-effort display sugar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) abi_name: Option<String>,
    // Source positions tied to this target, resolved from artifact debug
    // symbols: where the witness is produced (Brillig call site) and where it
    // is constrained/used. Empty for sanitized artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) source_locations: Vec<TargetSourceLocation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TargetSourceLocation {
    /// What this location is: e.g. `brillig call`, `constrained at`.
    pub(crate) role: String,
    #[serde(flatten)]
    pub(crate) location: SourceLocation,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetStatus {
    Verified,
    Unsafe,
    Unknown,
    Unsupported,
    /// The scan of this target failed. Recorded per target so one solver
    /// failure cannot discard the verdicts of every other target.
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecidedBy {
    /// A Picus/SMT call.
    Solver,
    /// The target is itself a fixed circuit input.
    FixedInput,
    /// Linear propagation proved the target determined, no solver call.
    LinearPropagation,
    /// No verdict was computed (unsupported opcode, or an error).
    NotDecided,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WitnessPair {
    pub(crate) original: String,
    pub(crate) alternative: String,
}

/// A full description of the divergence the solver found, keyed by ACIR witness
/// index. `fixed_inputs` is the shared input assignment; feeding it to
/// `nargo execute` reproduces the honest run that `diverging_witnesses`
/// contradicts.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Counterexample {
    pub(crate) original: Option<String>,
    pub(crate) alternative: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fixed_inputs: BTreeMap<u32, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) diverging_witnesses: BTreeMap<u32, WitnessPair>,
}

#[derive(Debug)]
pub(crate) struct SolverOutcome {
    pub(crate) status: TargetStatus,
    pub(crate) decided_by: DecidedBy,
    pub(crate) query_orig_constraint_count: Option<usize>,
    pub(crate) query_alt_constraint_count: Option<usize>,
    pub(crate) reason: Option<String>,
    pub(crate) counterexample: Option<Counterexample>,
    pub(crate) certificate: Option<Certificate>,
}

pub(crate) enum OutputFormat {
    Json,
}

impl TargetReport {
    pub(crate) fn from_solver(target: Target, outcome: SolverOutcome) -> Self {
        let target_signal = target.witness.witness_index() as usize + 1;
        Self {
            witness: target.witness.to_string(),
            witness_index: target.witness.witness_index(),
            target_signal,
            original_var: format!("x{target_signal}"),
            alternative_var: format!("y{target_signal}"),
            origins: target.origins,
            status: outcome.status,
            decided_by: outcome.decided_by,
            query_orig_constraint_count: outcome.query_orig_constraint_count,
            query_alt_constraint_count: outcome.query_alt_constraint_count,
            reason: outcome.reason,
            counterexample: outcome.counterexample,
            certificate: outcome.certificate,
            abstraction_notes: Vec::new(),
            abi_name: None,
            source_locations: Vec::new(),
        }
    }

    /// A target left undecided because solving was switched off.
    pub(crate) fn not_solved(target: Target) -> Self {
        let mut report = Self::unsupported(target, "solver skipped (--no-solve)".to_owned());
        report.status = TargetStatus::Unknown;
        report
    }

    /// A hint output that no constraint reads (see
    /// `translate::unread_hint_outputs`). Free, so not `verified`; but it
    /// cannot reach any other witness, so it is not sent to the solver, which
    /// would only confirm the freedom.
    pub(crate) fn unread_hint(target: Target) -> Self {
        let mut report = Self::unsupported(
            target,
            "hint output that no constraint reads: free, but nothing depends on it".to_owned(),
        );
        report.status = TargetStatus::Unknown;
        report
    }

    /// An undetermined target that only touches determined witnesses (see
    /// `AcirPicusModel::is_isolated`): whatever it takes, nothing else moves.
    pub(crate) fn isolated_hint(target: Target) -> Self {
        let mut report = Self::unsupported(
            target,
            "free only inside its own check: every other witness that reads it is determined, so nothing depends on it".to_owned(),
        );
        report.status = TargetStatus::Unknown;
        report
    }

    /// A target abandoned because it overran its wall-clock budget.
    pub(crate) fn timed_out(target: Target, budget_ms: u64) -> Self {
        let mut report = Self::unsupported(
            target,
            format!("target exceeded its {budget_ms} ms wall-clock budget"),
        );
        report.status = TargetStatus::Unknown;
        report
    }

    /// A target whose scan failed. Keeping the failure in the report rather
    /// than aborting the run means a long batch scan still returns every
    /// verdict it did compute.
    pub(crate) fn failed(target: Target, reason: String) -> Self {
        let mut report = Self::unsupported(target, reason);
        report.status = TargetStatus::Error;
        report
    }

    pub(crate) fn unsupported(target: Target, reason: String) -> Self {
        let target_signal = target.witness.witness_index() as usize + 1;
        Self {
            witness: target.witness.to_string(),
            witness_index: target.witness.witness_index(),
            target_signal,
            original_var: format!("x{target_signal}"),
            alternative_var: format!("y{target_signal}"),
            origins: target.origins,
            status: TargetStatus::Unsupported,
            decided_by: DecidedBy::NotDecided,
            query_orig_constraint_count: None,
            query_alt_constraint_count: None,
            reason: Some(reason),
            counterexample: None,
            certificate: None,
            abstraction_notes: Vec::new(),
            abi_name: None,
            source_locations: Vec::new(),
        }
    }
}

impl ScanReport {
    pub(crate) fn print(&self, format: OutputFormat) -> Result<()> {
        match format {
            OutputFormat::Json => {
                serde_json::to_writer_pretty(std::io::stdout(), self)?;
                println!();
            }
        }
        Ok(())
    }

    /// Non-zero when the scan found something a caller should act on. Lets a
    /// CI job or a fuzzing driver branch on the process exit code instead of
    /// parsing JSON.
    pub(crate) fn exit_code(&self) -> i32 {
        if self.summary.error > 0 {
            return 2;
        }
        i32::from(self.summary.unsafe_ > 0)
    }

    pub(crate) fn print_human(&self, verbose: bool) {
        println!("noir-picus-adapter scan: {}", self.artifact);
        println!(
            "summary: {} target(s) — {} verified, {} unsafe, {} unknown, {} unsupported, {} error",
            self.summary.targets,
            self.summary.verified,
            self.summary.unsafe_,
            self.summary.unknown,
            self.summary.unsupported,
            self.summary.error
        );
        if verbose {
            println!(
                "config: solver={} theory={} timeout={}ms fixed={} targets={}",
                self.solver, self.theory, self.timeout_ms, self.fixed_mode, self.target_mode
            );
            if let Some(dump_smt_dir) = &self.dump_smt_dir {
                println!("smt dumps: {dump_smt_dir}");
            }
        }
        for program in &self.programs {
            println!();
            println!("Program: {}", program.name);
            for circuit in &program.circuits {
                println!(
                    "  Circuit #{} {}: {} target(s), {} fixed witness(es), {} unsupported issue(s), {} abstracted",
                    circuit.index,
                    circuit.name,
                    circuit.targets.len(),
                    circuit.fixed_witnesses.len(),
                    circuit.unsupported_reasons.len(),
                    circuit.abstracted_reasons.len()
                );
                if verbose {
                    println!(
                        "    witnesses: private={}, public={}, returns={}, fixed={}",
                        format_witness_list(&circuit.private_parameters),
                        format_witness_list(&circuit.public_parameters),
                        format_witness_list(&circuit.return_values),
                        format_witness_list(&circuit.fixed_witnesses)
                    );
                    println!(
                        "    picus ir: n_wires={}, orig_constraints={}, alt_constraints={}",
                        circuit.n_wires,
                        circuit.orig_constraint_count,
                        circuit.alt_constraint_count
                    );
                    println!(
                        "    propagation: {} of {} witness(es) determined, {} constant",
                        circuit.determined_wires, circuit.witness_wires, circuit.constant_wires
                    );
                    println!(
                        "    refinement: {} wire(s) proved unique in {} local query(ies)",
                        circuit.refined_wires, circuit.refinement_queries
                    );
                    if !circuit.undetermined_witnesses.is_empty() {
                        println!(
                            "    undetermined: {}",
                            format_witness_list(&circuit.undetermined_witnesses)
                        );
                    }
                    println!("    self-composition: first copy uses x*, second copy uses y*");
                    println!("    fixed witnesses stay x* in both copies");
                }

                if circuit.targets.is_empty() {
                    println!("    no Brillig outputs or return values found");
                    continue;
                }

                for target in &circuit.targets {
                    let reason = target
                        .reason
                        .as_ref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default();
                    let abi_name = target
                        .abi_name
                        .as_ref()
                        .map(|name| format!(" [{name}]"))
                        .unwrap_or_default();
                    println!(
                        "    {}{}: {}{}",
                        target.witness,
                        abi_name,
                        target.status.as_str(),
                        reason
                    );
                    for source_location in &target.source_locations {
                        println!(
                            "      {}: {}",
                            source_location.role,
                            source_location.location.display()
                        );
                    }
                    if let Some(counterexample) = &target.counterexample {
                        println!(
                            "      counterexample: original={}, alternative={}",
                            counterexample.original.as_deref().unwrap_or("<missing>"),
                            counterexample.alternative.as_deref().unwrap_or("<missing>")
                        );
                        if !counterexample.fixed_inputs.is_empty() {
                            let inputs = counterexample
                                .fixed_inputs
                                .iter()
                                .map(|(witness, value)| format!("w{witness}={value}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            println!("      shared inputs: {inputs}");
                        }
                        if let Some(certificate) = &target.certificate {
                            println!(
                                "      certificate: {:?} after re-checking {} ACIR opcode(s){}",
                                certificate.status,
                                certificate.checked_opcodes,
                                certificate
                                    .detail
                                    .as_ref()
                                    .map(|detail| format!(" — {detail}"))
                                    .unwrap_or_default()
                            );
                        }
                        if !counterexample.diverging_witnesses.is_empty() {
                            println!(
                                "      diverging witnesses ({}):",
                                counterexample.diverging_witnesses.len()
                            );
                            for (witness, pair) in counterexample.diverging_witnesses.iter().take(8)
                            {
                                println!(
                                    "        w{witness}: {} vs {}",
                                    pair.original, pair.alternative
                                );
                            }
                        }
                    }
                    if !target.abstraction_notes.is_empty() {
                        let caveat = if matches!(target.status, TargetStatus::Unsafe) {
                            " — unsafe may be spurious under abstraction (a verified result would be sound)"
                        } else {
                            ""
                        };
                        println!(
                            "      note: verdict computed under determinism abstraction{caveat}"
                        );
                        if verbose {
                            for abstraction_note in &target.abstraction_notes {
                                println!("        - {abstraction_note}");
                            }
                        }
                    }
                    if verbose {
                        println!(
                            "      query target: {} != {} (ACIR {} -> Picus signal {})",
                            target.original_var,
                            target.alternative_var,
                            target.witness,
                            target.target_signal
                        );
                        if let (Some(orig), Some(alt)) = (
                            target.query_orig_constraint_count,
                            target.query_alt_constraint_count,
                        ) {
                            println!("      query constraints: orig={orig}, alt={alt}");
                        }
                        println!("      origins:");
                        for origin in &target.origins {
                            println!("        - {}", format_origin(origin));
                        }
                    }
                }

                for reason in &circuit.unsupported_reasons {
                    println!("    unsupported: {reason}");
                }

                for reason in &circuit.abstracted_reasons {
                    println!("    abstracted: {reason}");
                }
            }
        }
    }
}

impl TargetStatus {
    fn as_str(self) -> &'static str {
        match self {
            TargetStatus::Verified => "verified",
            TargetStatus::Unsafe => "unsafe",
            TargetStatus::Unknown => "unknown",
            TargetStatus::Unsupported => "unsupported",
            TargetStatus::Error => "error",
        }
    }
}

impl ScanSummary {
    pub(crate) fn record(&mut self, status: TargetStatus) {
        self.targets += 1;
        match status {
            TargetStatus::Verified => self.verified += 1,
            TargetStatus::Unsafe => self.unsafe_ += 1,
            TargetStatus::Unknown => self.unknown += 1,
            TargetStatus::Unsupported => self.unsupported += 1,
            TargetStatus::Error => self.error += 1,
        }
    }
}

fn format_witness_list(witnesses: &[u32]) -> String {
    if witnesses.is_empty() {
        return "[]".to_owned();
    }

    let values = witnesses
        .iter()
        .map(|witness| format!("w{witness}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn format_origin(origin: &TargetOrigin) -> String {
    match origin {
        TargetOrigin::BrilligSimpleOutput {
            opcode_index,
            function_id,
            function_name,
        } => format!(
            "Brillig simple output from opcode {opcode_index}, function {}",
            format_function(*function_id, function_name)
        ),
        TargetOrigin::BrilligArrayOutput {
            opcode_index,
            function_id,
            function_name,
            array_index,
        } => format!(
            "Brillig array output #{array_index} from opcode {opcode_index}, function {}",
            format_function(*function_id, function_name)
        ),
        TargetOrigin::ReturnValue { return_index } => {
            format!("return value #{return_index}")
        }
    }
}

fn format_function(function_id: u32, function_name: &Option<String>) -> String {
    match function_name {
        Some(function_name) => format!("#{function_id} ({function_name})"),
        None => format!("#{function_id}"),
    }
}

use color_eyre::eyre::Result;
use serde::Serialize;

use crate::debug_info::SourceLocation;
use crate::targets::{Target, TargetOrigin};

#[derive(Debug, Serialize)]
pub(crate) struct ScanReport {
    pub(crate) artifact: String,
    pub(crate) solver: String,
    pub(crate) theory: String,
    pub(crate) timeout_ms: u64,
    pub(crate) fixed_mode: String,
    pub(crate) target_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dump_smt_dir: Option<String>,
    pub(crate) programs: Vec<ProgramReport>,
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
    pub(crate) n_wires: usize,
    pub(crate) orig_constraint_count: usize,
    pub(crate) alt_constraint_count: usize,
    pub(crate) unsupported_reasons: Vec<String>,
    pub(crate) abstracted_reasons: Vec<String>,
    pub(crate) targets: Vec<TargetReport>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TargetReport {
    pub(crate) witness: String,
    pub(crate) witness_index: u32,
    pub(crate) target_signal: usize,
    pub(crate) original_var: String,
    pub(crate) alternative_var: String,
    pub(crate) origins: Vec<TargetOrigin>,
    pub(crate) status: TargetStatus,
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
    // Determinism-abstraction issues in this target's cone. When non-empty the
    // verdict was computed under the abstraction: `verified` is sound, `unsafe`
    // may be spurious. Empty for fully-translated targets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) abstraction_notes: Vec<String>,
    // ABI-derived name of this witness (parameter path or return slot), when
    // the artifact carries an ABI. Best-effort display sugar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) abi_name: Option<String>,
    // Source positions tied to this target, resolved from artifact debug
    // symbols: where the witness is produced (Brillig call site) and where it
    // is constrained/used. Empty for sanitized artifacts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) source_locations: Vec<TargetSourceLocation>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TargetSourceLocation {
    /// What this location is: e.g. `brillig call`, `constrained at`.
    pub(crate) role: String,
    #[serde(flatten)]
    pub(crate) location: SourceLocation,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetStatus {
    Verified,
    Unsafe,
    Unknown,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub(crate) struct Counterexample {
    pub(crate) original: Option<String>,
    pub(crate) alternative: Option<String>,
}

#[derive(Debug)]
pub(crate) struct SolverOutcome {
    pub(crate) status: TargetStatus,
    pub(crate) query_orig_constraint_count: Option<usize>,
    pub(crate) query_alt_constraint_count: Option<usize>,
    pub(crate) reason: Option<String>,
    pub(crate) counterexample: Option<Counterexample>,
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
            query_orig_constraint_count: outcome.query_orig_constraint_count,
            query_alt_constraint_count: outcome.query_alt_constraint_count,
            reason: outcome.reason,
            counterexample: outcome.counterexample,
            abstraction_notes: Vec::new(),
            abi_name: None,
            source_locations: Vec::new(),
        }
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
            query_orig_constraint_count: None,
            query_alt_constraint_count: None,
            reason: Some(reason),
            counterexample: None,
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

    pub(crate) fn print_human(&self, verbose: bool) {
        println!("noir-picus-adapter scan: {}", self.artifact);
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

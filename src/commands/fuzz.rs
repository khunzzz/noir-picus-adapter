//! `fuzz`: generated inputs, in-process execution, hint-override search.

use color_eyre::eyre::{Context, Result, eyre};

use crate::artifact;
use crate::cli::*;
use crate::dynamic::{certify, fuzz};

/// Search for a second accepting witness by mutation and repair.
pub(crate) fn fuzz(args: FuzzArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;
    let seed_inputs = match &args.inputs {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            let map: std::collections::BTreeMap<String, serde_json::Value> =
                serde_json::from_str(&raw)?;
            let mut values = certify::WitnessValues::new();
            for (key, value) in map {
                let index: u32 = key.trim_start_matches('w').parse()?;
                let text = match value {
                    serde_json::Value::String(text) => text,
                    other => other.to_string(),
                };
                values.insert(index, crate::field::parse_decimal(&text));
            }
            Some(values)
        }
        None => None,
    };
    let report = fuzz::fuzz(
        &program.program,
        program.abi.as_ref(),
        &fuzz::FuzzOptions {
            rounds: args.rounds,
            budget: std::time::Duration::from_secs(args.budget_secs),
            seed: args.seed,
            seed_inputs,
            attempts_per_witness: args.attempts,
            stop_at_first: !args.all,
            max_input_repairs: args.max_input_repairs,
        },
    );
    match args.format {
        CliOutputFormat::Json => {
            serde_json::to_writer_pretty(std::io::stdout(), &report)?;
            println!();
        }
        CliOutputFormat::Human => {
            println!(
                "fuzz: {} round(s), {} executed ({} with input repair), {} hint(s) tried, {} attempt(s), {} finding(s), {} ms",
                report.rounds,
                report.executed,
                report.input_repairs,
                report.hints,
                report.attempts,
                report.findings.len(),
                report.elapsed_ms
            );
            if !report.links.is_empty() {
                println!(
                    "  learned input links: {}",
                    report
                        .links
                        .iter()
                        .map(|(first, len)| format!("w{first}..+{len}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let mut failures = report.failures.iter().collect::<Vec<_>>();
            failures.sort_by(|a, b| b.1.cmp(a.1));
            for (message, count) in failures.iter().take(5) {
                println!("  execution failed {count}x: {message}");
            }
            for finding in &report.findings {
                println!(
                    "  FINDING (round {}): hint w{} {} -> {} [certificate: {}, {} opcode(s) checked]",
                    finding.round,
                    finding.hint,
                    finding.hint_honest,
                    finding.hint_alternative,
                    finding.certificate,
                    finding.checked_opcodes
                );
                for (witness, (honest, alternative)) in &finding.returns {
                    println!("    return w{witness}: {honest} vs {alternative}");
                }
                let shown = finding
                    .inputs
                    .iter()
                    .take(24)
                    .map(|(witness, value)| format!("w{witness}={value}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let more = finding.inputs.len().saturating_sub(24);
                println!(
                    "    inputs: {shown}{}",
                    if more > 0 {
                        format!(" ... (+{more}, use --format json)")
                    } else {
                        String::new()
                    }
                );
            }
        }
    }
    if report.findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

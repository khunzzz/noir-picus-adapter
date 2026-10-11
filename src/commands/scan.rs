//! `scan`: the SMT uniqueness check, plus the hidden `scan-target` and
//! `refine-circuit` subcommands it re-invokes itself through for hard timeouts.

use std::collections::{BTreeSet, HashSet};

use acir::{FieldElement, circuit::Circuit, circuit::Opcode};
use color_eyre::eyre::{Result, eyre};

use crate::cli::*;
use crate::debug_info::{AbiNaming, ProgramDebugData};
use crate::report::{
    CircuitReport, OutputFormat, ProgramReport, REPORT_SCHEMA_VERSION, ScanReport, ScanSummary,
    TargetReport, TargetSourceLocation,
};
use crate::solver::SolverOptions;
use crate::targets::{Target, TargetOrigin};
use crate::translate::{self, ModelOptions};
use crate::{artifact, refine, report, solver, targets};

pub(crate) fn scan(args: ScanArgs) -> Result<()> {
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

/// Run refinement for one circuit, streaming each proven wire. The
/// `refine-circuit` subcommand.
pub(crate) fn refine_one_circuit(args: RefineCircuitArgs) -> Result<()> {
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
pub(crate) fn scan_one_target(args: ScanTargetArgs) -> Result<()> {
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

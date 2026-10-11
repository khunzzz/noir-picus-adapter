//! `mutate`: mutation search from a witness file produced by `nargo execute`.

use acir::FieldElement;
use color_eyre::eyre::{Context, Result, eyre};

use crate::artifact;
use crate::cli::*;
use crate::dynamic::{certify, explain, mutate};

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

pub(crate) fn mutate(args: MutateArgs) -> Result<()> {
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
    for circuit in &program.program.functions {
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
                                honest
                                    .get(*index)
                                    .map(|known| known.to_string().as_str() != value.as_str())
                                    .unwrap_or(true)
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
    // A circuit with no matching witness was not searched at all. Saying so
    // keeps "no findings" from reading as "nothing there".
    if unpaired > 0 {
        eprintln!(
            "warning: {unpaired} circuit(s) had no matching witness in the stack and were not searched"
        );
    }
    if report.findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

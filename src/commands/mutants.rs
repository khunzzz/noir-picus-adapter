//! `mutants`: write circuit mutants of an artifact, with a manifest.

use std::collections::BTreeMap;
use std::io::Write;

use acir::{FieldElement, circuit::Program};
use color_eyre::eyre::{Context, Result, eyre};
use serde::Serialize;

use crate::artifact;
use crate::cli::{LabelMutantArgs, MutantsArgs};
use crate::mutants::{Mutant, mutants as circuit_mutants};

/// Sanitized artifact form, the same as the committed examples.
#[derive(Serialize)]
struct SanitizedArtifact<'a> {
    noir_version: Option<&'a str>,
    #[serde(serialize_with = "Program::serialize_program_base64")]
    bytecode: Program<FieldElement>,
}

pub(crate) fn mutants(args: MutantsArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let [program] = loaded.programs.as_slice() else {
        return Err(eyre!("expected a single-program artifact"));
    };
    let stem = args
        .artifact
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| eyre!("artifact path has no file name"))?;
    std::fs::create_dir_all(&args.out)
        .wrap_err_with(|| format!("failed to create {}", args.out.display()))?;

    let mut by_class: BTreeMap<&str, Vec<Mutant>> = BTreeMap::new();
    for mutant in circuit_mutants(&program.program) {
        by_class.entry(mutant.class).or_default().push(mutant);
    }

    let manifest_path = args.out.join("mutants.tsv");
    let fresh = !manifest_path.exists();
    let mut manifest = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest_path)
        .wrap_err_with(|| format!("failed to open {}", manifest_path.display()))?;
    if fresh {
        writeln!(
            manifest,
            "mutant\tsource\toperator\tclass\topcode_index\tbefore"
        )?;
    }

    let mut written = 0usize;
    for (class, all) in by_class {
        let total = all.len();
        for mutant in spread(all, args.max_per_class) {
            let id = format!("{stem}__{}_{}", mutant.operator, mutant.opcode_index);
            let path = args.out.join(format!("{id}.json"));
            let artifact = SanitizedArtifact {
                noir_version: loaded.noir_version.as_deref(),
                bytecode: mutant.apply(&program.program),
            };
            std::fs::write(&path, serde_json::to_vec(&artifact)?)
                .wrap_err_with(|| format!("failed to write {}", path.display()))?;
            writeln!(
                manifest,
                "{id}\t{}\t{}\t{class}\t{}\t{}",
                args.artifact.display(),
                mutant.operator,
                mutant.opcode_index,
                mutant.before.replace(['\t', '\n'], " ")
            )?;
            written += 1;
        }
        eprintln!("{stem}: {class}: {total} candidate(s)");
    }
    eprintln!(
        "{stem}: wrote {written} mutant(s) to {}",
        args.out.display()
    );
    Ok(())
}

/// Label one mutant against its original and print the report as JSON.
pub(crate) fn label_mutant(args: LabelMutantArgs) -> Result<()> {
    let load = |path: &std::path::Path| -> Result<Program<FieldElement>> {
        let loaded = artifact::load_programs(path)?;
        let [program] = loaded.programs.as_slice() else {
            return Err(eyre!(
                "expected a single-program artifact: {}",
                path.display()
            ));
        };
        Ok(program.program.clone())
    };
    let original = load(&args.original)?;
    let mutant = load(&args.mutant)?;
    if args.opcode >= original.functions[0].opcodes.len() {
        return Err(eyre!("opcode {} is out of range", args.opcode));
    }
    let inputs = crate::commands::fuzz::read_inputs(&args.inputs)?;
    // ACVM assertions are caught and read as rejections; keep their panic
    // reports off stderr, where a batch run would drown in them.
    std::panic::set_hook(Box::new(|_| {}));
    let report = crate::dynamic::label::label(
        &original,
        &mutant,
        args.opcode,
        &inputs,
        &crate::dynamic::label::LabelOptions {
            budget: std::time::Duration::from_secs(args.budget_secs),
            attempts: args.attempts,
        },
    )
    .map_err(|reason| eyre!(reason))?;
    serde_json::to_writer(std::io::stdout(), &report)?;
    println!();
    Ok(())
}

/// At most `limit` items, evenly spaced, so a large circuit contributes
/// mutants from its whole length rather than its first few gadgets.
fn spread<T>(items: Vec<T>, limit: usize) -> Vec<T> {
    let total = items.len();
    if total <= limit {
        return items;
    }
    items
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index * limit / total != (index + 1) * limit / total)
        .map(|(_, item)| item)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn spread_keeps_exactly_the_limit_across_the_whole_range() {
        let kept = super::spread((0..100).collect(), 7);
        assert_eq!(kept.len(), 7);
        assert!(kept[0] < 15 && *kept.last().unwrap() > 85);
        assert_eq!(super::spread((0..5).collect::<Vec<_>>(), 7).len(), 5);
    }
}

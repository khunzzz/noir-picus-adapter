//! A driver for the SSA fuzzer that runs without libFuzzer.
//!
//! The shipped target (`acir_vs_brillig.rs`) enables exactly one mode:
//!
//! ```ignore
//! let modes = vec![FuzzerMode::NonConstant];
//! ```
//!
//! and the other four variants of `FuzzerMode` carry `#[allow(dead_code)]`,
//! so nothing runs them. Those four exist to compare a program against itself
//! compiled differently — with constant arguments (for constant folding), with
//! idempotent morphing, without dead instruction elimination, and without
//! simplification. Each is a differential aimed at one optimizer stage.
//!
//! This driver enables all five. It reuses the project's own structure-aware
//! mutator, so the programs it produces are the same shape libFuzzer would
//! explore; only the set of comparisons is wider.
//!
//! Building requires no nightly toolchain: `fuzz_target` already compares its
//! outputs and panics on disagreement, so catching the panic is the whole
//! oracle.

pub(crate) mod fuzz_lib;
mod mutations;
mod utils;

use fuzz_lib::{
    fuzz_target_lib::fuzz_target,
    fuzzer::FuzzerData,
    options::{FuzzerCommandOptions, FuzzerMode, FuzzerOptions, InstructionOptions},
};
use mutations::mutate;
use noirc_driver::CompileOptions;
use noirc_evaluator::ssa::ir::function::RuntimeType;
use noirc_frontend::monomorphization::ast::InlineType as FrontendInlineType;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const INLINE_TYPE: FrontendInlineType = FrontendInlineType::Inline;
const TARGET_RUNTIMES: [RuntimeType; 2] =
    [RuntimeType::Acir(INLINE_TYPE), RuntimeType::Brillig(INLINE_TYPE)];

fn main() {
    let _ = env_logger::try_init();
    let args: Vec<String> = std::env::args().collect();
    let seed: u64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(1);
    let rounds: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1000);
    let out = args.get(3).cloned().unwrap_or_else(|| "/tmp/ssa_driver".to_string());
    std::fs::create_dir_all(&out).expect("cannot create the output directory");

    // The one instruction the shipped target disables, kept disabled: it has a
    // known unfixed bug (noir-lang/noir#9159) and would only rediscover it.
    let instruction_options =
        InstructionOptions { unsafe_get_set_enabled: false, ..InstructionOptions::default() };

    let modes = vec![
        FuzzerMode::NonConstant,
        FuzzerMode::Constant,
        FuzzerMode::NonConstantWithIdempotentMorphing,
        FuzzerMode::NonConstantWithoutDIE,
        FuzzerMode::NonConstantWithoutSimplifying,
    ];

    let options = FuzzerOptions {
        compile_options: CompileOptions::default(),
        instruction_options,
        modes,
        fuzzer_command_options: FuzzerCommandOptions {
            loops_enabled: true,
            ..FuzzerCommandOptions::default()
        },
        ..FuzzerOptions::default()
    };

    // Replay mode: `driver replay <file.json> <mode>` runs one saved program in
    // a single mode with the SSA printed. Needed because a disagreement is only
    // evidence once you can see what each mode actually compiled.
    if args.get(1).map(String::as_str) == Some("replay") {
        let path = args.get(2).expect("replay needs a path to a saved program");
        let wanted = args.get(3).cloned().unwrap_or_else(|| "NonConstant".to_string());
        let encoded = std::fs::read(path).expect("cannot read the saved program");
        let replayed: FuzzerData =
            serde_json::from_slice(&encoded).expect("the saved program is not valid JSON");
        let mode = match wanted.as_str() {
            "Constant" => FuzzerMode::Constant,
            "WithoutDIE" => FuzzerMode::NonConstantWithoutDIE,
            "WithoutSimplifying" => FuzzerMode::NonConstantWithoutSimplifying,
            "IdempotentMorphing" => FuzzerMode::NonConstantWithIdempotentMorphing,
            _ => FuzzerMode::NonConstant,
        };
        let single = FuzzerOptions {
            compile_options: CompileOptions { show_ssa: true, ..CompileOptions::default() },
            instruction_options,
            modes: vec![mode],
            fuzzer_command_options: FuzzerCommandOptions {
                loops_enabled: true,
                ..FuzzerCommandOptions::default()
            },
            ..FuzzerOptions::default()
        };
        let output = fuzz_target(replayed, TARGET_RUNTIMES.to_vec(), single);
        println!("return witnesses: {:?}", output.get_return_witnesses());
        return;
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut data = FuzzerData::default();
    let (mut ran, mut found) = (0usize, 0usize);

    for round in 0..rounds {
        mutate(&mut data, &mut rng);
        let attempt = data.clone();
        let options = options.clone();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            fuzz_target(attempt, TARGET_RUNTIMES.to_vec(), options)
        }));
        ran += 1;
        if outcome.is_err() {
            found += 1;
            let path = format!("{out}/disagreement_{seed}_{round}.json");
            if let Ok(encoded) = serde_json::to_string_pretty(&data) {
                let _ = std::fs::write(&path, encoded);
            }
            println!("DISAGREEMENT at round {round}, saved to {path}");
            // Start the next round from a fresh program: continuing to mutate a
            // program that already disagrees would just report it again.
            data = FuzzerData::default();
        }
        if ran % 50 == 0 {
            println!("{ran} programs, {found} disagreement(s)");
        }
    }
    println!("done: {ran} programs, {found} disagreement(s)");
}

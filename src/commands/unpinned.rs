//! `unpinned`: hint outputs nothing in the circuit appears able to pin.

use color_eyre::eyre::{Result, eyre};

use crate::artifact;
use crate::cli::*;
use crate::dynamic::explain;
use crate::translate::{self};

/// Report hint outputs that no constraint appears able to pin.
///
/// This is a triage pass, and it is careful about what it claims. Propagation
/// gives the witnesses that provably *are* determined by the inputs; the rest
/// are merely not known to be. A hint output among those, where every
/// assertion touching it also touches another undetermined witness, has the
/// exact shape of the class documented in
/// `findings/non-pinning-constraint-silences-checker`. That is a candidate,
/// not a proof: two assertions could still pin such a pair jointly. Confirming
/// one means running `mutate` or `scan` on it.
///
/// What it buys is reach. It needs no honest witness, so it applies to
/// artifacts that cannot be executed at all.
pub(crate) fn unpinned(args: UnpinnedArgs) -> Result<()> {
    let loaded = artifact::load_programs(&args.artifact)?;
    let program = loaded
        .programs
        .first()
        .ok_or_else(|| eyre!("artifact contains no program"))?;

    let mut candidates = 0usize;
    for (index, circuit) in program.program.functions.iter().enumerate() {
        let options = translate::ModelOptions {
            fixed_mode: if args.public_inputs_only {
                translate::FixedMode::Public
            } else {
                translate::FixedMode::AllParams
            },
            ..Default::default()
        };
        let model = translate::build_model(circuit, options);
        let mut determined = (1..model.witness_wire_limit)
            .filter(|wire| model.fixed_known_signals.contains(wire))
            .map(|wire| (wire - 1) as u32)
            .collect::<std::collections::BTreeSet<_>>();
        explain::refine_determined(circuit, &mut determined);
        let undetermined = (1..model.witness_wire_limit)
            .map(|wire| (wire - 1) as u32)
            .filter(|witness| !determined.contains(witness))
            .collect::<std::collections::BTreeSet<_>>();

        // A circuit with no assertions at all comes from an `unconstrained fn
        // main`: the whole program is the prover's to compute, by declaration.
        // Every hint in it is free, correctly so, and reporting them buries the
        // cases that matter — one such program in Noir's own corpus accounted
        // for 32 of the candidates.
        if !circuit
            .opcodes
            .iter()
            .any(|opcode| matches!(opcode, acir::circuit::Opcode::AssertZero(_)))
        {
            continue;
        }

        let reaching_output = explain::reachable_from_outputs(circuit, &undetermined);
        let bounds = explain::value_bounds(circuit);
        for witness in crate::dynamic::candidates::hint_witnesses(circuit) {
            if !undetermined.contains(&witness) {
                continue;
            }
            // A hint that never reaches what the circuit hands back cannot
            // change what a verifier sees, however free it is.
            if !reaching_output.contains(&witness) {
                continue;
            }
            let explanation =
                explain::explain_with_bounds(circuit, witness, &undetermined, &bounds);
            if !args.include_bits && explanation.looks_like_a_decomposition_digit() {
                continue;
            }
            if matches!(
                explanation.verdict,
                explain::Verdict::BoundedNeverPinned
                    | explain::Verdict::Unconstrained
                    | explain::Verdict::OnlyVanishingConstraints
                    | explain::Verdict::PropagatesFreedom
            ) {
                candidates += 1;
                println!("circuit {index}: {}", explanation.headline());
                for touch in &explanation.touches {
                    println!("    opcode {:>4}  {}", touch.index, touch.description);
                }
            }
        }
    }
    println!("{candidates} candidate(s)");
    if candidates == 0 {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

//! Ground-truth labels for circuit mutants.
//!
//! A mutant removes or relaxes one check. Whether that is a bug, and which
//! kind, is decided here by example, never by argument: every label except
//! `no-weakening` comes with a concrete assignment the mutant accepts and the
//! original check rejects.
//!
//! - `nondet`: for one input assignment the mutant accepts two assignments,
//!   one violating the removed check, with different public outputs. Both are
//!   re-checked against every mutant opcode. This is the class uniqueness
//!   checkers exist for. `nondet_inputs` says where: the honest inputs, inputs
//!   the original rejects (the mutant also over-accepts), or other inputs.
//! - `over-accept`: on some inputs the original program fails, yet the mutant
//!   accepts an assignment violating the removed check, and no hint found
//!   moves an output there. Outputs stay functions of inputs, so no
//!   uniqueness checker can see this; it is the missing assertion, not the
//!   missing determinism.
//! - `internal`: the mutant accepts an assignment violating the removed check,
//!   but no public output moves and the inputs are ones the original accepts.
//!   Witnesses are freed that nothing observable depends on.
//! - `no-weakening`: nothing was found within the budget. Either the removed
//!   check is implied by the rest of the circuit (an equivalent mutant) or the
//!   search was too weak; the label does not say which.
//!
//! Separately, `baseline_nondet` records an assignment that moves a public
//! output *without* violating the removed check: the original program was
//! already non-unique there, and the mutant tells us nothing.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Opcode, Program,
        brillig::BrilligOutputs,
        opcodes::{BlackBoxFuncCall, FunctionInput},
    },
    native_types::Expression,
};
use serde::Serialize;

use crate::dynamic::candidates::{candidate_values, hint_witnesses, public_outputs};
use crate::dynamic::certify::{self, WitnessValues};
use crate::dynamic::concrete::{self, ExecFailure};
use crate::field::to_decimal;

#[derive(Debug, Serialize)]
pub(crate) struct LabelReport {
    pub(crate) label: &'static str,
    /// How the evidence was produced: a hint override or an input change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) via: Option<String>,
    /// For `nondet`: whether the pair uses the honest inputs, inputs the
    /// original rejects, or other inputs the original accepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nondet_inputs: Option<&'static str>,
    /// Public outputs that moved, honest vs alternative.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) moved_outputs: Vec<(u32, String, String)>,
    /// Re-check of a `nondet` pair against every mutant opcode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate: Option<String>,
    pub(crate) baseline_nondet: bool,
    pub(crate) runs: usize,
    pub(crate) elapsed_ms: u128,
}

pub(crate) struct LabelOptions {
    pub(crate) budget: Duration,
    pub(crate) attempts: usize,
}

/// Label the mutant of `original` at `opcode_index` (a removed or relaxed
/// check), starting from honest `inputs` of the original.
pub(crate) fn label(
    original: &Program<FieldElement>,
    mutant: &Program<FieldElement>,
    opcode_index: usize,
    inputs: &WitnessValues,
    options: &LabelOptions,
) -> Result<LabelReport, String> {
    let started = Instant::now();
    let check = &original.functions[0].opcodes[opcode_index];
    let main = &mutant.functions[0];
    let mentioned = check_witnesses(check);
    // Hints the removed check reads come first: they are where the freed value
    // most likely is.
    let mut hints = hint_witnesses(main);
    hints.sort_by_key(|hint| !mentioned.contains(hint));
    hints.dedup();
    let search = Search {
        mutant,
        check,
        outputs: public_outputs(main),
        params: main
            .private_parameters
            .iter()
            .chain(&main.public_parameters.0)
            .map(|witness| witness.witness_index())
            .collect(),
        mentioned,
        hints,
        deadline: started + options.budget,
        attempts: options.attempts,
    };

    let honest = execute(original, inputs)
        .map_err(|failure| format!("the original rejects its own inputs: {}", failure.message))?;
    let mut report = LabelReport {
        label: "no-weakening",
        via: None,
        nondet_inputs: None,
        moved_outputs: Vec::new(),
        certificate: None,
        baseline_nondet: false,
        runs: 1,
        elapsed_ms: 0,
    };

    // Same inputs as the honest run: one hint answered differently.
    if search.overrides(inputs, &honest, "honest", &mut report) {
        report.elapsed_ms = started.elapsed().as_millis();
        return Ok(report);
    }

    // Other inputs, one parameter at a time plus all-zero and all-one: where
    // the mutant runs and the original does not, the mutant over-accepts, and
    // a hint there may still move an output.
    let mut variants = Vec::new();
    for constant in [FieldElement::zero(), FieldElement::one()] {
        variants.push((
            format!("all inputs {}", to_decimal(constant)),
            inputs
                .keys()
                .map(|index| (*index, constant))
                .collect::<WitnessValues>(),
        ));
    }
    for param in &search.params {
        let Some(&value) = inputs.get(param) else {
            continue;
        };
        for alternative in candidate_values(value, options.attempts) {
            let mut changed = inputs.clone();
            changed.insert(*param, alternative);
            variants.push((
                format!("input w{param} -> {}", to_decimal(alternative)),
                changed,
            ));
        }
    }
    for (description, changed) in variants {
        if Instant::now() >= search.deadline {
            break;
        }
        report.runs += 1;
        // Where an honest run fails inside a hint (a division by zero, say),
        // answering that hint is the only way through: take the first
        // override the mutant accepts as the base assignment.
        let Some(solved) = execute(mutant, &changed)
            .ok()
            .or_else(|| search.first_accepted(&changed, &mut report))
        else {
            continue;
        };
        report.runs += 1;
        let rejected = execute(original, &changed).is_err();
        if rejected && violates(check, &solved) && report.label != "over-accept" {
            report.label = "over-accept";
            report.via = Some(description.clone());
        }
        let kind = if rejected { "rejected" } else { "other" };
        // A free value in the original at these inputs is not the mutant's
        // doing; only the honest-input baseline flag is kept, so skip
        // searching where the original itself runs and was already non-unique.
        if search.overrides(&changed, &solved, kind, &mut report) {
            break;
        }
    }
    report.elapsed_ms = started.elapsed().as_millis();
    Ok(report)
}

struct Search<'a> {
    mutant: &'a Program<FieldElement>,
    check: &'a Opcode<FieldElement>,
    outputs: BTreeSet<u32>,
    params: BTreeSet<u32>,
    mentioned: BTreeSet<u32>,
    hints: Vec<u32>,
    deadline: Instant,
    attempts: usize,
}

impl Search<'_> {
    /// Any assignment the mutant accepts at `inputs` with one hint answered
    /// by a small value, hints the removed check reads first.
    fn first_accepted(
        &self,
        inputs: &WitnessValues,
        report: &mut LabelReport,
    ) -> Option<WitnessValues> {
        for &hint in self.hints.iter().take(8) {
            for value in [FieldElement::zero(), FieldElement::one()] {
                if Instant::now() >= self.deadline {
                    return None;
                }
                report.runs += 1;
                if let Ok(solved) = execute_with_override(self.mutant, inputs, hint, value) {
                    return Some(solved);
                }
            }
        }
        None
    }

    /// Answer one hint differently at `inputs`, where `base` is an assignment
    /// the mutant accepts. Returns `true` on a `nondet` finding, which ends
    /// the search; otherwise records `internal` and baseline evidence.
    fn overrides(
        &self,
        inputs: &WitnessValues,
        base: &WitnessValues,
        kind: &'static str,
        report: &mut LabelReport,
    ) -> bool {
        let main = &self.mutant.functions[0];
        for &hint in &self.hints {
            let Some(&value) = base.get(&hint) else {
                continue;
            };
            for alternative in
                hint_candidates(self.check, &self.mentioned, hint, value, self.attempts)
            {
                if Instant::now() >= self.deadline {
                    return false;
                }
                report.runs += 1;
                let Ok(solved) = execute_with_override(self.mutant, inputs, hint, alternative)
                else {
                    continue;
                };
                let moved = moved_outputs(&self.outputs, base, &solved);
                if !violates(self.check, &solved) {
                    report.baseline_nondet |= kind == "honest" && !moved.is_empty();
                    continue;
                }
                if moved.is_empty() {
                    if report.label == "no-weakening" {
                        report.label = "internal";
                        report.via = Some(format!("hint w{hint} -> {}", to_decimal(alternative)));
                    }
                    continue;
                }
                let component = base.keys().map(|index| *index as usize + 1).collect();
                let certificate = certify::certify(
                    main,
                    &component,
                    &self.params,
                    Some(moved[0].0),
                    base,
                    &solved,
                );
                report.label = "nondet";
                report.via = Some(format!("hint w{hint} -> {}", to_decimal(alternative)));
                report.nondet_inputs = Some(kind);
                report.moved_outputs = moved;
                report.certificate = Some(format!("{:?}", certificate.status));
                return true;
            }
        }
        false
    }
}

/// Values for `hint`: the generic neighbours of its honest value, plus, when
/// the relaxed check is a range on this very witness, values just past the
/// original bound, which is where an off-by-one range lets a prover through.
fn hint_candidates(
    check: &Opcode<FieldElement>,
    mentioned: &BTreeSet<u32>,
    hint: u32,
    value: FieldElement,
    attempts: usize,
) -> Vec<FieldElement> {
    let mut values = candidate_values(value, attempts);
    if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { num_bits, .. }) = check
        && mentioned.contains(&hint)
        && *num_bits < FieldElement::max_num_bits()
    {
        let bound = FieldElement::from(2u128).pow(&FieldElement::from(*num_bits as u128));
        values.insert(0, bound + value);
        values.insert(0, bound);
    }
    values.retain(|candidate| *candidate != value);
    values
}

/// The ACVM asserts on some inputs a relaxed check now lets through (a
/// black-box operand wider than `u128`, say). That is a rejection, not a
/// crash of the labeller.
fn guarded(
    run: impl FnOnce() -> Result<WitnessValues, ExecFailure>,
) -> Result<WitnessValues, ExecFailure> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
        Err(ExecFailure {
            opcode: None,
            message: "the ACVM panicked".to_string(),
            partial: WitnessValues::new(),
        })
    })
}

fn execute(
    program: &Program<FieldElement>,
    inputs: &WitnessValues,
) -> Result<WitnessValues, ExecFailure> {
    guarded(|| concrete::execute(program, inputs))
}

fn execute_with_override(
    program: &Program<FieldElement>,
    inputs: &WitnessValues,
    hint: u32,
    value: FieldElement,
) -> Result<WitnessValues, ExecFailure> {
    let failure = match guarded(|| concrete::execute_with_override(program, inputs, hint, value)) {
        Ok(solved) => return Ok(solved),
        Err(failure) => failure,
    };
    // The producing call itself failed (a division by zero inside the hint,
    // say), so it never got to answer. A prover is not bound by the hint's
    // code: skip the call and supply its outputs, `hint` = `value` and the
    // rest zero. Unconstrained calls are not part of what a verifier checks.
    if failure.partial.contains_key(&hint) {
        return Err(failure);
    }
    let main = &program.functions[0];
    let Some((producer, outputs)) = main.opcodes.iter().enumerate().find_map(|(index, opcode)| {
        let outputs = brillig_outputs(opcode);
        outputs.contains(&hint).then_some((index, outputs))
    }) else {
        return Err(failure);
    };
    let mut skipped = program.clone();
    skipped.functions[0].opcodes[producer] = Opcode::AssertZero(Expression::default());
    let mut seeded = inputs.clone();
    for output in outputs {
        seeded.insert(
            output,
            if output == hint {
                value
            } else {
                FieldElement::zero()
            },
        );
    }
    guarded(|| concrete::execute(&skipped, &seeded))
}

fn brillig_outputs(opcode: &Opcode<FieldElement>) -> Vec<u32> {
    let Opcode::BrilligCall { outputs, .. } = opcode else {
        return Vec::new();
    };
    outputs
        .iter()
        .flat_map(|output| match output {
            BrilligOutputs::Simple(witness) => vec![witness.witness_index()],
            BrilligOutputs::Array(witnesses) => witnesses
                .iter()
                .map(|witness| witness.witness_index())
                .collect(),
        })
        .collect()
}

fn check_witnesses(check: &Opcode<FieldElement>) -> BTreeSet<u32> {
    match check {
        Opcode::AssertZero(expression) => expression
            .mul_terms
            .iter()
            .flat_map(|(_, a, b)| [a.witness_index(), b.witness_index()])
            .chain(
                expression
                    .linear_combinations
                    .iter()
                    .map(|(_, w)| w.witness_index()),
            )
            .collect(),
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(witness),
            ..
        }) => BTreeSet::from([witness.witness_index()]),
        _ => BTreeSet::new(),
    }
}

/// Does `values` break the original check? Only the two shapes mutants touch.
fn violates(check: &Opcode<FieldElement>, values: &WitnessValues) -> bool {
    match check {
        Opcode::AssertZero(expression) => {
            certify::evaluate(expression, values).is_some_and(|value| !value.is_zero())
        }
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(witness),
            num_bits,
        }) => values
            .get(&witness.witness_index())
            .is_some_and(|value| value.num_bits() > *num_bits),
        _ => false,
    }
}

fn moved_outputs(
    outputs: &BTreeSet<u32>,
    honest: &WitnessValues,
    other: &WitnessValues,
) -> Vec<(u32, String, String)> {
    outputs
        .iter()
        .filter_map(|output| {
            let (left, right) = (honest.get(output)?, other.get(output)?);
            (left != right).then(|| (*output, to_decimal(*left), to_decimal(*right)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use acir::{FieldElement, circuit::Program};

    use super::{LabelOptions, label};
    use crate::dynamic::certify::WitnessValues;

    fn division_hint() -> Program<FieldElement> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/artifacts/verified_division_hint.json");
        crate::artifact::load_programs(&path).unwrap().programs[0]
            .program
            .clone()
    }

    fn label_drop(index: usize) -> super::LabelReport {
        let original = division_hint();
        let mutant = crate::mutants::mutants(&original)
            .into_iter()
            .find(|mutant| mutant.opcode_index == index)
            .unwrap()
            .apply(&original);
        let inputs = WitnessValues::from([
            (0, FieldElement::from(6u128)),
            (1, FieldElement::from(3u128)),
        ]);
        let options = LabelOptions {
            budget: std::time::Duration::from_secs(10),
            attempts: 7,
        };
        label(&original, &mutant, index, &inputs, &options).unwrap()
    }

    // `assert(numerator == denominator * quotient)` removed: the quotient
    // hint is free on the honest inputs themselves.
    #[test]
    fn dropping_the_quotient_check_is_nondet_on_honest_inputs() {
        let report = label_drop(2);
        assert_eq!(report.label, "nondet");
        assert_eq!(report.nondet_inputs, Some("honest"));
        assert_eq!(report.certificate.as_deref(), Some("Certified"));
    }

    // `assert(denominator * inverse == 1)` removed: harmless for a non-zero
    // denominator, but at 0 / 0, which the original rejects, the quotient is
    // free. Reaching it means answering a hint whose code divides by zero.
    #[test]
    fn dropping_the_inverse_check_is_nondet_where_the_original_rejects() {
        let report = label_drop(1);
        assert_eq!(report.label, "nondet");
        assert_eq!(report.nondet_inputs, Some("rejected"));
        assert_eq!(report.certificate.as_deref(), Some("Certified"));
    }
}

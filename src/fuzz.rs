//! Input fuzzing for the dynamic search.
//!
//! `mutate` needs an honest witness, and the witness has to be one on which
//! the ambiguity already shows. A non-strict substring search is only
//! ambiguous on a haystack that contains the needle twice; a hand-written
//! `Prover.toml` almost never does, so the search started from the wrong place
//! and reported nothing. This module makes the inputs itself:
//!
//! 1. generate inputs biased toward the shapes that expose ambiguity — values
//!    from the circuit's own constants (`0x30`, a DER tag, a length) and
//!    repeated windows inside array-like parameters;
//! 2. execute in-process (Brillig hints included), repairing parameters that
//!    a linear equation pins, such as a public commitment;
//! 3. run the hint search on the honest witness and certify every divergence
//!    against the ACIR opcodes, black boxes included.
//!
//! A finding is a pair of full assignments that agree on every parameter,
//! differ in a return value, and both satisfy every opcode. It cannot be a
//! false positive of the search; the remaining trust is in the ACVM's black-box
//! implementations, which are the ones `nargo` itself uses.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use acir::{
    AcirField, FieldElement,
    circuit::{Opcode, Program},
};
use serde::Serialize;

use crate::certify::{self, WitnessValues};
use crate::{concrete, mutate};

pub(crate) struct FuzzOptions {
    pub(crate) rounds: usize,
    pub(crate) budget: Duration,
    pub(crate) seed: u64,
    pub(crate) seed_inputs: Option<WitnessValues>,
    pub(crate) attempts_per_witness: usize,
    pub(crate) stop_at_first: bool,
    pub(crate) max_input_repairs: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct FuzzFinding {
    pub(crate) round: usize,
    /// The hint that was moved.
    pub(crate) hint: u32,
    pub(crate) hint_honest: String,
    pub(crate) hint_alternative: String,
    /// Return witness -> (honest value, alternative value).
    pub(crate) returns: BTreeMap<u32, (String, String)>,
    /// Every parameter, canonical decimal.
    pub(crate) inputs: BTreeMap<u32, String>,
    pub(crate) certificate: String,
    pub(crate) checked_opcodes: usize,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct FuzzReport {
    pub(crate) rounds: usize,
    pub(crate) executed: usize,
    pub(crate) input_repairs: usize,
    /// Execution failures by message, most frequent first in the printout.
    pub(crate) failures: BTreeMap<String, usize>,
    pub(crate) hints: usize,
    pub(crate) attempts: usize,
    pub(crate) findings: Vec<FuzzFinding>,
    /// Learned input links: (first parameter witness, window length).
    pub(crate) links: Vec<(u32, usize)>,
    pub(crate) elapsed_ms: u128,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: deterministic for a given --seed, no dependency needed.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// Parameter layout the generator works with.
struct Layout {
    params: Vec<u32>,
    /// Tightest RANGE width per parameter, if any.
    widths: BTreeMap<u32, u32>,
    /// Maximal runs of consecutive parameters with the same width: the shape
    /// an array parameter compiles to.
    runs: Vec<Vec<u32>>,
    /// Small constants the circuit compares against.
    dictionary: Vec<u128>,
}

/// Array parameters from the ABI, as runs of witness indices. Parameters are
/// flattened in declaration order into witnesses `0..N` (see `AbiNaming`).
fn abi_runs(abi: &crate::debug_info::Abi) -> (Vec<Vec<u32>>, u32) {
    use crate::debug_info::AbiType;
    fn walk(typ: &AbiType, cursor: &mut u32, runs: &mut Vec<Vec<u32>>) {
        match typ {
            AbiType::Field | AbiType::Boolean | AbiType::Integer {} => *cursor += 1,
            AbiType::String { length } => {
                runs.push((*cursor..*cursor + length).collect());
                *cursor += length;
            }
            AbiType::Array { length, typ } => match typ.as_ref() {
                AbiType::Field | AbiType::Boolean | AbiType::Integer {} => {
                    runs.push((*cursor..*cursor + length).collect());
                    *cursor += length;
                }
                inner => {
                    for _ in 0..*length {
                        walk(inner, cursor, runs);
                    }
                }
            },
            AbiType::Struct { fields } => {
                for field in fields {
                    walk(&field.typ, cursor, runs);
                }
            }
            #[allow(unreachable_patterns)]
            _ => *cursor += 1,
        }
    }
    let mut runs = Vec::new();
    let mut cursor = 0;
    for parameter in &abi.parameters {
        walk(&parameter.typ, &mut cursor, &mut runs);
    }
    (runs, cursor)
}

fn layout(program: &Program<FieldElement>, abi: Option<&crate::debug_info::Abi>) -> Layout {
    let circuit = &program.functions[0];
    let params = circuit
        .private_parameters
        .iter()
        .chain(circuit.public_parameters.0.iter())
        .map(|witness| witness.witness_index())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let widths = mutate::range_widths(circuit);

    let mut runs: Vec<Vec<u32>> = Vec::new();
    for &param in &params {
        let width = widths.get(&param).copied();
        match runs.last_mut() {
            Some(run)
                if *run.last().unwrap() + 1 == param
                    && widths.get(run.last().unwrap()).copied() == width =>
            {
                run.push(param)
            }
            _ => runs.push(vec![param]),
        }
    }
    // The ABI knows where one array ends and the next begins; two adjacent
    // `[u8; N]` parameters look like one run to the width heuristic.
    if let Some((abi_runs, count)) = abi.map(abi_runs) {
        let expected = (0..count).collect::<Vec<_>>();
        if expected == params {
            runs = abi_runs;
        }
    }
    runs.retain(|run| run.len() >= 4);

    let mut dictionary = BTreeSet::from([0u128, 1, 2, 3]);
    let limit = 1u128 << 16;
    let mut consider = |value: FieldElement| {
        for candidate in [value, -value] {
            if candidate.num_bits() <= 16 {
                let small = candidate.to_u128();
                if small < limit {
                    dictionary.insert(small);
                }
            }
        }
    };
    for opcode in &circuit.opcodes {
        if let Opcode::AssertZero(expression) = opcode {
            consider(expression.q_c);
            for (coefficient, _) in &expression.linear_combinations {
                consider(*coefficient);
            }
        }
    }
    Layout {
        params,
        widths,
        runs,
        dictionary: dictionary.into_iter().collect(),
    }
}

fn bounded(value: u128, width: Option<u32>) -> FieldElement {
    match width {
        Some(bits) if bits < 128 => FieldElement::from(value & ((1u128 << bits) - 1)),
        _ => FieldElement::from(value),
    }
}

fn generate(
    layout: &Layout,
    rng: &mut Rng,
    round: usize,
    seed: Option<&WitnessValues>,
    hot: &[usize],
) -> WitnessValues {
    let mut inputs = WitnessValues::new();
    let from_seed = seed.is_some() && (round == 0 || rng.chance(60));
    for &param in &layout.params {
        let width = layout.widths.get(&param).copied();
        let value = if from_seed {
            seed.and_then(|seed| seed.get(&param).copied())
                .unwrap_or_default()
        } else if round == 0 {
            FieldElement::zero()
        } else if rng.chance(70) {
            bounded(layout.dictionary[rng.below(layout.dictionary.len())], width)
        } else {
            bounded(rng.next() as u128, width.or(Some(32)))
        };
        inputs.insert(param, value);
    }
    if round == 0 {
        return inputs;
    }
    // Small point mutations on top of the seed. Rarely: on a structured
    // input most of them break a header and the round is wasted.
    if from_seed && rng.chance(25) {
        for _ in 0..rng.below(3) {
            let param = layout.params[rng.below(layout.params.len())];
            let width = layout.widths.get(&param).copied();
            inputs.insert(
                param,
                bounded(layout.dictionary[rng.below(layout.dictionary.len())], width),
            );
        }
    }
    // Plant a repeated window: the shape under which "find the first match",
    // "the index of this element" and similar hints stop being unique.
    //
    // Windows are taken where the array has content and dropped inside its
    // used prefix. A structured array — an eContent, a TBS certificate — is
    // mostly zero padding, and a copy that lands in the padding is either
    // ignored by a length check or rejected by a zero-padding check.
    if !layout.runs.is_empty() && rng.chance(85) {
        for _ in 0..1 + rng.below(2) {
            let run = &layout.runs[rng.below(layout.runs.len())];
            let active = run
                .iter()
                .rposition(|witness| !inputs[witness].is_zero())
                .map_or(run.len(), |last| last + 1)
                .max(2);
            let len = (2 + rng.below(15)).min(run.len());
            let nonzero = (0..run.len().saturating_sub(len - 1))
                .filter(|&start| !inputs[&run[start]].is_zero())
                .collect::<Vec<_>>();
            // Feedback: positions a position-like hint pointed at in an
            // honest run. Whatever was found there is what a second copy
            // would make ambiguous, so copy from just before it.
            let hot_here = hot
                .iter()
                .copied()
                .filter(|&position| position < run.len())
                .collect::<Vec<_>>();
            let (from, len) = if !hot_here.is_empty() && rng.chance(60) {
                let len = (8 + rng.below(17)).min(run.len());
                let anchor = hot_here[rng.below(hot_here.len())];
                let from = anchor.saturating_sub(rng.below(5)).min(run.len() - len);
                (from, len)
            } else if !nonzero.is_empty() && rng.chance(80) {
                (nonzero[rng.below(nonzero.len())], len)
            } else {
                (rng.below(run.len() - len + 1), len)
            };
            let span = if rng.chance(80) {
                active.min(run.len())
            } else {
                run.len()
            };
            let to = rng.below(span.saturating_sub(len) + 1).min(run.len() - len);
            let window = (0..len).map(|k| inputs[&run[from + k]]).collect::<Vec<_>>();
            for (k, value) in window.into_iter().enumerate() {
                inputs.insert(run[to + k], value);
            }
        }
    }
    inputs
}

/// Find parameter windows that equal computed witnesses in an honest run.
fn learn_links(
    program: &Program<FieldElement>,
    layout: &Layout,
    honest: &WitnessValues,
    inputs: &WitnessValues,
) -> Vec<concrete::InputLink> {
    let circuit = &program.functions[0];
    let params = layout.params.iter().copied().collect::<BTreeSet<_>>();
    // Memory reads copy values rather than compute them; linking an input to
    // its own copy would be a no-op. Hints stay: hash libraries split words
    // into bytes with a hint and constrain the split, so the digest bytes
    // themselves are hint outputs.
    let mut copies = BTreeSet::new();
    for opcode in &circuit.opcodes {
        if let Opcode::MemoryOp { op, .. } = opcode {
            copies.insert(op.value.witness_index());
        }
    }
    let mut by_value: BTreeMap<Vec<u8>, Vec<u32>> = BTreeMap::new();
    for (witness, value) in honest {
        if !params.contains(witness) && !copies.contains(witness) {
            by_value
                .entry(value.to_be_bytes())
                .or_default()
                .push(*witness);
        }
    }
    // Score every candidate window, then keep the best non-overlapping ones.
    // Sliding and taking the first match lined the window up one byte early
    // whenever the length byte before a digest happened to equal some nearby
    // witness; the true window is the one whose sources are packed tightest.
    let mut candidates: Vec<(i64, usize, usize, Vec<u32>)> = Vec::new();
    let mut run_maps: Vec<BTreeMap<Vec<u8>, Vec<u32>>> = Vec::new();
    for (run_index, run) in layout.runs.iter().enumerate() {
        // Which computed values do not depend on this array at all? Zero it,
        // run again, and keep only witnesses that came out the same. The
        // digest of *other* data stored in this array passes; a comparison
        // that merely copies the array's own bytes does not, and linking to
        // such a copy would write the mutated bytes back onto themselves.
        let mut zeroed = inputs.clone();
        for param in run {
            zeroed.insert(*param, FieldElement::zero());
        }
        let perturbed = match concrete::execute(program, &zeroed) {
            Ok(values) => values,
            Err(failure) => failure.partial,
        };
        let by_value = by_value
            .iter()
            .map(|(value, list)| {
                (
                    value.clone(),
                    list.iter()
                        .copied()
                        .filter(|witness| perturbed.get(witness) == honest.get(witness))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        run_maps.push(by_value.clone());
        for len in [32usize, 20, 28] {
            for start in 0..run.len().saturating_sub(len - 1) {
                let window = &run[start..start + len];
                let values = window
                    .iter()
                    .map(|witness| honest[witness])
                    .collect::<Vec<_>>();
                let distinct = values
                    .iter()
                    .map(|value| value.to_be_bytes())
                    .collect::<BTreeSet<_>>();
                // Digests look random; headers, padding and text do not.
                if distinct.len() < 3 * len / 4 {
                    continue;
                }
                // Digest bytes are computed together, so their witnesses sit
                // close; a header matched byte-by-byte to scattered values is
                // a coincidence.
                let span = 8 * len as i64;
                let anchors = by_value
                    .get(&values[0].to_be_bytes())
                    .cloned()
                    .unwrap_or_default();
                let mut best: Option<(i64, Vec<u32>)> = None;
                for &anchor in anchors.iter().take(64) {
                    let mut chosen = vec![anchor];
                    let mut used = BTreeSet::from([anchor]);
                    for value in &values[1..] {
                        let next = by_value.get(&value.to_be_bytes()).and_then(|list| {
                            list.iter()
                                .copied()
                                .filter(|witness| !used.contains(witness))
                                .filter(|witness| (*witness as i64 - anchor as i64).abs() <= span)
                                .min_by_key(|witness| (*witness as i64 - anchor as i64).abs())
                        });
                        match next {
                            Some(witness) => {
                                used.insert(witness);
                                chosen.push(witness);
                            }
                            None => break,
                        }
                    }
                    if chosen.len() == len {
                        let lo = *chosen.iter().min().unwrap() as i64;
                        let hi = *chosen.iter().max().unwrap() as i64;
                        let tightness = hi - lo;
                        if best.as_ref().is_none_or(|(score, _)| tightness < *score) {
                            best = Some((tightness, chosen));
                        }
                    }
                }
                if let Some((tightness, sources)) = best {
                    // Normalise by length so a 32-byte digest is not beaten by
                    // a 20-byte slice of itself.
                    candidates.push((tightness * 32 / len as i64, run_index, start, sources));
                }
            }
        }
    }
    candidates.sort_by_key(|(score, _, start, sources)| {
        (*score, std::cmp::Reverse(sources.len()), *start)
    });
    let candidates = candidates;
    let mut taken: Vec<(usize, usize, usize)> = Vec::new();
    let mut links = Vec::new();
    for (_, run_index, start, mut sources) in candidates {
        // Grow a short window to a full 32-byte digest when the missing bytes
        // also come from the same cluster of witnesses.
        let run = &layout.runs[run_index];
        if sources.len() < 32 && start + 32 <= run.len() {
            let lo = *sources.iter().min().unwrap();
            let hi = *sources.iter().max().unwrap();
            let mut used = sources.iter().copied().collect::<BTreeSet<_>>();
            let mut grown = sources.clone();
            for param in &run[start + sources.len()..start + 32] {
                let value = honest[param].to_be_bytes();
                let near = run_maps[run_index].get(&value).and_then(|list| {
                    list.iter()
                        .copied()
                        .filter(|witness| !used.contains(witness))
                        .filter(|witness| *witness + 32 >= lo && *witness <= hi + 32)
                        .min_by_key(|witness| (*witness as i64 - hi as i64).abs())
                });
                match near {
                    Some(witness) => {
                        used.insert(witness);
                        grown.push(witness);
                    }
                    None => break,
                }
            }
            if grown.len() == 32 {
                sources = grown;
            }
        }
        let end = start + sources.len();
        if taken
            .iter()
            .any(|(run, s, e)| *run == run_index && start < *e && *s < end)
        {
            continue;
        }
        taken.push((run_index, start, end));
        let window = &layout.runs[run_index][start..end];
        links.push(concrete::InputLink {
            params: window.to_vec(),
            sources,
            bits: layout.widths.get(&window[0]).copied(),
        });
    }
    links
}

pub(crate) fn fuzz(
    program: &Program<FieldElement>,
    abi: Option<&crate::debug_info::Abi>,
    options: &FuzzOptions,
) -> FuzzReport {
    let started = Instant::now();
    let deadline = started + options.budget;
    let circuit = &program.functions[0];
    let layout = layout(program, abi);
    let mut links: Vec<concrete::InputLink> = Vec::new();
    let params = layout.params.iter().copied().collect::<BTreeSet<_>>();
    let mut rng = Rng(options.seed.max(1));
    let mut report = FuzzReport::default();
    let mut seen = BTreeSet::new();
    let mut hot: Vec<usize> = Vec::new();
    let indexed = mutate::index_candidates(circuit);
    let widths = mutate::range_widths(circuit);

    for round in 0..options.rounds {
        if Instant::now() >= deadline {
            break;
        }
        report.rounds += 1;
        let mut inputs = generate(&layout, &mut rng, round, options.seed_inputs.as_ref(), &hot);
        let before = inputs.clone();
        let honest = match concrete::execute_with_repairs(
            program,
            &mut inputs,
            options.max_input_repairs,
            &links,
        ) {
            Ok(values) => values,
            Err(failure) => {
                let key = failure.message.chars().take(120).collect::<String>();
                *report.failures.entry(key).or_default() += 1;
                continue;
            }
        };
        report.executed += 1;
        if round == 0 && options.seed_inputs.is_some() {
            links = learn_links(program, &layout, &honest, &inputs);
            report.links = links
                .iter()
                .map(|link| (link.params[0], link.params.len()))
                .collect();
        }
        for (hint, slots) in &indexed {
            let Some(value) = honest.get(hint) else {
                continue;
            };
            if widths.get(hint).is_some_and(|bits| (2..=64).contains(bits))
                && value.num_bits() <= 32
                && (value.to_u128() as usize) < slots.len()
            {
                let position = value.to_u128() as usize;
                if !hot.contains(&position) {
                    hot.push(position);
                    if hot.len() > 32 {
                        hot.remove(0);
                    }
                }
            }
        }
        if inputs != before {
            report.input_repairs += 1;
        }

        // First, the direct attack: answer one hint differently and run the
        // rest of the program honestly.
        let (direct, tried) = override_search(
            program,
            &honest,
            &params,
            &inputs,
            options.attempts_per_witness,
            // A slice per round, so a big circuit still reaches the planted
            // inputs instead of spending the whole budget on the first one.
            deadline.min(Instant::now() + (options.budget / 10).max(Duration::from_secs(5))),
            round,
            &mut seen,
        );
        report.attempts += tried;
        report.findings.extend(direct);
        if options.stop_at_first && !report.findings.is_empty() {
            break;
        }

        let found = mutate::search_with(
            circuit,
            &honest,
            &mutate::SearchOptions {
                attempts_per_witness: options.attempts_per_witness,
                hints_only: true,
                skip_input_oracle: true,
                // The constraint-level repair is the slower, secondary path:
                // a slice of each round, not the whole budget.
                deadline: Some(deadline.min(Instant::now() + Duration::from_secs(2))),
            },
        );
        report.hints += found.funnel.hints;
        report.attempts += found.attempted;

        for mutation in found.findings {
            if !seen.insert(mutation.witness) {
                continue;
            }
            let Some(assignment) = mutation.assignment.as_ref() else {
                continue;
            };
            let alternative: WitnessValues = assignment
                .iter()
                .map(|(index, value)| (*index, parse_decimal(value)))
                .collect();
            // Independent re-check of the full claim: same parameters, a
            // return value differs, both assignments satisfy every opcode.
            let Some((&target, _)) = mutation.diverging_returns.iter().next() else {
                continue;
            };
            let component = honest.keys().map(|index| *index as usize + 1).collect();
            let certificate = certify::certify(
                circuit,
                &component,
                &params,
                Some(target),
                &honest,
                &alternative,
            );
            report.findings.push(FuzzFinding {
                round,
                hint: mutation.witness,
                hint_honest: mutation.original.clone(),
                hint_alternative: mutation.alternative.clone(),
                returns: mutation
                    .diverging_returns
                    .keys()
                    .map(|index| {
                        (
                            *index,
                            (
                                canonical(honest[index]),
                                canonical(alternative.get(index).copied().unwrap_or_default()),
                            ),
                        )
                    })
                    .collect(),
                inputs: params
                    .iter()
                    .map(|index| (*index, canonical(honest[index])))
                    .collect(),
                certificate: format!("{:?}", certificate.status),
                checked_opcodes: certificate.checked_opcodes,
            });
        }
        if options.stop_at_first && !report.findings.is_empty() {
            break;
        }
    }
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

pub(crate) fn parse_decimal(value: &str) -> FieldElement {
    num_bigint::BigUint::parse_bytes(value.trim().as_bytes(), 10)
        .map(|big| FieldElement::from_be_bytes_reduce(&big.to_bytes_be()))
        .unwrap_or_default()
}

/// Try every candidate value for every hint, each in a fresh run with that one
/// hint overridden. Returns certified findings and the number of runs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn override_search(
    program: &Program<FieldElement>,
    honest: &WitnessValues,
    params: &BTreeSet<u32>,
    inputs: &WitnessValues,
    attempts: usize,
    deadline: Instant,
    round: usize,
    seen: &mut BTreeSet<u32>,
) -> (Vec<FuzzFinding>, usize) {
    let circuit = &program.functions[0];
    let returns = mutate::public_outputs(circuit);
    let indexed = mutate::index_candidates(circuit);
    let wraps = mutate::wrap_candidates(circuit);
    let widths = mutate::range_widths(circuit);
    let mut hints = mutate::hint_witnesses(circuit)
        .into_iter()
        .filter(|hint| !params.contains(hint))
        .collect::<Vec<_>>();
    hints.dedup();
    // A hint is position-like when it reaches a memory index and its honest
    // value is a valid position. Comparison bits, quotients and the inverse
    // witnesses of `IsZero` gadgets also reach indices through the loop
    // predicate, but never hold a position; trying every slot of a 700-byte
    // block on each of them was most of the cost of a round.
    let position_like = |hint: &u32| {
        let Some(slots) = indexed.get(hint) else {
            return false;
        };
        let Some(value) = honest.get(hint) else {
            return false;
        };
        // Positions are integers, so the compiler range-checks them; the
        // inverse witnesses are field elements and carry no RANGE at all.
        widths.get(hint).is_some_and(|bits| (2..=64).contains(bits))
            && value.num_bits() <= 32
            && (value.to_u128() as usize) < slots.len()
    };
    // Position-like hints first: they are the ones with a second valid answer.
    hints.sort_by_key(|hint| !position_like(hint));

    let blocks = circuit
        .opcodes
        .iter()
        .filter_map(|opcode| match opcode {
            Opcode::MemoryInit { init, .. } => Some(
                init.iter()
                    .map(|witness| witness.witness_index())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .collect::<Vec<_>>();
    let component = honest.keys().map(|index| *index as usize + 1).collect();
    let mut findings = Vec::new();
    let mut tried = 0;
    for hint in hints {
        if seen.contains(&hint) {
            continue;
        }
        let Some(original) = honest.get(&hint).copied() else {
            continue;
        };
        let mut values = mutate::candidate_values(original, attempts);
        values.extend((2u128..=8).map(FieldElement::from));
        if position_like(&hint) {
            // Try the slots that look like the honest one first. A hint that
            // locates something has a second valid answer only where that
            // something occurs again, so content similarity around the slot is
            // a cheap, necessary condition; on a 700-byte eContent it puts the
            // right slot among the first few attempts instead of the 700th.
            let slots = indexed.get(&hint).cloned().unwrap_or_default();
            let here = original.to_u128() as usize;
            let similar = |slot: usize| -> usize {
                blocks
                    .iter()
                    .filter(|init| init.len() == slots.len())
                    .map(|init| {
                        (-3i64..12)
                            .filter(|k| {
                                let (a, b) = (here as i64 + k, slot as i64 + k);
                                a >= 0
                                    && b >= 0
                                    && (a as usize) < init.len()
                                    && (b as usize) < init.len()
                                    && honest.get(&init[a as usize])
                                        == honest.get(&init[b as usize])
                                    && honest.get(&init[a as usize]).is_some_and(|v| !v.is_zero())
                            })
                            .count()
                    })
                    .max()
                    .unwrap_or(0)
            };
            let mut ranked = slots
                .iter()
                .copied()
                .map(|value| (similar(value.to_u128() as usize), value))
                .collect::<Vec<_>>();
            ranked.sort_by_key(|(score, value)| (std::cmp::Reverse(*score), value.to_u128()));
            // Similar slots go to the front of the queue; the rest follow.
            let front = ranked
                .iter()
                .filter(|(score, _)| *score >= 4)
                .map(|(_, value)| *value);
            let mut ordered = front.collect::<Vec<_>>();
            ordered.append(&mut values);
            // A short block (a country list) is swept whole: similarity says
            // nothing about which index of a sorted list is valid. A long one
            // is a buffer being searched, and there only similar slots can
            // hold a second match.
            if slots.len() <= 64 {
                ordered.extend(ranked.into_iter().map(|(_, value)| value));
            }
            values = ordered;
        }
        values.extend(
            wraps
                .get(&hint)
                .into_iter()
                .flatten()
                .map(|step| original + *step),
        );
        let mut unique = BTreeSet::new();
        values.retain(|value| *value != original && unique.insert(value.to_be_bytes()));

        let trace = std::env::var_os("NOIR_PICUS_TRACE_FUZZ").is_some();
        let hint_started = Instant::now();
        let hint_candidates = values.len();
        let _guard = TraceOnDrop(
            trace,
            hint,
            hint_candidates,
            hint_started,
            position_like(&hint),
        );
        for value in values {
            if Instant::now() >= deadline {
                return (findings, tried);
            }
            tried += 1;
            let Ok(alternative) = concrete::execute_with_override(program, inputs, hint, value)
            else {
                continue;
            };
            let diverging = returns
                .iter()
                .filter(|witness| honest.get(witness) != alternative.get(witness))
                .copied()
                .collect::<Vec<_>>();
            let Some(&target) = diverging.first() else {
                continue;
            };
            let certificate = certify::certify(
                circuit,
                &component,
                params,
                Some(target),
                honest,
                &alternative,
            );
            seen.insert(hint);
            findings.push(FuzzFinding {
                round,
                hint,
                hint_honest: canonical(original),
                hint_alternative: canonical(value),
                returns: diverging
                    .iter()
                    .map(|index| {
                        (
                            *index,
                            (
                                canonical(honest[index]),
                                canonical(alternative.get(index).copied().unwrap_or_default()),
                            ),
                        )
                    })
                    .collect(),
                inputs: params
                    .iter()
                    .map(|index| (*index, canonical(honest[index])))
                    .collect(),
                certificate: format!("{:?}", certificate.status),
                checked_opcodes: certificate.checked_opcodes,
            });
            break;
        }
    }
    (findings, tried)
}

fn canonical(value: FieldElement) -> String {
    num_bigint::BigUint::from_bytes_be(&value.to_be_bytes()).to_string()
}

struct TraceOnDrop(bool, u32, usize, Instant, bool);

impl Drop for TraceOnDrop {
    fn drop(&mut self) {
        if self.0 {
            eprintln!(
                "  override w{}: {} candidate(s), position-like={}, {} ms",
                self.1,
                self.2,
                self.4,
                self.3.elapsed().as_millis()
            );
        }
    }
}

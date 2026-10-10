//! ACIR -> Picus IR translation.
//!
//! This module owns the model (`AcirPicusModel`), the per-opcode translation
//! driver (`build_model`), cone-of-influence slicing and unsupported-opcode
//! tracking. Per-opcode constraint emission lives in the submodules:
//!
//! - `expr`          — `AssertZero` expressions (linear + nonlinear)
//! - `range`         — `RANGE` bit decomposition
//! - `bitwise`       — `AND`/`XOR` via bit decomposition
//! - `memory`        — `MemoryOp`/`MemoryInit` one-hot selector model
//! - `determinism`   — determinism abstraction for other black boxes (Tier 2)
//! - `uniqueness`    — uniqueness propagation (determined-wire lemmas)
//! - `known`         — constant propagation
//! - `ir`            — wire mapping, variable naming, coefficient helpers
//! - `wires`         — wire enumeration over opcodes/expressions

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Range,
};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, BlockId},
    },
    native_types::Witness,
};
use num_bigint::BigUint;
use picus_smt::query::IRConstraint;

mod bitwise;
mod determinism;
mod expr;
mod ir;
mod known;
mod memory;
mod range;
mod uniqueness;
mod wires;

#[cfg(test)]
mod soundness_tests;
#[cfg(test)]
mod tests;

pub(crate) use ir::{field_modulus, picus_wire, target_signal};
pub(crate) use wires::opcode_wires;

/// Hint outputs that no constraint reads.
///
/// A `BrilligCall` output appears in the opcodes only where something
/// constrains it; one that appears nowhere else — not in an assertion, a black
/// box, a memory operation or a call, and not as a parameter or return — is
/// free, but nothing it could take affects any other witness. Noir emits them
/// whenever a hint returns a tuple and the caller discards part of it
/// (`let (quotient, _) = unsafe { hint() }`); Noir's own missing-constraint
/// check reports each one as a bug. Telling them apart from real unknowns keeps
/// a scan's `unknown` column about what is actually undecided.
pub(crate) fn unread_hint_outputs(
    circuit: &acir::circuit::Circuit<FieldElement>,
) -> std::collections::BTreeSet<acir::native_types::Witness> {
    use acir::circuit::{Opcode, brillig::BrilligOutputs};
    let mut read = std::collections::BTreeSet::new();
    for opcode in &circuit.opcodes {
        read.extend(opcode_wires(opcode));
    }
    for witness in circuit
        .private_parameters
        .iter()
        .chain(circuit.public_parameters.0.iter())
        .chain(circuit.return_values.0.iter())
    {
        read.insert(picus_wire(*witness));
    }
    let mut unread = std::collections::BTreeSet::new();
    for opcode in &circuit.opcodes {
        let Opcode::BrilligCall { outputs, .. } = opcode else {
            continue;
        };
        for output in outputs {
            let witnesses = match output {
                BrilligOutputs::Simple(witness) => vec![*witness],
                BrilligOutputs::Array(witnesses) => witnesses.clone(),
            };
            unread.extend(
                witnesses
                    .into_iter()
                    .filter(|witness| !read.contains(&picus_wire(*witness))),
            );
        }
    }
    unread
}

use bitwise::{BitwiseCall, BitwiseOp, bitwise_constraint_group};
use determinism::{call_determinism_group, determinism_constraint_group};
use expr::expression_to_ir;
use known::{infer_constant_signals, infer_constant_signals_from};
use memory::memory_constraint_group;
use range::{allocate_range_aux_wires, range_constraints};
use uniqueness::infer_fixed_known_signals;
use wires::{expression_wires, function_input_wires, max_witness_index};

/// One translated opcode: the wires it touches plus the constraints emitted
/// for the original and alternative self-composition copies.
type TranslatedGroup = Result<(Vec<usize>, Vec<IRConstraint>, Vec<IRConstraint>), String>;

#[derive(Clone, Debug)]
pub(crate) struct AcirPicusModel {
    pub(crate) n_wires: usize,
    pub(crate) input_indices: BTreeSet<usize>,
    pub(crate) orig_constraints: Vec<IRConstraint>,
    pub(crate) alt_constraints: Vec<IRConstraint>,
    pub(crate) unsupported_reasons: Vec<String>,
    pub(crate) abstracted_reasons: Vec<String>,
    pub(crate) fixed_known_signals: BTreeSet<usize>,
    /// Wires provably equal to a concrete field element. Used both to pin them
    /// in the query and to cut the cone of influence without losing their
    /// value (see `target_constraints_at`).
    pub(crate) constant_signals: BTreeMap<usize, BigUint>,
    /// Exclusive upper bound of the wires that map back to ACIR witnesses.
    /// Everything at or above it is a decomposition/selector wire this crate
    /// invented, which must not be reported as part of a counterexample.
    pub(crate) witness_wire_limit: usize,
    constraint_groups: Vec<ConstraintGroup>,
    /// Constraint groups that mention no wire, so no cone can ever reach them.
    /// They are added to every query instead.
    global_groups: Vec<ConstraintGroup>,
    unsupported_issues: Vec<UnsupportedIssue>,
    abstracted_issues: Vec<AbstractionIssue>,
    dependency_edges: Vec<Vec<usize>>,
}

/// One sliced per-target query plus whether the slice is already exact.
pub(crate) struct SlicedQuery {
    pub(crate) orig: Vec<IRConstraint>,
    pub(crate) alt: Vec<IRConstraint>,
    /// `true` when no constraint that could affect the target was dropped, so
    /// a `SAT` verdict can be reported as a real finding.
    pub(crate) is_exact: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FixedMode {
    Public,
    AllParams,
}

/// Knobs that change how faithfully opcodes are translated.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ModelOptions {
    pub(crate) fixed_mode: FixedMode,
    /// Widest `RANGE` still expanded into an exact bit decomposition.
    ///
    /// A `RANGE(n)` costs `n` boolean wires plus a weighted-sum constraint, in
    /// *both* self-composition copies. Noir emits wide ranges routinely — a
    /// single `Field` truncation produces `RANGE(222)` — and a query carrying a
    /// few of those puts hundreds of boolean unknowns into one Groebner basis
    /// computation, where cvc5 exhausts memory rather than time. Above this
    /// width the range is dropped instead, which is a relaxation: it only adds
    /// solutions, so `verified` stays sound while `unsafe` gains the same
    /// caveat the determinism abstraction carries. Wide ranges are also the
    /// least informative ones - `RANGE(222)` excludes a vanishing fraction of
    /// the field.
    pub(crate) max_range_bits: u32,
}

impl Default for ModelOptions {
    fn default() -> Self {
        Self {
            fixed_mode: FixedMode::AllParams,
            max_range_bits: 64,
        }
    }
}

#[derive(Clone, Debug)]
struct UnsupportedIssue {
    reason: String,
    wires: Vec<usize>,
}

// A deterministic black box that we do not translate exactly, but model with a
// determinism (uninterpreted-function) abstraction instead of blocking the
// target. Tracked separately from unsupported issues so we can annotate any
// target whose verdict depended on the abstraction. See SOUNDNESS.md.
#[derive(Clone, Debug)]
struct AbstractionIssue {
    reason: String,
    wires: Vec<usize>,
}

#[derive(Clone, Debug)]
struct ConstraintGroup {
    // All IR constraints emitted for one ACIR opcode. Keeping the wire set and
    // ranges lets us later slice a per-target query without losing aux wires.
    wires: Vec<usize>,
    orig_range: Range<usize>,
    alt_range: Range<usize>,
}

/// Everything constant propagation can derive once the given wires are fixed,
/// together with the first constraint it finds violated by those values.
///
/// A violated constraint settles the question outright: the circuit rejects
/// this assignment, and no solver call is needed. That is the common case when
/// the inputs come from a run the program itself rejected, which is exactly
/// when this is asked.
/// How much of the circuit a given assignment actually decides.
pub(crate) fn constraint_coverage(
    circuit: &Circuit<FieldElement>,
    constants: &BTreeMap<usize, BigUint>,
) -> (usize, usize) {
    known::constraint_coverage(circuit, constants)
}

pub(crate) fn evaluate_with_inputs(
    circuit: &Circuit<FieldElement>,
    seed: &BTreeMap<usize, BigUint>,
) -> (BTreeMap<usize, BigUint>, Option<String>) {
    let constants = infer_constant_signals_from(circuit, seed);
    let violation = known::first_violated_constraint(circuit, &constants);
    (constants, violation)
}

pub(crate) fn build_model(
    circuit: &Circuit<FieldElement>,
    options: ModelOptions,
) -> AcirPicusModel {
    build_model_with_calls(circuit, options, &BTreeSet::new())
}

/// Как `build_model`, но со списком уже доказанных детерминированными схем,
/// на которые ссылается `Opcode::Call`. Список приходит снаружи, потому что
/// доказательство даёт решатель, а переводчик лишь пользуется результатом.
pub(crate) fn build_model_with_calls(
    circuit: &Circuit<FieldElement>,
    options: ModelOptions,
    deterministic_calls: &BTreeSet<u32>,
) -> AcirPicusModel {
    let fixed_mode = options.fixed_mode;
    let mut input_indices = BTreeSet::new();
    input_indices.insert(0);

    if matches!(fixed_mode, FixedMode::AllParams) {
        for witness in &circuit.private_parameters {
            input_indices.insert(picus_wire(*witness));
        }
    }

    for witness in &circuit.public_parameters.0 {
        input_indices.insert(picus_wire(*witness));
    }

    let mut orig_constraints = Vec::new();
    let mut alt_constraints = Vec::new();
    let mut unsupported_issues = Vec::new();
    let mut abstracted_issues = Vec::new();
    let mut dependency_edges = Vec::new();
    let mut constraint_groups = Vec::new();
    let mut global_groups = Vec::new();
    let mut next_aux_wire = max_witness_index(circuit).map_or(1, |index| index as usize + 2);
    let witness_wire_limit = next_aux_wire;
    let mut memory_blocks = HashMap::<BlockId, Vec<usize>>::new();

    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                let wires = expression_wires(expression);
                push_dependency_edge(&mut dependency_edges, wires.clone());
                let orig = expression_to_ir(expression, false, &input_indices)
                    .into_iter()
                    .collect();
                let alt = expression_to_ir(expression, true, &input_indices)
                    .into_iter()
                    .collect();
                push_constraint_group(
                    &mut orig_constraints,
                    &mut alt_constraints,
                    &mut constraint_groups,
                    &mut global_groups,
                    wires,
                    orig,
                    alt,
                );
            }
            Opcode::BlackBoxFuncCall(black_box) => match black_box {
                BlackBoxFuncCall::AND {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                }
                | BlackBoxFuncCall::XOR {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                } => {
                    let op = if matches!(black_box, BlackBoxFuncCall::AND { .. }) {
                        BitwiseOp::And
                    } else {
                        BitwiseOp::Xor
                    };
                    let call = BitwiseCall {
                        op,
                        lhs: *lhs,
                        rhs: *rhs,
                        output: *output,
                        num_bits: *num_bits,
                    };
                    match bitwise_constraint_group(&call, &mut next_aux_wire, &input_indices) {
                        Ok((wires, orig, alt)) => {
                            push_dependency_edge(&mut dependency_edges, wires.clone());
                            push_constraint_group(
                                &mut orig_constraints,
                                &mut alt_constraints,
                                &mut constraint_groups,
                                &mut global_groups,
                                wires,
                                orig,
                                alt,
                            );
                        }
                        Err(reason) => push_unsupported_issue(
                            &mut unsupported_issues,
                            &mut dependency_edges,
                            opcode_index,
                            reason,
                            opcode_wires(opcode),
                        ),
                    }
                }
                BlackBoxFuncCall::RANGE { input, num_bits }
                    if *num_bits > options.max_range_bits
                        && *num_bits < FieldElement::max_num_bits() =>
                {
                    let wires = function_input_wires(input);
                    if !wires.is_empty() {
                        push_dependency_edge(&mut dependency_edges, wires.clone());
                        abstracted_issues.push(AbstractionIssue {
                            reason: format!(
                                "opcode {opcode_index}: RANGE({num_bits}) dropped, wider than the \
                                 {}-bit bit-decomposition budget",
                                options.max_range_bits
                            ),
                            wires,
                        });
                    }
                }
                BlackBoxFuncCall::RANGE { input, num_bits } => {
                    let aux_wires =
                        match allocate_range_aux_wires(*input, *num_bits, &mut next_aux_wire) {
                            Ok(aux_wires) => aux_wires,
                            Err(reason) => {
                                push_unsupported_issue(
                                    &mut unsupported_issues,
                                    &mut dependency_edges,
                                    opcode_index,
                                    reason,
                                    opcode_wires(opcode),
                                );
                                continue;
                            }
                        };
                    let mut wires = function_input_wires(input);
                    wires.extend(aux_wires.iter().copied());
                    push_dependency_edge(&mut dependency_edges, wires.clone());

                    let orig = match range_constraints(
                        *input,
                        *num_bits,
                        &aux_wires,
                        false,
                        &input_indices,
                    ) {
                        Ok(constraints) => constraints,
                        Err(reason) => {
                            push_unsupported_issue(
                                &mut unsupported_issues,
                                &mut dependency_edges,
                                opcode_index,
                                reason,
                                opcode_wires(opcode),
                            );
                            continue;
                        }
                    };
                    let alt = match range_constraints(
                        *input,
                        *num_bits,
                        &aux_wires,
                        true,
                        &input_indices,
                    ) {
                        Ok(constraints) => constraints,
                        Err(reason) => {
                            push_unsupported_issue(
                                &mut unsupported_issues,
                                &mut dependency_edges,
                                opcode_index,
                                reason,
                                opcode_wires(opcode),
                            );
                            continue;
                        }
                    };
                    push_constraint_group(
                        &mut orig_constraints,
                        &mut alt_constraints,
                        &mut constraint_groups,
                        &mut global_groups,
                        wires,
                        orig,
                        alt,
                    );
                }
                // Black boxes on the functional allow-list are deterministic
                // pure functions of their inputs (hashes, ECDSA, ...). Rather
                // than blocking the target as unsupported, abstract them:
                // forget the function, keep only that equal inputs force equal
                // outputs. Curve opcodes are deliberately not on that list —
                // ACIR does not enforce their preconditions, so they are not
                // functions and must block the target instead.
                _ => match determinism_constraint_group(black_box, &input_indices) {
                    Some((wires, orig)) => {
                        push_dependency_edge(&mut dependency_edges, wires.clone());
                        abstracted_issues.push(AbstractionIssue {
                            reason: format!(
                                "opcode {opcode_index}: deterministic black box {} modeled by \
                                 determinism abstraction (output is a pure function of its inputs)",
                                black_box.name()
                            ),
                            wires: wires.clone(),
                        });
                        push_constraint_group(
                            &mut orig_constraints,
                            &mut alt_constraints,
                            &mut constraint_groups,
                            &mut global_groups,
                            wires,
                            orig,
                            Vec::new(),
                        );
                    }
                    None => push_unsupported_issue(
                        &mut unsupported_issues,
                        &mut dependency_edges,
                        opcode_index,
                        format!(
                            "unsupported black box {} (not a function of its inputs, \
                             or no outputs to abstract)",
                            black_box.name()
                        ),
                        opcode_wires(opcode),
                    ),
                },
            },
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryOp { block_id, op } => match memory_constraint_group(
                *block_id,
                op,
                &mut memory_blocks,
                &mut next_aux_wire,
                &input_indices,
            ) {
                Ok((wires, orig, alt)) => {
                    push_dependency_edge(&mut dependency_edges, wires.clone());
                    push_constraint_group(
                        &mut orig_constraints,
                        &mut alt_constraints,
                        &mut constraint_groups,
                        &mut global_groups,
                        wires,
                        orig,
                        alt,
                    );
                }
                Err(reason) => push_unsupported_issue(
                    &mut unsupported_issues,
                    &mut dependency_edges,
                    opcode_index,
                    reason,
                    opcode_wires(opcode),
                ),
            },
            Opcode::MemoryInit { block_id, init, .. } => {
                memory_blocks.insert(
                    *block_id,
                    init.iter().copied().map(picus_wire).collect::<Vec<_>>(),
                );
            }
            Opcode::Call {
                id,
                inputs,
                outputs,
                predicate,
            } => {
                let callee_proved = deterministic_calls.contains(&(id.as_usize() as u32));
                // Предикат сам по себе может нести свободу, поэтому его сигналы
                // входят в число входов вызова.
                let mut input_wires =
                    inputs.iter().copied().map(picus_wire).collect::<Vec<_>>();
                input_wires.extend(expression_wires(predicate));
                let output_wires =
                    outputs.iter().copied().map(picus_wire).collect::<Vec<_>>();
                match callee_proved
                    .then(|| {
                        call_determinism_group(
                            input_wires,
                            output_wires,
                            &input_indices,
                        )
                    })
                    .flatten()
                {
                    Some((wires, orig)) => {
                        push_dependency_edge(&mut dependency_edges, wires.clone());
                        abstracted_issues.push(AbstractionIssue {
                            reason: format!(
                                "opcode {opcode_index}: call to ACIR function {} modeled by determinism \
                                 abstraction (its returns were proved unique given its parameters)",
                                id.as_usize()
                            ),
                            wires: wires.clone(),
                        });
                        let alt = orig.clone();
                        push_constraint_group(
                            &mut orig_constraints,
                            &mut alt_constraints,
                            &mut constraint_groups,
                            &mut global_groups,
                            wires,
                            orig,
                            alt,
                        );
                    }
                    None => push_unsupported_issue(
                        &mut unsupported_issues,
                        &mut dependency_edges,
                        opcode_index,
                        if callee_proved {
                            "Call with no outputs".to_owned()
                        } else {
                            format!(
                                "Call to ACIR function {} whose determinism is not established",
                                id.as_usize()
                            )
                        },
                        opcode_wires(opcode),
                    ),
                }
            }
        }
    }
    let unsupported_reasons = unsupported_issues
        .iter()
        .map(|issue| issue.reason.clone())
        .collect();
    let abstracted_reasons = abstracted_issues
        .iter()
        .map(|issue| issue.reason.clone())
        .collect();
    let fixed_known_signals = infer_fixed_known_signals(circuit, &input_indices);
    let constant_signals = infer_constant_signals(circuit);

    AcirPicusModel {
        n_wires: next_aux_wire,
        input_indices,
        orig_constraints,
        alt_constraints,
        unsupported_reasons,
        abstracted_reasons,
        fixed_known_signals,
        constant_signals,
        witness_wire_limit,
        constraint_groups,
        global_groups,
        unsupported_issues,
        abstracted_issues,
        dependency_edges,
    }
}

impl AcirPicusModel {
    pub(crate) fn is_fixed_known_signal(&self, signal: usize) -> bool {
        self.fixed_known_signals.contains(&signal)
    }

    /// Whether this target is decided without looking at any opcode: it is
    /// either a fixed input itself, or pinned by linear propagation from the
    /// fixed inputs. Such targets must not be reported `unsupported` just
    /// because something untranslated shares their component.
    pub(crate) fn is_trivially_determined(&self, target: Witness) -> bool {
        let signal = target_signal(target);
        self.input_indices.contains(&signal) || self.fixed_known_signals.contains(&signal)
    }

    /// Whether `target` is undetermined but sealed off: every opcode that reads
    /// it reads nothing else that is undetermined. Its value can then differ
    /// between two assignments without any other witness differing, so it
    /// cannot carry a divergence anywhere — the inverse hint of an `IsZero`
    /// gadget, free exactly when the tested value is zero, is the usual case.
    /// The witness itself may well be free; this only says nothing depends on
    /// it.
    pub(crate) fn is_isolated(&self, circuit: &Circuit<FieldElement>, target: Witness) -> bool {
        if self.is_trivially_determined(target) {
            return false;
        }
        let wire = picus_wire(target);
        let determined =
            |w: &usize| self.input_indices.contains(w) || self.fixed_known_signals.contains(w);
        let mut readers = 0usize;
        for opcode in &circuit.opcodes {
            let wires = opcode_wires(opcode);
            if !wires.contains(&wire) {
                continue;
            }
            readers += 1;
            if !wires.iter().all(|w| *w == wire || determined(w)) {
                return false;
            }
        }
        let is_interface = circuit
            .return_values
            .0
            .iter()
            .chain(circuit.public_parameters.0.iter())
            .chain(circuit.private_parameters.iter())
            .any(|w| *w == target);
        readers > 0 && !is_interface
    }

    pub(crate) fn unsupported_reasons_for_target(&self, target: Witness) -> Vec<String> {
        let component = self.dependency_component(target_signal(target));

        self.unsupported_issues
            .iter()
            .filter(|issue| {
                issue.wires.is_empty() || issue.wires.iter().any(|wire| component.contains(wire))
            })
            .map(|issue| issue.reason.clone())
            .collect()
    }

    /// Determinism-abstraction issues that lie in this target's cone. A verdict
    /// for such a target is computed under the abstraction: `verified` stays
    /// sound, but `unsafe` may be spurious (see SOUNDNESS.md). The caller
    /// surfaces these as caveats rather than blocking the scan.
    pub(crate) fn abstraction_reasons_for_target(&self, target: Witness) -> Vec<String> {
        let component = self.dependency_component(target_signal(target));

        self.abstracted_issues
            .iter()
            .filter(|issue| issue.wires.iter().any(|wire| component.contains(wire)))
            .map(|issue| issue.reason.clone())
            .collect()
    }

    /// The exact query for a target, i.e. the fixpoint of `target_constraints_at`.
    #[cfg(test)]
    pub(crate) fn target_constraints(
        &self,
        target: Witness,
    ) -> (Vec<IRConstraint>, Vec<IRConstraint>) {
        let query = self.target_constraints_at(target, usize::MAX);
        assert!(query.is_exact);
        (query.orig, query.alt)
    }

    /// Constraints for one target at abstraction level `depth`.
    ///
    /// Level 0 is the coarsest abstraction: the cone stops at every wire that
    /// propagation proved determined by the fixed inputs, keeping only Picus's
    /// `x_s = y_s`. Each further level admits one more hop past that boundary,
    /// pulling the constraints that *define* those wires back in. The sequence
    /// is monotone and reaches the exact query in finitely many steps.
    ///
    /// Soundness (see SOUNDNESS.md). Every level is an over-approximation:
    /// dropping constraints only adds solutions, and the `x_s = y_s`
    /// equalities are implied by the real system, so they remove none. Hence
    /// `UNSAT` at *any* level already proves the target unique. `SAT` proves
    /// nothing until the level is exact, which is what `is_exact` reports.
    ///
    /// This is what makes large circuits tractable without giving up
    /// correctness. A purely aggressive cut is fast but wrong — it reported the
    /// repository's own `verified_division_hint` example as `unsafe`, because
    /// `inverse * d = 1` (the proof that `d != 0`) lives outside the cone, and
    /// every Field division has that shape. A purely exact cone is right but
    /// hands the solver the whole circuit.
    pub(crate) fn target_constraints_at(&self, target: Witness, depth: usize) -> SlicedQuery {
        let signal = target_signal(target);
        let (component, is_exact) = self.layered_component(signal, depth);

        let mut orig = Vec::new();
        let mut alt = Vec::new();
        let mut pinned = BTreeSet::new();

        for group in self
            .constraint_groups
            .iter()
            .filter(|group| group.wires.iter().any(|wire| component.contains(wire)))
            .chain(&self.global_groups)
        {
            orig.extend(
                self.orig_constraints[group.orig_range.clone()]
                    .iter()
                    .cloned(),
            );
            alt.extend(
                self.alt_constraints[group.alt_range.clone()]
                    .iter()
                    .cloned(),
            );
            for wire in &group.wires {
                if self.constant_signals.contains_key(wire) {
                    pinned.insert(*wire);
                }
            }
        }

        // Re-pin every constant signal the sliced query still mentions. This is
        // the one cut that loses nothing: the wire has a single possible value
        // and it is restored explicitly.
        for wire in pinned {
            let value = &self.constant_signals[&wire];
            orig.push(IRConstraint::VarEq(format!("x{wire}"), value.clone()));
            if !self.input_indices.contains(&wire) {
                alt.push(IRConstraint::VarEq(format!("y{wire}"), value.clone()));
            }
        }

        SlicedQuery {
            orig,
            alt,
            is_exact,
        }
    }

    /// A deliberately small query around `target`: only the constraint groups
    /// within `radius` hops of it, with the cone cut at everything already
    /// determined.
    ///
    /// This is an over-approximation twice over — constraints outside the
    /// window are dropped, and determined wires are cut — so `SAT` on it means
    /// nothing, while `UNSAT` proves the target unique. That asymmetry is the
    /// whole point: a small window is cheap to solve, and every `UNSAT` feeds
    /// straight back into the determined set, which shrinks the next window.
    ///
    /// It exists because the exact cone is useless for scaling here. Influence
    /// is undirected for a satisfiability question, so in a program where each
    /// value feeds the next the cone of *any* witness is the entire circuit,
    /// and a few dozen quadratic constraints in two copies already exhaust the
    /// finite-field solver. Every `Field`-to-integer cast Noir emits is a
    /// self-contained five-constraint gadget that a radius-2 window settles in
    /// milliseconds.
    pub(crate) fn local_window(&self, target: Witness, radius: usize) -> SlicedQuery {
        let signal = target_signal(target);

        let mut cut = BTreeSet::new();
        cut.insert(0);
        cut.extend(self.constant_signals.keys().copied());
        cut.extend(self.fixed_known_signals.iter().copied());
        cut.remove(&signal);

        let mut window = BTreeSet::from([signal]);
        for _ in 0..radius {
            let mut grown = window.clone();
            for edge in &self.dependency_edges {
                if !edge.iter().any(|wire| window.contains(wire)) {
                    continue;
                }
                for wire in edge {
                    if !cut.contains(wire) {
                        grown.insert(*wire);
                    }
                }
            }
            if grown == window {
                break;
            }
            window = grown;
        }

        self.collect_groups(&window)
    }

    /// Emit the constraints of every group touching `component`, plus the
    /// global groups and the pins for any constant wire mentioned.
    fn collect_groups(&self, component: &BTreeSet<usize>) -> SlicedQuery {
        let mut orig = Vec::new();
        let mut alt = Vec::new();
        let mut pinned = BTreeSet::new();

        for group in self
            .constraint_groups
            .iter()
            .filter(|group| group.wires.iter().any(|wire| component.contains(wire)))
            .chain(&self.global_groups)
        {
            orig.extend(
                self.orig_constraints[group.orig_range.clone()]
                    .iter()
                    .cloned(),
            );
            alt.extend(
                self.alt_constraints[group.alt_range.clone()]
                    .iter()
                    .cloned(),
            );
            for wire in &group.wires {
                if self.constant_signals.contains_key(wire) {
                    pinned.insert(*wire);
                }
            }
        }

        for wire in pinned {
            let value = &self.constant_signals[&wire];
            orig.push(IRConstraint::VarEq(format!("x{wire}"), value.clone()));
            if !self.input_indices.contains(&wire) {
                alt.push(IRConstraint::VarEq(format!("y{wire}"), value.clone()));
            }
        }

        SlicedQuery {
            orig,
            alt,
            is_exact: false,
        }
    }

    /// Record a wire as determined. Used by the refinement loop when a local
    /// query proves uniqueness; every later cut and window gets tighter.
    pub(crate) fn mark_determined(&mut self, signal: usize) {
        self.fixed_known_signals.insert(signal);
    }

    /// Witnesses propagation left open, in ACIR order.
    pub(crate) fn undetermined_witnesses(&self) -> Vec<Witness> {
        (1..self.witness_wire_limit)
            .filter(|wire| !self.fixed_known_signals.contains(wire))
            .map(|wire| Witness((wire - 1) as u32))
            .collect()
    }

    /// The wires the exact query for this target constrains. A divergence can
    /// only involve these, so a certificate only has to re-check the opcodes
    /// that touch them.
    pub(crate) fn exact_component(&self, target: Witness) -> BTreeSet<usize> {
        self.layered_component(target_signal(target), usize::MAX).0
    }

    /// The target's component when `depth` layers of determined wires may be
    /// traversed. Also reports whether the result already equals the exact
    /// component, i.e. whether the abstraction has converged.
    fn layered_component(&self, signal: usize, depth: usize) -> (BTreeSet<usize>, bool) {
        // Constant wires are cut at every level: they are re-pinned by value,
        // so nothing is lost and nothing needs refining.
        let mut hard_cut = BTreeSet::new();
        hard_cut.insert(0);
        hard_cut.extend(self.constant_signals.keys().copied());

        let mut soft_cut = self
            .fixed_known_signals
            .difference(&hard_cut)
            .copied()
            .collect::<BTreeSet<_>>();
        soft_cut.remove(&signal);

        let mut component = BTreeSet::new();
        for _ in 0..=depth {
            // Whether *this* round's component is computed without cutting any
            // determined wire. It has to be decided before the refinement step
            // below, since that step mutates `soft_cut` for the next round.
            let exact = soft_cut.is_empty();
            let mut cut = hard_cut.clone();
            cut.extend(soft_cut.iter().copied());
            component = self.dependency_component_cut(signal, &cut);
            if exact {
                return (component, true);
            }
            // Refine: admit the determined wires that sit on the cone's
            // boundary, so the next round pulls in the constraints that give
            // them their value.
            let boundary = self
                .dependency_edges
                .iter()
                .filter(|edge| edge.iter().any(|wire| component.contains(wire)))
                .flat_map(|edge| edge.iter().copied())
                .filter(|wire| soft_cut.contains(wire))
                .collect::<Vec<_>>();
            if boundary.is_empty() {
                // No determined wire touches the cone, so admitting more of
                // them cannot grow it: this component is already the exact one.
                return (component, true);
            }
            for wire in boundary {
                soft_cut.remove(&wire);
            }
        }

        (component, false)
    }

    fn dependency_component(&self, target: usize) -> BTreeSet<usize> {
        self.dependency_component_cut(target, &self.input_indices)
    }

    fn dependency_component_cut(
        &self,
        target: usize,
        cut_set: &BTreeSet<usize>,
    ) -> BTreeSet<usize> {
        let mut component = BTreeSet::new();
        if cut_set.contains(&target) {
            return component;
        }

        component.insert(target);
        let mut changed = true;
        while changed {
            changed = false;
            for edge in &self.dependency_edges {
                if !edge.iter().any(|wire| component.contains(wire)) {
                    continue;
                }
                for wire in edge {
                    if !cut_set.contains(wire) && component.insert(*wire) {
                        changed = true;
                    }
                }
            }
        }

        component
    }
}

fn push_constraint_group(
    orig_constraints: &mut Vec<IRConstraint>,
    alt_constraints: &mut Vec<IRConstraint>,
    constraint_groups: &mut Vec<ConstraintGroup>,
    global_groups: &mut Vec<ConstraintGroup>,
    mut wires: Vec<usize>,
    orig: Vec<IRConstraint>,
    alt: Vec<IRConstraint>,
) {
    // ACIR opcodes can expand to several Picus constraints, especially
    // RANGE/AND/XOR with decomposition wires. We keep them as an indivisible
    // group so slicing cannot keep the public-facing wire and drop its aux bits.
    let orig_start = orig_constraints.len();
    let alt_start = alt_constraints.len();
    orig_constraints.extend(orig);
    alt_constraints.extend(alt);

    if orig_constraints.len() == orig_start && alt_constraints.len() == alt_start {
        return;
    }

    wires.sort_unstable();
    wires.dedup();
    let group = ConstraintGroup {
        wires,
        orig_range: orig_start..orig_constraints.len(),
        alt_range: alt_start..alt_constraints.len(),
    };
    // A constraint over no wire at all (only the constant term) cannot be
    // reached by any cone, so it goes to the always-included set rather than
    // being silently unreachable.
    if group.wires.is_empty() {
        global_groups.push(group);
    } else {
        constraint_groups.push(group);
    }
}

fn push_unsupported_issue(
    unsupported_issues: &mut Vec<UnsupportedIssue>,
    dependency_edges: &mut Vec<Vec<usize>>,
    opcode_index: usize,
    reason: String,
    wires: Vec<usize>,
) {
    push_dependency_edge(dependency_edges, wires.clone());
    unsupported_issues.push(UnsupportedIssue {
        reason: format!("opcode {opcode_index}: {reason}"),
        wires,
    });
}

fn push_dependency_edge(dependency_edges: &mut Vec<Vec<usize>>, mut wires: Vec<usize>) {
    wires.sort_unstable();
    wires.dedup();
    if !wires.is_empty() {
        dependency_edges.push(wires);
    }
}

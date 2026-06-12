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
//! - `known`         — fixed-known-signal propagation (incl. Tier 1)
//! - `ir`            — wire mapping, variable naming, coefficient helpers
//! - `wires`         — wire enumeration over opcodes/expressions

use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use acir::{
    FieldElement,
    circuit::{
        Circuit, Opcode,
        opcodes::{BlackBoxFuncCall, BlockId},
    },
    native_types::Witness,
};
use picus_smt::query::IRConstraint;

mod bitwise;
mod determinism;
mod expr;
mod ir;
mod known;
mod memory;
mod range;
mod wires;

#[cfg(test)]
mod soundness_tests;
#[cfg(test)]
mod tests;

pub(crate) use ir::{picus_wire, target_signal};
pub(crate) use wires::opcode_wires;

use bitwise::{BitwiseOp, bitwise_constraint_group};
use determinism::determinism_constraint_group;
use expr::expression_to_ir;
use known::infer_fixed_known_signals;
use memory::memory_constraint_group;
use range::{allocate_range_aux_wires, range_constraints};
use wires::{expression_wires, function_input_wires, max_witness_index};

#[derive(Clone, Debug)]
pub(crate) struct AcirPicusModel {
    pub(crate) n_wires: usize,
    pub(crate) input_indices: HashSet<usize>,
    pub(crate) orig_constraints: Vec<IRConstraint>,
    pub(crate) alt_constraints: Vec<IRConstraint>,
    pub(crate) unsupported_reasons: Vec<String>,
    pub(crate) abstracted_reasons: Vec<String>,
    pub(crate) fixed_known_signals: HashSet<usize>,
    constraint_groups: Vec<ConstraintGroup>,
    unsupported_issues: Vec<UnsupportedIssue>,
    abstracted_issues: Vec<AbstractionIssue>,
    dependency_edges: Vec<Vec<usize>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FixedMode {
    Public,
    AllParams,
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

pub(crate) fn build_model(
    circuit: &Circuit<FieldElement>,
    fixed_mode: FixedMode,
) -> AcirPicusModel {
    let mut input_indices = HashSet::new();
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
    let mut next_aux_wire = max_witness_index(circuit).map_or(1, |index| index as usize + 2);
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
                } => {
                    match bitwise_constraint_group(
                        BitwiseOp::And,
                        *lhs,
                        *rhs,
                        *output,
                        *num_bits,
                        &mut next_aux_wire,
                        &input_indices,
                    ) {
                        Ok((wires, orig, alt)) => {
                            push_dependency_edge(&mut dependency_edges, wires.clone());
                            push_constraint_group(
                                &mut orig_constraints,
                                &mut alt_constraints,
                                &mut constraint_groups,
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
                BlackBoxFuncCall::XOR {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                } => {
                    match bitwise_constraint_group(
                        BitwiseOp::Xor,
                        *lhs,
                        *rhs,
                        *output,
                        *num_bits,
                        &mut next_aux_wire,
                        &input_indices,
                    ) {
                        Ok((wires, orig, alt)) => {
                            push_dependency_edge(&mut dependency_edges, wires.clone());
                            push_constraint_group(
                                &mut orig_constraints,
                                &mut alt_constraints,
                                &mut constraint_groups,
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
                        wires,
                        orig,
                        alt,
                    );
                }
                // Every remaining black box is a deterministic pure function of
                // its inputs (hashes, ECDSA, curve ops, ...). Rather than
                // blocking the target as unsupported, abstract it: forget the
                // function, keep only that equal inputs force equal outputs.
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
                            "unsupported black box {} (no outputs to abstract)",
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
            Opcode::Call { .. } => push_unsupported_issue(
                &mut unsupported_issues,
                &mut dependency_edges,
                opcode_index,
                "unsupported Call".to_owned(),
                opcode_wires(opcode),
            ),
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

    AcirPicusModel {
        n_wires: next_aux_wire,
        input_indices,
        orig_constraints,
        alt_constraints,
        unsupported_reasons,
        abstracted_reasons,
        fixed_known_signals,
        constraint_groups,
        unsupported_issues,
        abstracted_issues,
        dependency_edges,
    }
}

impl AcirPicusModel {
    pub(crate) fn is_fixed_known_signal(&self, signal: usize) -> bool {
        self.fixed_known_signals.contains(&signal)
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

    pub(crate) fn target_constraints(
        &self,
        target: Witness,
    ) -> (Vec<IRConstraint>, Vec<IRConstraint>) {
        // Build a cone-of-influence for this exact target and stop at values
        // already determined by fixed/public inputs. This is the main scaling
        // guard: Picus sees the vulnerable boundary, not the whole circuit.
        //
        // Soundness (see SOUNDNESS.md): cutting at `fixed_known_signals` is safe
        // because a fixed-known signal takes the same value in both
        // self-composition copies (it is uniquely determined by the shared
        // inputs), so constraints reachable only *through* it cannot create a
        // divergence in the target. Dropping them never hides an `unsafe`. The
        // cone itself over-approximates influence (edges are undirected and
        // constraint groups are kept whole), so it never drops a constraint
        // that could matter.
        let component =
            self.dependency_component_cut(target_signal(target), &self.fixed_known_signals);
        let mut orig = Vec::new();
        let mut alt = Vec::new();

        for group in &self.constraint_groups {
            if !group.wires.iter().any(|wire| component.contains(wire)) {
                continue;
            }
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
        }

        (orig, alt)
    }

    fn dependency_component(&self, target: usize) -> HashSet<usize> {
        self.dependency_component_cut(target, &self.input_indices)
    }

    fn dependency_component_cut(&self, target: usize, cut_set: &HashSet<usize>) -> HashSet<usize> {
        let mut component = HashSet::new();
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

    wires.sort_unstable();
    wires.dedup();
    if !wires.is_empty()
        && (orig_constraints.len() > orig_start || alt_constraints.len() > alt_start)
    {
        constraint_groups.push(ConstraintGroup {
            wires,
            orig_range: orig_start..orig_constraints.len(),
            alt_range: alt_start..alt_constraints.len(),
        });
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

//! The determinism (uninterpreted-function) abstraction for deterministic
//! black boxes that are not translated exactly (Tier 2, see SOUNDNESS.md).

use std::collections::BTreeSet;

use acir::{FieldElement, circuit::opcodes::BlackBoxFuncCall};
use num_bigint::BigUint;
use num_traits::One;
use picus_smt::query::{IRConstraint, IRTerm};

use super::ir::{neg_mod_coeff, picus_wire, var_name};

/// Whether this black box really is a pure function of its declared inputs.
///
/// The abstraction below encodes exactly that property, so it must not be
/// applied to opcodes that ACIR does not constrain to be functional. Two are
/// documented as such in `acir`: `EmbeddedCurveAdd` "makes the following
/// assumptions but does not enforce them" (doubling vs addition, no infinity
/// point), and `MultiScalarMul` carries the analogous backend requirement. For
/// inputs violating those preconditions the gate is genuinely
/// under-constrained — which is the bug class this tool exists to find — so
/// they are routed to `unsupported` instead of being abstracted away.
/// `RecursiveAggregation` is excluded for the same reason: its meaning is
/// enforced by the proving backend, not by ACIR.
///
/// The list is an allow-list rather than a deny-list on purpose: a black box
/// added by a future Noir revision blocks the target until it has been reviewed
/// here, instead of silently inheriting a functionality claim.
pub(super) fn is_functional_black_box(black_box: &BlackBoxFuncCall<FieldElement>) -> bool {
    matches!(
        black_box,
        BlackBoxFuncCall::AES128Encrypt { .. }
            | BlackBoxFuncCall::AND { .. }
            | BlackBoxFuncCall::XOR { .. }
            | BlackBoxFuncCall::RANGE { .. }
            | BlackBoxFuncCall::Blake2s { .. }
            | BlackBoxFuncCall::Blake3 { .. }
            | BlackBoxFuncCall::EcdsaSecp256k1 { .. }
            | BlackBoxFuncCall::EcdsaSecp256r1 { .. }
            | BlackBoxFuncCall::Keccakf1600 { .. }
            | BlackBoxFuncCall::Sha256Compression { .. }
            | BlackBoxFuncCall::Poseidon2Permutation { .. }
    )
}

// Build the determinism abstraction (Tier 2) for a deterministic black box
// `outputs = F(inputs)` we do not translate exactly. Returns the wire set and
// one cross-copy constraint per output. `None` when there is nothing to
// abstract (no outputs, or the opcode is not functional), leaving the caller to
// fall back to `unsupported`.
pub(super) fn determinism_constraint_group(
    black_box: &BlackBoxFuncCall<FieldElement>,
    input_indices: &BTreeSet<usize>,
) -> Option<(Vec<usize>, Vec<IRConstraint>)> {
    if !is_functional_black_box(black_box) {
        return None;
    }

    let output_wires = black_box
        .get_outputs_vec()
        .into_iter()
        .map(picus_wire)
        .collect::<Vec<_>>();
    if output_wires.is_empty() {
        return None;
    }

    let mut input_wires = black_box
        .get_input_witnesses()
        .into_iter()
        .map(picus_wire)
        .collect::<Vec<_>>();
    if let Some(predicate) = black_box.get_predicate() {
        input_wires.push(picus_wire(predicate));
    }

    let constraints = output_wires
        .iter()
        .map(|&output| determinism_constraint(output, &input_wires, input_indices))
        .collect::<Vec<_>>();

    let mut wires = input_wires;
    wires.extend(output_wires);
    Some((wires, constraints))
}

/// Тот же приём детерминизма, но для вызова другой ACIR-схемы (`Opcode::Call`).
///
/// Применять можно ТОЛЬКО когда вызываемая схема уже доказана детерминированной:
/// её возвращаемые значения однозначны при её параметрах. Тогда «равные входы =>
/// равные выходы» — истинное свойство вызова, и абстракция лишь расширяет
/// множество решений, поэтому вердикт `verified` остаётся корректным.
///
/// Зачем понадобилось. Атрибут `#[fold]` компилирует функцию в ОТДЕЛЬНУЮ
/// ACIR-схему, связанную опкодом `Call`. Пока `Call` был неподдерживаемым, выходы
/// главной схемы у любой программы с `#[fold]` оставались неразобранными —
/// измерено на делительном гаджете: без `#[fold]` инструмент находил дыру при
/// a=b=0, с `#[fold]` выдавал `unsupported`. А `#[fold]` — ровно то, чем
/// пользуются боевые схемы для рекурсии.
pub(super) fn call_determinism_group(
    input_wires: Vec<usize>,
    output_wires: Vec<usize>,
    input_indices: &BTreeSet<usize>,
) -> Option<(Vec<usize>, Vec<IRConstraint>)> {
    if output_wires.is_empty() {
        return None;
    }
    let constraints = output_wires
        .iter()
        .map(|&output| determinism_constraint(output, &input_wires, input_indices))
        .collect::<Vec<_>>();
    let mut wires = input_wires;
    wires.extend(output_wires);
    Some((wires, constraints))
}

// Encode `inputs agree across the two copies => this output agrees`, i.e. the
// determinism of `F`, without modeling `F` itself:
//
//   out_x = out_y  OR  in_1^x != in_1^y  OR  ...  OR  in_n^x != in_n^y
//
// The solution set is a superset of the real one (we keep determinism, forget
// the value), so UNSAT / `verified` stays sound. Inputs fixed across both
// copies share a single `x` variable, so their disjunct is dropped here and the
// output is forced equal whenever it depends only on fixed inputs.
fn determinism_constraint(
    output: usize,
    inputs: &[usize],
    input_indices: &BTreeSet<usize>,
) -> IRConstraint {
    let mut disjuncts = vec![IRConstraint::Linear(vec![
        IRTerm {
            coeff: BigUint::one(),
            var: var_name(output, false, input_indices),
        },
        IRTerm {
            coeff: neg_mod_coeff(&BigUint::one()),
            var: var_name(output, true, input_indices),
        },
    ])];

    for &input in inputs {
        let original = var_name(input, false, input_indices);
        let alternative = var_name(input, true, input_indices);
        if original != alternative {
            disjuncts.push(IRConstraint::VarNeq(original, alternative));
        }
    }

    IRConstraint::Or(disjuncts)
}

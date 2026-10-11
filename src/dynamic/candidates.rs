//! Which values to try for a witness the search moves, and the circuit
//! structure those choices are read from (hints, outputs, ranges, the memory
//! blocks a hint indexes).

use std::collections::{BTreeMap, BTreeSet};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode,
        brillig::BrilligOutputs,
        opcodes::{BlackBoxFuncCall, BlockType, FunctionInput},
    },
    native_types::Witness,
};
use num_bigint::BigUint;

use crate::dynamic::repair::witnesses_of;
use crate::field::to_biguint;

/// Every value that makes a hint land on a valid position of a memory block it
/// indexes.
///
/// ACIR reads `block[idx]` with `idx` a witness; when the source wrote
/// `haystack[i + offset]`, `idx` is defined by `idx - offset - i = 0`. For such
/// a pair the hint can only matter at `k - i` for `k` in the block, so those
/// are exactly the values worth trying. Capped, so a huge block does not turn
/// one hint into thousands of repair passes.
pub(crate) fn index_candidates(
    circuit: &Circuit<FieldElement>,
) -> BTreeMap<u32, Vec<FieldElement>> {
    const CAP: usize = 1024;
    let mut block_len = std::collections::HashMap::new();
    let mut index_len: BTreeMap<u32, usize> = BTreeMap::new();
    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::MemoryInit { block_id, init, .. } => {
                block_len.insert(*block_id, init.len());
            }
            Opcode::MemoryOp { block_id, op } => {
                if let Some(len) = block_len.get(block_id) {
                    let entry = index_len.entry(op.index.witness_index()).or_insert(0);
                    *entry = (*entry).max(*len);
                }
            }
            _ => {}
        }
    }
    let mut found: BTreeMap<u32, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut add = |hint: u32, shift: FieldElement, len: usize| {
        let entry = found.entry(hint).or_default();
        for k in 0..len.min(CAP) {
            if entry.len() >= CAP {
                break;
            }
            entry.insert((FieldElement::from(k as u128) - shift).to_be_bytes());
        }
    };
    for (&index, &len) in &index_len {
        add(index, FieldElement::zero(), len);
    }
    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else {
            continue;
        };
        if !expression.mul_terms.is_empty() || expression.linear_combinations.len() != 2 {
            continue;
        }
        let [(a, x), (b, y)] = [
            expression.linear_combinations[0],
            expression.linear_combinations[1],
        ];
        // a*x + b*y + q = 0. If x is an index and y = x - c, then y's valid
        // values are k - c. Same with the roles swapped.
        for ((ci, idx), (ch, hint)) in [((a, x), (b, y)), ((b, y), (a, x))] {
            let Some(&len) = index_len.get(&idx.witness_index()) else {
                continue;
            };
            if ci.is_zero() || -(ch / ci) != FieldElement::one() {
                continue;
            }
            // idx = hint + c with c = -q / ci.
            let c = -(expression.q_c / ci);
            add(hint.witness_index(), c, len);
        }
    }
    // Indices are rarely the hint itself. A read inside a loop compiles to
    // `idx = hint * predicate` (or `(hint + i) * predicate`), which the exact
    // rule above cannot see. Walk the constraints that define each index back
    // to the hints they mention, a few steps deep, and give every hint found
    // the whole block as candidates: a wider net, still bounded by the block.
    let hints = hint_witnesses(circuit).into_iter().collect::<BTreeSet<_>>();
    let mut mentions: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (position, opcode) in circuit.opcodes.iter().enumerate() {
        if let Opcode::AssertZero(expression) = opcode {
            for witness in witnesses_of(expression) {
                mentions.entry(witness).or_default().push(position);
            }
        }
    }
    for (&index, &len) in &index_len {
        let mut frontier = vec![index];
        let mut visited = BTreeSet::from([index]);
        for _depth in 0..3 {
            let mut next = Vec::new();
            for witness in frontier {
                let Some(positions) = mentions.get(&witness) else {
                    continue;
                };
                // A witness in many constraints is a hub (a loop predicate);
                // following it would connect everything to everything.
                if positions.len() > 24 {
                    continue;
                }
                for &position in positions {
                    let Opcode::AssertZero(expression) = &circuit.opcodes[position] else {
                        continue;
                    };
                    for other in witnesses_of(expression) {
                        if !visited.insert(other) {
                            continue;
                        }
                        if hints.contains(&other) {
                            add(other, FieldElement::zero(), len);
                        } else {
                            next.push(other);
                        }
                    }
                }
            }
            frontier = next;
        }
    }

    found
        .into_iter()
        .map(|(hint, values)| {
            (
                hint,
                values
                    .into_iter()
                    .map(|bytes| FieldElement::from_be_bytes_reduce(&bytes))
                    .collect(),
            )
        })
        .collect()
}

/// Steps that make a hint wrap around the field modulus.
///
/// Neighbouring values find a hint that is simply free. They never find the
/// other shape, where a hint is pinned by an equation like `input = 2^k * q + r`
/// and the second solution lies a whole modulus away: `q` moves by `p / 2^k`
/// and `r` absorbs the difference, so the equation still holds over the field
/// while the integers it was meant to represent are completely different. That
/// is the arithmetic behind the `Field as uN` cast forgery, and a search that
/// only tries `original + 1` cannot reach it no matter how long it runs.
///
/// The step is derived from the coefficients the hint actually appears with,
/// so no guessing is involved: for a hint multiplied by `c`, moving it by
/// `p / c` shifts the term by very nearly the modulus.
pub(crate) fn wrap_candidates(circuit: &Circuit<FieldElement>) -> BTreeMap<u32, Vec<FieldElement>> {
    let modulus = crate::translate::field_modulus();
    let mut steps: BTreeMap<u32, BTreeSet<Vec<u8>>> = BTreeMap::new();

    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else {
            continue;
        };
        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = to_biguint(*coefficient);
            // Take the signed magnitude. A coefficient of `-2^128` is stored as
            // `p - 2^128`, and dividing the modulus by that gives 1, which is
            // no step at all — the whole point is to move by `p / 2^128`.
            let magnitude = std::cmp::min(coeff.clone(), &modulus - &coeff);
            if magnitude <= BigUint::from(1u32) {
                continue;
            }
            let quotient = &modulus / &magnitude;
            if quotient == BigUint::ZERO {
                continue;
            }
            let entry = steps.entry(witness.witness_index()).or_default();
            for step in [
                quotient.clone(),
                &quotient + BigUint::from(1u32),
                &modulus - &quotient,
            ] {
                entry.insert(step.to_bytes_be());
            }
        }
    }

    steps
        .into_iter()
        .map(|(witness, values)| {
            (
                witness,
                values
                    .into_iter()
                    .map(|bytes| FieldElement::from_be_bytes_reduce(&bytes))
                    .collect(),
            )
        })
        .collect()
}

/// Alternative values to try for a hint.
///
/// The order matters more than the count. A hint that is genuinely free
/// usually accepts anything, so a neighbouring value finds it immediately; a
/// hint that is pinned by a range check or a boolean constraint only breaks at
/// the edges, which is what `0`, `1` and `-1` are for. Trying a wide spread
/// first would waste attempts on values that any range check rejects outright.
pub(crate) fn candidate_values(original: FieldElement, attempts: usize) -> Vec<FieldElement> {
    let one = FieldElement::one();
    let mut values = vec![
        original + one,
        original - one,
        FieldElement::zero(),
        one,
        -one,
        original + original,
        original + FieldElement::from(256u128),
    ];
    values.retain(|value| *value != original);
    values.dedup();
    values.truncate(attempts.max(1));
    values
}

/// Values to try for an input.
///
/// An input is not free the way a hint is — the circuit range-checks it — so
/// the interesting values are the ones at the edge of that range. Overflow and
/// truncation checks only misbehave there, and both advisories in this class
/// were off-by-one guards: one that used `u128::MAX - 1` where it needed
/// `u128::MAX`, and one where a cast's quotient bound left the top of the
/// field reachable. A uniform draw would essentially never land on them.
pub(crate) fn input_candidates(
    original: FieldElement,
    width: Option<u32>,
    attempts: usize,
) -> Vec<FieldElement> {
    let mut values = candidate_values(original, attempts);
    if let Some(width) = width.filter(|width| *width <= 128) {
        let top = (BigUint::from(1u32) << width) - BigUint::from(1u32);
        for edge in [
            top.clone(),
            &top - BigUint::from(1u32),
            BigUint::from(1u32) << (width - 1),
        ] {
            values.push(FieldElement::from_be_bytes_reduce(&edge.to_bytes_be()));
        }
    }
    values.retain(|value| *value != original);
    values.dedup();
    values
}

/// The tightest `RANGE` width each witness carries, which is how wide the type
/// behind it is.
pub(crate) fn range_widths(circuit: &Circuit<FieldElement>) -> BTreeMap<u32, u32> {
    let mut widths = BTreeMap::new();
    for opcode in &circuit.opcodes {
        if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(witness),
            num_bits,
        }) = opcode
        {
            widths
                .entry(witness.witness_index())
                .and_modify(|known: &mut u32| *known = (*known).min(*num_bits))
                .or_insert(*num_bits);
        }
    }
    widths
}

/// The circuit's public outputs.
///
/// `return_values` is not the whole story. When a program is written
/// `-> return_data T`, Noir routes its outputs through a memory block of type
/// `ReturnData` and leaves `return_values` empty, so a search that only looked
/// there would compare nothing and call every divergence internal. Noir's own
/// AST fuzzer emits that form for roughly one program in eight, which is a
/// large blind spot to leave open.
pub(crate) fn public_outputs(circuit: &Circuit<FieldElement>) -> BTreeSet<u32> {
    let mut outputs = circuit
        .return_values
        .0
        .iter()
        .map(|witness| witness.witness_index())
        .collect::<BTreeSet<_>>();

    for opcode in &circuit.opcodes {
        if let Opcode::MemoryInit {
            init,
            block_type: BlockType::ReturnData,
            ..
        } = opcode
        {
            outputs.extend(init.iter().map(Witness::witness_index));
        }
    }

    outputs
}

/// Witnesses a `BrilligCall` produces. These are the prover's free choices.
pub(crate) fn hint_witnesses(circuit: &Circuit<FieldElement>) -> Vec<u32> {
    let mut found = Vec::new();
    for opcode in &circuit.opcodes {
        let Opcode::BrilligCall { outputs, .. } = opcode else {
            continue;
        };
        for output in outputs {
            match output {
                BrilligOutputs::Simple(witness) => found.push(witness.witness_index()),
                BrilligOutputs::Array(witnesses) => {
                    found.extend(witnesses.iter().map(Witness::witness_index));
                }
            }
        }
    }
    found
}

//! Translation of `MemoryOp` reads/writes over an initialized block, using a
//! boolean one-hot selector vector tied to the dynamic index.

use std::collections::{HashMap, HashSet};

use acir::{
    FieldElement,
    circuit::opcodes::{BlockId, MemOp, MemOpKind},
    native_types::Witness,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

use super::TranslatedGroup;
use super::ir::{boolean_wire_constraint, neg_mod_coeff, picus_wire, var_name};

pub(super) fn memory_constraint_group(
    block_id: BlockId,
    op: &MemOp<FieldElement>,
    memory_blocks: &mut HashMap<BlockId, Vec<usize>>,
    next_aux_wire: &mut usize,
    input_indices: &HashSet<usize>,
) -> TranslatedGroup {
    let cells = memory_blocks
        .get(&block_id)
        .cloned()
        .ok_or_else(|| format!("MemoryOp references uninitialized block {block_id}"))?;
    if cells.is_empty() {
        return Err(format!("MemoryOp references empty block {block_id}"));
    }

    let selectors = allocate_memory_aux_wires(cells.len(), next_aux_wire);
    let new_cells = if matches!(op.operation, MemOpKind::Write) {
        allocate_memory_aux_wires(cells.len(), next_aux_wire)
    } else {
        Vec::new()
    };

    let orig = memory_op_constraints(op, &cells, &selectors, &new_cells, false, input_indices);
    let alt = memory_op_constraints(op, &cells, &selectors, &new_cells, true, input_indices);

    let mut wires = vec![picus_wire(op.index), picus_wire(op.value)];
    wires.extend(cells.iter().copied());
    wires.extend(selectors.iter().copied());
    wires.extend(new_cells.iter().copied());

    if matches!(op.operation, MemOpKind::Write) {
        memory_blocks.insert(block_id, new_cells);
    }

    Ok((wires, orig, alt))
}

fn allocate_memory_aux_wires(len: usize, next_aux_wire: &mut usize) -> Vec<usize> {
    let start = *next_aux_wire;
    *next_aux_wire += len;
    (start..start + len).collect()
}

fn memory_op_constraints(
    op: &MemOp<FieldElement>,
    cells: &[usize],
    selectors: &[usize],
    new_cells: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRConstraint> {
    let mut constraints = memory_selector_constraints(op.index, selectors, is_alt, input_indices);
    match op.operation {
        MemOpKind::Read => {
            constraints.push(memory_read_constraint(
                picus_wire(op.value),
                cells,
                selectors,
                is_alt,
                input_indices,
            ));
        }
        MemOpKind::Write => {
            for ((&old_cell, &new_cell), &selector) in cells.iter().zip(new_cells).zip(selectors) {
                constraints.push(memory_write_constraint(
                    old_cell,
                    new_cell,
                    picus_wire(op.value),
                    selector,
                    is_alt,
                    input_indices,
                ));
            }
        }
    }
    constraints
}

fn memory_selector_constraints(
    index: Witness,
    selectors: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRConstraint> {
    let mut constraints = Vec::with_capacity(selectors.len() + 2);
    for &selector in selectors {
        constraints.push(boolean_wire_constraint(selector, is_alt, input_indices));
    }

    let mut one_hot_terms = selectors
        .iter()
        .map(|&selector| IRTerm {
            coeff: BigUint::one(),
            var: var_name(selector, is_alt, input_indices),
        })
        .collect::<Vec<_>>();
    one_hot_terms.push(IRTerm {
        coeff: neg_mod_coeff(&BigUint::one()),
        var: var_name(0, is_alt, input_indices),
    });
    constraints.push(IRConstraint::Linear(one_hot_terms));

    let mut index_terms = vec![IRTerm {
        coeff: BigUint::one(),
        var: var_name(picus_wire(index), is_alt, input_indices),
    }];
    for (cell_index, &selector) in selectors.iter().enumerate() {
        let coeff = neg_mod_coeff(&BigUint::from(cell_index));
        if coeff.is_zero() {
            continue;
        }
        index_terms.push(IRTerm {
            coeff,
            var: var_name(selector, is_alt, input_indices),
        });
    }
    constraints.push(IRConstraint::Linear(index_terms));

    constraints
}

fn memory_read_constraint(
    value: usize,
    cells: &[usize],
    selectors: &[usize],
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::NonLinear {
        lhs_terms: cells
            .iter()
            .zip(selectors)
            .map(|(&cell, &selector)| IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(cell, is_alt, input_indices),
                var_b: var_name(selector, is_alt, input_indices),
            })
            .collect(),
        rhs_terms: vec![IRTerm {
            coeff: BigUint::one(),
            var: var_name(value, is_alt, input_indices),
        }],
    }
}

fn memory_write_constraint(
    old_cell: usize,
    new_cell: usize,
    value: usize,
    selector: usize,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::NonLinear {
        lhs_terms: vec![
            IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(selector, is_alt, input_indices),
                var_b: var_name(value, is_alt, input_indices),
            },
            IRProductTerm {
                coeff: neg_mod_coeff(&BigUint::one()),
                var_a: var_name(selector, is_alt, input_indices),
                var_b: var_name(old_cell, is_alt, input_indices),
            },
        ],
        rhs_terms: vec![
            IRTerm {
                coeff: BigUint::one(),
                var: var_name(new_cell, is_alt, input_indices),
            },
            IRTerm {
                coeff: neg_mod_coeff(&BigUint::one()),
                var: var_name(old_cell, is_alt, input_indices),
            },
        ],
    }
}

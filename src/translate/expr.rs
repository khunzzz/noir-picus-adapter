//! Translation of `AssertZero` expressions (linear and nonlinear) into Picus
//! IR constraints.

use std::collections::HashSet;

use acir::{FieldElement, native_types::Expression};
use num_traits::Zero;
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

use super::ir::{field_to_biguint, picus_wire, var_name};

pub(super) fn expression_to_ir(
    expression: &Expression<FieldElement>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Option<IRConstraint> {
    if expression.mul_terms.is_empty() {
        let terms = expression_linear_terms(expression, is_alt, input_indices, false);
        return (!terms.is_empty()).then_some(IRConstraint::Linear(terms));
    }

    let lhs_terms = expression
        .mul_terms
        .iter()
        .filter_map(|(coefficient, lhs, rhs)| {
            let coeff = field_to_biguint(*coefficient);
            (!coeff.is_zero()).then(|| IRProductTerm {
                coeff,
                var_a: var_name(picus_wire(*lhs), is_alt, input_indices),
                var_b: var_name(picus_wire(*rhs), is_alt, input_indices),
            })
        })
        .collect::<Vec<_>>();

    if lhs_terms.is_empty() {
        let terms = expression_linear_terms(expression, is_alt, input_indices, false);
        return (!terms.is_empty()).then_some(IRConstraint::Linear(terms));
    }

    let rhs_terms = expression_linear_terms(expression, is_alt, input_indices, true);
    Some(IRConstraint::NonLinear {
        lhs_terms,
        rhs_terms,
    })
}

fn expression_linear_terms(
    expression: &Expression<FieldElement>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
    negate: bool,
) -> Vec<IRTerm> {
    let mut terms = Vec::new();
    for (coefficient, witness) in &expression.linear_combinations {
        push_linear_term(
            &mut terms,
            *coefficient,
            picus_wire(*witness),
            is_alt,
            input_indices,
            negate,
        );
    }
    push_linear_term(&mut terms, expression.q_c, 0, is_alt, input_indices, negate);
    terms
}

fn push_linear_term(
    terms: &mut Vec<IRTerm>,
    coefficient: FieldElement,
    wire: usize,
    is_alt: bool,
    input_indices: &HashSet<usize>,
    negate: bool,
) {
    let coefficient = if negate { -coefficient } else { coefficient };
    let coeff = field_to_biguint(coefficient);
    if coeff.is_zero() {
        return;
    }
    terms.push(IRTerm {
        coeff,
        var: var_name(wire, is_alt, input_indices),
    });
}

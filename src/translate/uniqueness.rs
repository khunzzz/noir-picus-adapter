//! Uniqueness propagation: proving that a witness is uniquely determined by the
//! fixed inputs, without calling a solver.
//!
//! This is the cheap half of the analysis, and on real Noir output it is the
//! half that does the work. A well-compiled circuit determines almost every
//! witness, and an SMT query is only worth building for the few that
//! propagation cannot settle.
//!
//! The lemmas are chosen for the idioms Noir's ACIR generator actually emits.
//! Every unconstrained hint the compiler inserts on its own — division,
//! modulo, truncation, inverse, comparison — lands in one of them:
//!
//! ```text
//! BRILLIG CALL inputs: [w0, 128], outputs: [w6, w7]   // quotient, remainder
//! RANGE w6 bits 1
//! RANGE w7 bits 7
//! ASSERT w7 = w0 - 128*w6                             // Euclidean split
//!
//! BRILLIG CALL inputs: [w9], outputs: [w10]           // inverse hint
//! ASSERT w11 = -w9*w10 + 1                            // IsZero gadget
//! ASSERT 0 = w9*w11
//! ```
//!
//! The second shape is worth spelling out, because every `==`, `!=` and
//! comparison in Noir goes through it and it is *not* solvable one constraint
//! at a time. With `A = w9`, the pair reads
//!
//! ```text
//! A * w11 = 0            // w11 is zero unless A is
//! A * w10 + w11 = 1      // and if A is zero, this pins w11 to 1
//! ```
//!
//! so `w11` is determined by a case split on `A`, while the inverse hint `w10`
//! stays genuinely free when `A = 0`. That free hint is correct behaviour, not
//! a bug — unless it reaches an output, which is precisely what the scan
//! checks.
//!
//! Handing either shape to a finite-field solver means expanding every `RANGE`
//! into one boolean unknown per bit, in both self-composition copies. A single
//! generated program can carry ninety-odd `RANGE(32)` opcodes, i.e. thousands
//! of boolean unknowns in one Groebner basis computation, which exhausts memory
//! long before it exhausts the timeout. The lemmas below settle both shapes in
//! linear time.
//!
//! Everything here is one-directional: a wire is only ever *added* to the
//! determined set, and only when it provably takes a single value. Marking a
//! genuinely free wire as determined would hide a real bug, so each lemma has
//! to carry its own uniqueness argument — recorded in the comment above it.

use std::collections::{BTreeMap, BTreeSet};

use acir::{
    AcirField, FieldElement,
    circuit::{Circuit, Opcode, opcodes::BlackBoxFuncCall, opcodes::FunctionInput},
    native_types::Expression,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::determinism::is_functional_black_box;
use super::ir::{field_modulus, field_to_biguint, picus_wire};

/// What propagation learned about the circuit.
pub(super) struct Uniqueness {
    /// Wires that take a single value once the fixed inputs are fixed.
    pub(super) determined: BTreeSet<usize>,
    /// Wires that are provably non-zero in every satisfying assignment.
    /// Needed to divide by a symbolic coefficient.
    nonzero: BTreeSet<usize>,
    /// Tightest `RANGE` width seen for a wire.
    range_bits: BTreeMap<usize, u32>,
    /// Inclusive upper bound on a wire's value, read as an integer in `[0, p)`.
    ///
    /// Bit widths alone are not enough. Noir bounds the quotient of a
    /// `Field as uN` cast not by a width but by an inequality against
    /// `floor(p / 2^N)`, emitted as `slack = floor(p/2^N) - quotient` with a
    /// range check on `slack`. Without turning that into a bound on the
    /// quotient, the Euclidean lemma cannot fire on any `Field`-to-integer
    /// cast — which is one of the most common shapes in compiled Noir.
    bounds: BTreeMap<usize, BigUint>,
}

pub(super) fn infer_uniqueness(
    circuit: &Circuit<FieldElement>,
    input_indices: &BTreeSet<usize>,
) -> Uniqueness {
    let mut state = Uniqueness {
        determined: input_indices.clone(),
        nonzero: BTreeSet::new(),
        range_bits: BTreeMap::new(),
        bounds: BTreeMap::new(),
    };

    // Ranges are structural, not derived, so collect them once up front.
    for opcode in &circuit.opcodes {
        if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(witness),
            num_bits,
        }) = opcode
        {
            let wire = picus_wire(*witness);
            state
                .range_bits
                .entry(wire)
                .and_modify(|bits| *bits = (*bits).min(*num_bits))
                .or_insert(*num_bits);
            state.tighten_bound(wire, (BigUint::one() << *num_bits) - BigUint::one());
        }
    }

    // Bounds feed the Euclidean lemma, so they are settled first.
    let mut changed = true;
    while changed {
        changed = false;
        for opcode in &circuit.opcodes {
            if let Opcode::AssertZero(expression) = opcode {
                changed |= state.propagate_bounds(expression);
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for opcode in &circuit.opcodes {
            changed |= state.apply(opcode);
        }
        // The conditional-zero lemma relates *pairs* of constraints, so it runs
        // over the whole circuit rather than per opcode.
        changed |= state.solve_conditional_zero(circuit);
    }

    state
}

/// A linear form over wires that are already determined, plus a constant.
/// Used to reason about a coefficient symbolically, without knowing its value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Form {
    terms: BTreeMap<usize, BigUint>,
    constant: BigUint,
    /// Set when the form absorbed a product of two determined wires. Such a
    /// value is determined but not linear, so it still counts as "some fixed
    /// quantity" while every structural test below has to give up on it.
    opaque: bool,
}

impl Form {
    fn add_term(&mut self, wire: usize, coefficient: BigUint, modulus: &BigUint) {
        let entry = self.terms.entry(wire).or_insert_with(BigUint::zero);
        *entry = (&*entry + coefficient) % modulus;
        if entry.is_zero() {
            self.terms.remove(&wire);
        }
    }

    fn add_constant(&mut self, value: BigUint, modulus: &BigUint) {
        self.constant = (&self.constant + value) % modulus;
    }

    fn is_zero(&self) -> bool {
        !self.opaque && self.terms.is_empty() && self.constant.is_zero()
    }

    /// The form as a plain non-zero constant, if that is what it is.
    fn as_nonzero_constant(&self) -> Option<&BigUint> {
        (!self.opaque && self.terms.is_empty() && !self.constant.is_zero())
            .then_some(&self.constant)
    }

    /// Whether `self == lambda * other` for some non-zero `lambda`, i.e.
    /// whether `other` vanishing forces `self` to vanish too.
    fn is_multiple_of(&self, other: &Form, modulus: &BigUint) -> bool {
        if self.opaque || other.opaque || other.is_zero() {
            return false;
        }
        if self.is_zero() {
            return true;
        }
        if self.terms.len() != other.terms.len() {
            return false;
        }
        // Fix lambda from any coordinate the two share, then check the rest.
        let (lambda_num, lambda_den) = match (self.terms.iter().next(), other.terms.iter().next()) {
            (Some((self_wire, self_coeff)), Some((other_wire, other_coeff)))
                if self_wire == other_wire =>
            {
                (self_coeff.clone(), other_coeff.clone())
            }
            (None, None) => (self.constant.clone(), other.constant.clone()),
            _ => return false,
        };
        if lambda_den.is_zero() {
            return false;
        }
        let scaled = |value: &BigUint| (value * &lambda_den) % modulus;
        let target = |value: &BigUint| (value * &lambda_num) % modulus;
        if scaled(&self.constant) != target(&other.constant) {
            return false;
        }
        for (wire, coefficient) in &self.terms {
            match other.terms.get(wire) {
                Some(other_coefficient) => {
                    if scaled(coefficient) != target(other_coefficient) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

impl Uniqueness {
    fn apply(&mut self, opcode: &Opcode<FieldElement>) -> bool {
        match opcode {
            Opcode::AssertZero(expression) => {
                let mut changed = self.learn_nonzero(expression);
                changed |= self.solve_single_unknown(expression);
                changed |= self.solve_euclidean(expression);
                changed
            }
            Opcode::BlackBoxFuncCall(black_box) => self.apply_black_box(black_box),
            _ => false,
        }
    }

    /// Record `bound` as an upper bound for `wire`, keeping the tighter of the
    /// two. Returns whether anything got tighter.
    fn tighten_bound(&mut self, wire: usize, bound: BigUint) -> bool {
        match self.bounds.get_mut(&wire) {
            Some(existing) if *existing <= bound => false,
            Some(existing) => {
                *existing = bound;
                true
            }
            None => {
                self.bounds.insert(wire, bound);
                true
            }
        }
    }

    fn bound(&self, wire: usize) -> Option<&BigUint> {
        self.bounds.get(&wire)
    }

    /// Turn a linear `AssertZero` into upper bounds on the wires it mentions.
    ///
    /// Split the relation by the sign of each coefficient, reading field
    /// elements as integers in `[0, p)` and coefficients as signed values:
    ///
    /// ```text
    ///   sum_{i in P} |c_i| * w_i  +  q_P  =  sum_{j in N} |c_j| * w_j  +  q_N
    /// ```
    ///
    /// Both sides are non-negative. If each side's maximum is below `p`, the
    /// congruence is an equation over the integers, and every term on one side
    /// is bounded by the other side's maximum. When a side's maximum cannot be
    /// computed — some wire has no bound yet — nothing is claimed.
    fn propagate_bounds(&mut self, expression: &Expression<FieldElement>) -> bool {
        if !expression.mul_terms.is_empty() {
            return false;
        }

        let modulus = field_modulus();
        let half = &modulus / BigUint::from(2u32);
        let mut positive: Vec<(usize, BigUint)> = Vec::new();
        let mut negative: Vec<(usize, BigUint)> = Vec::new();

        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let wire = picus_wire(*witness);
            if coeff > half {
                negative.push((wire, &modulus - coeff));
            } else {
                positive.push((wire, coeff));
            }
        }

        let constant = field_to_biguint(expression.q_c);
        let (positive_constant, negative_constant) = if constant > half {
            (BigUint::zero(), &modulus - constant)
        } else {
            (constant, BigUint::zero())
        };

        let side_maximum = |side: &[(usize, BigUint)], constant: &BigUint| -> Option<BigUint> {
            let mut total = constant.clone();
            for (wire, coefficient) in side {
                total += coefficient * self.bound(*wire)?;
            }
            Some(total)
        };

        let (Some(positive_max), Some(negative_max)) = (
            side_maximum(&positive, &positive_constant),
            side_maximum(&negative, &negative_constant),
        ) else {
            return false;
        };
        // Both sides must stay inside the field for the congruence to be an
        // integer equation.
        if positive_max >= modulus || negative_max >= modulus {
            return false;
        }

        let mut changed = false;
        for (side, opposite_max) in [(&positive, &negative_max), (&negative, &positive_max)] {
            for (wire, coefficient) in side {
                // `|c| * w <= opposite side's maximum`, so `w <= max / |c|`.
                changed |= self.tighten_bound(*wire, opposite_max / coefficient);
            }
        }
        changed
    }

    fn is_determined(&self, wire: usize) -> bool {
        self.determined.contains(&wire)
    }

    fn determine(&mut self, wire: usize) -> bool {
        self.determined.insert(wire)
    }

    /// A black box on the functional allow-list is a pure function of its
    /// inputs, so determined inputs give determined outputs. Opcodes that ACIR
    /// does not constrain to be functional (the curve operations) are excluded
    /// by `is_functional_black_box`.
    fn apply_black_box(&mut self, black_box: &BlackBoxFuncCall<FieldElement>) -> bool {
        if !is_functional_black_box(black_box) {
            return false;
        }
        let inputs_determined = black_box
            .get_input_witnesses()
            .into_iter()
            .all(|witness| self.is_determined(picus_wire(witness)))
            && black_box
                .get_predicate()
                .is_none_or(|witness| self.is_determined(picus_wire(witness)));
        if !inputs_determined {
            return false;
        }
        let mut changed = false;
        for witness in black_box.get_outputs_vec() {
            changed |= self.determine(picus_wire(witness));
        }
        changed
    }

    /// From `c * a * b + q = 0` with `c != 0` and `q != 0`: neither `a` nor `b`
    /// can be zero, since a zero factor would force `q = 0`. This is how the
    /// inverse hint proves its divisor non-zero, and knowing it is what lets
    /// `solve_single_unknown` divide by a symbolic coefficient later.
    fn learn_nonzero(&mut self, expression: &Expression<FieldElement>) -> bool {
        if expression.mul_terms.len() != 1
            || !expression.linear_combinations.is_empty()
            || expression.q_c.is_zero()
        {
            return false;
        }
        let (coefficient, lhs, rhs) = &expression.mul_terms[0];
        if field_to_biguint(*coefficient).is_zero() {
            return false;
        }
        let mut changed = self.nonzero.insert(picus_wire(*lhs));
        changed |= self.nonzero.insert(picus_wire(*rhs));
        changed
    }

    /// Solve `expression = 0` for a single unknown wire.
    ///
    /// Collect the equation as `A * u + B = 0`, where `u` is the only wire not
    /// yet determined. `u` is then determined provided `A != 0`, because over a
    /// prime field a non-zero coefficient is invertible. `A` is accepted as
    /// non-zero only when it is a non-zero constant, or a constant multiple of
    /// a single wire already proven non-zero — the two cases that cover every
    /// hint Noir emits. When `A` cannot be shown non-zero nothing is claimed:
    /// `A = 0` would leave `u` free, which is exactly the bug we are looking
    /// for and must not be assumed away.
    fn solve_single_unknown(&mut self, expression: &Expression<FieldElement>) -> bool {
        let mut unknown: Option<usize> = None;
        // Coefficient of the unknown, as a list of (constant, optional wire)
        // products. Empty means the unknown does not occur.
        let mut coefficient_terms: Vec<(BigUint, Option<usize>)> = Vec::new();

        let note_unknown = |wire: usize, unknown: &mut Option<usize>| -> bool {
            match unknown {
                Some(existing) if *existing == wire => true,
                Some(_) => false,
                None => {
                    *unknown = Some(wire);
                    true
                }
            }
        };

        for (coefficient, lhs, rhs) in &expression.mul_terms {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let (lhs_wire, rhs_wire) = (picus_wire(*lhs), picus_wire(*rhs));
            match (self.is_determined(lhs_wire), self.is_determined(rhs_wire)) {
                (true, true) => {}
                (false, true) => {
                    if !note_unknown(lhs_wire, &mut unknown) {
                        return false;
                    }
                    coefficient_terms.push((coeff, Some(rhs_wire)));
                }
                (true, false) => {
                    if !note_unknown(rhs_wire, &mut unknown) {
                        return false;
                    }
                    coefficient_terms.push((coeff, Some(lhs_wire)));
                }
                // `u * u` or `u * v` with both unknown: quadratic in the
                // unknown, which can have two roots. Never claimed.
                (false, false) => return false,
            }
        }

        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let wire = picus_wire(*witness);
            if self.is_determined(wire) {
                continue;
            }
            if !note_unknown(wire, &mut unknown) {
                return false;
            }
            coefficient_terms.push((coeff, None));
        }

        let Some(unknown) = unknown else {
            return false;
        };
        if !self.coefficient_is_nonzero(&coefficient_terms) {
            return false;
        }
        self.determine(unknown)
    }

    /// Whether the collected coefficient of the unknown is provably non-zero.
    fn coefficient_is_nonzero(&self, terms: &[(BigUint, Option<usize>)]) -> bool {
        match terms {
            // A single constant coefficient: non-zero by construction, zero
            // coefficients were skipped when collecting.
            [(coefficient, None)] => !coefficient.is_zero(),
            // A single `constant * wire` coefficient: non-zero exactly when the
            // wire is known non-zero.
            [(coefficient, Some(wire))] => !coefficient.is_zero() && self.nonzero.contains(wire),
            // A sum could cancel to zero; nothing is claimed.
            _ => false,
        }
    }

    /// Euclidean split: `E = c*Q + R` with `E` determined, `0 <= R < c` and `Q`
    /// bounded is the definition of division with remainder, so `Q` and `R` are
    /// unique.
    ///
    /// This is the shape every Noir integer division, modulo, truncation and
    /// bit-shift compiles to, with `Q` and `R` produced by an unconstrained
    /// hint and pinned only by their `RANGE` opcodes. Uniqueness needs the
    /// range bounds — without them the equation has one degree of freedom — and
    /// it needs the arithmetic not to wrap, which is why the widths are
    /// required to fit strictly inside the field.
    fn solve_euclidean(&mut self, expression: &Expression<FieldElement>) -> bool {
        // Products of two determined wires are fine — they are just part of the
        // dividend. Anything involving an unknown is not.
        for (coefficient, lhs, rhs) in &expression.mul_terms {
            if field_to_biguint(*coefficient).is_zero() {
                continue;
            }
            if !self.is_determined(picus_wire(*lhs)) || !self.is_determined(picus_wire(*rhs)) {
                return false;
            }
        }

        let modulus = field_modulus();
        let mut unknowns: Vec<(usize, BigUint)> = Vec::new();
        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let wire = picus_wire(*witness);
            if self.is_determined(wire) {
                // Determined wires contribute a fixed amount; their value is
                // irrelevant to the uniqueness argument, only their presence.
                continue;
            }
            match unknowns.iter_mut().find(|(existing, _)| *existing == wire) {
                Some((_, accumulated)) => *accumulated = (&*accumulated + coeff) % &modulus,
                None => unknowns.push((wire, coeff)),
            }
        }
        if unknowns.len() != 2 {
            return false;
        }
        let (first, second) = (unknowns[0].clone(), unknowns[1].clone());

        // One unknown must carry coefficient +/-1 (the remainder), the other
        // +/-2^k (the quotient scaled by the divisor).
        for (remainder, quotient) in [(&first, &second), (&second, &first)] {
            let (remainder_wire, remainder_coeff) = remainder;
            let (quotient_wire, quotient_coeff) = quotient;
            if !is_unit(remainder_coeff, &modulus) {
                continue;
            }
            let Some(shift) = power_of_two_exponent(quotient_coeff, &modulus) else {
                continue;
            };
            let (Some(remainder_bound), Some(quotient_bound)) =
                (self.bound(*remainder_wire), self.bound(*quotient_wire))
            else {
                continue;
            };
            let divisor = BigUint::one() << shift;
            // `R < c` puts the remainder below the divisor, and
            // `c * Qmax + Rmax < p` rules out wrap-around, so the split is the
            // integer one and therefore unique.
            if *remainder_bound < divisor && &divisor * quotient_bound + remainder_bound < modulus {
                let mut changed = self.determine(*remainder_wire);
                changed |= self.determine(*quotient_wire);
                return changed;
            }
        }

        false
    }
}

impl Uniqueness {
    /// Decompose `expression` into `sum_u Form_u * u + Form_0 = 0`, where every
    /// `Form` is linear over already-determined wires. Returns `None` when the
    /// expression does not have that shape (a product of two unknowns, or of
    /// two determined wires, neither of which is linear).
    fn decompose(
        &self,
        expression: &Expression<FieldElement>,
    ) -> Option<(Vec<(usize, Form)>, Form)> {
        let modulus = field_modulus();
        let mut unknown_forms: Vec<(usize, Form)> = Vec::new();
        let mut constant_form = Form::default();

        let form_for = |unknown_forms: &mut Vec<(usize, Form)>, wire: usize| -> usize {
            match unknown_forms.iter().position(|(known, _)| *known == wire) {
                Some(index) => index,
                None => {
                    unknown_forms.push((wire, Form::default()));
                    unknown_forms.len() - 1
                }
            }
        };

        for (coefficient, lhs, rhs) in &expression.mul_terms {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let (lhs_wire, rhs_wire) = (picus_wire(*lhs), picus_wire(*rhs));
            match (self.is_determined(lhs_wire), self.is_determined(rhs_wire)) {
                (false, true) => {
                    let index = form_for(&mut unknown_forms, lhs_wire);
                    unknown_forms[index].1.add_term(rhs_wire, coeff, &modulus);
                }
                (true, false) => {
                    let index = form_for(&mut unknown_forms, rhs_wire);
                    unknown_forms[index].1.add_term(lhs_wire, coeff, &modulus);
                }
                // A product of two determined wires is a fixed quantity, but
                // not a linear one; keep it as an opaque part of the constant.
                (true, true) => constant_form.opaque = true,
                // A product of two unknowns is quadratic; no lemma here applies.
                (false, false) => return None,
            }
        }

        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let wire = picus_wire(*witness);
            if self.is_determined(wire) {
                constant_form.add_term(wire, coeff, &modulus);
            } else {
                let index = form_for(&mut unknown_forms, wire);
                unknown_forms[index].1.add_constant(coeff, &modulus);
            }
        }
        constant_form.add_constant(field_to_biguint(expression.q_c), &modulus);

        unknown_forms.retain(|(_, form)| !form.is_zero());
        Some((unknown_forms, constant_form))
    }

    /// The IsZero gadget: `A * u = 0` together with a second constraint that
    /// pins `u` whenever `A` vanishes.
    ///
    /// From `A * u = 0` alone, `u = 0` in every solution with `A != 0`. If some
    /// other constraint reads `e * u + (multiples of A) + rest = 0` with `e` a
    /// non-zero constant, then in the remaining case `A = 0` it collapses to
    /// `e * u + rest = 0`, which pins `u` because `rest` is linear over
    /// determined wires. Both branches give a single value, so `u` is
    /// determined — with no assumption about which branch is taken, and no
    /// claim about the inverse hint `v`, which really is free when `A = 0`.
    fn solve_conditional_zero(&mut self, circuit: &Circuit<FieldElement>) -> bool {
        let modulus = field_modulus();

        // Candidates `u` with the witnessing form `A`.
        let mut conditional_zeros: Vec<(usize, Form)> = Vec::new();
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else {
                continue;
            };
            let Some((unknowns, constant_form)) = self.decompose(expression) else {
                continue;
            };
            if unknowns.len() == 1 && constant_form.is_zero() {
                let (wire, form) = &unknowns[0];
                if !self.is_determined(*wire) {
                    conditional_zeros.push((*wire, form.clone()));
                }
            }
        }
        if conditional_zeros.is_empty() {
            return false;
        }

        let mut changed = false;
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else {
                continue;
            };
            let Some((unknowns, _)) = self.decompose(expression) else {
                continue;
            };
            for (candidate, witnessing_form) in &conditional_zeros {
                if self.is_determined(*candidate) {
                    continue;
                }
                let Some((_, candidate_form)) = unknowns.iter().find(|(wire, _)| wire == candidate)
                else {
                    continue;
                };
                if candidate_form.as_nonzero_constant().is_none() {
                    continue;
                }
                // Every other unknown must disappear when `A` does.
                let others_vanish = unknowns
                    .iter()
                    .filter(|(wire, _)| wire != candidate)
                    .all(|(_, form)| form.is_multiple_of(witnessing_form, &modulus));
                if others_vanish {
                    changed |= self.determine(*candidate);
                }
            }
        }

        changed
    }
}

/// Whether `value` is `1` or `-1` in the field.
fn is_unit(value: &BigUint, modulus: &BigUint) -> bool {
    value == &BigUint::from(1u32) || value == &(modulus - BigUint::from(1u32))
}

/// The exponent `k` when `value` is `+/-2^k`, for `k` below the field width.
fn power_of_two_exponent(value: &BigUint, modulus: &BigUint) -> Option<u32> {
    for candidate in [value.clone(), modulus - value] {
        if candidate.count_ones() == 1 {
            let exponent = candidate.bits() - 1;
            if exponent < u64::from(FieldElement::max_num_bits()) {
                return u32::try_from(exponent).ok();
            }
        }
    }
    None
}

/// Convenience for callers that only need the determined set.
pub(super) fn infer_fixed_known_signals(
    circuit: &Circuit<FieldElement>,
    input_indices: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    infer_uniqueness(circuit, input_indices).determined
}

#[cfg(test)]
mod tests {
    use acir::circuit::{Circuit, PublicInputs, opcodes::BlackBoxFuncCall, opcodes::FunctionInput};
    use acir::native_types::Witness;

    use super::*;

    fn range(witness: u32, num_bits: u32) -> Opcode<FieldElement> {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(Witness(witness)),
            num_bits,
        })
    }

    fn inputs(circuit: &Circuit<FieldElement>) -> BTreeSet<usize> {
        let mut set = BTreeSet::from([0]);
        set.extend(circuit.public_parameters.0.iter().map(|w| picus_wire(*w)));
        set
    }

    // `w8 = w0 - 256*w7` with `w7 < 2^24` and `w8 < 2^8`: division with
    // remainder by 256, the shape every Noir integer division compiles to.
    #[test]
    fn euclidean_split_determines_quotient_and_remainder() {
        let mut split = Expression::default();
        split.push_addition_term(FieldElement::one(), Witness(8));
        split.push_addition_term(-FieldElement::one(), Witness(0));
        split.push_addition_term(FieldElement::from(256u32), Witness(7));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![range(7, 24), range(8, 8), Opcode::AssertZero(split)],
            ..Circuit::<FieldElement>::default()
        };

        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(7))));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(8))));
    }

    // Without the range bounds the same equation has a free parameter, so
    // neither wire may be claimed.
    #[test]
    fn euclidean_split_needs_the_range_bounds() {
        let mut split = Expression::default();
        split.push_addition_term(FieldElement::one(), Witness(8));
        split.push_addition_term(-FieldElement::one(), Witness(0));
        split.push_addition_term(FieldElement::from(256u32), Witness(7));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(split)],
            ..Circuit::<FieldElement>::default()
        };

        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(7))));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(8))));
    }

    // `slack = limit - value` with a range check on `slack` bounds `value` by
    // `limit`, which is tighter than any bit width. Noir bounds the quotient of
    // a `Field as uN` cast exactly this way.
    #[test]
    fn a_slack_variable_tightens_the_bound_below_the_bit_width() {
        // w1 + w0 - 1000 = 0, both range-checked to 16 bits.
        let mut slack = Expression::default();
        slack.push_addition_term(FieldElement::one(), Witness(1));
        slack.push_addition_term(FieldElement::one(), Witness(0));
        slack.q_c = -FieldElement::from(1000u32);

        let circuit = Circuit {
            opcodes: vec![range(0, 16), range(1, 16), Opcode::AssertZero(slack)],
            ..Circuit::<FieldElement>::default()
        };

        let uniqueness = infer_uniqueness(&circuit, &BTreeSet::from([0]));
        assert_eq!(
            uniqueness.bound(picus_wire(Witness(0))),
            Some(&BigUint::from(1000u32)),
            "the range check gives 2^16 - 1; the slack variable gives 1000"
        );
    }

    // The IsZero gadget: `w2 = 1 - w0*w1` and `w0*w2 = 0` determine `w2` by a
    // case split on `w0`, while the inverse hint `w1` stays free at `w0 = 0`.
    #[test]
    fn is_zero_gadget_determines_the_flag_but_not_the_hint() {
        let mut flag = Expression::default();
        flag.push_multiplication_term(-FieldElement::one(), Witness(0), Witness(1));
        flag.push_addition_term(-FieldElement::one(), Witness(2));
        flag.q_c = FieldElement::one();

        let mut guard = Expression::default();
        guard.push_multiplication_term(FieldElement::one(), Witness(0), Witness(2));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(flag), Opcode::AssertZero(guard)],
            ..Circuit::<FieldElement>::default()
        };

        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(
            uniqueness.determined.contains(&picus_wire(Witness(2))),
            "the IsZero flag is a function of its input"
        );
        assert!(
            !uniqueness.determined.contains(&picus_wire(Witness(1))),
            "the inverse hint is genuinely free when the input is zero"
        );
    }

    // `a * b = 1` proves both factors non-zero, which is what lets a later
    // constraint be divided by `a`.
    #[test]
    fn inverse_constraint_proves_both_factors_nonzero() {
        let mut inverse = Expression::default();
        inverse.push_multiplication_term(FieldElement::one(), Witness(0), Witness(1));
        inverse.q_c = -FieldElement::one();

        // w2 * w0 = w3, with w3 public: solvable for w2 only because w0 != 0.
        let mut divide = Expression::default();
        divide.push_multiplication_term(FieldElement::one(), Witness(0), Witness(2));
        divide.push_addition_term(-FieldElement::one(), Witness(3));

        let circuit = Circuit {
            public_parameters: PublicInputs([Witness(0), Witness(3)].into_iter().collect()),
            opcodes: vec![Opcode::AssertZero(inverse), Opcode::AssertZero(divide)],
            ..Circuit::<FieldElement>::default()
        };

        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(1))));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(2))));
    }
}

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
use num_bigint::{BigInt, BigUint, Sign};
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
    /// Signed interval `[lo, hi]` holding an integer representative of a
    /// wire's value.
    ///
    /// An upper bound in `[0, p)` cannot describe a *centered* value: a
    /// remainder kept in `[-h, h]` sits near `p` when negative, so it has no
    /// useful bound at all. Hand-written modular arithmetic pins exactly such
    /// values with two shifted copies — `w + h` and `h - w`, each
    /// range-checked — and the intersection of what each copy says is the
    /// window. Only small intervals are kept (see `INTERVAL_LIMIT`), so a field
    /// element in two of them has the same integer representative in both and
    /// intersecting them is sound.
    intervals: BTreeMap<usize, (BigInt, BigInt)>,
    /// Wires an assertion pins to a constant (`w - k = 0`), with that value.
    /// The modular-inverse lemma needs the right-hand side as a number, not
    /// just as "determined".
    constants: BTreeMap<usize, BigUint>,
}

/// Largest magnitude an interval endpoint may have. Far below `p / 4`, so two
/// representatives of one field element can never both lie within it.
fn interval_limit() -> BigInt {
    BigInt::from(1u32) << 200u32
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
        intervals: BTreeMap::new(),
        constants: BTreeMap::new(),
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
                changed |= state.propagate_intervals(expression);
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
                changed |= self.learn_constant(expression);
                changed |= self.solve_single_unknown(expression);
                changed |= self.solve_euclidean(expression);
                changed |= self.solve_modular_inverse(expression);
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

    /// The tightest known signed interval for `wire`: its own, or `[0, B]`
    /// from an upper bound.
    fn interval(&self, wire: usize) -> Option<(BigInt, BigInt)> {
        let from_bound = self
            .bound(wire)
            .map(|bound| {
                (
                    BigInt::from(0u32),
                    BigInt::from_biguint(Sign::Plus, bound.clone()),
                )
            })
            .filter(|(_, hi)| *hi < interval_limit());
        match (self.intervals.get(&wire).cloned(), from_bound) {
            (Some((lo, hi)), Some((blo, bhi))) => Some((lo.max(blo), hi.min(bhi))),
            (Some(interval), None) | (None, Some(interval)) => Some(interval),
            (None, None) => None,
        }
    }

    fn tighten_interval(&mut self, wire: usize, lo: BigInt, hi: BigInt) -> bool {
        let limit = interval_limit();
        if lo > hi || lo <= -&limit || hi >= limit {
            return false;
        }
        let (lo, hi) = match self.interval(wire) {
            Some((old_lo, old_hi)) => (lo.max(old_lo.clone()), hi.min(old_hi.clone())),
            None => (lo, hi),
        };
        if self.intervals.get(&wire) == Some(&(lo.clone(), hi.clone())) {
            return false;
        }
        let changed = match self.intervals.get(&wire) {
            Some((old_lo, old_hi)) => lo > *old_lo || hi < *old_hi,
            None => true,
        };
        if lo >= BigInt::from(0u32) {
            if let Some(bound) = hi.to_biguint() {
                self.tighten_bound(wire, bound);
            }
        }
        self.intervals.insert(wire, (lo, hi));
        changed
    }

    /// From `±s ± r + k = 0` with `s` in a known interval, `r` lies in the
    /// image of that interval under `r = ∓(±s + k)`. This is how an offset
    /// copy (`w + h`, `h - w`) bounds a centered value.
    fn propagate_intervals(&mut self, expression: &Expression<FieldElement>) -> bool {
        if !expression.mul_terms.is_empty() {
            return false;
        }
        let modulus = field_modulus();
        let signed = |value: BigUint| -> BigInt {
            if value > &modulus / BigUint::from(2u32) {
                -BigInt::from_biguint(Sign::Plus, &modulus - value)
            } else {
                BigInt::from_biguint(Sign::Plus, value)
            }
        };
        let mut terms: Vec<(usize, BigInt)> = Vec::new();
        for (coefficient, witness) in &expression.linear_combinations {
            let coeff = field_to_biguint(*coefficient);
            if coeff.is_zero() {
                continue;
            }
            let wire = picus_wire(*witness);
            match terms.iter_mut().find(|(existing, _)| *existing == wire) {
                Some((_, total)) => *total += signed(coeff),
                None => terms.push((wire, signed(coeff))),
            }
        }
        terms.retain(|(_, coeff)| *coeff != BigInt::from(0u32));
        let [(first, a), (second, b)] = terms.as_slice() else {
            return false;
        };
        let unit = |c: &BigInt| *c == BigInt::from(1u32) || *c == BigInt::from(-1i32);
        if !unit(a) || !unit(b) {
            return false;
        }
        let k = signed(field_to_biguint(expression.q_c));

        let mut changed = false;
        for ((source, source_coeff), (target, target_coeff)) in
            [((*first, a), (*second, b)), ((*second, b), (*first, a))]
        {
            let Some((lo, hi)) = self.interval(source) else {
                continue;
            };
            // target = -target_coeff * (source_coeff * source + k), since the
            // coefficient is ±1 and therefore its own inverse.
            let image = |value: &BigInt| -(target_coeff * (source_coeff * value + &k));
            let (x, y) = (image(&lo), image(&hi));
            let (new_lo, new_hi) = if x <= y { (x, y) } else { (y, x) };
            changed |= self.tighten_interval(target, new_lo, new_hi);
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
    ///
    /// The divisor `c` is any constant, not only a power of two: hand-written
    /// modular arithmetic reduces by a prime modulus (`n - q*quotient` with the
    /// remainder held in `[0, q)` by a slack variable). The argument does not
    /// depend on the shape of `c` or on the signs of the two coefficients. Two
    /// solutions give `±(R - R') ± c*(Q - Q') = 0` in the field; the left side
    /// is at most `Rmax + c*Qmax < p` in absolute value, so it is zero over the
    /// integers, `c` divides `R - R'`, and `|R - R'| <= Rmax < c` forces
    /// `R = R'` and then `Q = Q'`.
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
        let mut constant = field_to_biguint(expression.q_c);
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
                constant = (constant + coeff) % &modulus;
                continue;
            }
            match unknowns.iter_mut().find(|(existing, _)| *existing == wire) {
                Some((_, accumulated)) => *accumulated = (&*accumulated + coeff) % &modulus,
                None => unknowns.push((wire, coeff)),
            }
        }
        let _ = constant;

        if unknowns.len() != 2 {
            return false;
        }
        let (first, second) = (unknowns[0].clone(), unknowns[1].clone());

        // One unknown must carry coefficient +/-1 (the remainder), the other
        // +/-c (the quotient scaled by the divisor).
        for (remainder, quotient) in [(&first, &second), (&second, &first)] {
            let (remainder_wire, remainder_coeff) = remainder;
            let (quotient_wire, quotient_coeff) = quotient;
            if !is_unit(remainder_coeff, &modulus) {
                continue;
            }
            let divisor = signed_magnitude(quotient_coeff, &modulus);
            // Spreads, not upper bounds: a centered remainder `[-h, h]` has
            // spread `2h`, and only the spread enters the argument.
            let spread = |wire: usize| -> Option<BigUint> {
                let (lo, hi) = self.interval(wire)?;
                (hi - lo).to_biguint()
            };
            let (Some(remainder_bound), Some(quotient_bound)) =
                (spread(*remainder_wire), spread(*quotient_wire))
            else {
                continue;
            };
            let (remainder_bound, quotient_bound) = (&remainder_bound, &quotient_bound);
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
    /// `c * w + k = 0` with `c != 0` pins `w` to `-k / c`.
    fn learn_constant(&mut self, expression: &Expression<FieldElement>) -> bool {
        if !expression.mul_terms.is_empty() {
            return false;
        }
        let terms = expression
            .linear_combinations
            .iter()
            .filter(|(coefficient, _)| !coefficient.is_zero())
            .collect::<Vec<_>>();
        let [(coefficient, witness)] = terms.as_slice() else {
            return false;
        };
        let wire = picus_wire(*witness);
        if self.constants.contains_key(&wire) {
            return false;
        }
        let value = -expression.q_c * coefficient.inverse();
        self.constants.insert(wire, field_to_biguint(value));
        true
    }

    /// Modular inverse: `a*x + s*c*Q = E` with `a` determined, `E` a constant
    /// not divisible by the prime `c`, `x` in a window narrower than `c`, and
    /// every term small enough that the equation holds over the integers.
    ///
    /// This is the shape of a hinted inverse proven by a bounded reduction
    /// (`reduce_mod_bounded(a * inv, q) == 1`). Over the integers it says
    /// `a*x ≡ E (mod c)`. `E ≢ 0` rules out `a ≡ 0`, and `c` prime then makes
    /// `a` invertible, so `x` is fixed modulo `c`; a window of spread below
    /// `c` holds one representative, so `x` is unique, and `Q` follows from
    /// the equation since `c != 0`. Primality is required: modulo a composite
    /// `c`, `a` could share a factor with it and leave `x` free.
    fn solve_modular_inverse(&mut self, expression: &Expression<FieldElement>) -> bool {
        let modulus = field_modulus();
        let Some((unknowns, constant_form)) = self.decompose(expression) else {
            return false;
        };
        if unknowns.len() != 2 || constant_form.opaque {
            return false;
        }
        // The right-hand side as a number: every determined wire left in it
        // must have a known constant value.
        let mut rhs = constant_form.constant.clone();
        for (wire, coefficient) in &constant_form.terms {
            let Some(value) = self.constants.get(wire) else {
                return false;
            };
            rhs = (rhs + coefficient * value) % &modulus;
        }
        let rhs = signed_integer(&rhs, &modulus);

        for (x_index, q_index) in [(0, 1), (1, 0)] {
            let (x, x_form) = &unknowns[x_index];
            let (quotient, q_form) = &unknowns[q_index];
            // `x`'s coefficient must be exactly `±a` for one determined `a`.
            if x_form.opaque || !x_form.constant.is_zero() || x_form.terms.len() != 1 {
                continue;
            }
            let (multiplier, coefficient) = x_form.terms.iter().next().expect("one term");
            if !is_unit(coefficient, &modulus) {
                continue;
            }
            let Some(divisor) = q_form.as_nonzero_constant() else {
                continue;
            };
            let divisor = signed_magnitude(divisor, &modulus);
            if !is_prime(&divisor) {
                continue;
            }
            let divisor_int = BigInt::from_biguint(Sign::Plus, divisor.clone());
            if (&rhs % &divisor_int) == BigInt::from(0u32) {
                continue;
            }
            let (Some(a_range), Some(x_range), Some(q_range)) = (
                self.interval(*multiplier),
                self.interval(*x),
                self.interval(*quotient),
            ) else {
                continue;
            };
            let magnitude =
                |(lo, hi): &(BigInt, BigInt)| lo.magnitude().max(hi.magnitude()).clone();
            let Some(x_spread) = (&x_range.1 - &x_range.0).to_biguint() else {
                continue;
            };
            if x_spread >= divisor {
                continue;
            }
            // Integer lift: |a*x| + c*|Q| + |E| < p/2, so the field equation
            // and its signed integer reading agree.
            let lift = magnitude(&a_range) * magnitude(&x_range)
                + &divisor * magnitude(&q_range)
                + rhs.magnitude();
            if lift >= &modulus / BigUint::from(2u32) {
                continue;
            }
            let mut changed = self.determine(*x);
            changed |= self.determine(*quotient);
            return changed;
        }
        false
    }
}

/// The field element as a signed integer in `(-p/2, p/2]`.
fn signed_integer(value: &BigUint, modulus: &BigUint) -> BigInt {
    if *value > modulus / BigUint::from(2u32) {
        -BigInt::from_biguint(Sign::Plus, modulus - value)
    } else {
        BigInt::from_biguint(Sign::Plus, value.clone())
    }
}

/// Deterministic Miller–Rabin for `n < 3.3 * 10^24`, which covers every
/// modulus a field-native circuit reduces by in one step. Larger `n` is
/// reported composite: the caller then claims nothing, which is safe.
fn is_prime(n: &BigUint) -> bool {
    let small = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];
    if *n < BigUint::from(2u32) {
        return false;
    }
    for p in small {
        let p = BigUint::from(p);
        if *n == p {
            return true;
        }
        if (n % &p).is_zero() {
            return false;
        }
    }
    let limit = BigUint::parse_bytes(b"3317044064679887385961981", 10).expect("constant");
    if *n >= limit {
        return false;
    }
    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut r = 0u32;
    while (&d % 2u32).is_zero() {
        d >>= 1;
        r += 1;
    }
    'witness: for a in small {
        let mut x = BigUint::from(a).modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return false;
    }
    true
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

/// `|value|` with the field element read as a signed integer in
/// `(-p/2, p/2]`. A coefficient `-c` is stored as `p - c`.
fn signed_magnitude(value: &BigUint, modulus: &BigUint) -> BigUint {
    let negated = modulus - value;
    if negated < *value {
        negated
    } else {
        value.clone()
    }
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

    // Reduction by a prime modulus, as hand-written modular arithmetic emits it
    // (Interfold's `reduce_mod_bounded`): `w2 = w0 - q*w1` with the quotient
    // range-checked and the remainder held in `[0, q)` by a slack variable
    // `w3 = (q - 1) - w2`. The divisor is not a power of two.
    fn prime_reduction(quotient_bits: u32, remainder_limit: u64) -> Circuit<FieldElement> {
        let q = 68_719_403_009u64;
        let mut split = Expression::default();
        split.push_addition_term(FieldElement::one(), Witness(2));
        split.push_addition_term(-FieldElement::one(), Witness(0));
        split.push_addition_term(FieldElement::from(q as u128), Witness(1));

        let mut slack = Expression::default();
        slack.push_addition_term(FieldElement::one(), Witness(3));
        slack.push_addition_term(FieldElement::one(), Witness(2));
        slack.q_c = -FieldElement::from(remainder_limit as u128);

        Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![
                range(1, quotient_bits),
                Opcode::AssertZero(split),
                range(2, 36),
                Opcode::AssertZero(slack),
                range(3, 36),
            ],
            ..Circuit::<FieldElement>::default()
        }
    }

    #[test]
    fn euclidean_split_by_a_prime_modulus_is_unique() {
        let circuit = prime_reduction(42, 68_719_403_008);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(1))));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(2))));
    }

    // A remainder window one wider than the divisor admits both `R` and
    // `R + q` (with `Q - 1`), so nothing may be claimed.
    #[test]
    fn euclidean_split_needs_the_remainder_below_the_divisor() {
        let circuit = prime_reduction(42, 68_719_403_009);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(1))));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(2))));
    }

    // With a 253-bit quotient `q * Qmax` passes the field modulus, the split
    // can wrap, and the lemma has to stay silent.
    #[test]
    fn euclidean_split_must_not_wrap_the_field() {
        let circuit = prime_reduction(253, 68_719_403_008);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(1))));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(2))));
    }

    // A centered remainder, as `assert_zero_mod_bounded` over a centered
    // aggregate compiles (Interfold C5): `w2 = E - 101*w6` with `w2` held in
    // `[-half, half]` only by its two offset copies `w4 = w2 + half` and
    // `w5 = half - w2`, each range-checked. No upper bound in `[0, p)` exists
    // for `w2`, but its window has spread `2*half`, which is what matters.
    fn centered_reduction(half: u64) -> Circuit<FieldElement> {
        let mut split = Expression::default();
        split.push_addition_term(FieldElement::one(), Witness(2));
        split.push_addition_term(-FieldElement::one(), Witness(0));
        split.push_addition_term(FieldElement::from(101u128), Witness(6));

        let mut up = Expression::default();
        up.push_addition_term(FieldElement::one(), Witness(4));
        up.push_addition_term(-FieldElement::one(), Witness(2));
        up.q_c = -FieldElement::from(half as u128);

        let mut down = Expression::default();
        down.push_addition_term(FieldElement::one(), Witness(5));
        down.push_addition_term(FieldElement::one(), Witness(2));
        down.q_c = -FieldElement::from(half as u128);

        Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![
                Opcode::AssertZero(up),
                range(4, 8),
                Opcode::AssertZero(down),
                range(5, 8),
                range(6, 8),
                Opcode::AssertZero(split),
            ],
            ..Circuit::<FieldElement>::default()
        }
    }

    #[test]
    fn centered_remainder_window_is_unique() {
        let circuit = centered_reduction(50);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(2))));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(6))));
    }

    // `[-51, 51]` holds 103 values, more than the modulus 101: both `R` and
    // `R ± 101` can fit, so nothing may be claimed.
    #[test]
    fn centered_window_wider_than_the_modulus_is_not_unique() {
        let circuit = centered_reduction(51);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(2))));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(6))));
    }

    // A hinted inverse proven by a bounded reduction, as Interfold's
    // `inv_mod_bounded` compiles: `a*x - c*Q = w9` and `w9 = rhs`, with `a`
    // public and below `c`, `x` held in `[0, c)` by a slack variable and `Q`
    // range-checked.
    fn hinted_inverse(c: u64, rhs: u64) -> Circuit<FieldElement> {
        let mut product = Expression::default();
        product.push_multiplication_term(FieldElement::one(), Witness(0), Witness(1));
        product.push_addition_term(-FieldElement::from(c as u128), Witness(2));
        product.push_addition_term(-FieldElement::one(), Witness(9));

        let mut pin = Expression::default();
        pin.push_addition_term(FieldElement::one(), Witness(9));
        pin.q_c = -FieldElement::from(rhs as u128);

        let mut slack = Expression::default();
        slack.push_addition_term(FieldElement::one(), Witness(3));
        slack.push_addition_term(FieldElement::one(), Witness(1));
        slack.q_c = -FieldElement::from((c - 1) as u128);

        let mut a_slack = Expression::default();
        a_slack.push_addition_term(FieldElement::one(), Witness(4));
        a_slack.push_addition_term(FieldElement::one(), Witness(0));
        a_slack.q_c = -FieldElement::from((c - 1) as u128);

        Circuit {
            public_parameters: PublicInputs([Witness(0)].into_iter().collect()),
            opcodes: vec![
                range(0, 8),
                Opcode::AssertZero(a_slack),
                range(4, 8),
                range(1, 8),
                Opcode::AssertZero(slack),
                range(3, 8),
                range(2, 8),
                Opcode::AssertZero(product),
                Opcode::AssertZero(pin),
            ],
            ..Circuit::<FieldElement>::default()
        }
    }

    #[test]
    fn hinted_inverse_modulo_a_prime_is_unique() {
        let circuit = hinted_inverse(101, 1);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(1))));
        assert!(uniqueness.determined.contains(&picus_wire(Witness(2))));
    }

    // Modulo 100, `a = 10` makes `10*x ≡ 0` hold for ten values of `x`; a
    // composite modulus must not be trusted.
    #[test]
    fn hinted_inverse_modulo_a_composite_is_not_claimed() {
        let circuit = hinted_inverse(100, 1);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(1))));
    }

    // `a*x ≡ 0 (mod 101)` is satisfied by every `x` once `a = 0`.
    #[test]
    fn inverse_against_zero_is_not_claimed() {
        let circuit = hinted_inverse(101, 0);
        let uniqueness = infer_uniqueness(&circuit, &inputs(&circuit));
        assert!(!uniqueness.determined.contains(&picus_wire(Witness(1))));
    }

    #[test]
    fn miller_rabin_agrees_on_known_values() {
        for prime in [2u64, 101, 68_719_403_009, 68_719_230_977] {
            assert!(is_prime(&BigUint::from(prime)), "{prime} is prime");
        }
        for composite in [1u64, 100, 68_719_403_009 * 3, 3_215_031_751] {
            assert!(
                !is_prime(&BigUint::from(composite)),
                "{composite} is composite"
            );
        }
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

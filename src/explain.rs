//! Explain a finding by the opcodes that touch its witness.
//!
//! A finding names a witness the prover could move. The question a reader then
//! asks is *why the constraint system let it move*, and answering that used to
//! mean dumping the ACIR by hand and grepping for the witness index. That is
//! mechanical, so it belongs in the tool.
//!
//! The verdict deliberately claims little. Listing every opcode that mentions a
//! witness is exact; deciding whether an `AssertZero` *pins* it is not, because
//! that depends on the rest of the system. So only one case is asserted: when
//! nothing but the witness's own definition and bound checks mention it, it is
//! bounded and never pinned, and that is provable from the list alone.

use std::collections::BTreeSet;

use num_bigint::BigUint;

use acir::{
    AcirField, FieldElement,
    circuit::{Circuit, Opcode, opcodes::BlackBoxFuncCall},
    native_types::Expression,
};

/// What one opcode does to the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A `BrilligCall` produces it: the prover's free choice.
    Defines,
    /// A bound — a range check — which restricts the value without fixing it.
    Bounds,
    /// An `AssertZero` mentions it. Whether it pins the value is not decided here.
    Asserts,
    /// A memory or black box opcode mentions it.
    Other,
}

/// One opcode that mentions the witness.
#[derive(Debug, Clone)]
pub struct Touch {
    pub index: usize,
    pub role: Role,
    pub description: String,
    /// Other witnesses in this opcode that moved in the same finding.
    pub moved_with: Vec<u32>,
    /// The witness appears only inside product terms here, so its coefficient
    /// is itself a witness and may be zero.
    ///
    /// A constraint written under an `if` compiles to `c * (h - a) = 0`. It
    /// reads as pinning `h`, and does pin it when `c` is one, but for `c` zero
    /// the equation holds for every `h`. Counting such an assertion as pinning
    /// is what made this pass miss the predicated case entirely.
    pub may_vanish: bool,
}

/// What the opcode list says about the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing at all mentions it beyond its definition.
    Unconstrained,
    /// Only its definition and bounds mention it, so no opcode can fix its
    /// value. This is provable from the list and is the interesting case: a
    /// range check is a constraint against a constant that pins nothing.
    BoundedNeverPinned,
    /// Assertions do mention it, but in every one its coefficient is itself a
    /// witness and can be zero, so none of them is able to fix its value.
    ///
    /// Kept apart from `BoundedNeverPinned` because the two say different
    /// things and reporting the first for the second contradicted the opcode
    /// list printed right underneath it.
    OnlyVanishingConstraints,
    /// Every assertion that mentions it also mentions another witness that
    /// moved with it. Such an assertion relates the two but fixes neither, so
    /// it only carries the freedom along instead of removing it. This is
    /// decidable from the finding itself and needs no reasoning about the rest
    /// of the system.
    PropagatesFreedom,
    /// Assertions mention it; whether they pin it is left open.
    Asserted,
}

#[derive(Debug, Clone)]
pub struct Explanation {
    pub witness: u32,
    pub touches: Vec<Touch>,
    pub verdict: Verdict,
}

impl Explanation {
    /// Whether the witness is a single bit that some assertion shares with
    /// other undetermined witnesses.
    ///
    /// This is the shape of one digit of a decomposition. Such a digit is not
    /// pinned by any assertion on its own, yet the group is pinned jointly —
    /// 254 bits and one weighted sum have exactly one solution once each bit
    /// is a bit. A per-witness rule cannot see that, so on `to_le_bits` every
    /// digit looks free and the report drowns. Recognising the shape is the
    /// cheapest way to keep the pass usable; the cost is that a genuinely free
    /// boolean hint is skipped too, which `--include-bits` puts back.
    pub fn looks_like_a_decomposition_digit(&self) -> bool {
        let single_bit = self.touches.iter().any(|touch| {
            touch.role == Role::Bounds && touch.description.ends_with("to 1 bits")
        });
        single_bit
            && self
                .touches
                .iter()
                .any(|touch| touch.role == Role::Asserts && !touch.moved_with.is_empty())
    }
}

/// Witnesses of `expression` other than `witness` that are in `moved`.
fn companions(
    expression: &Expression<FieldElement>,
    witness: u32,
    moved: &BTreeSet<u32>,
) -> Vec<u32> {
    let mut found = BTreeSet::new();
    for (_, lhs, rhs) in &expression.mul_terms {
        for index in [lhs.witness_index(), rhs.witness_index()] {
            if index != witness && moved.contains(&index) {
                found.insert(index);
            }
        }
    }
    for (_, other) in &expression.linear_combinations {
        let index = other.witness_index();
        if index != witness && moved.contains(&index) {
            found.insert(index);
        }
    }
    found.into_iter().collect()
}

/// Whether the witness's coefficient in this expression is not a constant.
///
/// Collecting `w` out of the expression gives `linear + Σ c·other`, so the
/// moment `w` appears in any product its coefficient is an expression over
/// other witnesses and can be zero. Appearing linearly as well does not save
/// it: `(w - a)(1 - p) = 0` expands to terms that mention `w` both ways, and
/// its coefficient is still `1 - p`, which vanishes at `p = 1`.
///
/// Requiring the witness to appear *only* in products, as a first version did,
/// missed exactly that form — the one Noir generates for `if a > 10 { ... }`.
/// Whether fixing `partner` to `value` makes `expression` identically zero.
///
/// "Identically zero" means zero as a polynomial in the remaining witnesses,
/// not merely zero for some assignment: every coefficient left has to vanish.
/// That is what distinguishes a constraint which stops saying anything from one
/// which becomes impossible to satisfy.
fn vanishes_when(
    expression: &Expression<FieldElement>,
    partner: u32,
    value: FieldElement,
) -> bool {
    let mut linear: std::collections::BTreeMap<u32, FieldElement> = Default::default();
    let mut constant = expression.q_c;

    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let (l, r) = (lhs.witness_index(), rhs.witness_index());
        match (l == partner, r == partner) {
            (true, true) => constant += *coefficient * value * value,
            (true, false) => *linear.entry(r).or_default() += *coefficient * value,
            (false, true) => *linear.entry(l).or_default() += *coefficient * value,
            // A product of two other witnesses survives, so the expression
            // still constrains something.
            (false, false) => {
                if !coefficient.is_zero() {
                    return false;
                }
            }
        }
    }
    for (coefficient, witness) in &expression.linear_combinations {
        let index = witness.witness_index();
        if index == partner {
            constant += *coefficient * value;
        } else {
            *linear.entry(index).or_default() += *coefficient;
        }
    }

    constant.is_zero() && linear.values().all(|coefficient| coefficient.is_zero())
}

/// Whether some assignment to a partner leaves this assertion saying nothing
/// about `witness`.
///
/// The witness's coefficient here is an expression over the witnesses it is
/// multiplied by, so it can vanish. What matters is what is left when it does:
///
/// * `c * (h - a) = 0`, from a constraint under an `if`, expands so that every
///   term carries `c`. At `c = 0` the whole equation reads `0 = 0` and `h` is
///   free. Reportable.
/// * `(h - a) * (1 - p) = 0`, which Noir emits for `if a > 10 { ... }`, goes
///   quiet at `p = 1` rather than at `p = 0` — so the candidate values matter,
///   not just zero.
/// * `w0*w2 + w1*w2 - 1 = 0`, the inverse witness behind `a + b != 0`, never
///   goes quiet: zeroing a partner leaves `-1 = 0`, which no prover can meet.
///   The circuit rejects, and rejecting is not a soundness problem. Noir ships
///   this program as correctly constrained, and reporting it was wrong.
///
/// Zero and one are the values tried, because the predicates Noir generates are
/// booleans and those are the two they take.
/// Целое значение элемента поля, если он лежит в нижней половине поля.
///
/// В поле «отрицательных» чисел нет: -1 представлено как p-1. Поэтому
/// принадлежность нижней половине — это и есть проверка, что коэффициент
/// действительно неотрицателен, а не большое число, ведущее себя как минус.
fn nonneg_value(value: FieldElement) -> Option<BigUint> {
    let n = BigUint::from_bytes_be(&value.to_be_bytes());
    let modulus = crate::translate::field_modulus();
    if n * BigUint::from(2u32) < modulus { Some(BigUint::from_bytes_be(&value.to_be_bytes())) } else { None }
}

/// Сигналы, про которые доказано, что они НИКОГДА не равны нулю.
///
/// Зачем. Делительный гаджет `numer = q * denom` закрепляет частное `q` тогда и
/// только тогда, когда знаменатель ненулевой. Наш проход этого не знал и считал,
/// что коэффициент при `q` (а это сам сигнал `denom`) может обнулиться, поэтому
/// выдавал кандидата там, где схема корректна.
///
/// Случай найден измерением (итерация 70): на сгенерированной схеме проход
/// сообщал о незакреплённом `w40`, тогда как знаменатель `w41 = w38*w39 + 1`
/// строился из сигналов, ограниченных 8 и 1 битом. Произведение не превышает
/// 98 бит, а обнулить знаменатель в поле можно лишь достигнув 254 бит — то есть
/// нуль недостижим, и `w40` на самом деле закреплён.
///
/// Признаётся форма `w = <неотрицательная комбинация ограниченных сигналов> + c`
/// при `c >= 1`, где вся сумма меньше модуля. Тогда `w` лежит в отрезке
/// `[c, сумма]`, заворачивания нет, и нуля быть не может.
pub fn provably_nonzero(
    circuit: &Circuit<FieldElement>,
    bounds: &std::collections::BTreeMap<u32, BigUint>,
) -> BTreeSet<u32> {
    let modulus = crate::translate::field_modulus();
    let mut result = BTreeSet::new();
    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else {
            continue;
        };
        for (coefficient, target_witness) in &expression.linear_combinations {
            // Сигнал, выраженный через остальные. Знак коэффициента зависит от
            // того, в какую сторону компилятор свернул равенство, поэтому
            // рассматриваются оба: при -1 остальные члены берутся как есть, при
            // +1 — с обратным знаком.
            let negate = if (*coefficient + FieldElement::one()).is_zero() {
                false
            } else if (*coefficient - FieldElement::one()).is_zero() {
                true
            } else {
                continue;
            };
            let sign = |value: FieldElement| {
                nonneg_value(if negate { -value } else { value })
            };
            let target = target_witness.witness_index();
            let Some(constant) = sign(expression.q_c) else {
                continue;
            };
            if constant < BigUint::from(1u32) {
                continue;
            }
            let mut total = constant;
            let mut ok = true;
            for (factor, lhs, rhs) in &expression.mul_terms {
                match (
                    sign(*factor),
                    bounds.get(&lhs.witness_index()),
                    bounds.get(&rhs.witness_index()),
                ) {
                    (Some(factor), Some(left), Some(right)) => total += factor * left * right,
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            for (factor, other) in &expression.linear_combinations {
                if other.witness_index() == target {
                    continue;
                }
                match (sign(*factor), bounds.get(&other.witness_index())) {
                    (Some(factor), Some(bound)) => total += factor * bound,
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && total < modulus {
                result.insert(target);
            }
        }
    }
    result
}

/// Границы, доведённые по линейным определениям до производных сигналов.
///
/// `value_bounds` знает границы только тех сигналов, у которых есть своя
/// проверка диапазона. Но компилятор постоянно вводит производные:
/// `w38 = w0 + 4294967040*w5`, где ограничены `w0` и `w5`, а сам `w38` — нет.
/// Без этого шага доказать ненулевость знаменателя не удавалось: сомножителей
/// просто не было в таблице. Проход повторяется до неподвижной точки, потому что
/// производные могут строиться друг на друге.
fn derived_bounds(
    circuit: &Circuit<FieldElement>,
    bounds: &std::collections::BTreeMap<u32, BigUint>,
) -> std::collections::BTreeMap<u32, BigUint> {
    let modulus = crate::translate::field_modulus();
    let mut bounds = bounds.clone();
    for _ in 0..4 {
        let before = bounds.len();
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else {
                continue;
            };
            for (coefficient, target_witness) in &expression.linear_combinations {
                let target = target_witness.witness_index();
                if bounds.contains_key(&target) {
                    continue;
                }
                let negate = if (*coefficient + FieldElement::one()).is_zero() {
                    false
                } else if (*coefficient - FieldElement::one()).is_zero() {
                    true
                } else {
                    continue;
                };
                let sign = |value: FieldElement| {
                    nonneg_value(if negate { -value } else { value })
                };
                let Some(constant) = sign(expression.q_c) else {
                    continue;
                };
                let mut total = constant;
                let mut ok = true;
                for (factor, lhs, rhs) in &expression.mul_terms {
                    match (
                        sign(*factor),
                        bounds.get(&lhs.witness_index()),
                        bounds.get(&rhs.witness_index()),
                    ) {
                        (Some(factor), Some(left), Some(right)) => total += factor * left * right,
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                for (factor, other) in &expression.linear_combinations {
                    if other.witness_index() == target {
                        continue;
                    }
                    match (sign(*factor), bounds.get(&other.witness_index())) {
                        (Some(factor), Some(bound)) => total += factor * bound,
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                // Граница имеет смысл, только пока сумма не может завернуться:
                // за модулем «меньше или равно» уже ничего не означает.
                if ok && total < modulus {
                    bounds.insert(target, total);
                }
            }
        }
        // Второй приём: сужение границы по равенству с константой.
        //
        // Компилятор проверяет каноничность разложения так:
        //     ASSERT w6 = C - w4,  RANGE w6
        // то есть `w4 + w6 = C`. Раз обе части неотрицательны и сумма не может
        // завернуться, каждая не превосходит C. Для `w4` это резко сужает
        // границу: с 246 бит (его собственная проверка диапазона) до C.
        //
        // Без этого шага позиционное разложение `w0 = 256*w4 + w5` не
        // признавалось однозначным: при границе 2^246 сумма выходила за модуль,
        // и охранное условие справедливо отказывало. А это шаблон КАЖДОГО
        // приведения `Field` к целому типу, то есть один из самых частых в Noir.
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else {
                continue;
            };
            if !expression.mul_terms.is_empty() {
                continue;
            }
            // форма `сумма неотрицательных = C`: свободный член равен -C
            let Some(constant) = nonneg_value(-expression.q_c) else {
                continue;
            };
            let mut total = BigUint::from(0u32);
            let mut terms = Vec::new();
            let mut ok = true;
            for (factor, witness) in &expression.linear_combinations {
                match (nonneg_value(*factor), bounds.get(&witness.witness_index())) {
                    (Some(factor), Some(bound)) if factor > BigUint::from(0u32) => {
                        total += &factor * bound;
                        terms.push((witness.witness_index(), factor));
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok || terms.is_empty() || total >= modulus {
                continue;
            }
            for (witness, factor) in terms {
                let tightened = &constant / &factor;
                bounds
                    .entry(witness)
                    .and_modify(|known| {
                        if tightened < *known {
                            *known = tightened.clone();
                        }
                    })
                    .or_insert(tightened);
            }
        }
        if bounds.len() == before {
            break;
        }
    }
    bounds
}

fn coefficient_may_vanish(
    expression: &Expression<FieldElement>,
    witness: u32,
    nonzero: &BTreeSet<u32>,
) -> bool {
    let partners = expression
        .mul_terms
        .iter()
        .filter(|(coefficient, lhs, rhs)| {
            !coefficient.is_zero()
                && (lhs.witness_index() == witness || rhs.witness_index() == witness)
        })
        .map(|(_, lhs, rhs)| {
            if lhs.witness_index() == witness { rhs.witness_index() } else { lhs.witness_index() }
        })
        .filter(|partner| *partner != witness)
        .collect::<BTreeSet<_>>();

    partners.into_iter().any(|partner| {
        // Партнёр, про которого доказано, что он ненулевой, обнулить коэффициент
        // не может — проверять его подстановкой нуля бессмысленно.
        !nonzero.contains(&partner)
            && (vanishes_when(expression, partner, FieldElement::zero())
                || vanishes_when(expression, partner, FieldElement::one()))
    })
}

fn mentions(expression: &Expression<FieldElement>, witness: u32) -> bool {
    expression
        .mul_terms
        .iter()
        .any(|(_, lhs, rhs)| lhs.witness_index() == witness || rhs.witness_index() == witness)
        || expression
            .linear_combinations
            .iter()
            .any(|(_, other)| other.witness_index() == witness)
}

/// Witnesses the circuit hands back: its declared return values, plus the
/// contents of any `ReturnData` memory block.
///
/// A program that routes its result through `return_data` leaves
/// `return_values` empty, so reading only that field misses every such circuit.
pub fn exposed_witnesses(circuit: &Circuit<FieldElement>) -> BTreeSet<u32> {
    let mut exposed = circuit
        .return_values
        .0
        .iter()
        .map(|witness| witness.witness_index())
        .collect::<BTreeSet<_>>();
    for opcode in &circuit.opcodes {
        if let Opcode::MemoryInit { init, block_type, .. } = opcode {
            if matches!(block_type, acir::circuit::opcodes::BlockType::ReturnData) {
                exposed.extend(init.iter().map(|witness| witness.witness_index()));
            }
        }
    }
    exposed
}

/// Grow `exposed` along assertions that link undetermined witnesses.
///
/// A hint that never reaches what the circuit hands back is the prover's own
/// business: it can take any value without changing what a verifier sees. Only
/// the ones that do reach an output are a soundness question, and this is what
/// separates the two. Without it the pass reports every hint in a program whose
/// `main` is entirely unconstrained, where there is nothing to pin by design.
pub fn reachable_from_outputs(
    circuit: &Circuit<FieldElement>,
    undetermined: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    let mut reached = exposed_witnesses(circuit);
    // A circuit that hands nothing back still has observable behaviour: it
    // accepts or it rejects. A free hint feeding an assertion can decide that,
    // letting a prover satisfy a circuit that should have turned it away. With
    // no outputs to walk back from, the assertions are the surface, so every
    // witness in one is treated as reachable.
    //
    // Noir's own `underconstrained_value_detector_5425` is exactly this shape:
    // `main` returns nothing, and walking back from outputs alone found no
    // candidate in a program the team ships as under-constrained.
    if reached.is_empty() {
        for opcode in &circuit.opcodes {
            if let Opcode::AssertZero(expression) = opcode {
                reached.extend(
                    expression
                        .linear_combinations
                        .iter()
                        .map(|(_, witness)| witness.witness_index()),
                );
                reached.extend(expression.mul_terms.iter().flat_map(|(_, lhs, rhs)| {
                    [lhs.witness_index(), rhs.witness_index()]
                }));
            }
        }
    }
    loop {
        let before = reached.len();
        for opcode in &circuit.opcodes {
            if let Opcode::AssertZero(expression) = opcode {
                let witnesses = expression
                    .mul_terms
                    .iter()
                    .flat_map(|(_, lhs, rhs)| [lhs.witness_index(), rhs.witness_index()])
                    .chain(
                        expression
                            .linear_combinations
                            .iter()
                            .map(|(_, witness)| witness.witness_index()),
                    )
                    .collect::<BTreeSet<_>>();
                if witnesses.iter().any(|witness| reached.contains(witness)) {
                    reached.extend(witnesses.iter().filter(|w| undetermined.contains(w)));
                }
            }
        }
        if reached.len() == before {
            return reached;
        }
    }
}

/// Find `IsZero` gadgets whose tested value is already determined.
///
/// Noir emits two assertions for it: `y*inv + flag - 1 = 0` and `y*flag = 0`.
/// Neither pins `inv` or `flag` on its own — the first has `inv` multiplied by
/// `y`, the second is vacuous at `y = 0` — but together they pin both once `y`
/// is known: `y = 0` forces `flag = 1, inv` free-but-irrelevant, and `y != 0`
/// forces `flag = 0, inv = 1/y`.
///
/// Every `!=` and every integer comparison compiles to one, so leaving it out
/// meant a scan of real programs reported the gadget over and over. `bit_and`
/// in Noir's corpus produced twelve candidates, all of them this.
fn is_zero_gadgets(
    circuit: &Circuit<FieldElement>,
    determined: &BTreeSet<u32>,
) -> Vec<(u32, u32)> {
    let free = |witness: u32| !determined.contains(&witness);
    // Candidate flags from the vacuous half: every term is a product with the
    // flag, and the other side of each product is known.
    // The tested value is usually an expression, not one witness, so `y*flag`
    // arrives already expanded: `-w4*flag + K*flag`. Both a product and a plain
    // term then mention the flag, and requiring the linear part to be empty
    // matched nothing at all.
    let factors_out = |expression: &Expression<FieldElement>, candidate: u32| {
        !expression.mul_terms.is_empty()
            && expression.mul_terms.iter().all(|(coefficient, lhs, rhs)| {
                let (l, r) = (lhs.witness_index(), rhs.witness_index());
                coefficient.is_zero()
                    || (l == candidate && !free(r))
                    || (r == candidate && !free(l))
            })
            && expression
                .linear_combinations
                .iter()
                .all(|(coefficient, witness)| {
                    coefficient.is_zero() || witness.witness_index() == candidate
                })
    };

    let mut flags = BTreeSet::new();
    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else { continue };
        if !expression.q_c.is_zero() || expression.mul_terms.is_empty() {
            continue;
        }
        for candidate in [expression.mul_terms[0].1, expression.mul_terms[0].2] {
            let candidate = candidate.witness_index();
            if free(candidate) && factors_out(expression, candidate) {
                flags.insert(candidate);
            }
        }
    }

    let mut found = Vec::new();
    for opcode in &circuit.opcodes {
        let Opcode::AssertZero(expression) = opcode else { continue };
        // The other half: `y*inv + flag - 1 = 0`.
        if expression.q_c != -FieldElement::one() || expression.mul_terms.is_empty() {
            continue;
        }
        // One plain term with coefficient one is the flag; everything else has
        // to factor through the inverse.
        let Some((_, flag)) = expression
            .linear_combinations
            .iter()
            .find(|(coefficient, witness)| {
                *coefficient == FieldElement::one() && flags.contains(&witness.witness_index())
            })
        else {
            continue;
        };
        let flag = flag.witness_index();
        for candidate in [expression.mul_terms[0].1, expression.mul_terms[0].2] {
            let inverse = candidate.witness_index();
            if inverse == flag || !free(inverse) {
                continue;
            }
            let rest = Expression {
                mul_terms: expression.mul_terms.clone(),
                linear_combinations: expression
                    .linear_combinations
                    .iter()
                    .filter(|(_, witness)| witness.witness_index() != flag)
                    .cloned()
                    .collect(),
                q_c: FieldElement::zero(),
            };
            if factors_out(&rest, inverse) {
                found.push((flag, inverse));
                break;
            }
        }
    }
    found
}

/// Extend a determined set through memory reads and single-unknown assertions.
///
/// The model's propagation stops at `MemoryOp`, so every value read out of an
/// array stays "not known to be determined" and drags whatever depends on it
/// along. That one gap accounted for every false candidate left on both of the
/// samples measured: Noir's own `regression_8236` reads `w8` out of a constant
/// array, and the generated cases read a table entry and then split it.
///
/// Two rules, both sound. A read is determined when the index is determined and
/// every entry of the block is; whichever entry is selected, it is a determined
/// value. And a linear assertion with exactly one witness left determines it,
/// provided its coefficient does not vanish.
pub fn refine_determined(
    circuit: &Circuit<FieldElement>,
    determined: &mut BTreeSet<u32>,
) {
    // Границы расширяются один раз: производные сигналы и сужение по равенству
    // с константой. Дальше ими пользуются и правило деления, и признание
    // позиционного разложения.
    let bounds = derived_bounds(circuit, &value_bounds(circuit));
    let nonzero = provably_nonzero(circuit, &bounds);
    let mut blocks: std::collections::BTreeMap<u32, Vec<u32>> = Default::default();
    for opcode in &circuit.opcodes {
        if let Opcode::MemoryInit { block_id, init, .. } = opcode {
            blocks.insert(
                block_id.as_u32(),
                init.iter().map(|witness| witness.witness_index()).collect(),
            );
        }
    }

    loop {
        let before = determined.len();
        for (flag, inverse) in is_zero_gadgets(circuit, determined) {
            determined.insert(flag);
            determined.insert(inverse);
        }
        for opcode in &circuit.opcodes {
            match opcode {
                Opcode::MemoryOp { block_id, op } => {
                    let Some(cells) = blocks.get(&block_id.as_u32()) else {
                        continue;
                    };
                    if determined.contains(&op.index.witness_index())
                        && cells.iter().all(|cell| determined.contains(cell))
                    {
                        determined.insert(op.value.witness_index());
                    }
                }
                Opcode::AssertZero(expression) => {
                    // A product of two determined witnesses is a known quantity,
                    // so it does not stand in the way of solving for the one
                    // unknown left. Requiring the whole expression to be linear
                    // broke every chain that passes through a squaring — and
                    // `x << s` is exactly that: `2^s` is built by repeated
                    // squaring, so a dozen constraints of the form
                    // `w = w_prev*w_prev + ...` sat between the shift amount and
                    // the result, and everything downstream stayed "unknown".
                    if expression.mul_terms.iter().any(|(coefficient, lhs, rhs)| {
                        !coefficient.is_zero()
                            && (!determined.contains(&lhs.witness_index())
                                || !determined.contains(&rhs.witness_index()))
                    }) {
                        // Неизвестное стоит МНОЖИТЕЛЕМ, а не слагаемым. Линейное
                        // правило выше такое ограничение решить не может, но
                        // делительный гаджет `numer = q * denom` устроен именно
                        // так, и это самая частая форма подсказки в Noir. Если
                        // знаменатель определён и доказано ненулевой, на него
                        // можно поделить — тогда частное определено.
                        //
                        // Без этого правила проход сообщал о незакреплённом
                        // частном на корректных схемах: измерено на seed=9142,
                        // где знаменатель `w38*w39 + 1` строился из сигналов,
                        // ограниченных 8 и 1 битом, и нуля достичь не мог.
                        if let Some(solved) =
                            unknown_factor_solvable(expression, determined, &nonzero)
                        {
                            determined.insert(solved);
                        }
                        continue;
                    }
                    let unknown = expression
                        .linear_combinations
                        .iter()
                        .filter(|(_, witness)| !determined.contains(&witness.witness_index()))
                        .collect::<Vec<_>>();
                    match unknown.as_slice() {
                        [(coefficient, witness)] => {
                            if !coefficient.is_zero() {
                                determined.insert(witness.witness_index());
                            }
                        }
                        // A positional split determines *all* of its digits
                        // once everything else in the equation is determined.
                        // Used as a determinacy rule rather than only as a
                        // filter, it cascades: the quotient and remainder of a
                        // division hint become determined, which determines the
                        // index computed from them, which determines the value
                        // read out of an array, and so on down a chain that
                        // otherwise stayed free all the way to the output.
                        many if many.len() >= 2 => {
                            if pinned_by_positional_split(expression, &|w| !determined.contains(&w), &bounds) {
                                for (_, witness) in many {
                                    determined.insert(witness.witness_index());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if determined.len() == before {
            return;
        }
    }
}

/// Единственное неизвестное, стоящее множителем при ненулевом определённом
/// сомножителе, — если ограничение имеет ровно такую форму.
///
/// Требования намеренно узкие: ровно один сомножитель-неизвестное во всём
/// ограничении, его партнёр определён и доказано ненулевой, остальные
/// произведения полностью определены, и само неизвестное не входит в линейную
/// часть. Последнее существенно: иначе его полный коэффициент равен
/// `c*denom + linear`, и ненулевость партнёра уже ничего не гарантирует.
fn unknown_factor_solvable(
    expression: &Expression<FieldElement>,
    determined: &BTreeSet<u32>,
    nonzero: &BTreeSet<u32>,
) -> Option<u32> {
    let mut candidate = None;
    for (coefficient, lhs, rhs) in &expression.mul_terms {
        if coefficient.is_zero() {
            continue;
        }
        let left = lhs.witness_index();
        let right = rhs.witness_index();
        let known_left = determined.contains(&left);
        let known_right = determined.contains(&right);
        match (known_left, known_right) {
            (true, true) => continue,
            (true, false) => {
                if !nonzero.contains(&left) || candidate.is_some_and(|c| c != right) {
                    return None;
                }
                candidate = Some(right);
            }
            (false, true) => {
                if !nonzero.contains(&right) || candidate.is_some_and(|c| c != left) {
                    return None;
                }
                candidate = Some(left);
            }
            (false, false) => return None,
        }
    }
    let unknown = candidate?;
    if expression
        .linear_combinations
        .iter()
        .any(|(coefficient, witness)| {
            !coefficient.is_zero() && witness.witness_index() == unknown
        })
    {
        return None;
    }
    // всё остальное в линейной части обязано быть известным, иначе неизвестных два
    if expression.linear_combinations.iter().any(|(coefficient, witness)| {
        !coefficient.is_zero() && !determined.contains(&witness.witness_index())
    }) {
        return None;
    }
    Some(unknown)
}

/// The largest value each witness can take, as far as the opcodes say.
///
/// A `RANGE` to `k` bits gives `2^k - 1` directly. Noir also bounds a value
/// below a *non-power of two* by range-checking a shifted copy: `x / 7` emits
/// `w4 = w3 + 1` with `w4` held to three bits, which says `w3 <= 6`, one less
/// than the divisor. Reading only the direct ranges makes every division by a
/// non-power of two look ambiguous, since three bits would allow `7` itself —
/// and that mistake reported `x / 7` as under-constrained when it is not.
///
/// Widths at or above 127 are skipped rather than saturated: these bounds get
/// compared against divisors, and a wrong bound would be worse than none.
pub fn value_bounds(circuit: &Circuit<FieldElement>) -> std::collections::BTreeMap<u32, BigUint> {
    let mut bounds: std::collections::BTreeMap<u32, BigUint> = Default::default();
    // Held as big integers rather than machine words. A cast splits a field
    // element into a small low part and a 246-bit high part, and dropping the
    // wide one for not fitting a `u128` left the high limb unbounded — which
    // made every cast look ambiguous, since in a field the high limb can always
    // absorb a change to the low one unless a bound forbids it.
    let mut note = |bounds: &mut std::collections::BTreeMap<u32, BigUint>, witness, num_bits: u32| {
        let max = (BigUint::from(1u32) << num_bits) - BigUint::from(1u32);
        bounds
            .entry(witness)
            .and_modify(|known| {
                if max < *known {
                    *known = max.clone();
                }
            })
            .or_insert(max);
    };
    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { input, num_bits }) => {
                if let acir::circuit::opcodes::FunctionInput::Witness(witness) = input {
                    note(&mut bounds, witness.witness_index(), *num_bits);
                }
            }
            // AND and XOR bound their operands and result as a side effect, the
            // same fact Noir's own `redundant_range` pass relies on to drop
            // range checks it considers already implied. A cast like `x as u8`
            // followed by a bitwise operation leaves the low part bounded only
            // this way, with no `RANGE` opcode of its own — reading ranges alone
            // made every such cast look like an ambiguous split.
            Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::AND { lhs, rhs, num_bits, output }
                | BlackBoxFuncCall::XOR { lhs, rhs, num_bits, output },
            ) => {
                for input in [lhs, rhs] {
                    if let acir::circuit::opcodes::FunctionInput::Witness(witness) = input {
                        note(&mut bounds, witness.witness_index(), *num_bits);
                    }
                }
                note(&mut bounds, output.witness_index(), *num_bits);
            }
            _ => {}
        }
    }

    // Carry bounds across `shifted = value + offset`, in both directions.
    loop {
        let before = bounds.clone();
        for opcode in &circuit.opcodes {
            let Opcode::AssertZero(expression) = opcode else { continue };
            if !expression.mul_terms.is_empty() || expression.linear_combinations.len() != 2 {
                continue;
            }
            let (first_c, first) = &expression.linear_combinations[0];
            let (second_c, second) = &expression.linear_combinations[1];
            let one = FieldElement::one();
            let (plus, minus) = if *first_c == one && *second_c == -one {
                (first.witness_index(), second.witness_index())
            } else if *second_c == one && *first_c == -one {
                (second.witness_index(), first.witness_index())
            } else {
                continue;
            };
            // plus - minus + q_c = 0, so minus = plus + q_c.
            let forward = small_value(expression.q_c);
            let backward = small_value(-expression.q_c);
            let (offset, minus_is_larger) = match (forward, backward) {
                (Some(offset), _) => (offset, true),
                (None, Some(offset)) => (offset, false),
                (None, None) => continue,
            };
            let (larger, smaller) =
                if minus_is_larger { (minus, plus) } else { (plus, minus) };
            let offset = BigUint::from(offset);
            if let Some(max) = bounds.get(&larger).cloned() {
                let derived = if max >= offset { max - &offset } else { BigUint::from(0u32) };
                bounds
                    .entry(smaller)
                    .and_modify(|k| { if derived < *k { *k = derived.clone(); } })
                    .or_insert(derived);
            }
            if let Some(max) = bounds.get(&smaller).cloned() {
                let derived = max + &offset;
                bounds
                    .entry(larger)
                    .and_modify(|k| { if derived < *k { *k = derived.clone(); } })
                    .or_insert(derived);
            }
        }
        if bounds == before {
            return bounds;
        }
    }
}

/// A field element as a small non-negative integer, or `None` if it is large.
fn small_value(value: FieldElement) -> Option<u128> {
    if value.is_zero() {
        return Some(0);
    }
    if value.num_bits() > 64 {
        return None;
    }
    let bytes = value.to_be_bytes();
    let mut result = 0u128;
    for byte in bytes.iter().skip(bytes.len().saturating_sub(16)) {
        result = (result << 8) | u128::from(*byte);
    }
    Some(result)
}

/// Whether an assertion pins every free witness in it by positional weight.
///
/// Noir writes both `x / d` and a byte decomposition the same way:
/// `known - c0*d0 - c1*d1 - ... = 0`, with each digit bounded. Such a sum has
/// one solution exactly when the weights are *superincreasing* — each weight
/// larger than everything the lighter digits can add up to. Then no digit can
/// borrow from another and the representation is forced.
///
/// This covers the two-term division case and the eight-limb `u64` split with
/// the same test, which the earlier pairwise rule could not: it left every
/// multi-limb decomposition looking free, and those are everywhere in real
/// programs.
fn pinned_by_positional_split(
    expression: &Expression<FieldElement>,
    is_free: &dyn Fn(u32) -> bool,
    bounds: &std::collections::BTreeMap<u32, BigUint>,
) -> bool {
    // A product of two *determined* witnesses is a known quantity, no different
    // from the constant term. Bailing on any product at all made the rule miss
    // every shift: `x << s` compiles to `x * 2^s = 2^16 * high + low`, whose
    // left side is a product and whose right side is an ordinary positional
    // split with superincreasing weights.
    for (coefficient, lhs, rhs) in &expression.mul_terms {
        if coefficient.is_zero() {
            continue;
        }
        if is_free(lhs.witness_index()) || is_free(rhs.witness_index()) {
            return false;
        }
    }
    let mut free = Vec::new();
    for (coefficient, other) in &expression.linear_combinations {
        let index = other.witness_index();
        if coefficient.is_zero() || !is_free(index) {
            continue;
        }
        let Some(max) = bounds.get(&index).cloned() else {
            return false;
        };
        let Some(weight) = small_value(*coefficient).or_else(|| small_value(-*coefficient)) else {
            return false;
        };
        if weight == 0 {
            return false;
        }
        free.push((BigUint::from(weight), max));
    }
    if free.is_empty() {
        return false;
    }
    free.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut reach = BigUint::from(0u32);
    for (weight, max) in &free {
        if *weight <= reach {
            return false;
        }
        reach += weight * max;
    }
    // The whole sum has to stay below the modulus, or a representation could
    // wrap around and a second one appear where the bounds say there is none.
    reach < crate::translate::field_modulus()
}

/// Collect every opcode of `circuit` that mentions `witness`.
pub fn explain(
    circuit: &Circuit<FieldElement>,
    witness: u32,
    moved: &BTreeSet<u32>,
) -> Explanation {
    explain_with_bounds(circuit, witness, moved, &Default::default())
}

/// As [`explain`], but able to recognise a Euclidean split as pinning.
///
/// The bounds are passed in rather than recomputed so a caller scanning every
/// hint of a circuit collects them once.
pub fn explain_with_bounds(
    circuit: &Circuit<FieldElement>,
    witness: u32,
    moved: &BTreeSet<u32>,
    bounds: &std::collections::BTreeMap<u32, BigUint>,
) -> Explanation {
    let mut touches = Vec::new();
    let mut split_pinned = false;
    let bounds = &derived_bounds(circuit, bounds);
    let nonzero = provably_nonzero(circuit, bounds);

    for (index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) if mentions(expression, witness) => {
                split_pinned |=
                    pinned_by_positional_split(expression, &|w| moved.contains(&w), bounds);
                touches.push(Touch {
                    index,
                    role: Role::Asserts,
                    description: format!("AssertZero: {expression}"),
                    moved_with: companions(expression, witness, moved),
                    may_vanish: coefficient_may_vanish(expression, witness, &nonzero),
                });
            }
            Opcode::BrilligCall { outputs, id, .. }
                if outputs.iter().any(|output| match output {
                    acir::circuit::brillig::BrilligOutputs::Simple(single) => {
                        single.witness_index() == witness
                    }
                    acir::circuit::brillig::BrilligOutputs::Array(items) => {
                        items.iter().any(|item| item.witness_index() == witness)
                    }
                }) =>
            {
                touches.push(Touch {
                    index,
                    role: Role::Defines,
                    description: format!("BrilligCall {id:?}: produces w{witness}"),
                    moved_with: Vec::new(),
                    may_vanish: false,
                });
            }
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { input, num_bits })
                if input.to_witness().witness_index() == witness =>
            {
                touches.push(Touch {
                    index,
                    role: Role::Bounds,
                    description: format!("RANGE w{witness} to {num_bits} bits"),
                    moved_with: Vec::new(),
                    may_vanish: false,
                });
            }
            Opcode::MemoryOp { block_id, op } => {
                if op.index.witness_index() == witness || op.value.witness_index() == witness {
                    touches.push(Touch {
                        index,
                        role: Role::Other,
                        description: format!("MemoryOp on block {}", block_id.as_u32()),
                        moved_with: Vec::new(),
                    may_vanish: false,
                    });
                }
            }
            Opcode::MemoryInit { block_id, init, .. }
                if init.iter().any(|item| item.witness_index() == witness) =>
            {
                touches.push(Touch {
                    index,
                    role: Role::Other,
                    description: format!("MemoryInit of block {}", block_id.as_u32()),
                    moved_with: Vec::new(),
                    may_vanish: false,
                });
            }
            _ => {}
        }
    }

    let bounded = touches.iter().any(|touch| touch.role == Role::Bounds);
    let pinnable = touches.iter().any(|touch| {
        (touch.role == Role::Asserts && !touch.may_vanish) || touch.role == Role::Other
    });
    // Only assertions that could pin the witness are weighed. One whose
    // coefficient in the witness is itself a witness may vanish, and then it
    // constrains nothing at all.
    let assertions = touches
        .iter()
        .filter(|touch| touch.role == Role::Asserts && !touch.may_vanish)
        .collect::<Vec<_>>();
    let only_memory = touches
        .iter()
        .filter(|touch| touch.role == Role::Other)
        .count()
        == 0;
    let vanishing = touches
        .iter()
        .any(|touch| touch.role == Role::Asserts && touch.may_vanish);
    let verdict = if split_pinned {
        Verdict::Asserted
    } else if !assertions.is_empty()
        && only_memory
        && assertions.iter().all(|touch| !touch.moved_with.is_empty())
    {
        Verdict::PropagatesFreedom
    } else if pinnable {
        Verdict::Asserted
    } else if vanishing {
        Verdict::OnlyVanishingConstraints
    } else if bounded {
        Verdict::BoundedNeverPinned
    } else {
        Verdict::Unconstrained
    };

    Explanation { witness, touches, verdict }
}

impl Explanation {
    /// One line naming what the opcode list establishes.
    pub fn headline(&self) -> String {
        match self.verdict {
            Verdict::Unconstrained => format!(
                "w{} is produced and never mentioned again: the prover chooses it outright",
                self.witness
            ),
            Verdict::BoundedNeverPinned => format!(
                "w{} is bounded but never pinned — every opcode touching it is its own \
                 definition or a range check, so nothing can fix its value",
                self.witness
            ),
            Verdict::OnlyVanishingConstraints => format!(
                "w{} is never pinned: every assertion touching it multiplies it \
                 by another witness, so each one holds for any value once that \
                 witness is zero",
                self.witness
            ),
            Verdict::PropagatesFreedom => format!(
                "w{} is never pinned: every assertion touching it also moves \
                 another witness of the same finding, so each relates the two \
                 without fixing either",
                self.witness
            ),
            Verdict::Asserted => format!(
                "w{} appears in {} assertion(s); whether they pin it is not decided here",
                self.witness,
                self.touches
                    .iter()
                    .filter(|touch| touch.role == Role::Asserts)
                    .count()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acir::AcirField;
    use acir::circuit::opcodes::FunctionInput;
    use acir::native_types::Witness;

    fn circuit(opcodes: Vec<Opcode<FieldElement>>) -> Circuit<FieldElement> {
        Circuit { opcodes, ..Default::default() }
    }

    /// `w1 - w2` with both moving is the shape of a hint copied to an output:
    /// it relates the two and pins neither.
    #[test]
    fn an_assertion_that_moves_with_its_partner_does_not_pin() {
        let expression = Expression {
            mul_terms: Vec::new(),
            linear_combinations: vec![
                (FieldElement::one(), Witness(1)),
                (-FieldElement::one(), Witness(2)),
            ],
            q_c: FieldElement::zero(),
        };
        let moved = BTreeSet::from([1, 2]);
        let explanation = explain(&circuit(vec![Opcode::AssertZero(expression)]), 1, &moved);
        assert_eq!(explanation.verdict, Verdict::PropagatesFreedom);
    }

    /// The same assertion where the partner stayed put says nothing on its own,
    /// so the verdict must stay open rather than claim the witness is free.
    #[test]
    fn an_assertion_against_a_settled_witness_leaves_the_verdict_open() {
        let expression = Expression {
            mul_terms: Vec::new(),
            linear_combinations: vec![
                (FieldElement::one(), Witness(1)),
                (-FieldElement::one(), Witness(2)),
            ],
            q_c: FieldElement::zero(),
        };
        let moved = BTreeSet::from([1]);
        let explanation = explain(&circuit(vec![Opcode::AssertZero(expression)]), 1, &moved);
        assert_eq!(explanation.verdict, Verdict::Asserted);
    }

    /// `c * (h - a) = 0` is what a constraint written under an `if` compiles
    /// to. It pins `h` when `c` is one and says nothing when `c` is zero, so it
    /// must not count as pinning.
    #[test]
    fn a_constraint_whose_coefficient_is_a_witness_does_not_pin() {
        let expression = Expression {
            mul_terms: vec![
                (FieldElement::one(), Witness(1), Witness(3)),
                (-FieldElement::one(), Witness(1), Witness(2)),
            ],
            linear_combinations: Vec::new(),
            q_c: FieldElement::zero(),
        };
        let explanation = explain(&circuit(vec![Opcode::AssertZero(expression)]), 3, &BTreeSet::new());
        assert!(explanation.touches[0].may_vanish);
        // Not `Unconstrained`: an assertion *is* present, it just cannot pin.
        // Saying otherwise would contradict the opcode list printed with it.
        assert_eq!(explanation.verdict, Verdict::OnlyVanishingConstraints);
    }

    /// `w0*w2 + w1*w2 - 1 = 0` is the inverse witness behind `a + b != 0`.
    /// Zeroing a partner leaves `-1 = 0`, which no prover can satisfy, so the
    /// circuit rejects rather than letting `w2` roam. Noir ships this program
    /// as correctly constrained and reporting it was wrong.
    #[test]
    fn a_coefficient_that_cannot_vanish_without_breaking_the_equation_still_pins() {
        let expression = Expression {
            mul_terms: vec![
                (FieldElement::one(), Witness(0), Witness(2)),
                (FieldElement::one(), Witness(1), Witness(2)),
            ],
            linear_combinations: Vec::new(),
            q_c: -FieldElement::one(),
        };
        let explanation = explain(&circuit(vec![Opcode::AssertZero(expression)]), 2, &BTreeSet::new());
        assert!(!explanation.touches[0].may_vanish);
    }

    /// `(h - a) * (1 - p) = 0`, what Noir emits for a constraint under a
    /// comparison, goes quiet at `p = 1` rather than at `p = 0`.
    #[test]
    fn a_coefficient_can_vanish_at_one_as_well_as_at_zero() {
        // w0*w3 - w2*w3 - w0 + w2 = 0
        let expression = Expression {
            mul_terms: vec![
                (FieldElement::one(), Witness(0), Witness(3)),
                (-FieldElement::one(), Witness(2), Witness(3)),
            ],
            linear_combinations: vec![
                (-FieldElement::one(), Witness(0)),
                (FieldElement::one(), Witness(2)),
            ],
            q_c: FieldElement::zero(),
        };
        let explanation = explain(&circuit(vec![Opcode::AssertZero(expression)]), 2, &BTreeSet::new());
        assert!(explanation.touches[0].may_vanish);
    }

    /// A range check bounds a witness without fixing it, which is exactly the
    /// case the tool exists to name.
    #[test]
    fn a_range_check_alone_bounds_without_pinning() {
        let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(Witness(1)),
            num_bits: 8,
        });
        let explanation = explain(&circuit(vec![opcode]), 1, &BTreeSet::new());
        assert_eq!(explanation.verdict, Verdict::BoundedNeverPinned);
    }
}

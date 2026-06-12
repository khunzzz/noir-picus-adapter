//! Translation of the `AND`/`XOR` black boxes via bit decomposition of both
//! inputs and the output, with one IR constraint per bit position.

use std::collections::HashSet;

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};

use super::TranslatedGroup;
use super::ir::{field_to_biguint, neg_mod_coeff, picus_wire, var_name};
use super::range::{allocate_range_aux_wires, range_constraints};
use super::wires::function_input_wires;

#[derive(Clone, Copy, Debug)]
pub(super) enum BitwiseOp {
    And,
    Xor,
}

/// The operands of one `AND`/`XOR` black box call.
#[derive(Clone, Copy, Debug)]
pub(super) struct BitwiseCall {
    pub(super) op: BitwiseOp,
    pub(super) lhs: FunctionInput<FieldElement>,
    pub(super) rhs: FunctionInput<FieldElement>,
    pub(super) output: Witness,
    pub(super) num_bits: u32,
}

#[derive(Clone, Debug)]
struct BitwiseAuxWires {
    lhs: Vec<usize>,
    rhs: Vec<usize>,
    output: Vec<usize>,
}

#[derive(Clone, Copy, Debug)]
enum BitRef {
    Constant(bool),
    Wire(usize),
}

pub(super) fn bitwise_constraint_group(
    call: &BitwiseCall,
    next_aux_wire: &mut usize,
    input_indices: &HashSet<usize>,
) -> TranslatedGroup {
    let aux_wires = allocate_bitwise_aux_wires(call, next_aux_wire)?;
    let orig = bitwise_constraints(call, &aux_wires, false, input_indices)?;
    let alt = bitwise_constraints(call, &aux_wires, true, input_indices)?;
    let mut wires = function_input_wires(&call.lhs);
    wires.extend(function_input_wires(&call.rhs));
    wires.push(picus_wire(call.output));
    wires.extend(aux_wires.lhs.iter().copied());
    wires.extend(aux_wires.rhs.iter().copied());
    wires.extend(aux_wires.output.iter().copied());

    Ok((wires, orig, alt))
}

fn allocate_bitwise_aux_wires(
    call: &BitwiseCall,
    next_aux_wire: &mut usize,
) -> Result<BitwiseAuxWires, String> {
    let num_bits = call.num_bits;
    if num_bits >= FieldElement::max_num_bits() {
        return Err(format!(
            "unsupported {} width {num_bits}: bitwise opcodes require explicit bit decomposition",
            bitwise_op_name(call.op)
        ));
    }

    let mut local_next_aux_wire = *next_aux_wire;
    let aux_wires = BitwiseAuxWires {
        lhs: allocate_range_aux_wires(call.lhs, num_bits, &mut local_next_aux_wire)?,
        rhs: allocate_range_aux_wires(call.rhs, num_bits, &mut local_next_aux_wire)?,
        output: allocate_range_aux_wires(
            FunctionInput::Witness(call.output),
            num_bits,
            &mut local_next_aux_wire,
        )?,
    };
    *next_aux_wire = local_next_aux_wire;
    Ok(aux_wires)
}

fn bitwise_constraints(
    call: &BitwiseCall,
    aux_wires: &BitwiseAuxWires,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Result<Vec<IRConstraint>, String> {
    let num_bits = call.num_bits;
    let mut constraints = Vec::new();
    constraints.extend(range_constraints(
        call.lhs,
        num_bits,
        &aux_wires.lhs,
        is_alt,
        input_indices,
    )?);
    constraints.extend(range_constraints(
        call.rhs,
        num_bits,
        &aux_wires.rhs,
        is_alt,
        input_indices,
    )?);
    constraints.extend(range_constraints(
        FunctionInput::Witness(call.output),
        num_bits,
        &aux_wires.output,
        is_alt,
        input_indices,
    )?);

    let lhs_bits = input_bit_refs(call.lhs, num_bits, &aux_wires.lhs)?;
    let rhs_bits = input_bit_refs(call.rhs, num_bits, &aux_wires.rhs)?;
    let output_bits = input_bit_refs(
        FunctionInput::Witness(call.output),
        num_bits,
        &aux_wires.output,
    )?;

    for ((lhs_bit, rhs_bit), output_bit) in lhs_bits.into_iter().zip(rhs_bits).zip(output_bits) {
        constraints.push(bitwise_bit_constraint(
            call.op,
            lhs_bit,
            rhs_bit,
            output_bit,
            is_alt,
            input_indices,
        ));
    }

    Ok(constraints)
}

fn input_bit_refs(
    input: FunctionInput<FieldElement>,
    num_bits: u32,
    aux_wires: &[usize],
) -> Result<Vec<BitRef>, String> {
    let num_bits = usize::try_from(num_bits)
        .map_err(|_| format!("RANGE width {num_bits} does not fit usize"))?;
    match input {
        FunctionInput::Constant(value) => constant_bit_refs(value, num_bits),
        FunctionInput::Witness(_) if num_bits == 0 => Ok(Vec::new()),
        FunctionInput::Witness(witness) if num_bits == 1 => {
            Ok(vec![BitRef::Wire(picus_wire(witness))])
        }
        FunctionInput::Witness(_) => {
            if aux_wires.len() != num_bits {
                return Err(format!(
                    "bit decomposition internal error: expected {num_bits} aux wires, got {}",
                    aux_wires.len()
                ));
            }
            Ok(aux_wires.iter().copied().map(BitRef::Wire).collect())
        }
    }
}

fn constant_bit_refs(value: FieldElement, num_bits: usize) -> Result<Vec<BitRef>, String> {
    let mut value = field_to_biguint(value);
    let one = BigUint::one();
    let mut bits = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        bits.push(BitRef::Constant((&value & &one) == one));
        value >>= 1usize;
    }
    if value.is_zero() {
        Ok(bits)
    } else {
        Err("constant does not fit requested bit width".to_owned())
    }
}

fn bitwise_bit_constraint(
    op: BitwiseOp,
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match op {
        BitwiseOp::And => and_bit_constraint(lhs, rhs, output, is_alt, input_indices),
        BitwiseOp::Xor => xor_bit_constraint(lhs, rhs, output, is_alt, input_indices),
    }
}

fn and_bit_constraint(
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match (lhs, rhs) {
        (BitRef::Constant(false), _) | (_, BitRef::Constant(false)) => {
            bit_linear_constraint(vec![(BigUint::one(), output)], is_alt, input_indices)
        }
        (BitRef::Constant(true), bit) | (bit, BitRef::Constant(true)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (neg_mod_coeff(&BigUint::one()), bit),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Wire(lhs), BitRef::Wire(rhs)) => IRConstraint::NonLinear {
            lhs_terms: vec![IRProductTerm {
                coeff: BigUint::one(),
                var_a: var_name(lhs, is_alt, input_indices),
                var_b: var_name(rhs, is_alt, input_indices),
            }],
            rhs_terms: bit_linear_terms(vec![(BigUint::one(), output)], is_alt, input_indices),
        },
    }
}

fn xor_bit_constraint(
    lhs: BitRef,
    rhs: BitRef,
    output: BitRef,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    match (lhs, rhs) {
        (BitRef::Constant(false), bit) | (bit, BitRef::Constant(false)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (neg_mod_coeff(&BigUint::one()), bit),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Constant(true), bit) | (bit, BitRef::Constant(true)) => bit_linear_constraint(
            vec![
                (BigUint::one(), output),
                (BigUint::one(), bit),
                (neg_mod_coeff(&BigUint::one()), BitRef::Constant(true)),
            ],
            is_alt,
            input_indices,
        ),
        (BitRef::Wire(lhs), BitRef::Wire(rhs)) => IRConstraint::NonLinear {
            lhs_terms: vec![IRProductTerm {
                coeff: BigUint::from(2u32),
                var_a: var_name(lhs, is_alt, input_indices),
                var_b: var_name(rhs, is_alt, input_indices),
            }],
            rhs_terms: bit_linear_terms(
                vec![
                    (BigUint::one(), BitRef::Wire(lhs)),
                    (BigUint::one(), BitRef::Wire(rhs)),
                    (neg_mod_coeff(&BigUint::one()), output),
                ],
                is_alt,
                input_indices,
            ),
        },
    }
}

fn bit_linear_constraint(
    terms: Vec<(BigUint, BitRef)>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> IRConstraint {
    IRConstraint::Linear(bit_linear_terms(terms, is_alt, input_indices))
}

fn bit_linear_terms(
    terms: Vec<(BigUint, BitRef)>,
    is_alt: bool,
    input_indices: &HashSet<usize>,
) -> Vec<IRTerm> {
    let mut ir_terms = Vec::new();
    for (coeff, bit) in terms {
        if coeff.is_zero() {
            continue;
        }
        match bit {
            BitRef::Constant(false) => {}
            BitRef::Constant(true) => ir_terms.push(IRTerm {
                coeff,
                var: var_name(0, is_alt, input_indices),
            }),
            BitRef::Wire(wire) => ir_terms.push(IRTerm {
                coeff,
                var: var_name(wire, is_alt, input_indices),
            }),
        }
    }
    ir_terms
}

fn bitwise_op_name(op: BitwiseOp) -> &'static str {
    match op {
        BitwiseOp::And => "AND",
        BitwiseOp::Xor => "XOR",
    }
}

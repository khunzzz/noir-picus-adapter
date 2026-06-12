//! Wire enumeration over ACIR opcodes and expressions: which Picus wires an
//! opcode touches, and the maximum witness index used by a circuit.

use acir::{
    FieldElement,
    circuit::{Circuit, Opcode, opcodes::FunctionInput},
    native_types::{Expression, Witness},
};

use super::ir::picus_wire;

pub(crate) fn opcode_wires(opcode: &Opcode<FieldElement>) -> Vec<usize> {
    let mut wires = Vec::new();
    match opcode {
        Opcode::AssertZero(expression) => wires.extend(expression_wires(expression)),
        Opcode::BlackBoxFuncCall(black_box) => {
            for witness in black_box.get_input_witnesses() {
                wires.push(picus_wire(witness));
            }
            for witness in black_box.get_outputs_vec() {
                wires.push(picus_wire(witness));
            }
            if let Some(predicate) = black_box.get_predicate() {
                wires.push(picus_wire(predicate));
            }
        }
        Opcode::MemoryOp { op, .. } => {
            wires.push(picus_wire(op.index));
            wires.push(picus_wire(op.value));
        }
        Opcode::MemoryInit { init, .. } => {
            for witness in init {
                wires.push(picus_wire(*witness));
            }
        }
        Opcode::BrilligCall { .. } => {}
        Opcode::Call {
            inputs,
            outputs,
            predicate,
            ..
        } => {
            for witness in inputs {
                wires.push(picus_wire(*witness));
            }
            for witness in outputs {
                wires.push(picus_wire(*witness));
            }
            wires.extend(expression_wires(predicate));
        }
    }
    wires
}

pub(super) fn expression_wires(expression: &Expression<FieldElement>) -> Vec<usize> {
    let mut wires = Vec::new();
    for (_, lhs, rhs) in &expression.mul_terms {
        wires.push(picus_wire(*lhs));
        wires.push(picus_wire(*rhs));
    }
    for (_, witness) in &expression.linear_combinations {
        wires.push(picus_wire(*witness));
    }
    wires
}

pub(super) fn function_input_wires(input: &FunctionInput<FieldElement>) -> Vec<usize> {
    match input {
        FunctionInput::Witness(witness) => vec![picus_wire(*witness)],
        FunctionInput::Constant(_) => Vec::new(),
    }
}

pub(super) fn max_witness_index(circuit: &Circuit<FieldElement>) -> Option<u32> {
    let mut max = None;

    for witness in &circuit.private_parameters {
        observe_witness(&mut max, *witness);
    }
    for witness in &circuit.public_parameters.0 {
        observe_witness(&mut max, *witness);
    }
    for witness in &circuit.return_values.0 {
        observe_witness(&mut max, *witness);
    }

    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expression) => observe_expression(&mut max, expression),
            Opcode::BlackBoxFuncCall(black_box) => {
                for witness in black_box.get_input_witnesses() {
                    observe_witness(&mut max, witness);
                }
                for witness in black_box.get_outputs_vec() {
                    observe_witness(&mut max, witness);
                }
                if let Some(predicate) = black_box.get_predicate() {
                    observe_witness(&mut max, predicate);
                }
            }
            Opcode::MemoryOp { op, .. } => {
                observe_witness(&mut max, op.index);
                observe_witness(&mut max, op.value);
            }
            Opcode::MemoryInit { init, .. } => {
                for witness in init {
                    observe_witness(&mut max, *witness);
                }
            }
            Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                for input in inputs {
                    match input {
                        acir::circuit::brillig::BrilligInputs::Single(expression) => {
                            observe_expression(&mut max, expression);
                        }
                        acir::circuit::brillig::BrilligInputs::Array(expressions) => {
                            for expression in expressions {
                                observe_expression(&mut max, expression);
                            }
                        }
                        acir::circuit::brillig::BrilligInputs::MemoryArray(_) => {}
                    }
                }
                for output in outputs {
                    match output {
                        acir::circuit::brillig::BrilligOutputs::Simple(witness) => {
                            observe_witness(&mut max, *witness);
                        }
                        acir::circuit::brillig::BrilligOutputs::Array(witnesses) => {
                            for witness in witnesses {
                                observe_witness(&mut max, *witness);
                            }
                        }
                    }
                }
                observe_expression(&mut max, predicate);
            }
            Opcode::Call {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                for witness in inputs {
                    observe_witness(&mut max, *witness);
                }
                for witness in outputs {
                    observe_witness(&mut max, *witness);
                }
                observe_expression(&mut max, predicate);
            }
        }
    }

    max
}

fn observe_expression(max: &mut Option<u32>, expression: &Expression<FieldElement>) {
    for (_, lhs, rhs) in &expression.mul_terms {
        observe_witness(max, *lhs);
        observe_witness(max, *rhs);
    }
    for (_, witness) in &expression.linear_combinations {
        observe_witness(max, *witness);
    }
}

fn observe_witness(max: &mut Option<u32>, witness: Witness) {
    *max = Some(max.map_or(witness.witness_index(), |current| {
        current.max(witness.witness_index())
    }));
}

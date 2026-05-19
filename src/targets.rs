use std::collections::BTreeMap;

use acir::{
    FieldElement,
    circuit::{
        Circuit, Opcode, Program,
        brillig::{BrilligFunctionId, BrilligOutputs},
    },
    native_types::Witness,
};
use serde::Serialize;

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) witness: Witness,
    pub(crate) origins: Vec<TargetOrigin>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TargetMode {
    Returns,
    BrilligOutputs,
    All,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum TargetOrigin {
    BrilligSimpleOutput {
        opcode_index: usize,
        function_id: u32,
        function_name: Option<String>,
    },
    BrilligArrayOutput {
        opcode_index: usize,
        function_id: u32,
        function_name: Option<String>,
        array_index: usize,
    },
    ReturnValue {
        return_index: usize,
    },
}

pub(crate) fn discover_targets(
    program: &Program<FieldElement>,
    circuit: &Circuit<FieldElement>,
    mode: TargetMode,
) -> Vec<Target> {
    let mut targets = BTreeMap::<Witness, Target>::new();

    if matches!(mode, TargetMode::BrilligOutputs | TargetMode::All) {
        for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
            if let Opcode::BrilligCall { id, outputs, .. } = opcode {
                collect_brillig_outputs(program, &mut targets, opcode_index, *id, outputs);
            }
        }
    }

    if matches!(mode, TargetMode::Returns | TargetMode::All) {
        for (return_index, witness) in circuit.return_values.0.iter().copied().enumerate() {
            push_origin(
                &mut targets,
                witness,
                TargetOrigin::ReturnValue { return_index },
            );
        }
    }

    targets.into_values().collect()
}

fn collect_brillig_outputs(
    program: &Program<FieldElement>,
    targets: &mut BTreeMap<Witness, Target>,
    opcode_index: usize,
    function_id: BrilligFunctionId,
    outputs: &[BrilligOutputs],
) {
    let function_name = program
        .unconstrained_functions
        .get(function_id.as_usize())
        .map(|function| function.function_name.clone())
        .filter(|name| !name.is_empty());

    for output in outputs {
        match output {
            BrilligOutputs::Simple(witness) => push_origin(
                targets,
                *witness,
                TargetOrigin::BrilligSimpleOutput {
                    opcode_index,
                    function_id: function_id.0,
                    function_name: function_name.clone(),
                },
            ),
            BrilligOutputs::Array(witnesses) => {
                for (array_index, witness) in witnesses.iter().copied().enumerate() {
                    push_origin(
                        targets,
                        witness,
                        TargetOrigin::BrilligArrayOutput {
                            opcode_index,
                            function_id: function_id.0,
                            function_name: function_name.clone(),
                            array_index,
                        },
                    );
                }
            }
        }
    }
}

fn push_origin(targets: &mut BTreeMap<Witness, Target>, witness: Witness, origin: TargetOrigin) {
    targets
        .entry(witness)
        .or_insert_with(|| Target {
            witness,
            origins: Vec::new(),
        })
        .origins
        .push(origin);
}

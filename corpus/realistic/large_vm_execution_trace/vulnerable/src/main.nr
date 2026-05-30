use realistic_common::vm_execution_trace;

fn main(
    expected_anchor: pub Field,
    initial_pc: pub Field,
    register_seed: pub Field,
    alu_steps: [Field; 128],
    memory_steps: [Field; 128],
    final_steps: [Field; 128],
    pc_delta: Field,
    claimed_final_state: Field,
) -> pub Field {
    let anchor = vm_execution_trace(initial_pc, register_seed, alu_steps, memory_steps, final_steps);
    assert(anchor == expected_anchor);
    assert(claimed_final_state == anchor + pc_delta * 7);

    claimed_final_state
}

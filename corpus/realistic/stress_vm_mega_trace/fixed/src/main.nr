use realistic_common::stress_vm_mega_trace;

fn main(
    expected_anchor: pub Field,
    initial_pc: pub Field,
    register_seed: pub Field,
    decode_steps: [Field; 512],
    alu_steps: [Field; 512],
    memory_steps: [Field; 512],
    final_steps: [Field; 512],
    pc_delta: Field,
    claimed_final_register: Field,
) -> pub Field {
    let anchor = stress_vm_mega_trace(initial_pc, register_seed, decode_steps, alu_steps, memory_steps, final_steps);
    assert(anchor == expected_anchor);
    assert(pc_delta == 0);
    assert(claimed_final_register == expected_anchor);

    claimed_final_register
}

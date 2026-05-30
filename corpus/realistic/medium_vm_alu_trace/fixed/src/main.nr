use realistic_common::vm_alu_trace;

fn main(
    expected_anchor: pub Field,
    pc: pub Field,
    register_seed: pub Field,
    trace_domain: pub Field,
    alu_steps: [Field; 128],
    state_steps: [Field; 96],
    trace_guard: Field,
    claimed_register: Field,
) -> pub Field {
    let anchor = vm_alu_trace(pc, register_seed, trace_domain, alu_steps, state_steps);
    assert(anchor == expected_anchor);
    assert(trace_guard == 1);
    assert(claimed_register == expected_anchor);

    claimed_register
}

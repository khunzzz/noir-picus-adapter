use realistic_common::stress_rollup_mega_batch;

fn main(
    expected_anchor: pub Field,
    batch_id: pub Field,
    note_seed: pub Field,
    note_steps: [Field; 512],
    nullifier_steps: [Field; 512],
    fee_steps: [Field; 512],
    root_steps: [Field; 512],
    exit_guard: Field,
    claimed_exit_root: Field,
) -> pub Field {
    let anchor = stress_rollup_mega_batch(batch_id, note_seed, note_steps, nullifier_steps, fee_steps, root_steps);
    assert(anchor == expected_anchor);
    assert(exit_guard * (claimed_exit_root - anchor) == 0);

    claimed_exit_root
}

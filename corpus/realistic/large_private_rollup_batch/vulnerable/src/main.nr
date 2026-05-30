use realistic_common::private_rollup_batch;

fn main(
    expected_anchor: pub Field,
    batch_id: pub Field,
    note_seed: pub Field,
    note_steps: [Field; 128],
    nullifier_steps: [Field; 128],
    root_steps: [Field; 128],
    minted_delta: Field,
    claimed_batch_nullifier: Field,
) -> pub Field {
    let anchor = private_rollup_batch(batch_id, note_seed, note_steps, nullifier_steps, root_steps);
    assert(anchor == expected_anchor);
    assert(batch_id + claimed_batch_nullifier == note_seed + minted_delta);

    claimed_batch_nullifier
}

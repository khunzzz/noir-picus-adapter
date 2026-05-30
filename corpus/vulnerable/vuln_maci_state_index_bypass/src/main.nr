fn leaf_hash(state_index: Field, key_hash: Field, vote_weight: Field) -> Field {
    31 * state_index + 17 * key_hash + vote_weight + 99
}

fn batch_hash(leaf: Field, poll_id: Field) -> Field {
    leaf + 101 * poll_id + 7
}

fn main(
    expected_batch_root: pub Field,
    poll_id: pub Field,
    leaf_state_index: Field,
    msg_state_index: Field,
    old_key_hash: Field,
    msg_key_hash: Field,
    vote_weight: Field,
    already_invalid: Field,
) -> pub Field {
    // Inspired by MACI 1.0: state-index binding is skipped after invalidation.
    assert(already_invalid * (already_invalid - 1) == 0);

    let should_apply = 1 - already_invalid;
    assert(should_apply * (old_key_hash - msg_key_hash) == 0);
    assert(should_apply * (leaf_state_index - msg_state_index) == 0);

    let applied_vote = should_apply * vote_weight;
    let updated_leaf = leaf_hash(leaf_state_index, old_key_hash, applied_vote);
    let batch_root = batch_hash(updated_leaf, poll_id);

    assert(batch_root == expected_batch_root);
    msg_state_index
}

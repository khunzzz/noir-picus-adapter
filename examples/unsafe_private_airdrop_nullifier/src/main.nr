fn mix2(a: Field, b: Field) -> Field {
    let t0 = a + 17 * b + 12345;
    let t1 = t0 * t0 + a * b + 777;
    let t2 = t1 * t1 + 31 * a + 47 * b + 99;
    t2
}

fn note_commitment(secret: Field, note_randomness: Field) -> Field {
    let owner_tag = mix2(secret, note_randomness);
    mix2(owner_tag, 424242)
}

fn claim_leaf(commitment: Field, amount: Field, recipient: Field) -> Field {
    let spendable_note = mix2(commitment, amount);
    mix2(spendable_note, recipient)
}

fn merkle_root_depth_3(
    leaf: Field,
    path_0: Field,
    path_1: Field,
    path_2: Field,
) -> Field {
    let node_1 = mix2(leaf, path_0);
    let node_2 = mix2(node_1, path_1);
    mix2(node_2, path_2)
}

unconstrained fn nullifier_hint(
    secret: Field,
    note_randomness: Field,
    campaign_id: Field,
) -> Field {
    let commitment = note_commitment(secret, note_randomness);
    mix2(commitment, campaign_id)
}

fn main(
    secret: Field,
    note_randomness: Field,
    amount: Field,
    recipient: Field,
    path_0: Field,
    path_1: Field,
    path_2: Field,
    campaign_id: pub Field,
    expected_root: pub Field,
) -> pub Field {
    let commitment = note_commitment(secret, note_randomness);
    let leaf = claim_leaf(commitment, amount, recipient);
    let calculated_root = merkle_root_depth_3(leaf, path_0, path_1, path_2);

    assert(calculated_root == expected_root);

    // Safety: fixture leaves nullifier derivation unconstrained.
    let nullifier = unsafe { nullifier_hint(secret, note_randomness, campaign_id) };

    nullifier
}

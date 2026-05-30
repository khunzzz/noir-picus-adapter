use realistic_common::merkle_airdrop_path;

fn main(
    expected_anchor: pub Field,
    campaign_id: pub Field,
    note_secret: pub Field,
    path_domain: pub Field,
    commitment_steps: [Field; 96],
    root_steps: [Field; 96],
    epoch_guard: Field,
    claimed_nullifier: Field,
) -> pub Field {
    let anchor = merkle_airdrop_path(campaign_id, note_secret, path_domain, commitment_steps, root_steps);
    assert(anchor == expected_anchor);
    assert(epoch_guard == 1);
    assert(claimed_nullifier == expected_anchor);

    claimed_nullifier
}

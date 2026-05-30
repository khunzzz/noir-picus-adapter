use realistic_common::medium_chain_96;

fn main(
    expected_anchor: pub Field,
    message_domain: pub Field,
    message_seed: pub Field,
    hash_steps: [Field; 96],
    enabled: Field,
    claimed_hash: Field,
) -> pub Field {
    let anchor = medium_chain_96(message_seed, message_domain, hash_steps);
    assert(anchor == expected_anchor);
    assert(enabled == 1);
    assert(claimed_hash == expected_anchor);

    claimed_hash
}

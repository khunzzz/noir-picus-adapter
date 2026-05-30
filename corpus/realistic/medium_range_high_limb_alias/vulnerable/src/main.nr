use realistic_common::medium_chain_96;

fn main(
    expected_anchor: pub Field,
    range_domain: pub Field,
    packed_seed: pub Field,
    pack_steps: [Field; 96],
    low_limb: Field,
    high_limb: Field,
) -> pub Field {
    let anchor = medium_chain_96(packed_seed, range_domain, pack_steps);
    assert(anchor == expected_anchor);
    assert(low_limb + high_limb * 256 == anchor);

    high_limb
}

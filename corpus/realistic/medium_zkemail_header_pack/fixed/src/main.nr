use realistic_common::zkemail_header_pack;

fn main(
    expected_anchor: pub Field,
    header_domain: pub Field,
    from_hash: pub Field,
    pack_steps: [Field; 96],
    digest_steps: [Field; 96],
    packed_low_limb: Field,
    claimed_digest: Field,
) -> pub Field {
    let anchor = zkemail_header_pack(header_domain, from_hash, pack_steps, digest_steps);
    assert(anchor == expected_anchor);
    assert(packed_low_limb + claimed_digest * 256 == anchor);
    assert(claimed_digest == expected_anchor);

    claimed_digest
}

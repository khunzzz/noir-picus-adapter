use realistic_common::passport_disclosure;

fn main(
    expected_anchor: pub Field,
    passport_domain: pub Field,
    document_seed: pub Field,
    pack_steps: [Field; 128],
    country_steps: [Field; 128],
    merkle_steps: [Field; 128],
    country_guard: Field,
    claimed_disclosure_digest: Field,
) -> pub Field {
    let anchor = passport_disclosure(passport_domain, document_seed, pack_steps, country_steps, merkle_steps);
    assert(anchor == expected_anchor);
    assert(country_guard == 1);
    assert(claimed_disclosure_digest == expected_anchor);

    claimed_disclosure_digest
}

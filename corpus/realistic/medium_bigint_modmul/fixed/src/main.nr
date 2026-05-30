use realistic_common::bigint_modmul;

fn main(
    expected_anchor: pub Field,
    lhs: pub Field,
    rhs: pub Field,
    modulus_domain: pub Field,
    limb_steps: [Field; 128],
    reduction_steps: [Field; 96],
    quotient: Field,
    claimed_remainder: Field,
) -> pub Field {
    let anchor = bigint_modmul(lhs, rhs, modulus_domain, limb_steps, reduction_steps);
    assert(anchor == expected_anchor);
    assert(lhs * rhs == modulus_domain * quotient + claimed_remainder);
    assert(claimed_remainder == expected_anchor);

    claimed_remainder
}

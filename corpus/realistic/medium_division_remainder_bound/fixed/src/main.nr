use realistic_common::medium_chain_128;

fn main(
    expected_anchor: pub Field,
    dividend: pub Field,
    divisor: pub Field,
    division_steps: [Field; 128],
    quotient: Field,
    claimed_remainder: Field,
) -> pub Field {
    let anchor = medium_chain_128(dividend, divisor, division_steps);
    assert(anchor == expected_anchor);
    assert(dividend == divisor * quotient + claimed_remainder);
    assert(claimed_remainder == expected_anchor);

    claimed_remainder
}

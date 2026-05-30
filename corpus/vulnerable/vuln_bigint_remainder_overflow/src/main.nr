fn main(
    dividend: pub Field,
    divisor: pub Field,
    quotient: Field,
    remainder_limb_0: Field,
    remainder_limb_1: Field,
    divisor_inverse: Field,
) -> pub Field {
    // Inspired by circom-bigint/BigMod: remainder limbs need explicit range checks.
    assert(divisor * divisor_inverse == 1);

    let remainder = remainder_limb_0 + 256 * remainder_limb_1;
    assert(divisor * quotient + remainder == dividend);

    remainder
}

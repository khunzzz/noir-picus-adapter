fn main(
    numerator: pub Field,
    denominator: pub Field,
    denominator_inverse: Field,
    quotient: Field,
) -> pub Field {
    // Inspired by ark-r1cs-std mul_by_inverse: proving inverse is not enough.
    assert(denominator * denominator_inverse == 1);

    // Missing: quotient == numerator * denominator_inverse.
    quotient
}

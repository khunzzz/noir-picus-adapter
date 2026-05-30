fn main(
    dividend_low: pub Field,
    divisor: pub Field,
    quotient: Field,
    remainder: Field,
    carry: Field,
    divisor_inverse: Field,
) -> pub Field {
    // Inspired by zkEVM div/mod bugs: A * B + C is insufficient without C < A.
    assert(divisor * divisor_inverse == 1);
    assert(divisor * quotient + remainder == dividend_low + 256 * carry);

    remainder
}

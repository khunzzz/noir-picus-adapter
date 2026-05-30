fn main(
    dividend: pub Field,
    divisor: pub Field,
    quotient: Field,
    remainder: Field,
    divisor_inverse: Field,
) -> pub Field {
    // Risc0 zkVM division: quotient equation is insufficient without remainder bounds.
    assert(divisor * divisor_inverse == 1);
    assert(divisor * quotient + remainder == dividend);

    remainder
}

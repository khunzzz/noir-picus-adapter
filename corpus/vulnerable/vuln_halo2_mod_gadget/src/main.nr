fn main(
    lhs: pub Field,
    rhs: pub Field,
    modulus: pub Field,
    quotient: Field,
    remainder: Field,
    modulus_inverse: Field,
) -> pub Field {
    // Scroll ModGadget/MULMOD: multiplication equation is not enough without remainder bounds.
    assert(modulus * modulus_inverse == 1);
    assert(lhs * rhs == modulus * quotient + remainder);

    remainder
}

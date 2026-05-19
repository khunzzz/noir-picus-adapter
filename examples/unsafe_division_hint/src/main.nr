unconstrained fn div_hint(numerator: Field, denominator: Field) -> (Field, Field) {
    (numerator / denominator, 1 / denominator)
}

fn main(numerator: Field, denominator: Field) -> pub Field {
    // Safety: fixture leaves quotient correctness unconstrained.
    let (quotient, denominator_inverse) = unsafe { div_hint(numerator, denominator) };

    assert(denominator * denominator_inverse == 1);

    quotient
}

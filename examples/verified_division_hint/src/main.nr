unconstrained fn div_hint(numerator: Field, denominator: Field) -> (Field, Field) {
    (numerator / denominator, 1 / denominator)
}

fn main(numerator: Field, denominator: Field) -> pub Field {
    // Safety: constraints below bind both hint outputs.
    let (quotient, denominator_inverse) = unsafe { div_hint(numerator, denominator) };

    assert(denominator * denominator_inverse == 1);
    assert(numerator == denominator * quotient);

    quotient
}

fn main(
    expected_scaled_value: pub Field,
    value: pub Field,
    y: Field,
    quotient: Field,
) -> pub Field {
    // Cairo headers processor: y must be proven to be a power of two.
    assert(value == y * quotient);
    assert(value == expected_scaled_value);

    y
}

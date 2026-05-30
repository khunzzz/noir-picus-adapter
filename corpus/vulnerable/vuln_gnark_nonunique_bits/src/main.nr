fn main(
    decomposed_value: pub Field,
    bit_0: Field,
    bit_1: Field,
    bit_2: Field,
) -> pub Field {
    // gnark comparison: binary decomposition must be unique and boolean.
    assert(bit_0 + 2 * bit_1 + 4 * bit_2 == decomposed_value);

    bit_0
}

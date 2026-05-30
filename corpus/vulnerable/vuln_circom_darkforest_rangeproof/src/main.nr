fn main(
    comparison_word: pub Field,
    max_abs_value: pub Field,
    position: Field,
    overflow_alias: Field,
) -> pub Field {
    // Dark Forest RangeProof: LessThan assumes bit length but inputs were not range-checked.
    assert(max_abs_value + position + 65536 * overflow_alias == comparison_word);

    position
}

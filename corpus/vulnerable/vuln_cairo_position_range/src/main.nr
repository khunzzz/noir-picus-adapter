fn main(
    encoded_position_word: pub Field,
    low_part: Field,
    high_part: Field,
    position: Field,
) -> pub Field {
    // Cairo MMR/header helper: position must be range checked before bit extraction.
    assert(low_part + position * high_part == encoded_position_word);

    position
}

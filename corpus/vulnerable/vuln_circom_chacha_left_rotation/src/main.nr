fn main(
    input_word: pub Field,
    rotation_split: pub Field,
    part_low: Field,
    part_high: Field,
) -> pub Field {
    // Reclaim circom-chacha20 RotateLeft32Bits: split limbs must be bit-sized.
    assert(part_low + 65536 * part_high == input_word);
    assert(rotation_split == 16);

    part_high + 65536 * part_low
}

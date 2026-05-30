fn main(
    expected_rlc: pub Field,
    challenge: pub Field,
    rlp_prefix: pub Field,
    previous_rlc: Field,
    byte_value: Field,
) -> pub Field {
    // Scroll Halo2 RLP: byte values must be range-checked to [0, 255].
    let rlc = previous_rlc * challenge + rlp_prefix + byte_value;
    assert(rlc == expected_rlc);

    byte_value
}

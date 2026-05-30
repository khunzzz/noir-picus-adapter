fn main(
    encoded_rlc: pub Field,
    challenge: pub Field,
    is_lt_128: Field,
    byte_0: Field,
    byte_1: Field,
) -> pub Field {
    // Scroll RlpU64Gadget: multi-byte path is underconstrained when is_lt_128 is false.
    assert(is_lt_128 == 0);
    assert(byte_0 + challenge * byte_1 == encoded_rlc);

    byte_0
}

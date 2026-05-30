fn main(
    packed_data: pub Field,
    byte_0: Field,
    byte_1: Field,
) -> pub Field {
    // self.xyz PackBytesAndPoseidon: packed bytes need explicit byte range checks.
    assert(byte_0 + 256 * byte_1 == packed_data);

    byte_0
}

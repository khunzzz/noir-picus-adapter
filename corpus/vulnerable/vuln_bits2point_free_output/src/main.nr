fn main(
    compressed_y: pub Field,
    sign_bit: pub Field,
    decoded_y: Field,
    decoded_x: Field,
) -> pub Field {
    // Inspired by circomlib Bits2Point/Point2Bits: decoded coordinates need constraints.
    assert(sign_bit * (sign_bit - 1) == 0);
    assert(decoded_y == compressed_y);

    // Missing: curve equation and sign binding for decoded_x.
    decoded_x
}

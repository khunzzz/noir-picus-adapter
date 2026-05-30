fn main(
    expected_folded_xor: pub Field,
    xor_limb_0: Field,
    xor_limb_1: Field,
    xor_limb_2: Field,
) -> pub Field {
    // Telepathy ArrayXOR: folded output is constrained, individual XOR limbs are not boolean.
    assert(xor_limb_0 + 2 * xor_limb_1 + 4 * xor_limb_2 == expected_folded_xor);

    xor_limb_0
}

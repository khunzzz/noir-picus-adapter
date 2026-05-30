fn main(
    addend_a: pub Field,
    addend_b: pub Field,
    result_limb: Field,
    carry: Field,
) -> pub Field {
    // Penumbra fixed-point addition: carry/result limb ranges must be constrained.
    assert(addend_a + addend_b == result_limb + 1000000 * carry);

    result_limb
}

fn main(
    addend_a: pub Field,
    addend_b: pub Field,
    sum_low: Field,
    carry: Field,
) -> pub Field {
    // Reclaim circom-chacha20 addition: carry/low limb ranges must be constrained.
    assert(addend_a + addend_b == sum_low + 4294967296 * carry);

    sum_low
}

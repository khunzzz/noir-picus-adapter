fn main(
    lhs_bit: pub Field,
    rhs_bit: pub Field,
    and_hint: Field,
    xor_out: Field,
) -> pub Field {
    // Reclaim circom-chacha20 XOR: and_hint must be constrained to lhs_bit * rhs_bit.
    assert(lhs_bit * (lhs_bit - 1) == 0);
    assert(rhs_bit * (rhs_bit - 1) == 0);
    assert(xor_out == lhs_bit + rhs_bit - 2 * and_hint);

    xor_out
}

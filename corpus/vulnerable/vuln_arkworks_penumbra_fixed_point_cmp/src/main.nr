fn main(
    lhs_fixed: pub Field,
    rhs_fixed: pub Field,
    diff_limb: Field,
    borrow: Field,
) -> pub Field {
    // Penumbra fixed-point comparison: diff/borrow must be range constrained.
    assert(lhs_fixed + diff_limb == rhs_fixed + 1000000 * borrow);

    borrow
}

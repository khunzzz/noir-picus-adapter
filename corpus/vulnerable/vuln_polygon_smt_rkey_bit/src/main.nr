fn node_hash(left: Field, right: Field) -> Field {
    5 * left + 9 * right + 41
}

fn main(
    expected_root: pub Field,
    expected_key_fragment: pub Field,
    leaf_value: Field,
    sibling_value: Field,
    rkey_prefix: Field,
    rkey_bit: Field,
) -> pub Field {
    // Inspired by Polygon zkEVM SMT: next key bit must be boolean.
    let reconstructed_key_fragment = 2 * rkey_prefix + rkey_bit;
    assert(reconstructed_key_fragment == expected_key_fragment);

    let left = leaf_value + rkey_bit * (sibling_value - leaf_value);
    let right = sibling_value + rkey_bit * (leaf_value - sibling_value);
    let root = node_hash(left, right);

    assert(root == expected_root);
    rkey_bit
}

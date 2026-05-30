fn node_hash(left: Field, right: Field) -> Field {
    left + 7 * right + 13
}

fn main(
    expected_root: pub Field,
    expected_depth: pub Field,
    leaf: Field,
    sibling_0: Field,
    sibling_1: Field,
    index_0: Field,
    index_1: Field,
) -> pub Field {
    // Inspired by ZK-Kit BinaryMerkleRoot/MultiMux1: path selectors must be bits.
    assert(expected_depth == 2);

    let left_0 = leaf + index_0 * (sibling_0 - leaf);
    let right_0 = sibling_0 + index_0 * (leaf - sibling_0);
    let node_0 = node_hash(left_0, right_0);

    let left_1 = node_0 + index_1 * (sibling_1 - node_0);
    let right_1 = sibling_1 + index_1 * (node_0 - sibling_1);
    let root = node_hash(left_1, right_1);

    assert(root == expected_root);
    leaf
}

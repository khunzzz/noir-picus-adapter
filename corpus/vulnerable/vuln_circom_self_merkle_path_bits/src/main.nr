fn light_poseidon(left: Field, right: Field) -> Field {
    left + 17 * right + 91
}

fn main(
    expected_root: pub Field,
    leaf: Field,
    sibling: Field,
    path_index: Field,
) -> pub Field {
    // self.xyz Merkle path: path index must be boolean.
    let left = leaf + path_index * (sibling - leaf);
    let right = sibling + path_index * (leaf - sibling);
    let root = light_poseidon(left, right);

    assert(root == expected_root);
    leaf
}

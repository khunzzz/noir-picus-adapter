fn mix2(a: Field, b: Field) -> Field {
    a + 11 * b + 7
}

fn main(
    commitment: pub Field,
    expected_low_index: pub Field,
    expected_membership_tag: pub Field,
    low_index: Field,
    high_index_alias: Field,
    path_tag: Field,
) -> pub Field {
    // Inspired by Aztec 2.0: nullifier index used more bits than membership path checked.
    assert(low_index == expected_low_index);

    let membership_tag = mix2(commitment, low_index) + path_tag;
    assert(membership_tag == expected_membership_tag);

    let full_index = low_index + 4294967296 * high_index_alias;
    mix2(commitment, full_index)
}

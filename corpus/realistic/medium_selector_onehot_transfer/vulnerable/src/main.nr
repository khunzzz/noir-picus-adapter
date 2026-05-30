use realistic_common::medium_chain_96;

fn main(
    expected_anchor: pub Field,
    left_root: pub Field,
    right_root: pub Field,
    transfer_steps: [Field; 96],
    selector: Field,
    claimed_transfer_root: Field,
) -> pub Field {
    let anchor = medium_chain_96(left_root, right_root, transfer_steps);
    assert(anchor == expected_anchor);
    assert(claimed_transfer_root == left_root + selector * (anchor - left_root));

    claimed_transfer_root
}

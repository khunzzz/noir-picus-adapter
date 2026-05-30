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
    assert(selector * (selector - 1) == 0);
    assert(claimed_transfer_root == expected_anchor);

    claimed_transfer_root
}

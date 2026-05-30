use realistic_common::mpt_account_update;

fn main(
    expected_anchor: pub Field,
    account_key: pub Field,
    account_value: pub Field,
    mpt_domain: pub Field,
    nonce_steps: [Field; 96],
    balance_steps: [Field; 96],
    root_steps: [Field; 96],
    transition_selector: Field,
    claimed_account_root: Field,
) -> pub Field {
    let anchor = mpt_account_update(account_key, account_value, mpt_domain, nonce_steps, balance_steps, root_steps);
    assert(anchor == expected_anchor);
    assert(claimed_account_root == account_value + transition_selector * (anchor - account_value));

    claimed_account_root
}

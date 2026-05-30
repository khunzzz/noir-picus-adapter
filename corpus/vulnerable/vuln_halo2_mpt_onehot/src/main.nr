fn main(
    expected_selector_sum: pub Field,
    account_exists: Field,
    nonce_changed: Field,
    balance_changed: Field,
) -> pub Field {
    // Scroll MPT OneHot: sum-to-one without boolean constraints allows multiple active states.
    assert(account_exists + nonce_changed + balance_changed == expected_selector_sum);

    account_exists
}

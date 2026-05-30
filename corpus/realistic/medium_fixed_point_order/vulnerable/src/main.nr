use realistic_common::fixed_point_order;

fn main(
    expected_anchor: pub Field,
    balance: pub Field,
    price: pub Field,
    order_domain: pub Field,
    compare_steps: [Field; 96],
    update_steps: [Field; 96],
    settlement_delta: Field,
    claimed_order_state: Field,
) -> pub Field {
    let anchor = fixed_point_order(balance, price, order_domain, compare_steps, update_steps);
    assert(anchor == expected_anchor);
    assert(balance + claimed_order_state == price + settlement_delta);

    claimed_order_state
}

use realistic_common::rlp_tx_calldata;

fn main(
    expected_anchor: pub Field,
    chain_id: pub Field,
    calldata_domain: pub Field,
    tx_steps: [Field; 96],
    calldata_steps: [Field; 96],
    calldata_guard: Field,
    claimed_calldata_rlc: Field,
) -> pub Field {
    let anchor = rlp_tx_calldata(chain_id, calldata_domain, tx_steps, calldata_steps);
    assert(anchor == expected_anchor);
    assert(calldata_guard == 1);
    assert(claimed_calldata_rlc == expected_anchor);

    claimed_calldata_rlc
}

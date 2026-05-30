use realistic_common::zkevm_transaction;

fn main(
    expected_anchor: pub Field,
    block_number: pub Field,
    tx_seed: pub Field,
    rlp_steps: [Field; 128],
    calldata_steps: [Field; 128],
    gas_steps: [Field; 128],
    quotient: Field,
    claimed_tx_accumulator: Field,
) -> pub Field {
    let anchor = zkevm_transaction(block_number, tx_seed, rlp_steps, calldata_steps, gas_steps);
    assert(anchor == expected_anchor);
    assert(block_number == quotient * 17 + claimed_tx_accumulator);

    claimed_tx_accumulator
}

use realistic_common::large_chain_128;

fn main(
    expected_anchor: pub Field,
    batch_inflow: pub Field,
    batch_outflow: pub Field,
    note_steps: [Field; 128],
    fee_steps: [Field; 128],
    root_steps: [Field; 128],
    private_fee: Field,
    claimed_minted: Field,
) -> pub Field {
    let note_root = large_chain_128(batch_inflow, batch_outflow, note_steps);
    let fee_root = large_chain_128(note_root, batch_inflow + 9, fee_steps);
    let anchor = large_chain_128(fee_root, batch_outflow + 19, root_steps);
    assert(anchor == expected_anchor);
    assert(batch_inflow + claimed_minted == batch_outflow + private_fee);
    assert(claimed_minted == expected_anchor);

    claimed_minted
}

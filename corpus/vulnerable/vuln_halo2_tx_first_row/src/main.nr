fn main(
    tx_table_tag: pub Field,
    expected_delta: pub Field,
    first_tx_id: Field,
    second_tx_id: Field,
) -> pub Field {
    // Scroll Tx Circuit: first row must be bound to the expected first tx id.
    assert(tx_table_tag == 8);
    assert(second_tx_id == first_tx_id + expected_delta);

    // Missing: first_tx_id is bound to the first row of the public tx table.
    first_tx_id
}

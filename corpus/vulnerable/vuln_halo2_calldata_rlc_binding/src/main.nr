fn main(
    fixed_calldata_rlc: pub Field,
    challenge: pub Field,
    assigned_call_data_rlc: Field,
    actual_byte_0: Field,
    actual_byte_1: Field,
) -> pub Field {
    // Scroll Tx Circuit: fixed CallDataRLC must be validated against actual calldata bytes.
    assert(assigned_call_data_rlc == fixed_calldata_rlc);

    let actual_calldata_rlc = actual_byte_0 + challenge * actual_byte_1;
    actual_calldata_rlc
}

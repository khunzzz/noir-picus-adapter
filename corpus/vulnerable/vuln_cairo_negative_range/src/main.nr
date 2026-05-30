fn main(
    final_balance: pub Field,
    initial_balance: pub Field,
    signed_delta: Field,
    range_alias: Field,
) -> pub Field {
    // Cairo range-check bug: negative values need explicit signed range constraints.
    assert(initial_balance + signed_delta == final_balance + 65536 * range_alias);

    signed_delta
}

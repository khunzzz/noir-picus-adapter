use realistic_common::large_chain_128;

fn main(
    expected_anchor: pub Field,
    table_base: pub Field,
    table_stride: pub Field,
    first_lookup_steps: [Field; 128],
    second_lookup_steps: [Field; 128],
    final_lookup_steps: [Field; 128],
    lookup_index: Field,
    claimed_lookup_value: Field,
) -> pub Field {
    let first = large_chain_128(table_base, table_stride, first_lookup_steps);
    let second = large_chain_128(first, table_base + 17, second_lookup_steps);
    let anchor = large_chain_128(second, table_stride + 33, final_lookup_steps);
    assert(anchor == expected_anchor);
    assert(claimed_lookup_value == table_base + lookup_index * 17);

    claimed_lookup_value
}

fn main(
    sym_tag: pub Field,
    expected_env: pub Field,
    reduce_sym_output: Field,
    env_witness: Field,
) -> pub Field {
    // Lurk reduce_sym: output expression must be bound to the symbol/environment relation.
    assert(sym_tag == 44);
    assert(env_witness == expected_env);

    reduce_sym_output
}

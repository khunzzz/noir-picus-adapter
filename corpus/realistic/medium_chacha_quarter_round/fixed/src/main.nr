use realistic_common::chacha_quarter_round;

fn main(
    expected_anchor: pub Field,
    word_a: pub Field,
    word_b: pub Field,
    round_domain: pub Field,
    add_steps: [Field; 96],
    xor_steps: [Field; 96],
    rotate_steps: [Field; 96],
    carry_alias: Field,
    claimed_round_word: Field,
) -> pub Field {
    let anchor = chacha_quarter_round(word_a, word_b, round_domain, add_steps, xor_steps, rotate_steps);
    assert(anchor == expected_anchor);
    assert(carry_alias == 0);
    assert(claimed_round_word == expected_anchor);

    claimed_round_word
}

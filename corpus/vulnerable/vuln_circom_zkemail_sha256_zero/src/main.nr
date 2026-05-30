fn main(
    expected_digest: pub Field,
    digest_word: Field,
    message_word: Field,
) -> pub Field {
    // zk-email SHA256 templates: digest output could be zero for arbitrary inputs.
    assert(digest_word == expected_digest);

    // Missing: digest_word is constrained to the SHA256(message_word) computation.
    message_word
}

fn main(
    expected_digest: pub Field,
    message_0: Field,
    message_1: Field,
    padding_word: Field,
) -> pub Field {
    // Neptune: zero padding must be enforced before sponge absorption.
    let digest = message_0 + 31 * message_1 + 997 * padding_word;
    assert(digest == expected_digest);

    padding_word
}

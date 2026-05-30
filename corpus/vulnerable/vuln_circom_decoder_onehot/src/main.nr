fn main(
    selector: pub Field,
    out_0: Field,
    out_1: Field,
    out_2: Field,
) -> pub Field {
    // Inspired by circomlib Decoder: one-hot outputs need boolean constraints.
    assert(out_0 + out_1 + out_2 == 1);
    assert(out_1 + 2 * out_2 == selector);

    out_0
}

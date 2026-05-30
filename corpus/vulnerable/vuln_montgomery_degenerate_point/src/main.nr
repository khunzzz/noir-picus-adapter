fn main(
    montgomery_x: pub Field,
    montgomery_y: pub Field,
    edwards_x: Field,
    edwards_y: Field,
) -> pub Field {
    // Inspired by circomlib Montgomery2Edwards exceptional denominators.
    assert(edwards_x * montgomery_y == montgomery_x);
    assert(edwards_y * (montgomery_x + 1) == montgomery_x - 1);

    edwards_x
}

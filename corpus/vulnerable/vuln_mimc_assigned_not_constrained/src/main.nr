fn mimc_round(x: Field, key: Field, c: Field) -> Field {
    let t = x + key + c;
    let t2 = t * t;
    t2 * t + key
}

fn main(
    message: pub Field,
    expected_hash: pub Field,
    claimed_hash: Field,
) -> pub Field {
    // Inspired by circomlib MiMC: a computed state must be constrained to the public output.
    let r0 = mimc_round(message, 7, 11);
    let real_hash = mimc_round(r0, 13, 17);

    assert(real_hash == expected_hash);
    claimed_hash
}

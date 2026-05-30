fn main(inp: Field) -> pub bool {
    let mut x: Field = -1;
    for _i in 0..1 {
        x = -1;
    }

    let mut y = [inp / x];

    let expected = ((y[0] as u128) as Field);
    let mut actual: Field = 0;

    if inp.lt(42) {
        actual = ((y[0] as u128) as Field);
    }

    actual == expected
}

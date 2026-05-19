unconstrained fn hint(x: Field) -> Field {
    x + 1
}

fn main(x: Field) -> pub Field {
    // Safety: assertion below binds the hint output.
    let y = unsafe { hint(x) };
    assert(y == x + 1);
    y
}

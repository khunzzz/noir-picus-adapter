unconstrained fn hint(x: Field) -> Field {
    x + 1
}

fn main(x: Field) -> pub Field {
    // Safety: fixture leaves the hint output unconstrained.
    let y = unsafe { hint(x) };
    y
}

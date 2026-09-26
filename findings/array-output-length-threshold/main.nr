unconstrained fn hint(x: Field) -> [Field; 65] {
    [x; 65]
}

fn main(a: Field) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    assert(h[0] == a);
    h[1]
}

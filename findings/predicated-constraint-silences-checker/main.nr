unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field, c: bool) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    if c {
        assert(h == a);   // the only constraint, and it is predicated
    }
    h
}

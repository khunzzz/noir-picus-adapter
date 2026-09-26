unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field) {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    let mut t = h;
    let mut r = a;
    t = t * a + a;
    r = r * a + a;
    t = t * a + a;
    r = r * a + a;
    t = t * a + a;
    r = r * a + a;
    t = t * a + a;
    r = r * a + a;
    t = t * a + a;
    r = r * a + a;
    t = t * a + a;
    r = r * a + a;
    assert(t == r);
}

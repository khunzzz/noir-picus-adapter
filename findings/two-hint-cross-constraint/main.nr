unconstrained fn hint_a(x: Field) -> Field { x }
unconstrained fn hint_b(x: Field) -> Field { x }

fn main(a: Field, b: Field) -> pub Field {
    let h1 = unsafe { hint_a(a) };
    let h2 = unsafe { hint_b(b) };
    assert(h1 * h2 == 0);
    h1
}
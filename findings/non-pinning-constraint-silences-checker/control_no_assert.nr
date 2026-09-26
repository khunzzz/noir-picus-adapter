unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    h
}

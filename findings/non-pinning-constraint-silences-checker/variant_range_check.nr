unconstrained fn hint(x: Field) -> u8 { x as u8 }

fn main(a: Field) -> pub u8 {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    assert(h < 100);   // one constrained value, against a constant
    h
}

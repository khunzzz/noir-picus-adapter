use lib::math::modulo::U64::ModU64;
// Precondition from the doc comment: inputs already reduced (< m).
fn main(lhs: u64, rhs: u64) -> pub Field {
    let m: u64 = 1000003;
    assert(lhs < m); assert(rhs < m);
    ModU64::new(m).sub(lhs as Field, rhs as Field)
}

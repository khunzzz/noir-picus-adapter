use lib::math::modulo::U128::ModU128;
fn main(lhs: u64, rhs: u64) -> pub Field {
    let m: u64 = 1000003;
    assert(lhs < m); assert(rhs < m);
    ModU128::new(m as Field).sub(lhs as Field, rhs as Field)
}

use lib::math::modulo::U64::ModU64;
fn main(a: u64, b: u64) -> pub Field {
    let m: u64 = 1000003;
    assert(a < m); assert(b < m);
    ModU64::new(m).mul_mod(a as Field, b as Field)
}

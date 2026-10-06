use lib::math::modulo::U64::ModU64;
fn main(val: u64) -> pub Field {
    let m: u64 = 1000003;
    assert(val < m); assert(val != 0);
    ModU64::new(m).inv_mod(val as Field)
}

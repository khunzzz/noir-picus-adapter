use lib::math::modulo::U64::ModU64;
fn main(val: u64) -> pub Field {
    let m: u64 = 1000003;
    assert(val < m);
    ModU64::new(m).neg(val as Field)
}

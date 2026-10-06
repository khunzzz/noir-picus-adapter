// PoC: verbatim constraint bodies of ModU64::sub / ModU64::inv_mod from
// interfold circuits/lib/src/math/modulo/U64.nr, with the honest hint swapped for a
// malicious one. Execution succeeding = the constraints accept a non-canonical result.
use lib::math::modulo::U64::ModU64;

unconstrained fn evil_sub(lhs: Field, rhs: Field, m: u64) -> (u64, bool) {
    // honest: (lhs - rhs, false) when lhs >= rhs. Malicious: claim an underflow.
    (((lhs + m as Field) - rhs) as u64, true)
}
unconstrained fn evil_inv(val: Field, m: u64) -> u64 {
    let honest = unsafe { lib::math::modulo::unconstrained_U64::__inv_mod_u64(val, m) };
    honest + m
}

fn sub_body(self_m: u64, lhs: Field, rhs: Field) -> Field {
    // Safety: PoC
    let (res_u64, underflow) = unsafe { evil_sub(lhs, rhs, self_m) };
    if underflow {
        assert(lhs + (self_m as Field) == rhs + (res_u64 as Field), "Subtraction with underflow verification failed");
    } else {
        assert(lhs == rhs + (res_u64 as Field), "Subtraction verification failed");
    }
    res_u64 as Field
}

fn inv_body(self_m: u64, val: Field) -> Field {
    // Safety: PoC
    let result = unsafe { evil_inv(val, self_m) };
    assert(ModU64::new(self_m).mul_mod(val, result as Field) == 1, "Inverse verification failed");
    result as Field
}

fn main(lhs: u64, rhs: u64, val: u64) -> pub (Field, Field, Field, Field) {
    let m: u64 = 1000003;
    assert(lhs < m); assert(rhs < m); assert(val < m); assert(val != 0);
    let honest_sub = ModU64::new(m).sub(lhs as Field, rhs as Field);
    let evil_sub_res = sub_body(m, lhs as Field, rhs as Field);
    let honest_inv = ModU64::new(m).inv_mod(val as Field);
    let evil_inv_res = inv_body(m, val as Field);
    (honest_sub, evil_sub_res, honest_inv, evil_inv_res)
}

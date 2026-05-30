fn main(
    reduced_babybear_value: pub Field,
    raw_limb: Field,
    carry: Field,
) -> pub Field {
    // SP1/Plonky3 BabyBear arithmetic: raw limbs need sufficient range checks.
    assert(raw_limb == reduced_babybear_value + 2013265921 * carry);

    raw_limb
}

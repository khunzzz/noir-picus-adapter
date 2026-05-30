unconstrained fn evil(x: u32) -> u32 {
    x * 2
}

fn main(x: pub u32, idx: pub u32) -> pub u32 {
    let r = unsafe { evil(x) };
    let arr: [u32; 4] = [r, x, x, x];
    let z = arr[idx];
    assert(z == x);
    r
}

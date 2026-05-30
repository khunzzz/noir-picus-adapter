#[inline_never]
unconstrained fn g() -> [bool; 1] {
    [true]
}

unconstrained fn f() -> [bool; 1] {
    let mut b = g();
    let mut i: u32 = 0;
    loop {
        if i == 1 {
            break;
        }
        i += 1;
        b[0] = false;
    }
    g()
}

unconstrained fn main() -> pub [bool; 1] {
    f()
}

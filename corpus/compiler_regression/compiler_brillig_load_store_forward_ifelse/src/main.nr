unconstrained fn pick(cond: bool) -> Field {
    let mut a = (1, 2);
    let r = if cond { &mut a.1 } else { &mut a.0 };
    let val = *r;
    a = (3, 4);
    val
}

fn main(x: bool) -> pub Field {
    let expected = comptime { pick(true) };
    let result = unsafe { pick(x) };
    assert(result == expected);
    result
}

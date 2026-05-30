#[oracle(nested_tuple_array)]
unconstrained fn nested_tuple_array() -> [[(u8, u8); 3]; 2] {}

fn main(anchor: pub u8) -> pub u8 {
    let tuples = unsafe { nested_tuple_array() };
    tuples[0][0].0 + tuples[1][2].1 + anchor
}

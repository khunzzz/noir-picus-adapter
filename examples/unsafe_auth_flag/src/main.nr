unconstrained fn auth_hint(secret: Field) -> Field {
    if secret == 123 {
        1
    } else {
        0
    }
}

fn main(secret: Field) -> pub Field {
    // Safety: fixture constrains only boolean-ness.
    let authorized = unsafe { auth_hint(secret) };

    assert(authorized * (authorized - 1) == 0);

    authorized
}

fn main(
    opcode_add: pub Field,
    reg_a: pub Field,
    reg_b: pub Field,
    reg_c: Field,
) -> pub Field {
    // Risc0 zkVM 3-register instruction: destination register must be constrained to ALU output.
    assert(opcode_add == 1);

    // Missing: reg_c == reg_a + reg_b.
    reg_c
}

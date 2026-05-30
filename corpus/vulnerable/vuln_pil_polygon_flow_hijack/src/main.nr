fn main(
    expected_next_pc: pub Field,
    fallthrough_pc: Field,
    jump_pc: Field,
    jump_flag: Field,
) -> pub Field {
    // Polygon PIL: execution-flow selector must be constrained to the decoded opcode branch.
    let next_pc = fallthrough_pc + jump_flag * (jump_pc - fallthrough_pc);
    assert(next_pc == expected_next_pc);

    jump_flag
}

fn main(
    stack_x: pub Field,
    shift_low_byte: pub Field,
    opcode_tag: pub Field,
    extracted_shift_byte: Field,
    shifted_result: Field,
) -> pub Field {
    // Inspired by Scroll/PSE zkEVM shift bugs: helper byte must be bound to the stack word.
    assert(opcode_tag == 27);

    let shift_factor = 1 + extracted_shift_byte + extracted_shift_byte * extracted_shift_byte;
    assert(shifted_result == stack_x * shift_factor);

    // Missing: extracted_shift_byte == shift_low_byte.
    shifted_result
}

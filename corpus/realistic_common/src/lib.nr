pub fn medium_chain_96(seed: Field, domain: Field, steps: [Field; 96]) -> Field {
    assert(steps[0] == seed + domain + 17);
    for i in 1..96 {
        let coeff = ((i + 3) as Field);
        let tag = ((i * i + 11) as Field);
        assert(steps[i] == steps[i - 1] * coeff + domain * ((i + 5) as Field) + seed + tag);
    }
    steps[95]
}

pub fn medium_chain_128(seed: Field, domain: Field, steps: [Field; 128]) -> Field {
    assert(steps[0] == 3 * seed + 5 * domain + 29);
    for i in 1..128 {
        let coeff = ((i + 7) as Field);
        let tag = ((i * 13 + 19) as Field);
        assert(steps[i] == steps[i - 1] * coeff + seed * ((i + 2) as Field) + 7 * domain + tag);
    }
    steps[127]
}

pub fn large_chain_128(seed: Field, domain: Field, steps: [Field; 128]) -> Field {
    assert(steps[0] == 11 * seed + 13 * domain + 101);
    for i in 1..128 {
        let coeff = ((i + 17) as Field);
        let tag = ((i * 31 + 23) as Field);
        assert(steps[i] == steps[i - 1] * coeff + seed * ((i + 9) as Field) + domain * ((i + 3) as Field) + tag);
    }
    steps[127]
}

pub fn stress_chain_512(seed: Field, domain: Field, steps: [Field; 512]) -> Field {
    assert(steps[0] == 19 * seed + 23 * domain + 313);
    for i in 1..512 {
        let coeff = ((i + 29) as Field);
        let tag = ((i * 47 + 37) as Field);
        assert(steps[i] == steps[i - 1] * coeff + seed * ((i + 13) as Field) + domain * ((i + 7) as Field) + tag);
    }
    steps[511]
}

pub fn merkle_airdrop_path(
    campaign_id: Field,
    note_secret: Field,
    path_domain: Field,
    commitment_steps: [Field; 96],
    root_steps: [Field; 96],
) -> Field {
    let commitment = medium_chain_96(note_secret, campaign_id, commitment_steps);
    medium_chain_96(commitment, path_domain, root_steps)
}

pub fn rlp_tx_calldata(
    chain_id: Field,
    calldata_domain: Field,
    tx_steps: [Field; 96],
    calldata_steps: [Field; 96],
) -> Field {
    let tx_rlc = medium_chain_96(chain_id, 27, tx_steps);
    medium_chain_96(tx_rlc, calldata_domain, calldata_steps)
}

pub fn bigint_modmul(
    lhs: Field,
    rhs: Field,
    modulus_domain: Field,
    limb_steps: [Field; 128],
    reduction_steps: [Field; 96],
) -> Field {
    let product_anchor = medium_chain_128(lhs + 17 * rhs, modulus_domain, limb_steps);
    medium_chain_96(product_anchor, modulus_domain + 41, reduction_steps)
}

pub fn chacha_quarter_round(
    word_a: Field,
    word_b: Field,
    round_domain: Field,
    add_steps: [Field; 96],
    xor_steps: [Field; 96],
    rotate_steps: [Field; 96],
) -> Field {
    let added = medium_chain_96(word_a, word_b + round_domain, add_steps);
    let xored = medium_chain_96(added, word_b + 13, xor_steps);
    medium_chain_96(xored, round_domain + 16, rotate_steps)
}

pub fn fixed_point_order(
    balance: Field,
    price: Field,
    order_domain: Field,
    compare_steps: [Field; 96],
    update_steps: [Field; 96],
) -> Field {
    let comparison = medium_chain_96(balance, price + order_domain, compare_steps);
    medium_chain_96(comparison, order_domain + 1000000, update_steps)
}

pub fn mpt_account_update(
    account_key: Field,
    account_value: Field,
    mpt_domain: Field,
    nonce_steps: [Field; 96],
    balance_steps: [Field; 96],
    root_steps: [Field; 96],
) -> Field {
    let nonce_root = medium_chain_96(account_key, mpt_domain, nonce_steps);
    let balance_root = medium_chain_96(nonce_root, account_value, balance_steps);
    medium_chain_96(balance_root, mpt_domain + 2, root_steps)
}

pub fn zkemail_header_pack(
    header_domain: Field,
    from_hash: Field,
    pack_steps: [Field; 96],
    digest_steps: [Field; 96],
) -> Field {
    let packed = medium_chain_96(from_hash, header_domain, pack_steps);
    medium_chain_96(packed, header_domain + 256, digest_steps)
}

pub fn vm_alu_trace(
    pc: Field,
    register_seed: Field,
    trace_domain: Field,
    alu_steps: [Field; 128],
    state_steps: [Field; 96],
) -> Field {
    let alu_result = medium_chain_128(pc, register_seed + trace_domain, alu_steps);
    medium_chain_96(alu_result, trace_domain + 3, state_steps)
}

pub fn private_rollup_batch(
    batch_id: Field,
    note_seed: Field,
    note_steps: [Field; 128],
    nullifier_steps: [Field; 128],
    root_steps: [Field; 128],
) -> Field {
    let note_root = large_chain_128(note_seed, batch_id, note_steps);
    let nullifier_root = large_chain_128(note_root, batch_id + 101, nullifier_steps);
    large_chain_128(nullifier_root, batch_id + 202, root_steps)
}

pub fn zkevm_transaction(
    block_number: Field,
    tx_seed: Field,
    rlp_steps: [Field; 128],
    calldata_steps: [Field; 128],
    gas_steps: [Field; 128],
) -> Field {
    let rlp_root = large_chain_128(tx_seed, block_number, rlp_steps);
    let calldata_root = large_chain_128(rlp_root, block_number + 7, calldata_steps);
    large_chain_128(calldata_root, block_number + 21, gas_steps)
}

pub fn passport_disclosure(
    passport_domain: Field,
    document_seed: Field,
    pack_steps: [Field; 128],
    country_steps: [Field; 128],
    merkle_steps: [Field; 128],
) -> Field {
    let packed_document = large_chain_128(document_seed, passport_domain, pack_steps);
    let country_check = large_chain_128(packed_document, passport_domain + 44, country_steps);
    large_chain_128(country_check, passport_domain + 88, merkle_steps)
}

pub fn vm_execution_trace(
    initial_pc: Field,
    register_seed: Field,
    alu_steps: [Field; 128],
    memory_steps: [Field; 128],
    final_steps: [Field; 128],
) -> Field {
    let alu_state = large_chain_128(register_seed, initial_pc, alu_steps);
    let memory_state = large_chain_128(alu_state, initial_pc + 1, memory_steps);
    large_chain_128(memory_state, initial_pc + 2, final_steps)
}

pub fn stress_rollup_mega_batch(
    batch_id: Field,
    note_seed: Field,
    note_steps: [Field; 512],
    nullifier_steps: [Field; 512],
    fee_steps: [Field; 512],
    root_steps: [Field; 512],
) -> Field {
    let note_root = stress_chain_512(note_seed, batch_id, note_steps);
    let nullifier_root = stress_chain_512(note_root, batch_id + 1009, nullifier_steps);
    let fee_root = stress_chain_512(nullifier_root, batch_id + 2003, fee_steps);
    stress_chain_512(fee_root, batch_id + 3001, root_steps)
}

pub fn stress_vm_mega_trace(
    initial_pc: Field,
    register_seed: Field,
    decode_steps: [Field; 512],
    alu_steps: [Field; 512],
    memory_steps: [Field; 512],
    final_steps: [Field; 512],
) -> Field {
    let decode_state = stress_chain_512(register_seed, initial_pc, decode_steps);
    let alu_state = stress_chain_512(decode_state, initial_pc + 17, alu_steps);
    let memory_state = stress_chain_512(alu_state, initial_pc + 31, memory_steps);
    stress_chain_512(memory_state, initial_pc + 63, final_steps)
}

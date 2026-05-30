fn main(
    expected_gas_cost: pub Field,
    base_call_gas: pub Field,
    charged_access_cost: Field,
    warm_status: Field,
) -> pub Field {
    // Scroll CALL opcodes: warm/cold status must be constrained to the gas cost branch.
    assert(base_call_gas + charged_access_cost == expected_gas_cost);

    // Missing: charged_access_cost is selected by boolean warm_status.
    warm_status
}

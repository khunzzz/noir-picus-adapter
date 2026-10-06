// HARNESS: C7 with the decoded message returned instead of compared to a public input.
use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, N_PARTIES, T};
use lib::configs::default::threshold::{
    DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_BIT_K,
    DECRYPTED_SHARES_AGGREGATION_BIT_Q, DECRYPTED_SHARES_AGGREGATION_BIT_Q_TOTAL,
    DECRYPTED_SHARES_AGGREGATION_BIT_T, DECRYPTED_SHARES_AGGREGATION_CONFIGS, L,
};
use lib::core::threshold::decrypted_shares_aggregation::DecryptedSharesAggregation;
use lib::math::polynomial::Polynomial;

fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
) -> pub [Field; MAX_MSG_NON_ZERO_COEFFS] {
    let c7: DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, N_PARTIES, DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_BIT_Q, DECRYPTED_SHARES_AGGREGATION_BIT_K, DECRYPTED_SHARES_AGGREGATION_BIT_T, DECRYPTED_SHARES_AGGREGATION_BIT_Q_TOTAL> = DecryptedSharesAggregation::new(
        DECRYPTED_SHARES_AGGREGATION_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        Polynomial::new([0; MAX_MSG_NON_ZERO_COEFFS]),
    );
    c7.execute_decode()
}

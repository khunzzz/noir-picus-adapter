# Corpus Diversity Audit

The realistic corpus was reworked because the first version overused one
boundary shape:

```text
claimed_output + slack == computed_anchor
```

That was useful for proving the scanner could find a long underconstrained
alias, but it made too many source families look the same. The current tier
keeps the long source-family chains, but spreads the vulnerable boundary across
different constraint failure modes.

## Boundary Classes

| Boundary class | Cases |
| --- | --- |
| Guarded equality bypass | `medium_merkle_airdrop_nullifier`, `medium_rlp_tx_calldata`, `medium_guarded_hash_bypass`, `medium_vm_alu_trace`, `large_passport_disclosure` |
| Quotient/remainder or division alias | `medium_bigint_modmul`, `medium_division_remainder_bound`, `large_zkevm_transaction` |
| Carry/high-limb/range alias | `medium_chacha_quarter_round`, `medium_zkemail_header_pack`, `medium_range_high_limb_alias` |
| Selector/one-hot interpolation | `medium_mpt_account_update`, `medium_selector_onehot_transfer` |
| Balance/fee conservation alias | `medium_fixed_point_order`, `large_private_rollup_batch`, `large_fee_conservation_alias` |
| VM transition delta | `large_vm_execution_trace` |
| Lookup/index membership alias | `large_lookup_index_membership` |
| Artificial mega-chain guard/delta stress | `stress_rollup_mega_batch`, `stress_vm_mega_trace` |

## Current Counts

| Tier | Families | Variants |
| --- | ---: | ---: |
| Micro | 40 | 40 vulnerable |
| Realistic medium | 12 | 12 vulnerable + 12 fixed |
| Realistic large | 6 | 6 vulnerable + 6 fixed |
| Realistic stress | 2 | 2 vulnerable + 2 fixed |

The realistic gate now expects 40 variants total:

```text
20 vulnerable -> unsafe
20 fixed      -> verified
```

## What Was Changed

- The repeated `slack` alias was removed from realistic sources.
- Existing cases were rewritten to source-specific boundary classes: guards,
  selectors, quotient/remainder equations, high-limb aliases, fee conservation,
  and VM deltas.
- Six new realistic families were added:
  - `medium_selector_onehot_transfer`
  - `medium_division_remainder_bound`
  - `medium_guarded_hash_bypass`
  - `medium_range_high_limb_alias`
  - `large_lookup_index_membership`
  - `large_fee_conservation_alias`
- Two artificial stress families were added to exercise much larger circuits:
  - `stress_rollup_mega_batch`
  - `stress_vm_mega_trace`
- The realistic gate no longer hard-codes `12/12`; it derives expected counts
  from `realistic_manifest.tsv`.

## Remaining Similarity

All realistic cases still share the same high-level harness shape:

```text
long source-faithful chain -> public anchor -> returned target uniqueness check
```

That similarity is intentional. It keeps the scanner target stable while varying
the vulnerable boundary. A future third tier should use whole-program Noir
fixtures with multiple return targets and mixed public outputs, but that should
be separate from this corpus gate because runtime will be much higher.

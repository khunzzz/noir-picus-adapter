# Real-world Noir targets and audit-derived vulnerability classes (as of 2026-09-29)

Method note (read first). Many primary sites were blocked by this environment's egress proxy
(nethermind.io, diligence.consensys.io / diligence.security, openzeppelin.com, aztec.network,
cantina.xyz, reports.zksecurity.xyz, noir-lang.org, docs.aztec.network). For those, only search-engine
snippets were available and are marked "(search snippet)". GitHub was reachable, so most quantitative
data below comes from **shallow clones made on 2026-09-29** and simple `grep` counts over `*.nr` files
(excluding paths containing `test`). Counts are: Noir LOC, number of `unconstrained fn` definitions,
number of `unsafe {` blocks, and number of `assert_max_bit_size|as_bits|to_le_bits|to_be_bits`
occurrences (a rough proxy for hand-written range checks). These are crude lexical metrics, not ACIR
opcode counts. Two audit PDFs (zkemail.nr: Veridise + Consensys Diligence) are committed in the
zkemail.nr repo and were read directly.

## Q1. Which major Noir projects hold value, and which use many unconstrained hints?

### Takeaway
The highest-value, hint-heavy, human-written Noir today is (a) ZKPassport's circuits (now owned by Aztec Labs) and the forked libraries they pin, (b) the zkEmail stack (zkemail.nr, noir-jwt, zk-regex's Noir output) and the noir-lang parsing libraries it depends on (string_search, base64, json_parser, sort), (c) Interfold (Gnosis Guild) FHE/threshold circuits whose hand-written modular-arithmetic hints are explicitly outside their audits, and (d) Aztec (aztec-nr oracles, token/NFT/vault standards, protocol circuits) where a paid Cantina bounty exists but circuit sizes are far above the scanner's limit. Payy, Stellar confidential tokens, zerosats hold value but use almost no hints.

### Cited Findings

Static metrics from shallow clones (2026-09-29; last-commit date in brackets):

| Repo | Noir LOC | `unconstrained fn` | `unsafe {` | range/bit calls | Notes |
|---|---:|---:|---:|---:|---|
| [zkpassport/circuits](https://github.com/zkpassport/circuits) [2026-09-14] | 81,242 (813 files, most are generated per-algorithm `bin/` variants) | 11 | 940 | 7 | hand-written libs `facematch`, `exclusion-check`, `inclusion-check`, `utils` ≈ 5.9k LOC |
| [AztecProtocol/aztec-packages `noir-projects/fnd`](https://github.com/AztecProtocol/aztec-packages) (branch `next`) [2026-09-29] | 88,362 | 371 | 117 | 87 | protocol circuits; `private-kernel-lib` has 21 files with `unsafe` |
| [AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr) [2026-09-29] | 27,975 | 650 | 79 | 0 | aztec-nr now lives in its own repo |
| [defi-wonderland/aztec-standards](https://github.com/defi-wonderland/aztec-standards) [2026-07-09] | 4,605 | 7 | 2 | 0 | Token / NFT / Vault contracts for Aztec |
| [gnosisguild/interfold](https://github.com/gnosisguild/interfold) [2026-09-29] | 37,394 | 15 | 78 | 13 | circuits/lib + CRISP voting example |
| [noir-lang/noir_json_parser](https://github.com/noir-lang/noir_json_parser) [2026-09-01] | 10,604 | 33 | 37 | 76 | RFC 8259 JSON parsing |
| [noir-lang/noir_bigcurve](https://github.com/noir-lang/noir_bigcurve) | 16,413 | 54 | 11 | 3 | already audited by researcher |
| [noir-lang/eth-proofs](https://github.com/noir-lang/eth-proofs) [2026-02-09] | 15,912 | 12 | 62 | 1 | RLP/MPT/storage proofs, fork of vlayer's Noir code |
| [noir-lang/noir-bignum](https://github.com/noir-lang/noir-bignum) | 6,886 | 94 | 37 | 24 | already audited by researcher |
| [noir-lang/noir_base64](https://github.com/noir-lang/noir_base64) [2026-09-01] | 4,402 | 20 | 7 | 7 | |
| [zkemail/zk-regex](https://github.com/zkemail/zk-regex) [2026-09-17] | 4,383 | 8 | 7 | 10 | Noir regex templates/generator output |
| [sparq-org/noir_IEEE754](https://github.com/sparq-org/noir_IEEE754) [2026-07-06] | 3,356 | 25 | 30 | 24 | floating point |
| [polybase/payy](https://github.com/polybase/payy) [2026-06-24] | 2,821 | 0 | 0 | 10 | private stablecoin payments; UTXO + aggregation circuits |
| [zerosats/zerosats](https://github.com/zerosats/zerosats) [2026-07-08] | 2,600 | 0 | 0 | 12 | private BTC payments |
| [noir-lang/sha512](https://github.com/noir-lang/sha512) [2026-04-08] | 2,297 | 22 | 15 | 3 | |
| [hashcloak/noir-bigint](https://github.com/hashcloak/noir-bigint) [2024-08-02] | 2,101 | 17 | 0 | 8 | stale |
| [zkemail/zkemail.nr](https://github.com/zkemail/zkemail.nr) [2026-03-03] | 1,745 | 4 | 7 | 8 | audited 2024 (see Q2) |
| [OpenZeppelin/stellar-contracts (confidential tokens)](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/tokens/src/confidential) | 1,734 | 0 | 0 | 20 | repo has `audits/` PDFs |
| [zkemail/noir-jwt](https://github.com/zkemail/noir-jwt) [2025-12-04] | 1,646 | 4 | 7 | 0 | hints `extract_claim_unconstrained`, `search_for_key` |
| [Slokh/anoncast](https://github.com/Slokh/anoncast) [2026-01-13] | 1,095 | 5 | 0 | 0 | anonymous X/Farcaster posting |
| [privacy-scaling-explorations/zk-kit.noir](https://github.com/privacy-scaling-explorations/zk-kit.noir) | 941 | 0 | 0 | 7 | Merkle trees, ECDH |
| [noir-lang/noir_string_search](https://github.com/noir-lang/noir_string_search) [2026-07-24] | 727 | 5 | 2 | 0 | |
| [noir-lang/sha256](https://github.com/noir-lang/sha256) | 691 | 19 | 8 | 0 | |
| [noir-lang/sparse_array](https://github.com/noir-lang/sparse_array) [2026-07-29] | 646 | 4 | 4 | 7 | |
| [noir-lang/noir-edwards](https://github.com/noir-lang/noir-edwards) | 635 | 7 | 6 | 6 | already audited by researcher |
| [RadNi/mpt-noir](https://github.com/RadNi/mpt-noir) | 619 | 0 | 0 | 0 | README: "unaudited and should not be used in production" |
| [noir-lang/noir_sort](https://github.com/noir-lang/noir_sort) [2026-07-29] | 416 | 12 | 4 | 1 | |
| zkpassport/noir_rsa, zkpassport/noir-ecdsa, noir-lang/noir_rsa, d3mage/zk-QES, madztheo/noir-date | 388–570 each | 0 | 0–1 | 0–3 | small |

(Source for all rows: the linked GitHub repos, shallow-cloned and grepped on 2026-09-29.)

Ecosystem / usage facts:
- The awesome-noir list names as applications: Payy, Stellar Confidential Tokens, Zerosats, anoncast, Aztec, Interfold; and as libraries: noir-bignum, IEEE754, wad.nr, noir-date, noir_base64, noir_json_parser, noir_string_search, noir_XPath, noir_sort, sparse_array, noir_bigcurve, keccak256/mimc/poseidon/ripemd160/sha256/sha512, zk-kit ECDH, noir-rlwe-gadgets, eddsa, zkpassport/noir-ecdsa, zkpassport/noir_rsa, schnorr, zk-QES, zk-kit Merkle trees, ecrecover-noir, eip712-noir, mpt-noir, eth-proofs; plus ZKPassport and ZK Email as projects and MoPro / noir_rs / Swoir / noir_android as mobile tooling — [awesome-noir README](https://raw.githubusercontent.com/noir-lang/awesome-noir/main/README.md)
- `noir-lang/eth-proofs` is described as "forked from vlayer-monorepo, updated for compatibility with recent Noir releases" — [awesome-noir](https://raw.githubusercontent.com/noir-lang/awesome-noir/main/README.md). The current vlayer repo contains 0 `.nr` files (clone of [vlayer-xyz/vlayer](https://github.com/vlayer-xyz/vlayer), 2026-09-29).
- Dependency tally across the cloned repos' `Nargo.toml` files: `noir-lang/poseidon` (48 refs), `aztec-packages` (34), `noir-lang/sha256` (25), `noir-lang/noir-bignum` (9), `keccak256` (8), `TaceoLabs/oprf-nr` (5), `zkpassport/sha512` (4), `zkpassport/noir-bignum` (4), `noir_sort` (3), `noir-date` (3) — measured from the clones listed above.
- ZKPassport pins **forks** rather than upstream libraries: `zkpassport/noir_json_parser` (tag `v0.4.0-4`, used by `lib/facematch`), `zkpassport/noir_base64`, `zkpassport/noir-bignum`, `zkpassport/noir_bigcurve`, `zkpassport/noir_rsa`, `zkpassport/noir-ecdsa`, `zkpassport/sha512`, plus `TaceoLabs/oprf-nr` (babyjubjub, OPRF for scoped nullifiers), `zac-williamson/sha1`, `madztheo/noir-date` — [zkpassport/circuits Nargo.toml files](https://github.com/zkpassport/circuits)
- noir-jwt depends on noir-bignum, noir_base64, noir_string_search, sha256, nodash, zkemail.nr, zkpassport/noir_rsa; zkemail.nr depends on noir-bignum, noir_base64, noir_rsa, poseidon, sha256, nodash — [noir-jwt](https://github.com/zkemail/noir-jwt), [zkemail.nr](https://github.com/zkemail/zkemail.nr)
- Aztec Labs acquired ZKPassport; the iOS app and Noir circuits stay open source — [crypto.news](https://crypto.news/aztec-labs-acquires-zkpassport-code-stays-open/) (search snippet). zkpassport/circuits `SECURITY.md` routes reports to GitHub private vulnerability reporting or security@aztec-labs.com and states "ZKPassport is currently under internal and external review" — [SECURITY.md](https://github.com/zkpassport/circuits/blob/main/SECURITY.md)
- Aztec's core circuits (private execution, public execution, proof recursion) were rewritten from C++ to Noir — [Aztec blog](https://aztec.network/blog/aztecs-core-cryptography-now-in-noir) (search snippet).

Concrete hint sites in ZKPassport hand-written libs (from the clone):
- `lib/exclusion-check/country/src/lib.nr`: `let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, country_sum) }; constrain_closest_index(...)` — sorted-list non-membership via a hinted index; the list is "assumed to be sorted", checked elsewhere by `validate_country_list` — [zkpassport/circuits](https://github.com/zkpassport/circuits/blob/main/src/noir/lib/exclusion-check/country/src/lib.nr)
- `lib/facematch/src/ios/mod.nr`: `let auth_data_len = unsafe { unsafe_calculate_auth_data_length(auth_data) }; assert(auth_data_len > 0); assert(auth_data_len <= AUTH_DATA_MAX_LEN);` — a hinted length constrained only by bounds, with a `// Safety:` comment that soundness comes from the later hash/nonce binding; inside the hint, CBOR lengths are parsed by `unsafe_parse_cbor_length_at` — [ios/mod.nr](https://github.com/zkpassport/circuits/blob/main/src/noir/lib/facematch/src/ios/mod.nr)
- `lib/facematch/src/android/token.nr`: `let length = unsafe { unsafe_get_integrity_token_length(token) };` (Play Integrity token, JSON-parsed with the forked json parser) — [android/token.nr](https://github.com/zkpassport/circuits/blob/main/src/noir/lib/facematch/src/android/token.nr)
- Other hint helpers: `unsafe_get_asn1_element_length`, `find_subarray_index_unsafe`, `find_subarray_index_after_index_unsafe`, `unsafe_get_index`, `unsafe_get_last_index`, `unsafe_be16_at`, `unsafe_parse_cbor_length_slice` — [zkpassport/circuits src/noir/lib](https://github.com/zkpassport/circuits/tree/main/src/noir/lib)

Hint functions elsewhere (from clones):
- noir-jwt / zk-regex: `extract_claim_unconstrained`, `search_for_key`, `__build_capture_mask`, `__build_capture_start_end_mask`, `__build_is_capture`, `__select_subarray`, `__substring_from_mask`, `__sort_field_as_u32`, `__unpack_sparse_value`, `build_msg_block_iter` — [noir-jwt](https://github.com/zkemail/noir-jwt), [zk-regex](https://github.com/zkemail/zk-regex)
- Interfold circuits: `__div_mod`, `__inv_mod`, `__mul_mod`, `__mul_with_quotient`, `__mul_with_quotient_u128`, `__sub_with_underflow`, `__sub_with_underflow_u64`, `__reduce_witness_u64`, `__pow_mod`, `__compute_mod_reduction`, `__neg` — i.e. hand-rolled modular arithmetic with quotient/borrow hints (the same pattern family as noir-bignum's non-unique borrow flags) — [gnosisguild/interfold circuits](https://github.com/gnosisguild/interfold/tree/main/circuits). Interfold depends on its own forks `gnosisguild/noir-bignum` and `gnosisguild/zk-kit.noir`.
- Aztec-nr oracles (36 files with `#[oracle]`): e.g. `aztec_prv_getHashPreimage`, `aztec_prv_getAppTaggingSecret`, `aztec_prv_isNullifierPending`, `aztec_prv_notifyCreatedNote`, `aztec_prv_notifyNullifiedNote`, `aztec_prv_callPrivateFunction`, `aztec_prv_assertValidPublicCalldata`, `aztec_misc_getRandomField`, `aztec_prv_resolveTaggingStrategy`, plus L1→L2 membership witness (`get_l1_to_l2_membership_witness.nr`) and many `aztec_avm_*` — [AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr)

### Inferences
- Ranked target list for an ACIR scanner limited to "a few thousand opcodes" and focused on hand-written hint + weak-assert patterns (inference; value/usage/audit as cited above):
  1. **ZKPassport hand-written libs** (`facematch` iOS App Attest CBOR / Android Play Integrity JSON, `exclusion-check`/`inclusion-check` sorted-list index hints, `utils` subarray/ASN.1 length hints) and the **zkpassport forks** (`noir_json_parser v0.4.0-4`, `noir_base64`, `noir-bignum`, `sha512`) — diff forks against upstream. High value (production identity app, Aztec-owned), hint-heavy, per-function harnesses are small. Audit status of the newer facematch code is unknown (Q2 gaps). The iOS `auth_data_len` pattern is exactly "hint + bounds-only assert"; whether it is exploitable depends on the downstream hash/nonce binding — a good triage candidate, not a confirmed bug.
  2. **Interfold (Gnosis Guild) circuits** — 37k LOC, modular-arithmetic hints with quotient/borrow witnesses, threshold/DKG circuits plus CRISP voting; their own audit README states the audits "cover no Rust and no circuits". Best "unaudited + hint-heavy + holds value" combination found.
  3. **noir-jwt + zk-regex Noir output + zkemail.nr (post-audit code)** — small circuits (1.6–4.4k LOC), string/claim extraction hints; zkemail.nr's 2024 audits found many parsing/partial-hash issues (Q2), so post-audit changes and the regex/JWT layers built on it are fertile.
  4. **noir-lang parsing/collection libs**: `noir_json_parser` (largest, 33 hints, 76 range/bit calls), `noir_string_search`, `noir_sort`, `noir_base64`, `sparse_array`, `sha512` (README: "has not been reviewed by the Noir team and is unaudited"). Each can be harnessed with small generic parameters to stay under the opcode limit.
  5. **Aztec**: aztec-standards Token/NFT/Vault private functions and aztec-nr note/nullifier helpers (oracle outputs = Brillig foreign-call outputs = exactly the scanner's nondeterministic targets); protocol circuits' `private-kernel-lib` reset/ordering hints are likely too large whole-circuit but can be unit-harnessed. Paid Cantina bounty (Q3) makes this the only target with a clear payout path.
  6. **eth-proofs / mpt-noir** (RLP/MPT decoding with 62 `unsafe` blocks; mpt-noir self-declared unaudited).
  7. Lower priority: `noir_IEEE754` (hint-heavy but little usage), anoncast (small, value moderate), Payy / zerosats / Stellar confidential (value but ~no hints → less suited to a hint-focused tool; still candidates for field-vs-integer and missing-range classes).
- The `unsafe {` count in zkpassport (940) is inflated by generated per-algorithm `bin/` circuits that re-instantiate the same library calls; the distinct hand-written hint functions number ~11 `unconstrained fn` plus library forks.

### Gaps
- No ACIR opcode counts were produced (no `nargo` compile done here); LOC is only a proxy.
- Semaphore-Noir, Mopro example circuits, zkLogin-style Noir projects, Hashcloak Noir libs beyond noir-bigint, zkVerify/Mina uses of Noir, and privacy-pool/mixer Noir implementations could not be located under guessed repo names (clone attempts for `semaphore-protocol/semaphore-noir`, `privacy-scaling-explorations/semaphore-noir` failed as not found/private). Not assessed.
- User counts / TVL per project not found.

## Q2. Published audits of Noir code — findings relevant to under-constraint, range checks, field-vs-integer, predicates, bounds, BoundedVec, parsing

### Takeaway
The best-documented Noir audits are the two zkemail.nr audits (Veridise, Nov 11–25 2024; Consensys Diligence, Nov–Dec 2024); their findings are dominated by parsing/"edge-case" soundness bugs (unanchored substring match, unchecked delimiters/CRLF, unchecked sequence length vs BoundedVec max, partial-SHA state not binding trailing bytes, non-canonical limbs enabling nullifier malleability, unvalidated precomputed `redc` hint input). Most noir-lang libraries (json_parser, string_search, sort, base64, sha512, bigcurve) have no public audit that could be found; Interfold's circuits are explicitly unaudited.

### Cited Findings

zkemail.nr — Veridise (commit 2f81196, Nov 11–25 2024, 6 person-weeks, 14 issues) — [report PDF in repo](https://github.com/zkemail/zkemail.nr/tree/main/audits/v1), also [Veridise PDF](https://veridise.com/wp-content/uploads/2025/04/VAR_Mach34_241104_zkemail_nr_V2.pdf):
- V-ZEML-VUL-001 **High**: `get_body_hash()` finds `bh=` constrained to be inside the dkim-signature header but not checked to be at a tag boundary (first tag or preceded by `;`); a user-controlled tag (e.g. inside `z=` or a crafted value) can supply a fake body hash → "full control over the contents in the proven message".
- V-ZEML-VUL-002 **Medium**: `RSAPubkey.redc` (Barrett reduction parameter) is never checked against `modulus` (only the modulus hash is registered) → attacker may manipulate `redc` toward signature forgery. Class: precomputed helper parameter supplied by prover and trusted.
- V-ZEML-VUL-003 Low: `email_nullifier = pedersen_hash(signature)`; signature limbs (intended 120-bit) are not range-constrained, so adding the modulus yields a distinct-but-valid signature → many nullifiers per email. Class: non-canonical limb representation / missing range check.
- V-ZEML-VUL-004 Low un-normalized signature/DKIM keys; VUL-005 Low non-standard email parsing; VUL-006 Low first header value chars not validated; VUL-010 Warning: `partial_sha256_var_start` hashes `N / BLOCK_SIZE` blocks, silently ignoring leftover bytes; VUL-011 wrong value compared to DKIM header length; VUL-012 nullifiers may leak info; VUL-013 ignored DKIM tags.
- Recommendations: wrap all unconstrained calls in `unsafe` blocks; "verify if a function called from the standard library is unsafe"; avoid casts to `u32` which "may silently truncate bits".

zkemail.nr — Consensys Diligence (Nov–Dec 2024; Heiko Fisch, George Kobakhidze, Rai Yang) — [report PDF in repo](https://github.com/zkemail/zkemail.nr/tree/main/audits/v1), [Diligence page](https://diligence.security/audits/2024/12/zk-email-noir/) (page itself blocked; titles read from PDF):
- 5.1 **Critical**: header field extraction can be fooled by passing a simple-canonicalized header.
- 5.2 Major: first characters of claimed header field value unchecked for CRLF. 5.3 Major: missing validation of characters in `header_field_name`. 5.4 Major: missing validation of header field sequence length.
- 5.5 Major: `partial_sha256_var_start` with size not a multiple of 64 gives the same `h` for different data (e.g. `data1` and `data1 + "previous content is false"`). 5.6 Major: `partial_sha256_var_interstitial` same state for data smaller than `message_size`. 5.7 Major: N < BLOCK_SIZE → loop skipped, same hash state for all data.
- 5.8 Medium: sync `partial_hash.nr` with Aztec's updated sha256 lib, which added `if !is_unconstrained() { verify_msg_block(...) }` constraints on the hinted `build_msg_block_iter` output. 5.9 Medium N ≫ message_size case. 5.10 Medium several leniencies in `get_body_hash`.
- 5.11 Medium: no check that `email_address_sequence.length <= MAX_EMAIL_ADDRESS_LENGTH` (320); only the first 320 chars are validated and the returned `BoundedVec` length can exceed its capacity. Class: BoundedVec length not constrained.
- 5.12–5.14 Medium (special chars, multiple `To` recipients, library use). 5.15 Minor: `header.get_unchecked(end_index + 1)` may read the first out-of-bounds BoundedVec slot. 5.16–5.18 Minor.
- Defaulting `ignore_body_hash_check` to true bypasses body authentication — [search snippet of Diligence report](https://diligence.security/audits/2024/12/zk-email-noir/).
- Both audits were part of Aztec's NRG#1 grants round (Z-Imburse + ZKEmail.nr) — [search snippet, Veridise/Mach34](https://veridise.com/?p=13234).

vlayer — Veridise (Mar–May 2025, V3 12 May 2025) — [audit PDF](https://github.com/vlayer-xyz/vlayer/blob/main/audits/audit-2025-q2-veridise.pdf): 3 Critical (incl. V-VLYR-VUL-002 "Missing DNS record validation allows email forgery", VUL-003 "Inconsistent dependencies allow injection of malicious" email bodies), High VUL-006 "Information not included in DKIM signature can be…", Medium VUL-013 "Incorrect From email address can be extracted", VUL-014 "Email address validation does not match specification", VUL-025 "Unexpected JSON path syntax for nested arrays". Note: this audit targets vlayer's Rust/zkVM stack (current repo has no `.nr` files), so it is evidence of the *same semantic bug classes* (email/JSON parsing), not of Noir-specific findings.

Other audits / status:
- Nethermind published "Our First Deep Dive into Aztec's Noir Language, What ZK Auditors Learned" comparing Noir to Circom/o1js — [Nethermind blog](https://www.nethermind.io/blog/our-first-deep-dive-into-noir-what-zk-auditors-learned) (page blocked; specific findings not retrieved).
- Veridise audited Aztec Governance (Aug 25–Sep 4 2025, Solidity) — [Veridise](https://veridise.com/audits-archive/company/aztec/governance-2025-10-13/) (search snippet); zkSecurity audited Aztec Foreign Field Arithmetic (bigfield, 2024-07-01) — [zkSecurity reports](https://reports.zksecurity.xyz/) (search snippet). Neither is a Noir-circuit audit.
- Consensys Diligence and TU Wien contributed security reviews of ZKPassport — [crypto.news](https://crypto.news/aztec-labs-acquires-zkpassport-code-stays-open/) (search snippet); no report found.
- Interfold: three Zenith audits (2026-07-02 FOLD token; 2026-08-17 protocol contracts, 62 issues: 1 Critical, 6 High, 18 Medium; 2026-09-08 protocol update). The README states: "It covers no Rust and no circuits." — [interfold audits README](https://github.com/gnosisguild/interfold/tree/main/packages/interfold-contracts/audits)
- Self-declared unaudited: `noir-lang/sha512` ("has not been reviewed by the Noir team and is unaudited"), `RadNi/mpt-noir`, `sparq-org/noir_IEEE754` (should not be used in production without thorough audit); zerosats README lists "Security audits" as an unchecked TODO — respective READMEs in [noir-lang/sha512](https://github.com/noir-lang/sha512), [mpt-noir](https://github.com/RadNi/mpt-noir), [noir_IEEE754](https://github.com/sparq-org/noir_IEEE754), [zerosats](https://github.com/zerosats/zerosats).
- OpenZeppelin Stellar contracts repo holds audits v0.1.0-RC through v0.7.0 — [stellar-contracts/audits](https://github.com/OpenZeppelin/stellar-contracts/tree/main/audits) (whether the Noir confidential-token circuits are in scope was not verified).
- Compiler-level: CVE-2026-41197 (noir-lang), "Brillig: Heap corruption in foreign call results with nested tuple arrays", CWE-131, CVSS 9.8, published 2026-04-23 — [cve.imfht.com](https://cve.imfht.com/product/noir?lang=en) (search snippet). Consensys + TU Wien ZK fuzzers found 59 major bugs (27 critical soundness) across eight ZK systems including Noir — [ZKM blog](https://www.zkm.io/blog/inside-zirens-security-collaboration-with-consensys-diligence) (search snippet).
- Other ZK-identity audits used Picus: Halborn's Rarimo passport circuits assessment (Circom, 2024) used circomspect and Picus — [Halborn](https://www.halborn.com/audits/rarimo/passport-zk-circuits).

### Inferences
Catalogue of vulnerability classes actually observed in Noir audits (mapped to scanner capability):
1. **Unanchored substring / sequence extraction** (bh= in wrong tag; header field fooled by canonicalization; missing CRLF/char validation at sequence start) — semantic, mostly not detectable as witness non-uniqueness; needs spec-level properties.
2. **Hinted/advice parameter not validated against its definition** (`redc` vs modulus) — detectable as "public/param input that the circuit trusts"; a scanner could flag bignum params whose relation to modulus is never constrained.
3. **Non-canonical limb / missing range check → malleable outputs** (signature + modulus → new nullifier) — this is directly a uniqueness failure of the *output* (nullifier) when the input is not fixed; fits a "fix only the semantic value, vary representation" query.
4. **Hash-state not binding all bytes** (partial SHA with N % 64 != 0, N < 64) — detectable as output independent of some input bytes (a dependency/"unused input" check), not as under-constrained witness.
5. **BoundedVec length exceeding capacity / unchecked `get_unchecked` OOB** — matches "hint length + weak assert" patterns.
6. **Silent truncation via casts to u32** — field-vs-integer confusion (Veridise recommendation).
7. **Hinted message-block construction without `verify_msg_block`** in constrained mode (stdlib sha256 fix, `if !is_unconstrained()`), i.e. hints whose verification is gated — matches the predicated-assert class the researcher already detects.
- Most noir-lang libraries named in the objective (json_parser, string_search, sort, base64, sparse_array, sha512, bigcurve) appear to have **no public third-party audit** (no audit folders or README audit statements found in the clones; sha512 explicitly unaudited). This is an absence-of-evidence inference.

### Gaps
- Could not read the Nethermind Noir post, the OpenZeppelin guide in full, the zkSecurity report index, or any Cantina/Code4rena contest report on Noir (all blocked). No OtterSec, Zellic, Spearbit, Hashcloak, ChainSafe or Nethermind Noir-circuit audit report was located.
- No public ZKPassport audit report found despite claims of Consensys Diligence/TU Wien reviews.
- Whether zkemail.nr fixed all 2024 findings (repo last commit 2026-03-03) was not verified line-by-line.

## Q3. Aztec-specific: oracles in aztec-nr, known advisories/bugs, bug bounty/contests

### Takeaway
Aztec contracts rely on unconstrained oracle calls (notes, preimages, tagging secrets, randomness, membership witnesses) whose outputs must be re-constrained in-circuit, which is exactly the Brillig-output target class the scanner handles; but public Aztec disclosures in 2026 were proving-system (barretenberg) bugs, not Noir-contract bugs. A Cantina bug bounty (search snippet: started 2026-05-04, up to $50k critical) is the concrete payout path.

### Cited Findings
- aztec-nr (separate repo `AztecProtocol/aztec-nr`, 27,975 LOC, 650 `unconstrained fn`, 79 `unsafe` blocks, 36 files with `#[oracle]`) — [AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr) (clone 2026-09-29).
- Issue #25494 (2026-09-15, v5.2.0): contract code `let secret: Field = unsafe { random() }; ... self.context.push_nullifier_unsafe(secret_hash);` — the reporter notes that "Every `unsafe { ... }` block in an Aztec contract carries a safety rationale about what a malicious prover could substitute. Today none of those rationales can be exercised in a test at the contract level", because `random()` shares the `aztec_misc_getRandomField` oracle with aztec-nr internals and TXE ignores `OracleMock`; it also found a vacuous test in `handshake_registry_contract/src/test.nr:519` — [aztec-packages#25494](https://github.com/AztecProtocol/aztec-packages/issues/25494)
- Issue #21502 "Unsafe initialization, message delivery, and nullifier patterns in aztec-nr" (opened 2026-03-13, closed) — [aztec-packages#21502](https://github.com/AztecProtocol/aztec-packages/issues/21502) (title only retrieved).
- Issue #11087 "aztec-nr is breaking `unsafe` block rules" (2025-01-07, closed) — [aztec-packages#11087](https://github.com/AztecProtocol/aztec-packages/issues/11087) (title only).
- Issue #22844 (2026-04-29): `#[authorize_once]` macro enforces `nonce == 0` when `from == msg_sender`; defi-wonderland reverted their Vault to manual `_validate_from_private` / `_validate_from_public` authwit checks — [aztec-packages#22844](https://github.com/AztecProtocol/aztec-packages/issues/22844). (Functional, not a soundness bug, but shows hand-rolled auth checks exist in aztec-standards Vault.)
- Alpha V4 critical vulnerability discovered 2026-03-17: a barretenberg bug allowing incorrect proofs into the mempool; nodes told to upgrade to ≥ v4.1.2; fixes shipped with v5 — [Aztec blog](https://aztec.network/blog/critical-vulnerability-in-alpha-v4) (search snippet).
- Alpha V5 proving-system vulnerability identified 2026-07-27 "through internal AI-assisted auditing"; a proof could pass verification for a transaction the network should reject; to be addressed in V6 with circuit updates — [Aztec blog](https://aztec.network/blog/alpha-v5-proving-system-vulnerability) (search snippet); V4 users told to withdraw before June 25 — [The Defiant](https://thedefiant.io/news/defi/aztec-v4-withdraw-june-25-v5-upgrade-security-vulnerability) (search snippet).
- Aztec bug bounty on Cantina: started 2026-05-04; max $50,000 critical / $10,000 high / $3,000 medium / $1,000 low; 161 findings submitted; >234 researchers participated — [Cantina bounty page](https://cantina.xyz/bounties/80e74370-10d8-4e52-8e4b-7294deb7c9ee), [Cantina blog](https://cantina.xyz/blog/aztec-network-bug-bounty-on-cantina) (search snippets; page blocked, scope not verified).
- Historical (pre-Noir, Aztec 2.0): a Pedersen hash input-check bug meant every hash effectively had two outputs, allowing two nullifiers per note (double spend) — [Aztec blog "Vulnerabilities patched in Aztec 2.0"](https://aztec.network/blog/vulnerabilities-patched-in-aztec-2-0) (search snippet).
- aztec-packages `next` now hosts protocol circuits under `noir-projects/fnd/noir-protocol-circuits` (private-kernel init/inner/reset/tail variants, rollup base/merge/block-root/checkpoint/root, bignum, bigcurve, blob) and only 4 protocol contracts in `noir-projects/fnd/noir-contracts` (aztec_sublib, contract class/instance registries, fee_juice) — [aztec-packages](https://github.com/AztecProtocol/aztec-packages/tree/next/noir-projects/fnd) (clone 2026-09-29).

### Inferences
- Aztec private-function ACIR turns every oracle into a Brillig foreign call; the scanner's "BrilligCall outputs are targets" model maps 1:1 onto "did the contract re-constrain the oracle result?" (e.g. note contents vs note hash, preimage vs hash, membership witness vs root). Best entry points: aztec-standards Token/NFT/Vault and custom-note contracts, plus aztec-nr `messages/`, `keys/`, `oracle/` helpers harnessed as small circuits.
- Whole protocol circuits (private kernels, rollups) are almost certainly well beyond the scanner's ~few-thousand-opcode limit (inference from 88k LOC and recursion); target only their hint validators (21 `private-kernel-lib` files with `unsafe`) via harnesses.
- Both 2026 critical Aztec disclosures were in the proving system, not Noir application logic — so Noir-level under-constraint in aztec-nr/contracts remains comparatively unmined publicly.

### Gaps
- Bounty scope (whether aztec-nr/contracts/protocol circuits are in scope, and payout for Noir-level bugs) could not be verified (cantina.xyz blocked).
- No public list of Cantina/Code4rena contest findings on Noir code was found.
- Bodies of #21502 and #11087 not retrieved.

## Q4. Published Noir security guidance / checklists

### Takeaway
Guidance converges on: every `unsafe { hint() }` needs an in-circuit re-check with a `// Safety:` rationale; explicit range checks for dynamic/limb values; beware field overflow and integer casts; and BoundedVec/length handling — i.e. exactly the patterns the scanner targets.

### Cited Findings
- OpenZeppelin, "A Developer's Guide to Building Safe Noir Circuits" (2025-08-26, Felix Wegener): covers logical constraints, field arithmetic (x+y==z can pass when x+y wraps the modulus), explicit range checks (implicit for fixed-size inputs; explicit needed for dynamic objects such as vectors/slices), privacy leaks, implementation mismatches, and `unsafe` blocks making the programmer responsible for constraining hint outputs — [OpenZeppelin](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) (search snippets; page blocked).
- Noir language change requiring unconstrained calls from constrained code to be inside `unsafe` blocks — [noir-lang/noir#4442](https://github.com/noir-lang/noir/issues/4442); Noir docs page on unconstrained functions — [noir-lang.org](https://noir-lang.org/docs/noir/concepts/unconstrained) (blocked here).
- noir-bignum README: recommended pattern is several unconstrained `__add/__sub/...` then one `evaluate_quadratic_expression` constraint; `__div`, `__pow`, `__sqrt` are unconstrained; README carries a "Security warning: private modulus" section — [noir-bignum](https://github.com/noir-lang/noir-bignum)
- Veridise zkemail.nr recommendations (wrap unconstrained calls in `unsafe`, check whether stdlib functions are unsafe, avoid truncating casts) — [zkemail.nr audits/v1](https://github.com/zkemail/zkemail.nr/tree/main/audits/v1)
- Community tooling: ThurinLabs noir-audit-skill (Claude Code skill), 0xVikasRushi noir-claude-auditor — [codeberg](https://codeberg.org/ThurinLabs/noir-audit-skill), [awesome-noir](https://raw.githubusercontent.com/noir-lang/awesome-noir/main/README.md)

### Inferences
- The `// Safety:` comment convention (seen in zkpassport and aztec-nr) is a cheap signal to extract each hint's claimed invariant and turn it into a scanner target/assertion.

### Gaps
- Could not retrieve the full OpenZeppelin checklist or an official Noir "security best practices" page; no Aztec-authored contract security checklist was retrieved.

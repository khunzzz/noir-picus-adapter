# Under-explored soundness surfaces in Noir/Aztec beyond ACIR codegen and the Brillig-constraint checker (as of 2026-09-29)

Method note: primary sources are GitHub issues/PRs/advisories (read via github.com pages and GitHub issue search) plus web-search snippets of Aztec blog posts. The domains `aztec.network`, `docs.aztec.network`, `noir-lang.org` and `thedefiant.io` were **blocked by the egress proxy**, so Aztec blog and doc content is cited from search-result snippets only. Treat those points as lower-confidence and re-check them. Issue numbers without a repo prefix are `noir-lang/noir`. `aztec-packages#N` means `AztecProtocol/aztec-packages`.

**Disambiguation:** "#13188" means different things in the two repos. `noir-lang/noir#13188` is the `Validate` trait / BoundedVec-at-ABI issue. `aztec-packages#13188` is "Proper handling of the pairing point object in yarn-project", a recursion issue that is still open.

---

## Q1. Aztec public functions: Noir → Brillig → avm-transpiler → AVM. Do Brillig bugs become soundness bugs? What is the status, and how is it tested?

### Takeaway
Yes. Aztec public functions are compiled by Noir to **Brillig**, then transpiled by `avm-transpiler` to AVM bytecode, which is executed and proven by the AVM (barretenberg `vm2`). Three things make this layer look like the most fertile next target:
- About 20 Brillig miscompilation advisories were published in Feb–Jun 2026. Noir rates them only "Moderate/Low" because Brillig is "just unconstrained code".
- The AVM has not finished its audits.
- A transpiler bug that silently truncates addresses is still open.
- Noir's only Brillig↔AVM differential fuzzer turned out to have been dead for about 9 months and was deleted on 2026-09-18.

### Cited Findings
**Pipeline**
- The avm-transpiler "takes Brillig bytecode produced by nargo compile and transpiles it to AVM bytecode for public functions". Aztec.nr compiles to ACIR (private), Brillig (utility) and AVM bytecode (public). If a public function uses a Noir blackbox the AVM does not support, transpilation fails at compile time. — [Aztec glossary (search snippet)](https://docs.aztec.network/developers/docs/resources/glossary); [Public Execution (AVM) docs (search snippet)](https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits/public_execution)
- The transpiler README says its input is an Aztec contract artifact JSON and its output is transpiled JSON. The documented testing is only: compile test contracts → `scripts/transpile.sh` → TS simulator tests (`avm_simulator.test.ts`) and bb prover tests (`avm_proving.test.ts`). The README says nothing about fuzzing or soundness checks. — [avm-transpiler dir/README](https://github.com/AztecProtocol/aztec-packages/tree/next/avm-transpiler)
- AVM execution now runs in barretenberg's C++ **VM2** over IPC, and the TS AVM simulator was removed. The AVM fuzzer lives at `barretenberg/cpp/src/barretenberg/avm_fuzzer` and uses an in-memory `MemoryMerkleDB`. — [search snippets on aztec-packages PRs, e.g. acvm-sim #24525](https://github.com/AztecProtocol/aztec-packages/pull/24525); [noir PR #13764](https://github.com/noir-lang/noir/pull/13764)

**Security and audit status (2026)**
- Per an Aztec blog snippet, the AVM "has not yet completed its internal and external audits". This is intentional: all AVM execution is public, so it relies on a "Training Wheel", namely re-execution by a committee of validators. — [Alpha Network Security: What to Expect (snippet)](https://aztec.network/blog/alpha-network-security-what-to-expect)
- Alpha v4 had a critical vulnerability, discovered 17 March 2026, that "affects the proving system as a whole, and is not mitigated via public re-execution by the committee of validators". Fixes shipped with v5 (planned for July 2026), and details were to be withheld until v5. The same post mentions two separate barretenberg bugs:
  - one let incorrect proofs into the mempool (fixed in node ≥ v4.1.2);
  - one "medium" bug was found by Consensys Diligence & TU Vienna.
  — [Critical Vulnerability in Alpha v4 (snippet)](https://aztec.network/blog/critical-vulnerability-in-alpha-v4)
- Alpha **V5** critical vulnerability, found **27 July 2026** by "internal AI-assisted auditing": an attacker could construct "a proof that passes verification for a transaction the network should reject". The fix is planned for V6. Contributors "cannot determine whether anyone exploited the flaw". **The component was not named in the snippets available to me.** — [Alpha V5 Proving System Vulnerability (snippet)](https://aztec.network/blog/alpha-v5-proving-system-vulnerability)
- The main network bug bounty is "not yet live, other than for the non-cryptographic L1 smart contracts as audits are ongoing". — [search snippet, Aztec blog](https://aztec.network/blog/alpha-network-security-what-to-expect)

**Brillig miscompilations: the Noir advisory list, Feb–Jun 2026**
All of these are rated Moderate unless noted. — [noir advisories p1](https://github.com/noir-lang/noir/security/advisories), [p2](https://github.com/noir-lang/noir/security/advisories?page=2)
- **High:** GHSA-j4p3-qjx6-rmvx, "Load Store Forwarding incorrectly eliminates stores read through IfElse", 2026-05-19.
- GHSA-v2q4-prvf-7h73, "Incorrect conditional mutable reference assignment in Brillig", 2026-06-09.
- 2026-05-19 batch:
  - GHSA-wvh3-mhm3-7wwv (function result mutation)
  - GHSA-35pp-g9jq-9vf7 (variable not updated in inlined loop)
  - GHSA-qqxj-59g5-7jcv (constant-folding dedup)
  - GHSA-35h6-769r-84c9 (array aliasing)
  - GHSA-mfqg-6wvq-m7mr (mutable reference handling)
  - GHSA-2v53-vfw3-w489 (signed 128-bit div/mod overflow check bypassed)
- 2026-04-20 batch:
  - GHSA-w58m-gfcx-8pjq (non-dominating RangeCheck removes sibling-branch truncate)
  - GHSA-jhqf-jg5f-f357 (no-op loops return stale value)
  - GHSA-5pjx-p7xp-457j (wrong conditional branch)
  - GHSA-mh2f-jqp7-m6gm
  - GHSA-43f8-pw4p-5f5g (`&mut bool` array deref discrepancy comptime vs Brillig)
  - several crash advisories
- GHSA-3fmx-gqpv-c758 (comptime vs Brillig, mutable arrays in loop), 2026-02-09.
- GHSA-683h-pgp9-8cq4 (constant Field division omits truncation), 2026-05-07.

**Known transpiler and AVM-vs-Brillig bugs**
- **aztec-packages#24115 (open, 2026-06-16).** "AVM transpiler wraps Brillig memory addresses into u16 operands". `MemoryAddress(70000)` lowers to `U16(4464)`, so distinct Brillig addresses collide. The cause is a `to_u32() as u16` pattern in `avm-transpiler/src/transpile.rs` for fixed-width opcodes such as `RETURN` and `CALLDATACOPY`. PR #24119 is linked as a candidate fix. — [aztec-packages#24115](https://github.com/AztecProtocol/aztec-packages/issues/24115)
- **aztec-packages#16948 (open, 2025-09-11, label "security").** The AVM does not fail on scalar multiplication of an invalid non-infinite point (0,0), while Brillig fails. Found by the simulator fuzzer. — [aztec-packages#16948](https://github.com/AztecProtocol/aztec-packages/issues/16948)
- Related AVM-vs-Brillig divergences from the same fuzzer:
  - #17182: AVM doesn't fail on `to_le_radix` (closed 2025-11)
  - #16944: AVM doesn't fail on dead `shl` (closed 2026-02)
  - #17183: AVM fails to return an array of size 60480 (open)
  - #15572: open request, "Fuzz AVM simulation of opcodes against brillig vm implementation"
  — [issue search results](https://github.com/AztecProtocol/aztec-packages/issues/17183)
- **aztec-packages#24075 (closed 2026-06-19).** `aztec compile` silently **skipped AVM transpilation** when nargo artifacts already existed. — [link](https://github.com/AztecProtocol/aztec-packages/issues/24075)
- **aztec-packages#21518 (2026-03-13).** Four AVM *simulator* correctness issues from audit items 168/172/173/174, including an `ExternalCall` constructor with swapped parameter order vs wire format and shallow-copied DB checkpoints across forks. — [aztec-packages#21518](https://github.com/AztecProtocol/aztec-packages/issues/21518)

**Fuzzing gap (key finding)**
- Noir PR #13764 was merged 2026-09-18. The `brillig` target of `ssa_fuzzer` "compares Noir's Brillig VM against an external VM reached through two binaries" (`TRANSPILER_BIN_PATH`, `SIMULATOR_BIN_PATH`). It was broken on two counts:
  - The simulator coverage protocol was deleted in Dec 2025.
  - A corpus codec bug from Jan 2026 made "every mutated case... the empty default".
  "Nothing runs this" in CI, so the breakage went unnoticed for about 9 months. The PR recommends rebuilding Brillig↔AVM inside `barretenberg/cpp/src/barretenberg/avm_fuzzer`. — [noir#13764](https://github.com/noir-lang/noir/pull/13764)
- Noir PR #13766 (2026-09-18) removed the whole SSA fuzzer. The AST fuzzer (modes `acir_vs_brillig`, `orig_vs_morph`, `min_vs_full`, `pass_vs_prev`, …) is now the only one. The PR notes that ACIR and the Brillig VM "dispatch blackboxes through the same implementation", so ACIR-vs-Brillig cannot find blackbox bugs, and the AST fuzzer does not yet emit blackbox calls. — [noir#13766](https://github.com/noir-lang/noir/pull/13766)

### Inferences
- **Threat model nuance (inference).** A Brillig *miscompilation* in a public function is not a proof forgery. Validators re-execute the same (wrong) bytecode and the AVM circuit faithfully proves it, so everyone agrees on the wrong semantics. This makes it a contract-correctness bug, comparable to a solc miscompile, and exploitable only when it produces attacker-favourable behaviour such as a skipped balance check.
- **The real forgery surfaces are narrower:**
  - (a) AVM **circuit** vs AVM **simulator** divergence. The circuit accepts a trace the simulator/validators would reject, or the reverse.
  - (b) Transpiler bugs that differ between the proving path and the re-execution path. Both use the same transpiled bytecode, so this is also mostly a correctness bug.
  - (c) Error-semantics divergences such as #16948, where Brillig reverts but the AVM succeeds. Contract authors test with the Noir/Brillig semantics, but mainnet executes the AVM semantics.
- **Why Noir's "Moderate" ratings are misleading here (inference).** The Brillig advisory list shows Noir rates Brillig miscompiles as Moderate because unconstrained code is supposed to be checked by constraints. In Aztec public functions nothing re-checks Brillig outputs. Each such advisory is effectively a "public-function semantics" bug. Nobody appears to have publicly re-assessed these advisories against Aztec public functions.
- **Where to look first (inference).** The dead Brillig↔AVM differential (Sep 2025 → Sep 2026), the open u16 address truncation, and the unfinished AVM audits together make Brillig→AVM the least-covered layer with the largest blast radius.

### Concrete testing ideas
1. **Three-way differential per program:** Brillig VM (nargo `unconstrained` main) vs AVM VM2 simulation of the transpiled bytecode vs `vm2` check-circuit on the produced trace.
   - Reuse the researcher's own generator and the Noir AST fuzzer to generate `unconstrained fn main` programs. Wrap them into a minimal Aztec contract public function, or feed the transpiler a raw Brillig artifact.
   - Oracle: equal return data **and** equal revert/no-revert status. Then run a circuit check that the simulator trace satisfies the AVM circuit, and a mutated-trace negative test.
2. **Targeted transpiler stress** (see [aztec-packages#24115](https://github.com/AztecProtocol/aztec-packages/issues/24115) for the class):
   - programs that push Brillig stack/heap addresses above 2^16, such as large arrays or deep recursion;
   - large returns (#17183);
   - blackboxes with invalid inputs: invalid EC points, `to_radix` edge cases, zero-size arrays.
3. **Replay Noir's Brillig GHSA PoCs through the transpiler + AVM** to classify them as "affects Aztec public functions". This is cheap and high-signal, and could produce an advisory-quality write-up.
4. **Tag and range semantics:** check that transpiled code preserves Noir integer-width semantics. AVM memory is tagged, and truncation/cast opcodes may map differently. Test `as` casts, wrapping ops, and u128/i128 div/mod (compare GHSA-2v53).

### Gaps
- The component behind the V4 (Mar 2026) and V5 (Jul 2026) critical vulnerabilities was not disclosed in the snippets I could read, and the Aztec blog was blocked. It is unknown whether either was AVM-related.
- It is unconfirmed whether public functions are live on Aztec mainnet/alpha with AVM proving enforced, or only re-executed. The "Training Wheel" language suggests re-execution is the primary safety net.
- No public AVM audit report was found. There was also no confirmation that avm_fuzzer currently runs Brillig↔AVM differentials.
- The fix status of PR #24119 is unknown.

---

## Q2. Recursion and proof aggregation from Noir (`std::verify_proof`, Honk recursion, pairing points, vk binding)

### Takeaway
Recursive verification is lowered to a single `RecursiveAggregation` blackbox that bb expands. Historical and recent issues show the recurring pitfalls:
- vk not bound;
- predicates not applied to `verify_proof` in conditionals;
- `key_hash` being ignored and then removed;
- pairing-point object handling still open in Aztec.

The researcher's ACIR scanner currently treats blackboxes as deterministic functions, which is **not** a valid model for `RecursiveAggregation`: its "output" is a deferred pairing check.

### Cited Findings
- **#3092 (2023, closed).** "Recursive verifier is bogus - prover creates a proof on ANY verification key". This is the historical precedent for vk-binding failures. — [noir#3092](https://github.com/noir-lang/noir/issues/3092)
- **#5805 (2024, closed).** A user reports that `bb verify` accepts a proof against the vk of a *different* program (nargo 0.31 / bb 0.41). — [noir#5805](https://github.com/noir-lang/noir/issues/5805)
- **#8998 (opened 2025-06-23, closed 2025-10-14).** "Predicates are not applied to `RecursiveAggregation` blackbox function". A `verify_proof` inside an `if` "is equivalent to running it unconditionally". Proposed fixes: proof-system-agnostic predicate handling, or erroring on conditional `verify_proof`. — [noir#8998](https://github.com/noir-lang/noir/issues/8998)
  - *Note:* the summarizer labelled this "soundness high". As described (verification enforced even when disabled), it is primarily a **completeness** issue. It becomes soundness-relevant only if a later "fix" drops the check under a predicate the prover controls.
- **#8093 (closed 2026-08-25).** "Remove `key_hash` argument from `RecursiveAggregation`". The body says "UltraHonk now seems to disregard the key hash entirely", and that vk hashing should be done in-circuit. — [noir#8093](https://github.com/noir-lang/noir/issues/8093)
- **aztec-packages#13188 (open since 2025-03-31).** "Proper handling of the pairing point object in yarn-project". **aztec-packages#16716 (open):** "Remove code unsetting free witness Origin Tag in VK Commitments in AVM Recursive Verification". — [#13188](https://github.com/AztecProtocol/aztec-packages/issues/13188), [#16716](https://github.com/AztecProtocol/aztec-packages/issues/16716)
- **aztec-packages#14431 (closed 2025-05-21).** "bb outputs the same vkey for different ACIR bytecode inputs". — [link](https://github.com/AztecProtocol/aztec-packages/issues/14431)
- **#11248 (closed 2026-06-04).** "Update 'Recursive Proofs' documentations", which indicates the API changed recently. — [noir#11248](https://github.com/noir-lang/noir/issues/11248)

### Inferences
- The vk hash was removed as a separate argument (#8093). The *user circuit* is therefore responsible for binding the vk to an expected constant or hash. Noir programs that take `verification_key` as a private input without asserting it against a constant are under-constrained **by design**. The "which circuit was verified?" question is a classic application-level bug that the researcher's scanner could flag.
- Pairing points or the aggregation object must be propagated to the public outputs and checked by the final verifier. If a Noir circuit (or its bb lowering) drops them, the inner proof is never actually checked. aztec-packages#13188 shows this is still being worked on in 2025–26.

### Concrete testing ideas
1. **Mutation oracle for recursion:** for a recursive circuit, flip one element of the proof, vk, or inner public inputs, and require that witness generation + `bb prove` + `bb verify` of the outer proof **fails**. Any success is a soundness bug. Include `verify_proof` inside `if` with predicate 0/1 (regression for #8998).
2. **Scanner extension:** model the `RecursiveAggregation` outputs (pairing-point witnesses) as "must reach public outputs". Flag circuits where the `verification_key` witness is not fixed or constrained to a constant or hash, and where inner `public_inputs` are not connected to outer public inputs or asserted.
3. **VK-uniqueness test:** compile N distinct ACIR programs and assert pairwise-distinct vks (regression class for aztec-packages#14431).

### Gaps
- Current Noir recursion doc text could not be retrieved (noir-lang.org blocked; the docs path 404'd on GitHub).
- No 2026 bb recursion-soundness advisory found. The fixing PR for #8998 was not identified.

---

## Q3. Multi-circuit programs (`#[fold]`, `Opcode::Call`) and databus (`call_data` / `return_data`)

### Takeaway
Both are niche and lightly used outside Aztec. The databus has had a steady stream of crash and semantics issues through 2025–Jan 2026, including a silent-drop bug. `#[fold]`/`Opcode::Call` has several open predicate-related issues. The researcher's scanner itself marks `Opcode::Call` unsupported, which is a known blind spot.

### Cited Findings
- **#10653 (closed 2026-06-01 via PR #10682, milestone "Group 3 Audited - Internal").** `call_data`/`return_data` used in non-`main` functions were **silently stripped** from the final SSA instead of rejected. Related issues: #10425 and #10794 (Nov–Dec 2025). — [noir#10653](https://github.com/noir-lang/noir/issues/10653)
- Other databus bugs:
  - #11319 (compiler crash returning directly from calldata, closed 2026-01-29)
  - #9984 ("constant_folding: potential bug when mapping data_bus", closed 2025-11-03)
  - #8913 ("call_data and return_data generate invalid SSA", 2025-07)
  - #8451 (call_data + empty arrays)
  — [noir#9984](https://github.com/noir-lang/noir/issues/9984), [noir#8913](https://github.com/noir-lang/noir/issues/8913)
- Open predicate issues around calls:
  - #8387: "`Instruction::requires_acir_gen_predicate` incorrectly reports pure function calls as not requiring a predicate" (open since 2025-05)
  - #11317: "`#[no_predicates]` function inlining is forced if the called function is simple…" (open, 2026-01)
  - #10820: recursive ACIR call gives an opaque inlining error (open)
  — [noir#8387](https://github.com/noir-lang/noir/issues/8387), [noir#11317](https://github.com/noir-lang/noir/issues/11317)
- **#9390 (closed 2025-09).** "Inlining ACIR into Brillig can trigger incorrect semantics". — [noir#9390](https://github.com/noir-lang/noir/issues/9390)

### Inferences
- Predicate handling across a `Call` boundary is where under-constraint can hide: a callee's constraints are applied or skipped per call-site predicate. The open #8387 is a direct lead.
- Multi-circuit soundness also depends on how bb/the Aztec kernel links circuits, meaning how the caller's inputs/outputs are bound to the callee's proof. That linkage is outside the ACIR artifact the researcher scans.

### Concrete testing ideas
1. **Fold-vs-inline differential:** for generated programs, compile each helper function with and without `#[fold]` and compare execution results. Then scan both ACIRs with the Picus adapter, after adding `Opcode::Call` support by inlining callee constraints with fresh witnesses under the call predicate. Under-constrained results in the fold version only indicate a bug.
2. **Databus differential:** `main(x: call_data(0) [Field; N]) -> return_data ...` vs the same program with plain `pub` params. Results and scanner verdicts must match.
3. **Predicate probe:** a `#[fold]` function called inside `if c {}` with `c = false` and inputs that would fail. Execution must succeed (completeness), and with `c = true` it must fail (soundness).

### Gaps
- I found no specific bb-side issue on how `#[fold]` circuits are proven or linked outside Aztec's Chonk/ClientIVC, and no 2026 advisory for fold/databus.

---

## Q4. ACVM (partial witness generator) vs backend semantics

### Takeaway
The ACVM only *generates* witnesses. Soundness is determined solely by bb's constraints. ACVM↔bb divergences are therefore mostly completeness issues, *except* where ACVM-side checks give developers false confidence. The tracker shows ongoing ACIR↔Brillig and ACVM-solver divergence reports, and a `check_witness` API was only added in Jan 2026.

### Cited Findings
- **#10849 (closed 2026-01-12).** "Add `check_witness` method to ACVM". #10067 (open) asks for a new `OpcodeResolutionError` for "different values at the same Witness in a WitnessMap". — [noir#10849](https://github.com/noir-lang/noir/issues/10849), [noir#10067](https://github.com/noir-lang/noir/issues/10067)
- **#12636 (open, 2026-05-12, TomAFrench).** An ACIR/Brillig divergence found by `acir_vs_brillig`: a checked u32 subtraction underflow is masked by a later OOB assertion. The two paths report different first failures. — [noir#12636](https://github.com/noir-lang/noir/issues/12636)
- **#12451 (closed 2026-04-28).** "Completeness bug: inconsistency between brillig and ACIR inside a disabled if branch (ACIR rejects valid witness)". — [noir#12451](https://github.com/noir-lang/noir/issues/12451)
- Other solver and blackbox issues:
  - #10074: "ACVM can't solve AssertZero when witness cancels out" (closed 2025-10)
  - #10037: ecdsa verify with predicate=0 solved in ACIR but not Brillig (closed 2026-03)
  - #5638: "ACVM `XOR` associativity test failing" (open since 2024)
  — [noir#10074](https://github.com/noir-lang/noir/issues/10074), [noir#10037](https://github.com/noir-lang/noir/issues/10037), [noir#5638](https://github.com/noir-lang/noir/issues/5638)
- **#12581 (closed 2026-05-07, fix PR #12545).** A soundness bug in the *missing-Brillig-constraints checker* (`build_tainted` over-credits `arr[idx] == x` as constraining all elements), leading to forgeable public output. Affects nargo 1.0.0-beta.20+. This is listed here as context: it is the checker the researcher said to exclude, and it shows that tooling-level false negatives count as "soundness bugs" in Noir's triage. — [noir#12581](https://github.com/noir-lang/noir/issues/12581)

### Inferences
- The researcher's existing pipeline checks *static* under-constraint. A strong, cheap complement is **dynamic witness-perturbation**: take an ACVM-solved witness, perturb one non-input witness, and ask bb `check_circuit` whether it still satisfies. A satisfying perturbation that changes a return value is a concrete counterexample. This validates or refutes scanner `unsafe`/`unknown` results against the *real* bb constraint semantics, including how bb lowers blackboxes, RANGE and memory, which the Picus translation only approximates.
- Divergences in blackbox lowering (ACVM solver vs bb gadget) are the soundness-relevant part. Examples: RANGE widths, AND/XOR widths, `MemoryOp` with predicates, and blackbox predicates (#10037). ACVM is not in the proof, so a gadget in bb that is weaker than ACVM's semantics is a genuine soundness bug.

### Concrete testing ideas
1. **bb-backed perturbation oracle,** as above. Use the new ACVM `check_witness` (#10849) and bb `check_circuit` side by side. Any witness that bb accepts and the ACVM `check_witness` rejects is an ACVM/backend divergence. If it changes an output, it is under-constraint in bb's lowering.
2. **Blackbox-gadget differential:** for each blackbox (ranges at 1/8/32/64/128/253/254 bits, AND/XOR widths, EC ops with invalid points, `to_radix`), solve with ACVM on boundary inputs, then check bb constraints on *adversarial* witnesses produced by your SMT/Picus model.

### Gaps
- No public list of bb-gadget-vs-ACVM soundness divergences in 2026 was found.

---

## Q5. Young frontend features (enums/match, comptime, traits/monomorphization, closures/defunctionalization, `&mut` aliasing, `unconstrained` boundaries, oracles)

### Takeaway
Bug churn in 2026 concentrates in:
- **`&mut`/array aliasing** across Brillig (multiple GHSAs) and comptime;
- **comptime↔runtime** discrepancies (a GHSA plus AST-fuzzer `comptime_vs_brillig_nargo` findings);
- **enums** (-Z enums), mostly crashes and type confusion in monomorphization.

Defunctionalization had an external-audit finding in 2025. Most frontend bugs manifest as crashes or ACIR-vs-Brillig divergences, which the existing AST fuzzer already targets.

### Cited Findings
- **`&mut` and aliasing:** GHSA-v2q4-prvf-7h73 (conditional `&mut` assignment, 2026-06-09), GHSA-35h6-769r-84c9 (array aliasing), GHSA-mfqg-6wvq-m7mr (mutable reference handling), GHSA-43f8-pw4p-5f5g (`&mut bool` array deref comptime vs Brillig), GHSA-fvmx-g2j7-8v59 (arrays of `&mut`). — [advisories](https://github.com/noir-lang/noir/security/advisories)
- **Comptime:**
  - GHSA-3fmx-gqpv-c758 (comptime vs Brillig, mutable arrays in loop, 2026-02-09)
  - #11463 (`noir_ast_fuzzer` `comptime_vs_brillig_nargo` disagreement, closed 2026-02-18)
  - #11451: "Can pass runtime variables to comptime using global lambdas" (closed 2026-02-20). This is a staging-boundary violation.
  - #11617: different behaviour for comptime blocks in statements vs expressions (closed 2026-02-23)
  - #12461: stdlib comptime code has inconsistent return types and behaviour (open)
  — [noir#11451](https://github.com/noir-lang/noir/issues/11451), [noir#11463](https://github.com/noir-lang/noir/issues/11463), [noir#12461](https://github.com/noir-lang/noir/issues/12461)
- **Enums/match:**
  - #13037: "Generic enum compilation problems" (closed 2026-06-23)
  - #11146: "enum with unused const generic monomorphizes with type vs data mismatch" (closed 2026-01-15)
  - #10914: "Pattern matching of struct parameters ignores type" (closed 2025-12-22)
  - #7637: unreachable-match warning for a reachable match (closed 2026-06-26)
  - #10404: cyclic enums not detected (open)
  - #7636: mutable enums can't be passed to unconstrained (open)
  — [noir#13037](https://github.com/noir-lang/noir/issues/13037), [noir#11146](https://github.com/noir-lang/noir/issues/11146), [noir#10914](https://github.com/noir-lang/noir/issues/10914)
- **Defunctionalization (Veridise audit finding, #8897, closed 2025-06-13).** With self-recursive calls taking function-typed args, the apply function is looked up with the post-mutation signature. "Dynamic dispatches involving self-recursive functions… will be compiled to instructions with the wrong semantics." — [noir#8897](https://github.com/noir-lang/noir/issues/8897)
- **Audits:** Noir issues carry milestones such as "Group 3 Audited - Internal" (e.g., #10653), and #8897 cites a Veridise AuditHub finding. That indicates at least one external (Veridise) compiler audit in 2025 plus internal audit groups. I found no public 2026 Noir compiler audit report. — [noir#10653](https://github.com/noir-lang/noir/issues/10653), [noir#8897](https://github.com/noir-lang/noir/issues/8897); [Veridise fireside chat with Aztec's Michael Klein on Noir security, May 2026](https://veridise.com/blog/audit-insights/fireside-chat-with-michael-klein-inside-noir-aztecs-zk-language-security-and-tools-explained/)

### Inferences
- Enum `match` lowering is a decision tree over tag fields. When an enum is a **`main` input**, the tag's range is a nominal invariant not enforced by the ABI-to-ACIR layer (see Q6). A tag outside the variant set could fall into a default or last-branch arm. This is a concrete soundness hypothesis to test. It is untested by me.
- Frontend bugs mostly produce *miscompilations*, which the researcher's differential fuzzers already cover. The unexplored angle is frontend **invariant-lowering**: whether type-level guarantees such as enum tag validity, `BoundedVec` length, and `u1`/bool domain survive to constraints.

### Concrete testing ideas
1. **Enum-tag oracle:** `fn main(e: MyEnum) -> pub Field { match e { A => 1, B(x) => x, C => 3 } }`. Use the Picus scanner with a fixed witness set that excludes the tag's validity. Ask whether a tag value outside {0,1,2} yields a satisfying witness, and whether two distinct outputs exist for the same "semantic" input.
2. **Metamorphic match↔if-chain:** rewrite `match` to equivalent `if` chains and compare ACIR/Brillig results. Do the same for closures to explicit dispatch (defunctionalization) and for generic to hand-monomorphized code.
3. **Staging-boundary probes** (the #11451 class): generate programs that leak runtime values into comptime via globals, lambdas or traits, and assert a compile error.

### Gaps
- I could not verify the specific `&mut`/array aliasing fixes #13514/#13520/#13524/#13525 cited by the researcher. Web search did not surface them.
- The -Z enums stabilization status as of Sep 2026 is unconfirmed.

---

## Q6. The ABI boundary: type invariants not enforced at `main` (BoundedVec, bool/u1, signed ints, strings, enums, nested structs)

### Takeaway
Noir's ABI encoder and ACIR input handling range-constrain **primitive** numeric inputs (bit widths, bool), but not **nominal refinements**:
- `BoundedVec.len ≤ MaxLen`;
- enum tags;
- struct-level invariants.

This is acknowledged in the **open** noir#13188 (2026-06-26), a proposal for a `Validate` trait with auto-validation of `main` params. Brillig entry points accept out-of-domain primitives entirely. That was closed "not planned" because the ABI layer normally validates, which matters for any raw-witness or non-nargo caller, and plausibly for Aztec public-function calldata.

### Cited Findings
- **noir#13188 (open, opened 2026-06-26 by aakoshh).** "`Validate` trait + `#[derive(Validate)]` for structural validation of circuit inputs".
  - Problem statement: "A value crossing the nondeterministic → constrained boundary can violate an invariant the circuit then assumes", e.g. `BoundedVec` arriving at `main` with `len > MaxLen`. Existing checks validate bit-widths and scalar domains but miss nominal refinements such as length bounds or enum tags.
  - Proposal: auto-validate `main` params; opt-in validation of unconstrained outputs; a lint for boundary inputs lacking `Validate`.
  - Depends on #13186 and #13187, refines #4218, supersedes stale #7520.
  — [noir#13188](https://github.com/noir-lang/noir/issues/13188)
- **noir#13191 (closed "not planned", 2026-07-22).** "Brillig entry points accept out-of-domain primitive inputs (e.g. `bool` ∉ {0,1}) that ACIR rejects".
  - ACIR's `add_numeric_input_var` range-constrains numeric inputs. Brillig has no equivalent, so `bool = 2` silently steers `if x`.
  - Scope: raw `WitnessMap` calldata only. `nargo execute` goes through ABI parsing, and oracle returns are already checked.
  — [noir#13191](https://github.com/noir-lang/noir/issues/13191)
- Historical ABI integer-range bugs:
  - #7304: "8-bit signed integer doesn't have correct range when passed as a `main` parameter" (closed 2025-02-07)
  - #9106: "Signed typed main seems to be returning unsigned values" (closed 2025-07-30)
  - #2623: incorrect range of u128 (2023)
  - #1446: add range constraints for bounded-integer main params (2023)
  - #9142: "Derive an ABI from SSA alone for input validation" (open since 2025-07)
  — [noir#7304](https://github.com/noir-lang/noir/issues/7304), [noir#9106](https://github.com/noir-lang/noir/issues/9106), [noir#9142](https://github.com/noir-lang/noir/issues/9142)

### Inferences
- **What is actually in the circuit (inference).** Only the ACIR input range constraints bind a verifier. The ABI encoder's checks in nargo/noir_js are prover-side conveniences, and a malicious prover bypasses them by constructing the witness directly. So any invariant not in ACIR is prover-controlled:
  - `BoundedVec` len;
  - enum tag;
  - `str<N>` byte validity: strings are byte arrays, and whether each byte is range-constrained to u8 should be checked;
  - struct invariants.
  This is exactly what noir#13188 aims to close, and it is still open.
- **Why BoundedVec is the prime example (inference).** A `BoundedVec` input with `len > MaxLen` interacts with stdlib methods that loop to `MaxLen` and use `i < len` predicates. For example, `len()` used as a count or public output could be forged, and `get_unchecked` paths could misbehave.
- **The Aztec angle (inference, unverified).** Public-function args arrive as raw field calldata to transpiled Brillig/AVM code. Whether aztec-nr macros or the transpiler insert per-type domain checks (bool, u8, enum, BoundedVec) at the public entry point is the direct analogue of #13191. If they don't, `bool = 2` or out-of-range integers in public-function args would violate contract assumptions in a context where no ACIR re-check exists.

### Concrete testing ideas
1. **Scanner "ABI-invariant" mode.** For each `main` parameter type from the ABI JSON (the researcher already loads artifacts), emit the *intended* type invariants as SMT predicates: `len ≤ MaxLen`, `tag ∈ variants`, `bool ∈ {0,1}`, `u8` bytes of `str`, signed range. Then query `exists W: SemACIR(W) ∧ ¬Invariant(inputs)`.
   - SAT means the invariant is not enforced by the circuit.
   - Then run the self-composition query restricted to such witnesses, to find **observable** impact on public outputs.
   - This is a direct, novel extension of the existing noir-picus-adapter.
2. **Corpus of stdlib types as `main` inputs:** BoundedVec, Option (the `_is_some` flag), U128-style structs, EmbeddedCurvePoint (`is_infinite` flag + on-curve), enums. Build a must-fail oracle: a hand-built witness with the invariant violated should fail `bb check_circuit`.
3. **Aztec public-function calldata fuzz:** call a public function via raw AVM calldata with out-of-domain values (bool=2, u8=256, BoundedVec len>Max) and compare against contract intent.

### Gaps
- No PR implementing noir#13188 was found. Its dependencies #13186 and #13187 were not checked.
- Whether aztec-nr public-function entry points validate argument domains was not verified (Aztec docs blocked).

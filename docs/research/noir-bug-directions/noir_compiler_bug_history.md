# Noir compiler soundness-bug history and landscape (as of 2026-09-29)

Method: primary sources only where possible. (1) The GitHub advisory list for noir-lang/noir (all 6 pages; 55 advisories) plus about 20 individual advisory pages. (2) A shallow clone of `noir-lang/noir` master at `a6fcfd28` (2026-09-29) with 2,500 commits of history, going back to 2025-09-04. From it I mined fix commits, regression tests and fuzzing infrastructure. (3) Issue and milestone pages on GitHub. (4) Web search for bounties and audits. aztec.network, cantina.xyz, immunefi.com, medium.com, nethermind.io and strix.ai were blocked by the egress proxy, so claims from those sites come from search-result snippets only and are marked that way. PR and commit URLs are `https://github.com/noir-lang/noir/pull/<N>`. The PR numbers come from squash-merge commit titles in the clone.

## Q1. Noir GitHub Security Advisories: class, component, fixed version, discoverer

### Takeaway
There are 55 published GHSAs (2025-11 to 2026-06). About 40% are Brillig-only or comptime/Brillig discrepancies. Most of the rest are SSA-pass or ACIR-gen miscompilations: slices and vectors, DIE, mem2reg/alias, LICM purity, constant folding. Only a handful are true "missing constraint" (under-constrained) bugs in ACIR. Those few were found by humans: external researcher dominik-duke, Veridise (Jon Stephens), vfaltings, and the pair stry-tt/franfrandev. No advisory has been published for anything fixed after 2026-06-09, so the Aug–Sep 2026 soundness fixes have no GHSA yet.

### Cited Findings
**Advisory inventory.** The list has 6 pages, 55 advisories. The oldest was published 2025-11-11 (GHSA-r693) and the newest 2026-06-09 (GHSA-v2q4). Publication came in batches: 2025-12-01, 2026-01-15, 2026-03-03, 2026-04-14, 2026-04-20, 2026-05-19 and 2026-06-04/09 — [p1](https://github.com/noir-lang/noir/security/advisories), [p2](https://github.com/noir-lang/noir/security/advisories?page=2), [p3](https://github.com/noir-lang/noir/security/advisories?page=3), [p4](https://github.com/noir-lang/noir/security/advisories?page=4), [p5](https://github.com/noir-lang/noir/security/advisories?page=5), [p6](https://github.com/noir-lang/noir/security/advisories?page=6)

**Advisories whose pages I read** (versions, component and credits are taken from the advisory text):
- **GHSA-cp84-xrj5-49vg.** "Soundness bug allowing proof forgery when casting from Field to u128". Critical. Affected <1.0.0-beta.16, patched in beta.16 (published 2025-12-01). It is an ACIR under-constraint: witnesses with inconsistent values pass verification. Reporter: **dominik-duke** (external). Fix by TomAFrench — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-cp84-xrj5-49vg)
- **GHSA-683h-pgp9-8cq4.** "Constant division of `Field` values potentially leads to omission of truncation instructions". Moderate. The regression was introduced in nightly-2026-03-27 and patched in beta.21 (published 2026-05-07). Casts to unsigned integers inside `if` branches lose their truncation, so invalid witnesses pass `bb` prove/verify. Reporter: **dominik-duke** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-683h-pgp9-8cq4)
- **GHSA-7w64-wfwp-hh3q.** "Arrays may be indexed out-of-bounds". Moderate. Affected ≤beta.18, patched in beta.19. ACIR memory lowering assumed accesses were in bounds; calldata and slices expose values past the declared bounds. Reporter: **vfaltings** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-7w64-wfwp-hh3q)
- **GHSA-rj6g-3r23-hw6x.** "RemoveIfElse incorrectly tracks slice sizes". Critical. Affected ≤beta.17, patched in beta.18. RemoveIfElse assumes the logical slice length equals the backing-array size, then inserts OOB reads when merging conditionally modified slices. Reporter: **vfaltings** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-rj6g-3r23-hw6x)
- **GHSA-h47v-w5hw-q4x3.** "Can pop from an empty slice". Critical. Affected ≤beta.18, patched in beta.19. It is an ACIR under-constraint: `pop_back`/`pop_front`/`remove` lack size checks, so provers can read invalid data or create a negative size. Reporter: **stephensj2** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-h47v-w5hw-q4x3). stephensj2 is Jon Stephens, "CEO of Veridise" — [profile](https://github.com/stephensj2)
- **GHSA-wq62-cp93-4556.** "Unsafe usage of `assert_always_fail`". High. Patched in beta.19. It is an over-constraint (completeness) bug: the assertion ignores the side-effects predicate, in Euclidean division and `pop_back`. Reporter: **stephensj2** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-wq62-cp93-4556)
- **GHSA-7cqc-cj32-3xq2.** "Missing `get_inputs_vec` inputs for AES128Encrypt". High. Patched in beta.16. ACIR blackbox input lists were incomplete, which can trigger unsafe optimisations. Reporter: **stephensj2** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-7cqc-cj32-3xq2)
- **GHSA-x8xh-hm9j-f85p.** "ECDSA blackbox functions incorrectly marked pure". High. Patched in beta.16. LICM hoisted ECDSA calls because `is_pure()` returned true. Finders: **stry-tt, franfrandev** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-x8xh-hm9j-f85p)
- **GHSA-4462-q25g-3fmc.** "Potential stale value from data bus in unrolling pass". Patched in beta.16. It is in the Unrolling/FunctionInserter code. Finders: **stry-tt, franfrandev** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-4462-q25g-3fmc)
- **GHSA-8wpq-5mw8-8j85.** "DIE removes side-effectual div/mod". Patched in beta.16. DIE dropped the trapping `MIN / -1` case. Finders: **stry-tt, franfrandev** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-8wpq-5mw8-8j85)
- **GHSA-9v2p-vwxc-jfh4.** "`as_witness` call gets eliminated when unused but in return data". Patched in beta.19. It is in DIE. Finders: **stry-tt, franfrandev** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-9v2p-vwxc-jfh4)
- **GHSA-24hw-hj99-xgg2.** "Constant folding ignores enable_side_effects predicates". Patched in beta.19. Constant folding forwarded an ArraySet value into an ArrayGet while ignoring the predicate, so the ArrayGet returned the wrong value. Reporter: **stry-tt** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-24hw-hj99-xgg2)
- **GHSA-w58m-gfcx-8pjq.** "Non-dominating RangeCheck removes sibling-branch truncate". Patched in beta.20. The bug is in `remove_truncate_after_range_check` and is **Brillig-only**: `flatten_cfg` skips Brillig functions, and the pass does no dominance check. Reporter: **qedbot** — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-w58m-gfcx-8pjq). The qedbot account links to QED Audit (qedaudit.io, @QED_Audit) — [profile](https://github.com/qedbot)
- **GHSA-2v53-vfw3-w489.** "Signed 128-bit div/mod overflow check is silently bypassed". Patched in beta.21. An off-by-one in `expand_signed_math` (`u128::MAX - 1`). The advisory says the bug is not reachable from source code because i128 is not exposed. Reporter: an independent researcher identified only by an Ethereum address — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-2v53-vfw3-w489)
- **GHSA-j4p3-qjx6-rmvx.** "Load Store Forwarding incorrectly eliminates stores". High. Patched in beta.21. LSF ignores an indirect read through `IfElse`. Credited to Savio-Sou — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-j4p3-qjx6-rmvx)
- **GHSA-v2q4-prvf-7h73.** "Incorrect conditional mutable reference assignment in Brillig". Patched in beta.22. Credited to Savio-Sou — [advisory](https://github.com/noir-lang/noir/security/advisories/GHSA-v2q4-prvf-7h73)

**Remaining advisories** (title, severity and publication date only; the class is my classification from the title):
- Brillig codegen/VM: GHSA-wvh3 (function result mutation), GHSA-qqxj (Brillig constant-folding dedup), GHSA-35h6 (array aliasing), GHSA-mfqg (mutable reference handling), GHSA-jhqf (no-op loops), GHSA-mh2f, GHSA-5pjx (wrong branch taken), GHSA-pw32, GHSA-4wj9, GHSA-7qph, GHSA-fvmx, GHSA-7c3c, GHSA-hjcm (unchecked integer arithmetic in Brillig codegen), GHSA-jj7c (Critical, heap corruption in foreign-call results with nested tuple arrays), GHSA-j54m (Critical, array only used in a while condition not cloned), GHSA-62rj (paired RC elimination), GHSA-jf3m, GHSA-r693, GHSA-wc93 (mutable argument array corruption in Brillig) — [p1](https://github.com/noir-lang/noir/security/advisories)–[p6](https://github.com/noir-lang/noir/security/advisories?page=6)
- SSA memory and alias: GHSA-rh9h (High, repeat/known load eliminated across a call that mutates via an indirect reference), GHSA-pgh4 (DIE removes Stores with references), GHSA-ghvp (High, mem2reg `handle_terminator` Jmp with unknown alias set), GHSA-fch6 (High, `add_array_aliases` misses nested references in MakeArray, so mem2reg store elimination is unsound). All published 2026-04-14 — [p3](https://github.com/noir-lang/noir/security/advisories?page=3)
- ACIR slices and vectors: GHSA-fjwm (Critical, `convert_slice_pop_back` index), GHSA-qqgg (High, `convert_slice_push_back` doesn't update the length), GHSA-wv86 (Critical, incorrect `element_type_sizes` array), GHSA-jcmw (High, unsafe `read_array`), GHSA-xw6r (conditional `slice_push_back` in ACIR gives an all-zero slice), GHSA-g27f (ICE in `AsSlice`). Mostly published 2026-03-03 — [p4](https://github.com/noir-lang/noir/security/advisories?page=4), [p5](https://github.com/noir-lang/noir/security/advisories?page=5)
- Blackbox side effects and ACVM: GHSA-3878 (`multi_scalar_mul`/`embedded_curve_add` removable despite side effects), GHSA-6j45 (unreachable arm on the identity point in ECDSA verify), GHSA-q37h (MergeOptimizer may produce incorrect code) — [p4](https://github.com/noir-lang/noir/security/advisories?page=4), [p5](https://github.com/noir-lang/noir/security/advisories?page=5)
- Comptime/frontend discrepancies: GHSA-vx9w (tuple element corruption in comptime), GHSA-g6r5 (shift behaviour comptime vs ACIR), GHSA-43f8, GHSA-3fmx, GHSA-h8h7 (comptime vs Brillig), GHSA-959m (Low, `CallGraph::from_ssa` footgun), GHSA-35pp (variable not updated in an inlined loop) — [p1](https://github.com/noir-lang/noir/security/advisories), [p2](https://github.com/noir-lang/noir/security/advisories?page=2), [p5](https://github.com/noir-lang/noir/security/advisories?page=5), [p6](https://github.com/noir-lang/noir/security/advisories?page=6)

**Other context:**
- Release dates (commit date of each tag): beta.15 2025-11-05, beta.16 2025-12-01, beta.18 2026-01-06, beta.19 2026-02-17, beta.20 2026-04-13, beta.21 2026-05-07, beta.22 2026-06-01, beta.26 2026-07-30. Source: `git ls-remote --tags` on [noir-lang/noir](https://github.com/noir-lang/noir/tags)
- A search snippet mentions CVE-2026-41197, "a critical vulnerability in SSA-to-Brillig compilation" in Noir. I could not open the page (strix.ai blocked), so I could not map it to a GHSA — [search result](https://www.strix.ai/cve/CVE-2026-41197)
- The in-repo "entomotaxy" bug list (older, about 2024–mid 2025) records the finding mechanism for each bug:
  - Most SSA and ACIR bugs were found by internal fuzzers: `ast_fuzzer` (@aakoshh) and `ssa_fuzzer` (@defkit).
  - The stdlib soundness bugs (U128, schnorr, radix) were found by manual review (@Rumata888, @defkit).
  - Soundness-typed rows include "Incorrect flattening of CFG" (#7961), "Negative loop bounds skipped" (#8011), "Global array ownership" (#8259) and "Handling array offsets during optimization" (#8262).
  - Source: [security/entomotaxy/Security Bug List.md](https://github.com/noir-lang/noir/blob/master/security/entomotaxy/Security%20Bug%20List.md)

### Inferences
- **Rough class counts over the 55** (from titles plus the pages I read):
  - About 22 Brillig-only codegen/VM bugs.
  - About 6 comptime/frontend discrepancies.
  - About 12 SSA-pass miscompilations that apply to both runtimes: DIE, mem2reg/alias, LSF, LICM purity, constant folding, unrolling data bus.
  - About 10 ACIR slice/vector/array lowering bugs.
  - About 5 blackbox/ACVM bugs.
- **Truly under-constrained ACIR bugs are a small minority.** Clear cases are cp84 (Field→u128 cast), 683h (truncation dropped inside branches), h47v (pop from an empty slice), 7w64 (OOB memory reads) and possibly rj6g, fjwm, qqgg and wv86. All sit at **type-width/truncation boundaries or slice/vector length bookkeeping in ACIR memory**. This matches the Field-as-u128 pattern the researcher rediscovered.
- **Externally found** (non-Noir-team) advisories: dominik-duke (2), Veridise/stephensj2 (3), vfaltings (2; affiliation unknown), stry-tt + franfrandev (5; affiliation unknown, stry-tt's account is empty), QED Audit/qedbot (1), and an anonymous ETH-address researcher (1).
- Savio-Sou is credited on the Brillig and LSF advisories. That account is a Noir team member (it authored the Security Policy PR #10262), so the credit is probably the publisher rather than the finder.
- Anyone rediscovering an already-published class should expect it to be treated as a duplicate.

### Gaps
- I did not open 35 of the 55 advisory pages, so credits and fixed versions for those are missing. Opening each page at `/security/advisories/GHSA-…` would fill them in.
- I could not confirm the affiliations of vfaltings, stry-tt, franfrandev or dominik-duke; search returned nothing.
- CVE-to-GHSA mapping (e.g. CVE-2026-41197) is unverified.

## Q2. Recent (2025 to Sep 2026) soundness fixes by area, and what "regression_claude_*" means

### Takeaway
Since mid-2026 most compiler fixes come from an internal Claude-driven pipeline, "ClaudeBox". It runs as the `AztecBot` account and files issues in a private tracker, `noir-lang/noir-claude`, referenced as `noir-claude#N` with N up to at least 1844. The `regression_claude_*` / `regression_noir_claude_*` / `regression_ncNNNN` tests are its regression tests. The hottest areas by fix count are Brillig IR/gen, constant folding, ACIR call/array lowering, unrolling, the SSA interpreter, LICM and mem2reg. The Aug–Sep 2026 wave clusters around **LICM/unrolling induction-bound inference**, **alias analysis for constant-folding caches**, **predicated/zero-width array ops in acir_gen**, and **ownership/RC clone elision**.

### Cited Findings
**What `noir-claude` and ClaudeBox are:**
- Test comments cite a separate tracker. Examples: "Regression test for noir-lang/noir-claude#1640: LICM applied the `while` loop's induction bounds to the sibling `for` loop" ([test](https://github.com/noir-lang/noir/blob/master/test_programs/execution_failure/regression_claude_1640/src/main.nr)) and "noir-claude#1654 … ACIR gen resolved the safe-index read on the taken branch as a disabled access … a prover could satisfy a circuit whose source rejects the same witness" ([test](https://github.com/noir-lang/noir/blob/master/test_programs/execution_failure/regression_claude_1654/src/main.nr))
- The clone has 52 distinct `noir-claude#N` references, ranging from #102 to #1844. They sit in `ssa/opt/{loop_invariant,unrolling,constant_folding,pure,evaluate_static_assert…,load_store_forwarding}.rs`, `ssa/validation/rc_invariant/call.rs`, the frontend tests, the formatter and the AST fuzzer. One comment in `acvm/src/compiler/validator.rs:1013` calls noir-claude#502 an "audit finding". Another, in `loop_invariant.rs:3380`, says noir-claude#244 was "found by the AST fuzzer `pass_vs_prev`" — [repo](https://github.com/noir-lang/noir/tree/master/compiler/noirc_evaluator/src/ssa/opt)
- The nightly fuzz workflow dispatches a "ClaudeBox" session (Slack thread plus Claude session) on failure ([nightly-fuzz-test.yml](https://github.com/noir-lang/noir/blob/master/.github/workflows/nightly-fuzz-test.yml), [claudebox-dispatch action](https://github.com/noir-lang/noir/tree/master/.github/actions/claudebox-dispatch)). Added by "chore: hand nightly fuzz failures straight to ClaudeBox" on 2026-08-03 — [PR #13442](https://github.com/noir-lang/noir/pull/13442)
- AztecBot opens GitHub issues labelled `claudebox`. Examples: #13472 "AST fuzzer cannot generate arrays with non-homogeneous element types, hiding a class of acir_gen predication bugs" (Aug 6, closed) and #13358 "Elaborator: casting a negative integer literal truncates differently than casting a signed variable" (open) — [label search](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20label%3Aclaudebox)
- Commit "fix(acir): add defensive checks from security audit (#13006)" (2026-06-11, jfecher) carries the trailer `Co-authored-by: Claude Fable 5 <noreply@anthropic.com>` — [PR #13006](https://github.com/noir-lang/noir/pull/13006)
- "Aztec Bot"-authored `fix` commits per month: 0 through Feb 2026, then 4 (Mar), 6 (Apr), 10 (May), 23 (Jun), 18 (Jul), 19 (Aug) and **56 of 61** in Sep 2026. Total `fix` commits: 33 (Sep 2025) → 114 (Jan 2026) → 144 (Jun 2026) → 61 (Sep 2026) — git log of [noir-lang/noir master](https://github.com/noir-lang/noir/commits/master)
- Aztec says the Alpha V5 proving-system vulnerability (a forged-proof class) was found on 27 July 2026 "through internal AI-assisted auditing", and that "contributors continue AI-assisted auditing". This is a search snippet only; the page was blocked, and it concerns the Aztec proving system, not necessarily the Noir compiler — [Aztec blog](https://aztec.network/blog/alpha-v5-proving-system-vulnerability)

**Files touched most by fix commits, 2025-09 to 2026-09** (tests and snapshots excluded; counted with git log): `brillig/brillig_ir/*` 44, `brillig/brillig_gen/*` 41, `ssa/opt/constant_folding/*` 37, `acir/call/*` 32, `acir/arrays.rs` 30, `ssa/opt/unrolling.rs` 26, `ssa/interpreter/mod.rs` 26, `ssa/opt/loop_invariant.rs` 23 (+13 in `loop_invariant/*`), `acir/acir_context/*` 23, `ssa/ssa_gen/mod.rs` 22, `ssa/opt/mem2reg.rs` 21, `remove_unreachable_instructions.rs` 12, `remove_if_else.rs`/`load_store_forwarding.rs`/`die.rs` 11 each, `simplify_cfg.rs` 8, `pure.rs` 7, `defunctionalize.rs` 6, `remove_enable_side_effects.rs`/`flatten_cfg.rs`/`alias_analysis.rs` 5 each, `remove_bit_shifts.rs`/`expand_signed_math.rs` 4 each — [evaluator tree](https://github.com/noir-lang/noir/tree/master/compiler/noirc_evaluator/src)

**Fixes from May to Sep 2026 relevant to constrained (ACIR) soundness** (titles verbatim, PR numbers linked):
- LICM and loop bounds:
  - #12797 "fix(licm): only apply to ascending loops" (May 29)
  - #12969 "guard Div/Mod hoist against inverted induction-variable bounds" (Jun 9)
  - #12981 "don't use loop bounds as a value range for non-unit-step != loops" (Jun 10)
  - #13057 "incorrect empty-loop condition for `!=` loops" (Jun 19)
  - #13481 "scope LICM outer induction bounds to nested loops" (Aug 11)
  - #13754 "only derive loop bounds from a header guard that exits the loop" (Sep 16, = noir-claude#1844, which also affects `static_assert` evaluation)
  - Links: [#12797](https://github.com/noir-lang/noir/pull/12797), [#13481](https://github.com/noir-lang/noir/pull/13481), [#13754](https://github.com/noir-lang/noir/pull/13754)
- acir_gen arrays and predicates:
  - #13444 "fold array reads at an index only ACIR gen knows is constant" (Aug 6)
  - #13462 "array_index_needs_explicit_oob_check must consider flattened size" (Aug 19)
  - #13486 "do not resolve a safe-index array read as a disabled access" (Aug 10)
  - #13501 "guard empty vector pop/remove on the semantic length" (Aug 19)
  - #13541 "emit an unsatisfiable constraint for unreachable terminators" (Aug 20)
  - #13546/#13547 zero-width `array_set` block init and aliasing (Aug 20)
  - #13776 "attach the logical OOB payload whenever the memory-op index is scaled" (Sep 22)
  - Links: [#13462](https://github.com/noir-lang/noir/pull/13462), [#13486](https://github.com/noir-lang/noir/pull/13486), [#13541](https://github.com/noir-lang/noir/pull/13541)
- Range, truncation and arithmetic:
  - #12826 "truncate signed-to-signed narrowing cast constants" (Jun 18)
  - #12982 "keep checked overflow check when simplifying +0/-0/*1 on unfit operands" (Jun 10)
  - #13130 "fix(acvm): treat Opcode::Call as a side-effect boundary in RangeOptimizer" (Jun 22)
  - #13269 "range check removal unchecked acir" (Jul 13)
  - #13343 "don't trust the static type of a `u1` unchecked mul in ACIR bit bounds" (Jul 29)
  - #12544 "gate squared-zero constraint decomposition on Field or checked Mul" (Jul 7)
  - #13743 "eval_const_binary executes unchecked ops right away in ACIR" (Sep 16)
  - Links: [#13130](https://github.com/noir-lang/noir/pull/13130), [#13343](https://github.com/noir-lang/noir/pull/13343), [#12544](https://github.com/noir-lang/noir/pull/12544)
- Blackbox lowering: #12658 "check that msm and embedded_curve_add points are all or nothing" (Jun 1), #12885 "retain MSM scalar limb range checks for constant infinity points" (Jun 3), #13512 "enforce all-or-nothing scalar limbs in MultiScalarMul" (Aug 12), #12795 "require recursive aggregation operands in validate_witness" (May 26), #12975 "correct transposed sha256_compression constant-fold bindings" (Jun 10) — [#12885](https://github.com/noir-lang/noir/pull/12885), [#13512](https://github.com/noir-lang/noir/pull/13512)
- Alias analysis and constant folding caches: #13040 LSF re-insertion with a frozen AliasAnalysis (Jun 15), #13695/#13697/#13701 invalidating constant folding's array cache via alias chains (Sep 14–15), #13759 "`may_reference` must walk `points_to`" (Sep 17), #13789 "do not derive must-alias allocation sites through memory" (Sep 25) — [#13701](https://github.com/noir-lang/noir/pull/13701), [#13789](https://github.com/noir-lang/noir/pull/13789)
- Ownership and RC (mostly Brillig): #13446, #13520, #13524, #13781 "compute moves with backward liveness" (Sep 25) — [#13781](https://github.com/noir-lang/noir/pull/13781)
- The researcher's three August bugs appear to match noir-claude items. #13481 matches `regression_claude_1640` (LICM applied sibling-loop induction bounds). #13486 matches `regression_claude_1654` (safe-index read treated as a disabled access in ACIR) — [1640 test](https://github.com/noir-lang/noir/blob/master/test_programs/execution_failure/regression_claude_1640/src/main.nr), [1654 test](https://github.com/noir-lang/noir/blob/master/test_programs/execution_success/regression_claude_1654/src/main.nr)

### Inferences
- `noir-lang/noir-claude` is a private issue tracker. It is fed by an AI-driven audit/triage process (ClaudeBox) run by the Noir/Aztec team. Its numbering, 1800+ issues by Sep 2026, implies a very high volume of machine-generated findings. Some come from the AST fuzzer (#244), some are labelled "audit findings" (#502), and the rest come from code review by the agent.
- I found no evidence of Anthropic itself running the campaign. The trailers name Claude models as co-authors of Aztec's own PRs.
- Most recent fixes are **miscompilations of range/bounds reasoning** (LICM, `static_assert` evaluation, checked→unchecked) and **acir_gen array/predicate plumbing**. They are not missing-constraint bugs in hand-written gadgets. This matches the researcher's observation.
- Several fix titles show the right semantics being produced but with a *fixed wrong value*. #13486 is an example: the read was bound to constant 0. This is invisible to a uniqueness query.

### Gaps
- The noir-claude tracker is private, so the ratio of soundness to completeness issues in it is unknown.
- I could not read PR bodies. The squash commits are terse, so discoverer and tool per fix are unknown for most PRs.

## Q3. Open soundness-relevant issues and what the team considers under-tested

### Takeaway
Few open issues are explicitly tagged soundness: #13360, #13188 and #6793. The biggest open design gap is **invariant validation at the nondeterministic→constrained boundary** (#13188). The team is also openly cycling through audit "Groups". Group 11 (SSA optimisation and Brillig gen) is still in internal audit, and the External-2 audits of the elaborator and Groups 9/10 have no filed issues yet.

### Cited Findings
- **#13188** (aakoshh, 2026-06-26, open): "`Validate` trait + `#[derive(Validate)]`". It states that a `BoundedVec<T, MaxLen>` reaching `main` with `len > MaxLen` breaks methods that assume `len <= MaxLen`. The ABI layer checks bit widths and ACIR enforces ranges, but neither checks "nominal refinements", which is exploitable by feeding a raw `WitnessMap`. The proposal is an auto-validation compiler pass for `main` params. It depends on #13186 and #13187 — [issue](https://github.com/noir-lang/noir/issues/13188)
- Open issues matching "soundness": #13360 (AztecBot, `claudebox`: `mark_type_as_used` and the visibility lint don't recurse through all Type variants), #13188, and #6793 (jfecher, 2024-12-12: "Brillig function call isn't properly covered by a manual constraint" in the stdlib) — [search](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20state%3Aopen%20soundness)
- Open #12843 (1sgtpepper, 2026-05-29): "Artifact cache ignores validation policy for skipped Brillig/underconstrained checks" — [search](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20missing%20brillig%20constraints%20check)
- Open `claudebox` issues: #13358 (negative-literal cast truncates differently from casting a signed variable), #13361 (wildcard type error returns a fresh type variable), #13280 (`rc_invariant::array_set` false positive) — [label](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20label%3Aclaudebox)
- Closed #13472 (AztecBot): the AST fuzzer "cannot generate arrays with non-homogeneous element types, hiding a class of acir_gen predication bugs". Follow-ups: feat #13473 (non-homogeneous arrays, Aug 6) and #13490 "generate doomed conditional branches" (Aug 10) — [issue list](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20label%3Aclaudebox), [PR #13490](https://github.com/noir-lang/noir/pull/13490)
- **Audit milestones:**
  - Open: "Group 11 Audited - Internal" (SSA optimisation and Brillig generation, 3 open / 75 closed); "Group 7 & 8 Audited - External 2" (elaborator excluding comptime.rs, 0 issues); "Group 9/10 Audited - External 2" (0 issues); "1.0 – first Minimally Viable Audit candidate" (16 open / 137 closed) — [milestones](https://github.com/noir-lang/noir/milestones?state=all)
  - Closed, internal: Group 0 defunctionalization; Groups 1–2 SSA passes; Group 3 arrays + SSA (9/17); Group 4 SSA optimisations; Group 5 ACIR (25/33); Group 6 Brillig (14/21); Group 7 elaborator (69/79); Group 8 traits; Group 9 comptime (46/47); Group 10 ownership and monomorphization (17/19)
  - Closed, external: "External 1" and "External 2" milestones for Groups 0–6. Examples: G5 Ext-1 21/27, G4 Ext-2 8/17, G3 Ext-2 13/14 — [closed milestones](https://github.com/noir-lang/noir/milestones?state=closed)
- Open bugs in these milestones include #11204 and #11202 (OOM in the monomorphizer; "Group 10 Audited - Internal") and #11057 (stephensj2: "Poseidon2 implementation missing SAFE"; "Group 5 Audited - External 1") — [bug list](https://github.com/noir-lang/noir/issues?q=is%3Aissue%20state%3Aopen%20label%3Abug%20sort%3Acreated-desc)
- SECURITY.md: "Noir is not fully audited and is not recommended for use in production", and no version is supported — [SECURITY.md](https://github.com/noir-lang/noir/blob/master/SECURITY.md)

### Inferences
- The G5 (ACIR) External-1 milestone contains stephensj2's issue, and stephensj2 filed three ACIR advisories. So Veridise is likely the "External 1" auditor for at least Group 5. This is not confirmed.
- Areas that are least audited or newest, and so candidates:
  - Anything added after the Group-N freezes: `brillig_function_specialization`, `array_set_window_optimization`, `lower_refs_at_acir_brillig_boundary`, `black_box_bypass`, `check_u128_mul_overflow` and the new `mem2reg` "simpler" pass (#11500, Mar 2026). These are pass names in `ssa/opt/`.
  - Group 11 (SSA opt + Brillig gen), still internal-only.
  - Validation at the ABI/`main` boundary (#13188).
- Pass file list: [ssa/opt](https://github.com/noir-lang/noir/tree/master/compiler/noirc_evaluator/src/ssa/opt)

### Gaps
- There is no GitHub label for "soundness", so the search is text-based and may miss issues.
- I did not enumerate all open issues with the `ssa`/`acir` labels.

## Q4. Noir's fuzzing infrastructure and published external audits

### Takeaway
Noir's fuzzing is now **only the AST fuzzer**. The SSA fuzzer was deleted on 2026-09-18. The AST fuzzer's oracles are all *differential execution*: ACIR vs Brillig, pass vs previous pass, minimal vs full pipeline, metamorphic, comptime vs Brillig. They catch miscompilation and crashes, **not** under-constraint. It also disables the under-constrained checks while fuzzing. Named external auditors appear only through advisory credits (Veridise, QED Audit). I found no public Noir-compiler audit report.

### Cited Findings
- **AST fuzzer targets:** `acir_vs_brillig`, `comptime_vs_brillig_direct`, `comptime_vs_brillig_nargo`, `fmt_line_comments`, `min_vs_full`, `orig_vs_morph`, `pass_vs_prev`, `valid_after_pass`. It generates random monomorphized ASTs and compares execution across strategies — [ast_fuzzer README](https://github.com/noir-lang/noir/blob/master/tooling/ast_fuzzer/README.md), [targets](https://github.com/noir-lang/noir/tree/master/tooling/ast_fuzzer/fuzz/src/targets)
- The fuzz harness comment says "under-constrained and Brillig-constraint checks are skipped" (`tooling/ast_fuzzer/fuzz/src/lib.rs:34`). The comptime comparison sets `skip_underconstrained_check: true` — [fuzz lib](https://github.com/noir-lang/noir/blob/master/tooling/ast_fuzzer/fuzz/src/lib.rs)
- **CI budget:**
  - The nightly job runs at 03:00 with `NOIR_AST_FUZZER_BUDGET_SECS: 1800` (30 min) and an alias-analysis property-test budget of 120 s. On failure it extracts seeds and dispatches ClaudeBox on weekdays — [nightly-fuzz-test.yml](https://github.com/noir-lang/noir/blob/master/.github/workflows/nightly-fuzz-test.yml)
  - Per PR, `fuzz_with_arbtest` runs in a dedicated "Run fuzz tests" job with a 15-min timeout, skipped in the merge queue — [test-rust-workspace.yml](https://github.com/noir-lang/noir/blob/master/.github/workflows/test-rust-workspace.yml)
- **SSA fuzzer removed:** "chore: remove the SSA fuzzer" (#13766, AztecBot, 2026-09-18). The rationale: "Almost everything it does, the AST fuzzer also does…". It "lacked an active runner", and an ACIR-vs-Brillig differential over a hash "compares one implementation with itself". Also removed: the `brillig` ssa_fuzzer target (#13764) and the unused AFL target (#13607) — [PR #13766](https://github.com/noir-lang/noir/pull/13766), [PR #13764](https://github.com/noir-lang/noir/pull/13764)
- Recent AST-fuzzer widening: #13476 "widen AST fuzzer generation and stop first-failure shielding" (Aug 11), #13473, #13490, #13687 (`u128` inputs drawn from the whole range), and #13235 "Validate between SSA passes" (Jul 2) — [PR #13476](https://github.com/noir-lang/noir/pull/13476), [PR #13235](https://github.com/noir-lang/noir/pull/13235)
- `tooling/greybox_fuzzer` is the `nargo fuzz` engine for user programs. Its README recommends `--skip-underconstrained-check` — [greybox_fuzzer](https://github.com/noir-lang/noir/tree/master/tooling/greybox_fuzzer)
- Historical attribution: of the fuzzer-found bugs in the entomotaxy list, about 20 SSA/ACIR bugs are from `ast_fuzzer` (aakoshh) and 4 SSA plus 1 Brillig VM from `ssa_fuzzer` (defkit) — [Security Bug List](https://github.com/noir-lang/noir/blob/master/security/entomotaxy/Security%20Bug%20List.md)
- **External audits:**
  - Nethermind published "Our First Deep Dive into Aztec's Noir Language, What ZK Auditors Learned". The snippet suggests it is about auditing Noir *circuits*, around April 2025; the page was blocked — [Nethermind](https://www.nethermind.io/blog/our-first-deep-dive-into-noir-what-zk-auditors-learned)
  - OpenZeppelin published "A Developer's Guide to Building Safe Noir Circuits" (developer guidance, not a compiler audit) — [OpenZeppelin](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits)
  - Searches for Veridise, zkSecurity, Trail of Bits and OtterSec Noir-compiler audit reports returned nothing specific — [Veridise archive](https://veridise.com/audits-archive/zero-knowledge-security/), [zkSecurity reports](https://reports.zksecurity.xyz/)

### Inferences
- **Blind spot for the researcher's tool:** every automated oracle Noir runs solves the witness with ACVM and compares outputs on one input. A missing constraint on a Brillig-hinted or memory-read witness does not change the executed value, so the fuzzers cannot see it. Under-constraint bugs are therefore found by humans or auditors (dominik-duke, Veridise, vfaltings). A self-composition/Picus approach is complementary to the team's tooling, not redundant with it.
- The loss of the SSA fuzzer (which could build arbitrary SSA, including shapes the frontend cannot emit) is a coverage reduction. It affects SSA shapes unreachable from the AST generator. The team claims those shapes are mostly covered anyway.

### Gaps
- I could not find a public audit report (PDF) for the Noir compiler by any firm, and I could not identify the "External 1/2" auditors beyond the inference above.
- The ClaudeBox/noir-claude process is not publicly documented.

## Q5. Bug bounties, and whether checker (lint) gaps count as security issues

### Takeaway
There is no evidence of a current bounty covering the Noir compiler. Aztec's current Cantina bounty (up to $50K) targets rollup contracts and the on-chain Honk verifier. The older $2M Immunefi-era bounty (Aztec Connect era) is historical. Gaps in the Brillig under-constrained checker have been reported as public issues and fixed, but none became a GHSA.

### Cited Findings
- Aztec's Cantina bounty (search snippets only; page blocked): up to $50K. Critical is $10K–$50K (10% of affected funds, $10K floor), High $5K–$10K, Medium $3K, Low $1K. Scope is rollup infrastructure (Rollup.sol, EscapeHatch.sol, Inbox/Outbox/FeeJuicePortal, RewardBooster, Slasher, TallySlashingProposer, FlushRewarder) and **BaseHonkVerifier**. Noir is not mentioned — [Cantina blog](https://cantina.xyz/blog/aztec-network-bug-bounty-on-cantina), [Cantina bounty](https://cantina.xyz/bounties/80e74370-10d8-4e52-8e4b-7294deb7c9ee)
- Historical: "Aztec Network Raises Total Bug Bounty to $2 Million" (Aztec Connect launch era, with Immunefi, up to $1M each for smart-contract and cryptography bugs). A snippet says Noir and Barretenberg were in scope. The date and page were not verifiable because the site was blocked — [Aztec blog](https://aztec.network/blog/aztec-network-raises-total-bug-bounty-to-2-million), [2021 Immunefi tweet](https://x.com/aztecnetwork/status/1404905365813215237)
- Noir's SECURITY.md mentions no bounty; it only says to report privately through a GitHub advisory — [SECURITY.md](https://github.com/noir-lang/noir/blob/master/SECURITY.md)
- **Checker gaps handled publicly:**
  - #12581 "Soundness bug: symbolic runtime witness bug allows malicious prover to forge any public output" (anon-researchers-123, 2026-05-07, on beta.20). `check_for_missing_brillig_constraints::build_tainted` treated `arr[idx]` with a witness `idx` as constraining all the Brillig outputs. It was closed via PR #12545, and no GHSA appears — [issue](https://github.com/noir-lang/noir/issues/12581)
  - #12506 (same reporter): order-dependent false positive, because `constrain_tainted` does a single reverse-post-order pass without a fixpoint. Fixed by #13113 "make missing-Brillig-constraint check order-independent" (2026-07-02) — [issue](https://github.com/noir-lang/noir/issues/12506), [PR #13113](https://github.com/noir-lang/noir/pull/13113)
  - Related refactors: #12008 "Separate the two underconstrained checks" (2026-03-26) and #11945 "Disjoint set data structure in Brillig underconstrained check" (2026-03-25) — [PR #12008](https://github.com/noir-lang/noir/pull/12008)
- The 55-advisory list has no entry about the under-constrained/Brillig-constraint lint — [advisories](https://github.com/noir-lang/noir/security/advisories)

### Inferences
- Checker (lint) false negatives are treated as ordinary bugs: public issue, quick fix, no advisory and no bounty. Codegen soundness bugs (the compiler emits constraints that don't match the source) are what get GHSAs, including Moderate ones.
- A reported checker gap is unlikely to be paid anywhere. A codegen under-constraint in ACIR would get a GHSA with a credit (cp84 was Critical), but there is no confirmed cash bounty for the compiler.

### Gaps
- I could not load the live Cantina, Immunefi or Aztec pages to confirm the current scope and whether Noir or Barretenberg are included, and the date of the "$2 million" post is unverified.
- I did not verify whether anon-researchers-123's #12581 got any bounty or credit.

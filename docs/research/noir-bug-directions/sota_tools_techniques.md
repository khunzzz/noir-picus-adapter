# SOTA (2023 – Sept 2026): automated bug finding for ZK circuits and ZK compilers, and what transfers to Noir/ACIR

Research-method note: arxiv.org, eprint.iacr.org, usenix.org, ndss-symposium.org, veridise.com, zksecurity blog, hackmd and diligence.security were **blocked by the sandbox egress proxy** for full-text fetch. Only raw.githubusercontent.com and the GitHub code-search API were reachable. So most paper-level facts below come from search-engine abstracts/snippets of the primary pages (URLs cited are the primary pages). Repo facts (Circuzz BUGS.md, Picus README, zkp-security-tools README, noir-lang/noir `regression_claude_*` tests) were read directly. Per-paper numbers that only appeared in snippets are marked as such where there is doubt.

---

## Q1. Under-constrained detection tools and their scaling tricks: which ones apply to ACIR?

### Takeaway
The methods that scale for under-constraint detection are: (1) **modular / per-component determinism with pre/post-conditions** (CIVER, which already verified ZisK circuits with 1M–5M+ constraints and explicitly accepts ACIR); (2) **better finite-field solving** (cvc5 Split/BitSplit for bitsums, the 2026 "orchestral" DPLL(T) solver from the CIVER group); (3) **cheap rule-based inference before SMT** (ConsCS inference rules plus a Binary Property Graph; AC4 dispatch by degree); and (4) **fuzzing with mutated witness computation** (zkFuzz, S&P'26), which already has a Noir/Brillig prototype. NAVe (Jan 2026) is the one direct competitor on ACIR+cvc5. It reports range checks as its hardest constraint type, which is the same bottleneck the researcher hit. Its team also found a **soundness bug in cvc5's finite-field split solver** (fixed Feb 2026), so the researcher needs to pin a cvc5 version that includes the fix.

### Cited Findings

**Picus / QED² (PLDI'23) and current Picus**
- Picus implements QED²: it checks uniqueness of signals (under-constraint) in ZKP circuits. Today it supports Circom, R1CS and gnark (`.sr1cs`), not ACIR. CLI options include `--solver cvc4|cvc5|z3` (cvc5 recommended), `--precondition <json>`, `--noprop` (disable propagation), `--nosolve`, `--strong` (strong safety) and `--selector counter|first` — [Picus README (raw GitHub)](https://github.com/Veridise/Picus)
- Veridise docs describe Picus as supporting Circom and other DSLs, "extensible to additional frameworks like Zirgen", with more coverage planned through the **LLZK** framework — [Veridise ZK tool page](https://veridise.com/tools/zk-tool/); [docs.veridise.com/picus](https://docs.veridise.com/picus)
- LLZK is Veridise's open-source ZK-circuit IR ("LLVM, but for ZK"), funded by an EF grant. It sits between DSL frontends and proving backends — [Veridise LLZK announcement](https://veridise.com/blog/veridise-announcements/veridise-secures-ethereum-foundation-grant-to-develop-llzk-a-new-intermediate-representation-ir/)
- The QED² paper is "Automated Detection of Under-Constrained Circuits in Zero-Knowledge Proofs" (PLDI'23) — [ePrint 2023/512](https://eprint.iacr.org/2023/512.pdf); [ACM DL](https://dl.acm.org/doi/abs/10.1145/3591282)

**NAVe (Noir ACIR formal Verifier), arXiv:2601.09372, submitted 14 Jan 2026, The Blockhouse Technology Ltd (TBTL), Oxford**
- NAVe formalizes a subset of ACIR in SMT-LIB and uses cvc5 to check whether Noir programs are properly constrained. It offers two encodings, integer arithmetic and cvc5's finite-field theory — [arXiv abs](https://arxiv.org/abs/2601.09372); [ResearchGate](https://www.researchgate.net/publication/399776888_Formally_Verifying_Noir_Zero_Knowledge_Programs_with_NAVe)
- Evaluated on 4 sets of Noir programs. Findings: constraints induced by opcodes like **range checks can significantly increase verification time**, and the two encodings are **complementary** (some programs are faster in one, some in the other). The tool is open source and "integrated into Nargo" — [arXiv abs / search abstract](https://arxiv.org/abs/2601.09372)
- While testing NAVe, TBTL found and fixed a **soundness bug in cvc5's finite-field split solver** (a misplaced overflow check that could make a verifier wrongly report a ZK program safe). The fix is cvc5 PR #12457, reviewed by Alex Ozdemir and merged into cvc5 main on **27 Feb 2026** — [TBTL HackMD](https://hackmd.io/@tbtl/BJ8ak2W9bl)

**Finite-field SMT improvements**
- "Satisfiability Modulo Finite Fields" (Ozdemir et al., CAV'23): a Gröbner-basis and triangular-decomposition decision procedure in cvc5 — [ePrint 2023/091](https://eprint.iacr.org/2023/091)
- "Split Gröbner Bases for Satisfiability Modulo Finite Fields" (CAV'24, Stanford + Veridise) uses several simpler Gröbner bases instead of one full basis. "BitSplit" is the instantiation optimised for **bitsums**, and it solves bitsum-heavy determinism benchmarks far faster than prior solvers with little overhead elsewhere — [ePrint 2024/572](https://eprint.iacr.org/2024/572); [Veridise blog](https://veridise.com/blog/zero-knowledge/satisfiability-modulo-finite-fields-unlocking-smt-for-zk-verification/)
- An SMT-LIB theory of finite fields (FFA) has been proposed for interoperability (Hader, Ozdemir et al., SMT'24) — [arXiv 2407.21169](https://arxiv.org/html/2407.21169v1)
- "An Effective Orchestral Approach to Satisfiability Modulo Prime Fields" (Isabel, Rodríguez-Carbonell, Rodríguez-Núñez, Rubio; arXiv 2604.26709, Apr 2026) is a DPLL(T) theory solver that orchestrates several modules with different completeness/efficiency trade-offs. Its prototype beats the state of the art on existing benchmarks and on new ones from arithmetic-circuit verification — [arXiv 2604.26709](https://arxiv.org/abs/2604.26709)

**CIVER (COSTA group, UCM Madrid)**
- CIVER verifies **weak safety (determinism)**. Beyond Circom it accepts circuits "given as a constraints system (in R1CS format, PLONK, **ACIR**, …)". It analyses the circuit **modularly** to scale and to localise the faulty part — [COSTA news: CIVER on ZisK](https://costa.fdi.ucm.es/web/news/CIVER_ZisK.html)
- Applied to ZisK recursion/aggregation circuits of **1M to 5M+ constraints**, where "other tools have shown to be unable to handle circuits of this size at once". It found **2 subtle soundness bugs**, identified the problematic components and produced a buggy instance — [COSTA news](https://costa.fdi.ucm.es/web/news/CIVER_ZisK.html)
- Paper: "Scalable Verification of Zero-Knowledge Protocols" (Isabel, Rodríguez-Núñez, Rubio) describes a modular technique based on transformation and deduction rules over polynomial equations in a prime field, using pre/post-conditions per component. It was applied to circomlib — [Semantic Scholar](https://www.semanticscholar.org/paper/Scalable-Verification-of-Zero-Knowledge-Protocols-Isabel-Rodr%C3%ADguez-N%C3%BA%C3%B1ez/886f4010722dd6894d739de38750c204599ecc45); code: [costa-group/circom_civer](https://github.com/costa-group/circom_civer)

**ConsCS (ICSE'25)**
- Three pieces: circuit **inference rules** that shrink the circuit and extract facts, a **Binary Property Graph (BPG)** reasoning engine, and domain-specific guidance for SMT on non-linear constraints. The snippet says this raises the SMT-query success rate "from 2.68%" (target figure not recovered) — [ICSE'25 page](https://conf.researchr.org/details/icse-2025/icse-2025-research-track/189/ConsCS-Effective-and-Efficient-Verification-of-Circom-Circuits); [ACM DL](https://dl.acm.org/doi/10.1109/ICSE55347.2025.00200)

**AC4**
- Models circuits as polynomial systems over finite fields, **classifies them by degree** and applies a specialised method per class. It reports improvements over halo2-analyzer — [arXiv 2403.15676](https://arxiv.org/pdf/2403.15676)

**ZKAP (USENIX Security'24)**
- Uses a **Circuit Dependence Graph (CDG)** abstraction with vulnerability patterns written as queries in a DSL. 9 detectors, 258 Circom circuits, 16.4% false-positive rate, detects over 98.6% of the vulnerabilities, 32 previously unknown vulnerabilities — [USENIX'24](https://www.usenix.org/conference/usenixsecurity24/presentation/wen); [ePrint 2023/190](https://eprint.iacr.org/2023/190)

**ZEQUAL (CAV 2025; Veridise/UT Austin)**
- Verifies **consistency** of Circom templates (constraints ⇔ witness computation) by combining static analysis with deductive verification. Lightweight static reasoning infers pairwise equivalences between array elements to simplify the **product program**, then it infers quantified array invariants. It verifies templates for **any instantiation**, with no manually crafted parameters. Queries go to Z3 over integers — [Springer](https://link.springer.com/chapter/10.1007/978-3-031-98668-0_16); [ePrint 2025/916](https://eprint.iacr.org/2025/916.pdf); [search snippet on Z3/integers](https://www.cs.utexas.edu/~isil/zequal.pdf)

**Coda (refinement types)**
- Coda is a statically typed ZK language with refinement types. It re-implemented 79 Circom circuits, found 6 previously unknown vulnerabilities, and discharges hard field lemmas via Coq plus a tactic library — [arXiv 2304.07648](https://arxiv.org/pdf/2304.07648); [ePrint 2023/547](https://eprint.iacr.org/2023/547)

**Halo2 / PLONKish**
- halo2-analyzer (SMT'23 workshop) uses abstract interpretation plus SMT to find unused gates/columns, assigned-but-unconstrained cells and under-constrained circuits — [ePrint 2023/1051](https://eprint.iacr.org/2023/1051); [Aarhus pure](https://pure.au.dk/portal/da/publications/automated-analysis-of-halo2-circuits/). No source on "Korrekt" was found.

**zkVM / tabular constraint systems (2025–2026)**
- ZIVER (ePrint 2025/2204) gives a circuit-irrelevant semantic model of tabular constraints (gate/lookup/permutation) with **inductive row-indexed reasoning that avoids expanding the full circuit**. It validates SP1 chips — [ePrint 2025/2204](https://eprint.iacr.org/2025/2204)
- "Efficient Branch-and-Bound Testing and Verification of zkVMs" (arXiv 2609.15020, Sept 2026) uses branch-and-bound lattice search with interval splitting over localised constraints to find under/over-constrained bugs — [arXiv 2609.15020](https://arxiv.org/pdf/2609.15020)

**zkFuzz (IEEE S&P'26; Takahashi et al.)**
- Formalises bugs as a **Trace-Constraint Consistency Test (TCCT)**: under-constraint means an invalid trace is accepted, over-constraint means a valid trace is rejected. It mutates the **witness-computation program** (not the constraints), guided by a **min-sum fitness function**, plus tailored input heuristics — [arXiv 2504.11961](https://arxiv.org/abs/2504.11961); [GitHub](https://github.com/Koukyosyumei/zkFuzz)
- On 452 real Circom circuits it found 85 bugs (59 zero-days, 39 confirmed, 14 fixed). Baselines were Circomspect, ZKAP, Picus (Z3 and cvc5) and ConsCS. zkFuzz reports precision 1.00 on several benchmarks, versus higher false-positive rates for Circomspect/ZKAP — [zkFuzz README](https://github.com/Koukyosyumei/zkFuzz); [paper](https://arxiv.org/pdf/2504.11961)
- **Noir prototype**: works on ACIR (constraints) and Brillig (witness computation). The mutation **rewrites the source operand of Brillig `Mov` instructions to read special memory regions that return random, correctly typed values**. This mutates witness computation without touching the constraints. No target selectors are implemented for Noir yet. It re-detected a previously reported real Noir bug. The README says zkFuzz "currently supports Circom" — [paper text via search snippet](https://arxiv.org/pdf/2504.11961); [README](https://github.com/Koukyosyumei/zkFuzz)
- zkCraft (arXiv 2602.00667, 2026) builds on TCCT. It uses R1CS-aware localisation, encodes candidate constraint edits into one "Row-Vortex" polynomial, and uses a "Violation IOP" instead of repeated solver calls. LLMs serve as deterministic mutation-template oracles. Evaluated on Circom only — [arXiv 2602.00667](https://arxiv.org/pdf/2602.00667)

**Other**
- "Sound Debloating of Redundant Checks in ZKML circuits" (arXiv 2609.10149, Sept 2026): up to **48.7% of constraints** in the evaluated ZKML circuits are well-formedness checks (range checks, sign lookups, division-remainder bounds, bit-decomposition validity) — [arXiv 2609.10149](https://arxiv.org/pdf/2609.10149)

### Inferences (applicability to ACIR / noir-picus-adapter)
- **cvc5 version hygiene (urgent).** The adapter's `verified` verdicts use cvc5's FF solver. If the pinned `picus-smt`/cvc5 predates the Feb 27 2026 fix (PR #12457), some UNSAT results may be unsound. Check the cvc5 revision, re-run the corpus's `verified` rows with a fixed cvc5, and cross-check a sample with `--theory nia` / z3. That NAVe found this is a strong signal that cross-encoding/cross-solver checks belong in a publishable pipeline.
- **Bitsum/RANGE bottleneck.** NAVe independently reports that range checks dominate time, matching the adapter's timeouts on bit decompositions. Options:
  - Make sure the cvc5 split solver (`--ff-solver split`, BitSplit) is actually used.
  - Instead of expanding `RANGE(x,n)` into n bits, encode it abstractly as "x in [0,2^n)" plus a **uniqueness lemma**: the bits are unique given x, and x is unique if the bits are. This is sound for the uniqueness query because the bits of a fixed-known x are determined when n < field bits. This generalises the adapter's existing uniqueness-propagation lemmas.
  - Run a portfolio (FF vs NIA) per target, since NAVe reports the encodings are complementary.
- **Modularity à la CIVER.** ACIR is mostly flattened, but modularity boundaries can be recovered from (a) `#[fold]` functions, which stay separate ACIR circuits linked by `Call`; (b) debug-info call stacks mapping opcodes to Noir functions (not in the sanitized artifacts, but available from `nargo compile`); (c) repeated stdlib gadgets (to_le_bits, u64 div/mod, sha/poseidon wrappers), which can be summarised once and reused. A per-gadget determinism summary ("outputs unique given inputs, under precondition P") proven once and then used as an axiom would directly address the 20k-opcode library timeouts. CIVER already claims ACIR input, so it is **both a baseline to compare against and a tool to try directly** on the researcher's large circuits.
- **Pre-SMT inference (ConsCS/AC4).** The adapter's linear fixed-known propagation skips `mul_terms`. ConsCS-style rules (e.g. `x*(x-1)=0` ⇒ boolean; `a*b = 0 ∧ a ≠ 0` patterns; `inv*x = 1` ⇒ inv unique if x fixed) and a boolean/binary property graph could settle many targets without SMT. AC4's degree split suggests sending purely linear cones to a linear-algebra rank check (exact, polynomial time) and only the non-linear remainder to cvc5.
- **Cast-guard false candidates.** Picus's `--precondition` and CIVER's pre/post-conditions are the standard remedy. Encoding Noir ABI type ranges of inputs and known guard idioms as preconditions (and reporting them) could remove false candidates in a principled way.
- **zkFuzz vs the mutation search.** zkFuzz's Noir prototype mutates Brillig `Mov` operands, which is a finer granularity than the adapter's "move hint outputs, re-derive the rest". That may reach states where the honest hint crashes: mutating an intermediate `Mov` can skip the crashing path while outputs stay well-typed. zkFuzz has no Noir target selectors yet; the adapter's static "unpinned" pass and SMT cone could serve as those selectors. That combination looks publishable (see Q5).

### Gaps
- Full NAVe evaluation numbers (circuit sizes, timeouts, which 4 program sets, exact opcode coverage, whether it does self-composition or only specific properties) could not be read because arXiv was blocked.
- The ConsCS "2.68% → X%" figure and its benchmark sizes are not recovered.
- Whether CIVER's ACIR front end is public/maintained, and which ACIR opcodes it supports, is unverified. The only source is the COSTA news page.
- No source found for a tool literally named "Korrekt" or for a later "Picus v2" paper. Whether the orchestral solver is released is unknown.
- zkFuzz's "Bug 13 found in the latest Noir release, independently fixed by developers" appears only in a search snippet. Its precise nature is unknown.

---

## Q2. ZK compiler testing: tools, bug classes, oracles; did any target Noir?

### Takeaway
Four academic compiler/toolchain fuzzers tested **Noir** directly:
- **MTZK** (NDSS'25): ZoKrates, Noir, Cairo, Leo; 21 bugs.
- **Circuzz** (CCS'25): Circom, Corset, gnark, Noir; 16 bugs, 3 in Noir.
- **Liezz** (arXiv Aug 2026, adversarial witness injection): Circom, Corset, gnark, Noir; 13 bugs, 7 with soundness impact.
- **zkFuzz**'s Noir prototype, for circuit bugs rather than compiler bugs.

Their oracles are metamorphic equivalence, cross-backend/cross-stage agreement, and spliced invalid witnesses that must be rejected. In 2026 the largest Noir bug stream seems to come from an **AI-driven internal effort** (`noir-lang/noir-claude` issues, referenced by `regression_claude_*` tests with issue numbers up to ~1721). The bugs it surfaced include SSA-optimisation (LICM) miscompilations in Brillig and ACIR-gen ICEs.

### Cited Findings
- **Circuzz** ("Fuzzing Processing Pipelines for Zero-Knowledge Circuits", Hochrainer, Wüstholz, Christakis et al., **ACM CCS 2025**): the IR **CircIL** plus rewrite rules produce metamorphic circuit pairs. It translates them into each DSL, generates inputs by black-box fuzzing, and flags violations of metamorphic and other correctness oracles. 16 bugs across Circom/Corset/gnark/Noir, 15 fixed — [CCS'25 PDF](https://mariachris.github.io/Pubs/CCS-2025.pdf); [arXiv 2411.02077](https://arxiv.org/pdf/2411.02077)
- Circuzz BUGS.md: circom 5/5/4, corset 4/4/4, gnark 4/4/4, **noir 3/3/3** (reported/confirmed/fixed). The Noir bugs:
  - "Wrong Computation of Assertion" ([noir#5463](https://github.com/noir-lang/noir/issues/5463), fixed by PR #5100)
  - "BB Prover Error in MemBn254CrsFactory" ([noir#6147](https://github.com/noir-lang/noir/issues/6147) / aztec-packages#8745)
  - "Stack Overflow for `lt` with Medium Expression Depth" ([noir#6150](https://github.com/noir-lang/noir/issues/6150), fixed by PR #6180)
  
  Rewrite rules are algebraic/bitwise identities (comm/assoc/distributivity, `a^a→0`, `a|0→a`, `a&a`, `a/b → (1/b)*a`, ...) — [Circuzz BUGS.md](https://github.com/Rigorous-Software-Engineering/circuzz/blob/main/BUGS.md); [rules.json](https://github.com/Rigorous-Software-Engineering/circuzz/blob/main/res/configs/rules/rules.json)
- Circuzz's Noir config only exposes `boundary_input_probability` and `test_iterations`, so Noir testing is shallow compared with the Circom/Corset settings — [Circuzz README](https://github.com/Rigorous-Software-Engineering/circuzz)
- **MTZK** (NDSS 2025, HKUST, Shuai Wang's group): metamorphic relations mutate ZK compiler inputs. Tested **ZoKrates, Noir, Cairo, Leo**; 21 bugs, 15 patched; the paper shows possible exploitations — [NDSS'25 paper page](https://www.ndss-symposium.org/ndss-paper/mtzk-testing-and-exploring-bugs-in-zero-knowledge-zk-compilers/); [PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-530-paper.pdf)
- **Liezz / "Lie to Me: Finding Bugs in ZK DSL Toolchains with Adversarial Witness Injection"** (Watzinger, Hochrainer, Wüstholz, Christakis; arXiv 2608.30648, ~Aug 2026): for each generated deterministic program it runs two public-input assignments with different outputs and **splices** the witnesses (input of one, output of the other). The result is invalid by construction, so acceptance is a soundness bug. Supports Circom, Corset, gnark, Noir. 13 bugs, 7 with soundness impact, 6 exposed by accepted injected witnesses. The bugs span compilers, witness generation, constraint lowering, stdlibs and prover backends. A valid-execution baseline with the same budget found **none** of those soundness failures — [arXiv 2608.30648](https://arxiv.org/abs/2608.30648)
- **Arguzz** (USENIX Security 2026): metamorphic testing plus **fault injection** into zkVMs (mimicking a malicious prover). Tested RISC Zero, Nexus, Jolt, SP1, OpenVM and Pico; 11 bugs in 3 VMs (8 completeness via metamorphic, 3 soundness via fault injection). RISC Zero paid a $50k bounty — [USENIX'26](https://www.usenix.org/conference/usenixsecurity26/presentation/hochrainer); [arXiv 2509.10819](https://arxiv.org/pdf/2509.10819)
- Consensys Diligence (Apr 2026) credits Wüstholz with **30+ critical bugs** in ZK compilers/zkVMs and calls Circuzz a defensive layer for the Aztec/Noir ecosystem — [Diligence blog](https://diligence.security/blog/2026/04/zk-fuzzing-valentin-w%C3%BCstholz-has-surfaced-30-critical-bugs-in-zk-compilers-and-zkvms/)
- zkSecurity's **zkvmBlast** does differential fuzzing of Ethereum zkVMs — [zkSecurity blog](https://blog.zksecurity.xyz/posts/zkvmblast/)
- **"Towards Fuzzing Zero-Knowledge Proof Circuits"** (Chaliasos, Al-Fath, Donaldson; ISSTA Companion 2025): discusses the oracle problem (soundness bugs are hardest), witness generation (random mutation rarely satisfies constraints) and proving cost. A zk-regex fuzzer found **13 confirmed bugs** — [PDF](https://www.doc.ic.ac.uk/~afd/papers/2025/FUZZING.pdf)
- **AI-found Noir compiler bugs (`regression_claude_*`)**: test comments reference a private issue tracker `noir-lang/noir-claude`. Examples read directly:
  - #1640: "LICM applied the `while` loop's induction bounds to the sibling `for` loop, folding `i < 3` to true and **satisfying this false assertion**" (execution_failure).
  - #1303: LICM rewrote checked `i - 1` into `unchecked_sub`, returning 4294967295 instead of trapping on underflow.
  - #1124: `add_to_data_bus` used the wrong SSA-index stride for `call_data` arrays, causing an ACIR-gen ICE.
  - #1019: zero-limb decomposition of zero in constrained/comptime/Brillig contexts.
  - #1544: an i8→u8→i16 cast chain.
  - #1721: `push_front` on vectors under nested if/else.
  
  Sources: [regression_claude_1640](https://github.com/noir-lang/noir/tree/master/test_programs/execution_failure/regression_claude_1640), [1303](https://github.com/noir-lang/noir/tree/master/test_programs/execution_failure/regression_claude_1303), [1124](https://github.com/noir-lang/noir/tree/master/test_programs/execution_success/regression_claude_1124), [1019](https://github.com/noir-lang/noir/tree/master/test_programs/execution_success/regression_claude_1019), [1544](https://github.com/noir-lang/noir/tree/master/test_programs/compile_success_empty/regression_claude_1544), [1721](https://github.com/noir-lang/noir/tree/master/test_programs/execution_success/regression_claude_1721)
- Noir commits in Aug–Sep 2026 co-authored by Claude models fix SSA/ACIR issues, for example:
  - "fix(ssa): follow alias chains through Call/ArraySet/IfElse" (#13701, 2026-09-15)
  - "fix(acir): guard empty vector pop/remove on the semantic length" (#13501)
  - "fix: array_index_needs_explicit_oob_check must consider flattened size" (#13462)
  - "fix(brillig): emit a trap for unreachable terminators" (#13448)
  - "feat(ssa): check purity contracts during SSA interpretation" (#13518)
  - "chore(acir): validate predicate use against requires_acir_gen_predicate" (#13517)
  
  Source: [noir-lang/noir commit search](https://github.com/noir-lang/noir/commits/master)
- **SoK (USENIX Security'24, Chaliasos et al.)**: 141 real SNARK vulnerabilities over about 6 years. The **circuit layer accounts for about 70%**, mostly soundness breaks; under-constraint is the dominant class. Four layers: circuit, frontend (compiler), backend, integration — [USENIX'24](https://www.usenix.org/conference/usenixsecurity24/presentation/chaliasos); [arXiv 2402.15293](https://arxiv.org/pdf/2402.15293)

### Inferences
- The researcher's fuzzing stack (ast_fuzzer/ssa_fuzzer, `--skip-ssa-pass` differential, version diffing, comptime-vs-runtime, must-fail oracles) already covers the **Circuzz/MTZK oracle classes** (equivalence across transformations and stages). The oracle they are missing is **Liezz-style adversarial witness injection**: splicing two honest executions' witnesses and checking ACIR (or `bb verify`) rejection. It is cheap, needs no SMT, and in Liezz's experiments exposed soundness bugs that valid-execution testing never found. The adapter's certificate re-check against ACIR opcodes is the natural checker for such spliced witnesses.
- The AI-found Noir bugs cluster in **SSA optimisation passes** (LICM, alias analysis, array/vector length handling, predicates) and in **Brillig** semantics. Several of them make **false assertions pass**. Soundness-relevant miscompilations therefore still exist in 2026, but were found by an LLM-driven reviewer rather than random program generation. That suggests pass-specific, semantics-aware generators, or LLM-seeded generators, reach these bugs better than generic generators. (This is inference: the private tracker's methodology is not public.)
- #1640 is a *Brillig* miscompilation inside `unsafe { }`. The adapter's under-constraint analysis would treat that Brillig output as nondeterministic, which is correct, but the bug is a *completeness/semantic* bug in the hint. Only an execution oracle (Brillig vs SSA interpreter vs comptime) catches it.

### Gaps
- MTZK's Noir-specific bug list and metamorphic relations could not be retrieved because NDSS/arXiv were blocked.
- Which Liezz bugs were in Noir, and in which stage (ACIR-gen, bb backend, stdlib), is not known.
- Access, tooling and model details of `noir-lang/noir-claude` are not public. There is no blog post explaining the effort, so the count of AI-found bugs cannot be quantified; issue numbers only give an upper bound on tracker size.
- No evidence found of Cairo/o1js compiler fuzzers beyond MTZK (Cairo); o1js was not found.

---

## Q3. Translation validation / verified compilation for Noir: can "compare witness sets with/without a pass" be done symbolically?

### Takeaway
No published work does **translation validation of Noir SSA passes or ACIR generation**. Existing Noir formal work is source-level (Lampe → Lean, rocq-of-noir → Rocq) or ACIR-property-level (NAVe). Equivalence techniques exist elsewhere: ZEQUAL uses product programs, Tabby does SMT-based equivalence of components, and there is R1CS normalisation for equivalence. The adapter's self-composition engine is already a **miter**, so turning it into a cross-circuit equivalence checker (ACIR_A vs ACIR_B from different pass pipelines) is a natural extension and looks unclaimed.

### Cited Findings
- **Lampe** (Reilabs): a Lean model of Noir semantics, aimed at verifying both the language and programs. It is actively developed (PRs such as "require the postcondition at the final state in `Omni.loopDone`") — [reilabs/lampe](https://github.com/reilabs/lampe); [PR #315](https://github.com/reilabs/lampe/pull/315)
- **rocq-of-noir** (Formal Land): translates Noir's JSON representation to Rocq, with a semantics and reasoning building blocks — [formal-land/rocq-of-noir](https://github.com/formal-land/rocq-of-noir)
- **NAVe**: an SMT-LIB formalisation of an ACIR subset, integrated into Nargo — [arXiv 2601.09372](https://arxiv.org/abs/2601.09372)
- **Clean** (zkSecurity / Verified-zkEVM): a Lean 4 embedded DSL for circuits (AIR/PLONK/R1CS targets) with formally proven gadgets — [zkSecurity blog](https://blog.zksecurity.xyz/posts/clean); **zkLean** (Galois): a Lean DSL for ZK statements (R1CS, lookups, MLE lookups, RAM) — [Galois](https://www.galois.com/articles/zklean-a-dsl-for-zk-statement-verification)
- **ZEQUAL** builds a product program (a self-composition of constraints and witness code) and proves equivalence with static simplification and quantified invariants — [Springer](https://link.springer.com/chapter/10.1007/978-3-031-98668-0_16)
- **Tabby** (synthesis-aided ZK compiler, ACM 2025) decomposes programs into components and verifies semantic equivalence via SMT — [ACM DL](https://dl.acm.org/doi/10.1145/3763110)
- A data-flow-based R1CS normalisation algorithm was proposed so that R1CS from different optimisation levels can be compared for equivalence — [arXiv 2309.04274](https://arxiv.org/pdf/2309.04274)
- The Noir team added SSA-interpreter-based checks (e.g. "check purity contracts during SSA interpretation", #13518, Aug 2026). This indicates the compiler uses the SSA interpreter as an internal oracle — [noir commit 14e9dc3](https://github.com/noir-lang/noir/commit/14e9dc36b518b1a79fa97b97ed95246b97e33449)
- The 2026 SoK finds that formal-verification work "focuses primarily on constraint correctness" and identifies gaps in the other layers — [arXiv 2607.23752](https://arxiv.org/abs/2607.23752)

### Inferences: a concrete symbolic recipe for ACIR pass validation
Let `A` = ACIR compiled normally and `B` = ACIR compiled with `--skip-ssa-pass P` (or at a different version). Both share the ABI, so public inputs/returns and parameters map 1:1 by ABI position. Internal witnesses do not correspond, so treat them as disjoint (`x*` for A, `y*` for B).
1. **Output-functional disagreement (soundness or miscompilation):** `∃ in, W_A, W_B : A(W_A) ∧ B(W_B) ∧ in_A = in_B ∧ out_A ≠ out_B`. This is exactly the adapter's uniqueness query with two different circuits instead of two copies of one: reuse `var_name` (fixed wires shared, others split), cone slicing and uniqueness lemmas. SAT means that either one of the circuits is under-constrained or they compute different relations. Disambiguate by running the adapter's single-circuit check on `A` and `B` separately. If both are unique and the joint query is SAT, it is a **real miscompilation**, with a concrete input as witness, confirmable by `nargo execute` on both builds.
2. **Dropped assertion (relation weakening):** `∃ in, W_B : B(W_B) ∧ ¬∃W_A. A(W_A)`. This is ∀-quantified and not directly SMT-friendly. Practical under-approximation: since `A` is usually functional in its non-Brillig witnesses, compute `W_A` symbolically by propagation (the adapter's fixed-known propagation plus determinism abstraction), then check `B(W_B) ∧ in_A=in_B ∧ ¬C_i(W_A)` for each A-constraint `C_i` individually (one small query per constraint). Brillig outputs in A must be existentially re-chosen, which is where the adapter's mutation/certificate machinery helps.
3. **Scaling via correspondence hints.** Most passes preserve most witnesses. Matching witnesses by Brillig call sites, call-stack/debug locations, or structural hashing of opcodes (similar to ZEQUAL's pairwise array-equivalence inference) and adding them as *assumed-equal lemmas* checked incrementally would make the miter mostly trivial. This mirrors "equivalence checking with cut points" in hardware CEC.
4. Why it is publishable: it replaces the researcher's sampling-based `--skip-ssa-pass` differential with an exhaustive per-program check. It works at the ACIR boundary (backend-agnostic), and it reuses a proven self-composition engine. No Noir/ACIR translation validator has been published per the sources found.

### Gaps
- No source found on Aztec or third parties performing SMT-based translation validation of Noir SSA passes or ACIR-gen. Aztec's internal audit methodology is not public.
- Lampe's coverage of ACIR (versus source semantics only) and the status of "noir-lean" were not verified. Whether any Lean model connects source semantics to ACIR (a compiler-correctness theorem) is unknown; none was found.
- Tabby details (which DSL, what equivalence notion) were not read in full.

---

## Q4. LLM-assisted auditing of ZK circuits (2025–2026)

### Takeaway
LLM auditing moved from experiments (SnarkSentinel, 2025) to strong benchmark numbers in 2026. zkSecurity's open-source **circom-auditor** skill for Claude Code/Codex detects up to 66/70 known zkbugs on isolated circuits and 40/56 on full codebases, "far ahead of existing Circom security tools". The 2026 SoK finds conventional tools drop from 45.7% to 19.6% detection on full codebases. For Noir specifically, the visible evidence is the Noir team's AI-driven `noir-claude` compiler bug stream. I found no published LLM-auditor benchmark for Noir circuits.

### Cited Findings
- **circom-auditor** (zkSecurity zk-skills v0.1.0, MIT): encodes auditor methodology as skills for **Claude Code (Opus 4.8) and Codex (GPT-5.5)**. It detects up to **66 of 70** known bugs pointed at vulnerable circuits and **40 of 56** on full original codebases. zkSecurity presents it as a first line of defence, not a replacement for manual review or formal verification — [zkSecurity blog](https://blog.zksecurity.xyz/posts/circom-auditor/)
- **SnarkSentinel** (zkSecurity, 2025): an experimental AI ZK auditor using RAG and agent-led probing, with successes and failures reported — [zkSecurity blog](https://blog.zksecurity.xyz/posts/snarksentinel/)
- **zkao 2.0** (2026-07-24): multi-agent LLM workflows for auditing Circom and other ZK systems — [zkSecurity zkao](https://blog.zksecurity.xyz/posts/zkao-launch/) (release date from search snippet)
- zkSecurity, "The Year Finding and Exploiting Bugs Became Cheap": by late 2025 AI-assisted bug finding/exploitation "became reality"; the recommended strategy is continuous testing, AI tools, manual review and formal verification — [zkSecurity blog](https://blog.zksecurity.xyz/posts/the-year-finding-bugs-became-cheap/)
- **2026 SoK "ZKP Security Tools and Verification: Coverage, Effectiveness, Adoption, and Challenges"** (Kolozyan, Sorger, Hicks, Chaliasos; arXiv 2607.23752):
  - most tools target Circom
  - tools detect 45.7% of bugs on isolated targets but **19.6% on full codebases**
  - a survey of 48 practitioners: security is human-led and **LLMs are widely used**; high onboarding effort reported by 57% of developers and 45% of auditors
  - artifacts: `zkhydra` (tool orchestration) and an extended `zkbugs` dataset, with isolated vs project modes
  
  Sources: [arXiv 2607.23752](https://arxiv.org/abs/2607.23752); [artifact repo](https://github.com/t-sorger/zkp-security-tools)
- **zkCraft** uses LLMs as deterministic mutation-pattern oracles on top of TCCT fuzzing (Circom) — [arXiv 2602.00667](https://arxiv.org/pdf/2602.00667)
- **Noir `regression_claude_*`**: regression tests for issues from `noir-lang/noir-claude` (issue numbers seen: 1019, 1124, 1201, 1303, 1544, 1640, 1654, 1721). Around 13 code-search hits for the prefix in test_programs/snapshots. Noir commits in Aug–Sep 2026 carry `Co-Authored-By: Claude ...` trailers — [GitHub code search results in noir-lang/noir](https://github.com/noir-lang/noir/tree/master/test_programs); [example test](https://github.com/noir-lang/noir/tree/master/test_programs/execution_failure/regression_claude_1640)
- zkSecurity also runs **bugs.zksecurity.xyz**, a ZK bug knowledge base with reproducible exploits — [zkbugs website post](https://blog.zksecurity.xyz/posts/zkbugs-website/); [Reproducing and exploiting](https://blog.zksecurity.xyz/posts/zkbugs/)

### Inferences
- An **LLM triage layer** on top of the adapter is a low-cost, high-yield addition. It would take each `unsafe`/`unknown` candidate with its counterexample (x*/y* assignments), the ACIR cone and the Noir source span, and have an agent classify it (real / cast-guard false positive / needs precondition) and write a PoC `Prover.toml`. The adapter's certificate re-check keeps the LLM honest: an LLM claim counts only if a concrete second witness passes the ACIR re-check. This pairing of LLM hypothesis with solver/executor certificate is the pattern zkCraft pursues for Circom, and nobody has shown it for Noir.
- The noir-claude stream suggests the Noir team is already mining **compiler** bugs with LLMs at scale. For an external researcher, competing on compiler bugs through generic fuzzing is therefore low-yield. Better options: (a) **circuit-level under-constraint in real Noir libraries** (where the adapter plus LLM triage is differentiated), or (b) **symbolic pass validation** (Q3), which LLM review is poor at.

### Gaps
- No public benchmark of LLM auditors on Noir circuits was found. The zkbugs Noir subset size was not verified; the SoK says Circom dominates.
- The exact scale, false-positive rate and tooling of `noir-claude` are unknown (private).
- zkao 2.0's Noir support is unverified.

---

## Q5. Open problems / publishable gaps named in the literature, and combinations with noir-picus-adapter

### Takeaway
The literature repeatedly names these gaps:
1. Tools are Circom-centric, with weak support for newer DSLs (Noir) and zkVMs.
2. Scale: formal tools fail on real-size circuits, and detection drops sharply on full codebases.
3. The oracle problem for soundness bugs, and generating witnesses that satisfy constraints.
4. Range checks and bitsums as the solver bottleneck (NAVe, BitSplit).
5. Trust in the verifier itself (the cvc5 FF soundness bug).
6. Formal verification limited to constraint correctness rather than compiler or pipeline correctness.

The adapter already sits on 1, 2 and 4 for Noir. Adding Liezz-style injection, zkFuzz-style in-Brillig mutation, CIVER-style modular summaries and cross-circuit miters gives a distinct contribution.

### Cited Findings
- Coverage gap: "most security tools target Circom, leaving newer DSLs and zkVMs with limited support". Effectiveness drops from 45.7% (isolated) to 19.6% (full codebases). Formal verification focuses on constraint correctness — [2026 SoK, arXiv 2607.23752](https://arxiv.org/abs/2607.23752)
- Static analysers are imprecise (high false-positive rates) and formal tools struggle with real-world circuit scale. This is zkFuzz's stated motivation — [zkFuzz, arXiv 2504.11961](https://arxiv.org/abs/2504.11961)
- The oracle problem (soundness bugs especially), witness generation (random mutations rarely satisfy constraints) and proving overhead are open challenges — [Chaliasos, Al-Fath, Donaldson, ISSTA Companion 2025](https://www.doc.ic.ac.uk/~afd/papers/2025/FUZZING.pdf)
- Range-check-induced constraints significantly increase verification time, and the int vs FF encodings are complementary. NAVe describes this as an improvement path for its framework — [NAVe, arXiv 2601.09372](https://arxiv.org/abs/2601.09372)
- "Other tools have shown to be unable to handle circuits of this size [1M–5M constraints] at once." Modular analysis is CIVER's answer — [COSTA/CIVER](https://costa.fdi.ucm.es/web/news/CIVER_ZisK.html)
- Verifier soundness: the cvc5 FF split-solver bug "could invalidate the formal verification of ZK programs" — [TBTL HackMD](https://hackmd.io/@tbtl/BJ8ak2W9bl)
- Valid-execution testing misses soundness failures that adversarial witness injection finds — [Liezz, arXiv 2608.30648](https://arxiv.org/abs/2608.30648)
- zkFuzz's Noir prototype lacks target selectors — [zkFuzz paper](https://arxiv.org/pdf/2504.11961)
- Well-formedness checks (range/bit-decomposition/remainder bounds) are up to 48.7% of ZKML constraints. The same check family creates both solver cost and redundancy/under-constraint risk — [arXiv 2609.10149](https://arxiv.org/pdf/2609.10149)
- Circuit-layer bugs are about 70% of the 141 SNARK vulnerabilities studied — [SoK USENIX'24](https://www.usenix.org/conference/usenixsecurity24/presentation/chaliasos)

### Inferences: candidate contributions ranked by (bug yield × novelty)
1. **Hybrid "SMT-selected, fuzz-confirmed" under-constraint finder for Noir** (novel; addresses zkFuzz's missing Noir target selectors and the adapter's hint-crash limitation):
   - use the adapter's cone/unpinned analysis and SMT-SAT models as **targets and seeds**
   - apply zkFuzz-style **Brillig-level mutation** (mutate `Mov`/intermediate registers, not just outputs) guided by a min-sum fitness over ACIR constraint residuals
   - confirm every candidate with the adapter's **ACIR certificate re-check**
   
   Metric: bugs found and time-to-bug on real Noir libraries versus Picus-only, zkFuzz-Noir and NAVe.
2. **ACIR translation validation via cross-circuit self-composition** (Q3 recipe). It is exhaustive per program where `--skip-ssa-pass` differential is sampling-based. Evaluation: re-find known fixed Noir SSA bugs (e.g. regression_claude LICM ones, Circuzz's #5463) by checking the old compiler's output against pass-skipped output. This is a plausible CAV/FSE/ICSE-style paper.
3. **Range/bitsum abstraction and modular gadget summaries for ACIR.**
   - Replace bit expansion with a "RANGE predicate + bit-uniqueness lemma".
   - Prove per-gadget determinism summaries once (stdlib `to_le_bits`, integer div/mod, comparison gadgets) and reuse them CIVER-style.
   - Use a portfolio of cvc5-FF(split) / NIA / the orchestral solver.
   
   This directly attacks the 2000+-constraint and 20k-opcode timeouts. Report the effect of BitSplit and of the cvc5 soundness fix.
4. **Liezz-style witness splicing for Noir + bb.** Take two honest executions of the same program with different outputs, splice `(inputs_1, outputs_2, internal witnesses mixed)`, and check with the adapter's ACIR re-check and `bb prove/verify`. This is a cheap soundness oracle for the fuzzing pipeline that complements must-fail oracles.
5. **Verifier trust / cross-validation.** Every `verified` gets a second opinion (other theory or solver). Every `unsafe` gets a concrete ACIR-checked certificate, which the adapter already produces. Publishing a Noir under-constraint benchmark (the corpus tiers) as a zkbugs-compatible dataset fills the "Circom-only" coverage gap that the 2026 SoK names explicitly.
6. **LLM triage and precondition synthesis** for cast-guard false candidates: the LLM proposes preconditions/invariants, and SMT checks that they hold in the honest semantics before using them. This follows the practitioner trend in the SoK survey while keeping machine-checked guarantees.

### Gaps
- No paper was found that explicitly lists "Noir under-constraint at library scale" or "Noir pass translation validation" as an open problem. These are inferred from Circom-centric coverage and the absence of such work in the results.
- Whether NAVe does self-composition uniqueness (overlapping the adapter) or only user-specified properties/asserts could not be confirmed (arXiv blocked). This matters for novelty claims and should be checked by reading the NAVe paper and repo directly.
- Dates and venues: zkFuzz is S&P'26 (repo title); Circuzz CCS'25; Arguzz USENIX Sec'26; MTZK NDSS'25; ZKAP USENIX Sec'24; SoK USENIX Sec'24; ConsCS ICSE'25; ZEQUAL CAV'25 (Springer LNCS chapter; venue inferred from the LNCS volume, not confirmed); Split-GB CAV'24; Coda (preprint 2023; publication at IEEE S&P 2024 per my background knowledge, **not confirmed by search**); NAVe, orchestral solver, Liezz, the 2026 SoK and zkVM branch-and-bound are 2026 arXiv preprints (no venue confirmed).

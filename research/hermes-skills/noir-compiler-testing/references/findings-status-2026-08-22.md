# Findings status after 2026-08-22 session

## Changes this session

| Что | Статус |
|---|---|
| Memory fix in `mutate.rs` (soft hints in `MemOpKind::Write`) | ✅ Merged, tested (60 passed) |
| `execution_success` campaign (66 pkgs, `--only-hints`) | 0 findings, 60 clean, 6 self-flagged |
| `nightly-returndata-loop` reduction | 5129→1908 chars, confirmed same class as `non-pinning-constraint` |
| Two-hint-cross-constraint (`h1*h2==0`, `h1+h2==0`) | ❌ NOT a compiler bug (weak constraint, not lost) |
| Gadget audit rerun with memory fix | Running (471 gadgets) |

## Real bugs found (by this instrument, all on beta.26)

| Finding | Type | Status |
|---|---|---|
| `no-bug-corpus-underconstrained` (regression_11490) | Lost constraint in compilation | ✅ Confirmed |
| `non-pinning-constraint-silences-checker` | Broken checker heuristic (`is_against_const`) | ✅ Confirmed |
| `predicated-constraint-silences-checker` | Broken checker heuristic | ✅ Confirmed |
| `array-output-length-threshold` | Documented trade-off > 64 elements | ✅ Confirmed, bound proven |
| `ancestor-distance-false-positive` | Documented trade-off > 10 steps | ✅ Confirmed, bound proven |
| `nightly-returndata-loop` | Same class as non-pinning-constraint | ✅ Confirmed |

## Non-bugs (findings that are NOT compiler bugs)

| Pattern | Why not a bug | Evidence |
|---|---|---|
| `assert(h1 * h2 == 0)` | ACIR correctly encodes `w2*w3 = 0`; programmer has two degrees of freedom | Certificate passes, control rejects honest-returned witness |
| `assert(h1 + h2 == 0)` | Same — two degrees of freedom | Same |
| `(h1 & h2) == 0` | Same through bitwise | Same |

## How to distinguish

See the three checks in `SKILL.md` Classification Pitfalls:
1. **ACIR faithfulness** — does ACIR have fewer constraints than source?
2. **Certificate** — does the forged witness pass every opcode?
3. **Control** — does returning the honest value get rejected?
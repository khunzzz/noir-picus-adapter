# A constraint inside an `if` silences the checker, and holds only when the branch is taken

```noir
unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field, c: bool) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    if c {
        assert(h == a);
    }
    h
}
```

`nargo compile` reports nothing. The program looks correct: the hint *is*
constrained to equal `a`. But the constraint is predicated on `c`, and `c` is
an input the prover chooses.

## Soundness depends on an input value

The same compiled circuit, run twice with different inputs:

| `c` | honest output | second witness found | search |
| --- | --- | --- | --- |
| `0` | `5` | **yes — output `6`** | 3 findings in 5 attempts |
| `1` | `5` | no | 0 findings in 24 attempts |

With `c = 1` the assertion pins the hint and the search cannot move it. With
`c = 0` the hint is entirely free and goes straight to the public output. This
is the control that makes the finding sharp: nothing changes but the input.

## The ACIR says it plainly

```
BLACKBOX::RANGE input: w1, bits: 1     // c is a bool
BRILLIG CALL predicate: 1, inputs: [w0], outputs: [w3]
ASSERT 0 = -w0*w1 + w1*w3              // c * (h - a) = 0
ASSERT w2 = w3                         // the return value is the hint
```

The only constraint on `w3` is `c * (h - a) = 0`. Its coefficient in `w3` is
`w1`, which is `c`. When `c = 0` the whole equation reads `0 = 0` and holds for
every `w3`, while `w2 = w3` still sends it to the caller.

## Reach of the class

| shape | `nargo compile` | second witness found |
| --- | --- | --- |
| `if c { assert(h == a) }`, `c` a `bool` input | **silent** | yes |
| `if a > 10 { assert(h == a) }`, predicate from a comparison | **silent** | yes |
| `if c { if d { assert(h == a) } }`, nested | **silent** | yes |
| `if g { assert(h == a) }` where `g` is itself a hint | flagged | yes |
| `if c { assert(h == a) } else { assert(h == 0) }` | silent | no |

Two rows behave correctly, and both are instructive. When the predicate is
itself an unconstrained hint the checker does flag it — that case it handles.
And an `if` with a matching `else` constrains the hint on every path, so the
program is sound and the silence is right.

What is left is the middle of the table: an ordinary conditional over ordinary
data, where a reader sees a constraint and the compiler agrees.

## Relation to the other finding

`../non-pinning-constraint-silences-checker/` is a constraint that never pins.
This one *does* pin — but only when a prover-chosen input says so. The shared
root is the same: the checker treats "a constraint mentions this output" as "the
output is determined". Here that is even harder to spot by eye, because the
source reads like properly constrained code, and it is, on the branch a reader
has in mind.

Neither documented heuristic limit explains it. Recompiling with
`--brillig-constraints-check-max-array-output-length 4096` and
`--brillig-constraints-check-max-ancestor-distance 500` still reports zero
`bug:` lines.

## Verification

| | |
| --- | --- |
| compiler | `nargo compile --force` → exit 0, zero `bug:` lines |
| honest run | `a = 5, c = 0` → output `0x05` |
| forged | same inputs → output `6` |
| independent re-check | `feasible --propagate-only` on `forged_witness.json` → `no-violation` |
| control | the same program with `c = 1` → 0 findings in 24 attempts |

## Versions

Present on both the released 1.0.0-beta.26 (git 40d6574) and
1.0.0-beta.26+e088a9e: zero `bug:` lines on each.

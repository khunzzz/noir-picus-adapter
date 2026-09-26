# An assertion that does not pin a value silences the under-constrainedness checker

Six lines. `nargo compile` reports nothing, and the public output is a Brillig
result that no constraint determines.

```noir
unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    assert(h != 0);
    h
}
```

`assert(h != 0)` rules out exactly one value out of the whole field. The
compiler treats it as having constrained `h`.

## The assertion is what silences it

Three programs differing only in that one line:

| line | `nargo compile` | is `h` actually determined? |
| --- | --- | --- |
| *(no assertion)* | `bug: Brillig function call isn't properly covered` | no |
| `assert(h != 0)` | **silent** | **no** |
| `assert(h == a)` | silent | yes |

Removing the assertion brings the diagnostic back, so the assertion is doing
the silencing. The checker does not distinguish the middle row from the
bottom one.

## Not one of the documented trade-offs

Unlike `../array-output-length-threshold/`, raising both heuristic limits to
the maximum changes nothing:

```
nargo compile --force \
  --brillig-constraints-check-max-array-output-length 4096 \
  --brillig-constraints-check-max-ancestor-distance 500
```

still reports zero `bug:` lines. Neither the array-length over-approximation
nor the BFS depth cutoff explains this.

## The realistic form

The same gap fires on what looks like defensive code — range-checking a hint:

```noir
unconstrained fn hint(x: Field) -> u8 { x as u8 }

fn main(a: Field) -> pub u8 {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    assert(h < 100);
    h
}
```

Silent, and `h` may be any value below 100 regardless of `a`. A developer who
bounds a hint and relies on the checker for the rest gets no warning. This is
the shape a real vulnerability would take. See `variant_range_check.nr`.

## The canonical instance: a division gadget

The shape everyone writes for division is `assert(a * b == c)`, with `b` the
hinted quotient. It pins `b` — as long as `a` is not zero.

```noir
unconstrained fn hint(x: Field, y: Field) -> Field {
    if x == 0 { 0 } else { y / x }
}

fn main(a: Field, c: Field) -> pub Field {
    let b = unsafe { hint(a, c) };
    assert(a * b == c);
    b
}
```

The same compiled circuit, run on two different inputs:

| inputs | second witness found | search |
| --- | --- | --- |
| `a = 6, c = 42` | no | 0 findings |
| **`a = 0, c = 0`** | **yes — output `1` instead of `0`** | 3 findings in 9 attempts |

At `a = 0` the constraint reads `0 * b == 0`, which every `b` satisfies. The
compiler is silent on both, on the released 1.0.0-beta.26.

Verified: honest output `0`; forged output `1` for the same inputs;
`feasible --propagate-only` reports `no-violation (2 of 2 constraints evaluated)`;
the control with the output restored to `0` is rejected.

This is also the clearest illustration of what the tool asks. It does not ask
whether `a * b == c` has many solutions — it does. It asks whether the *target*
can take two values with the *committed inputs* held fixed. Three arrangements
of the same equation come back clean:

| circuit | fixed | target | verdict |
| --- | --- | --- | --- |
| `a * b` returned | `a`, `b` | product | clean |
| `c` hinted, `assert(a * b == c)` | `a`, `b` | `c` | clean |
| `b` hinted, `assert(a * b == c)`, `a = 6` | `a`, `c` | `b` | clean |
| `b` hinted, `assert(a * b == c)`, **`a = 0`** | `a`, `c` | `b` | **3 findings** |

## Reach of the class

Every form below is a constraint that survives optimization and does not
determine the hint. All were compiled on 1.0.0-beta.26+e088a9e (a build after that release) and searched with
the mutation oracle.

| constraint on the hint | `nargo compile` | second witness found |
| --- | --- | --- |
| `assert(h != 0)` — `Field` | **silent** | yes |
| `assert(h * h != 7)` — `Field` | **silent** | yes |
| `assert(h < 100)` — `u8` | **silent** | yes |
| `assert(h > 2)` — `u8` | **silent** | yes |
| `assert(h >= 3); assert(h <= 9)` — `u8` | **silent** | yes |
| `assert(h & 1 == 0)` — `u8` | **silent** | yes |
| `h.assert_max_bit_size::<8>()` — `Field` | **silent** | yes |
| `assert(h == h)` | flagged | yes |
| `assert(h[0] != 0)` on `[Field; 4]`, return `h[0]` | flagged | yes |

Two rows do *not* silence the checker, and both for understandable reasons.
`assert(h == h)` is optimized away, so no constraint survives to mislead it.
The array row keeps per-index tracking alive: elements 1..3 are never mentioned,
so the call is reported regardless of what happens to element 0.

The bound-style rows matter most. `h.assert_max_bit_size::<8>()` and
`assert(h < 100)` are the idiomatic way to range-check a Brillig hint. Writing
one is enough to convince the checker the hint is fully constrained.

## It survives realistic downstream use

The hint does not have to be returned raw. Each of these bounds a hint and then
uses it the way ordinary code would:

| shape | `nargo compile` | second witness found |
| --- | --- | --- |
| `assert(h < 1000)`, return `h * 3 + 1` | **silent** | yes |
| `assert(h < 8)`, use `h` as an array index | **silent** | yes |
| `r.assert_max_bit_size::<32>()`, return `r` | **silent** | yes |
| `assert(h < 100)`, return `if h > 50 { h } else { h + 1 }` | **silent** | yes |

The last row was undecided when this was first written — the search bailed at
the first constraint two open hints could both absorb, which every integer
comparison produces. Adding a bounded choice at those points closed it: honest
output `6`, forged output `7` for the same input, `no-violation` on the
independent re-check.

The third row is the shape that matters in practice. Bounding a hint and
relying on the checker for the rest is exactly how a division or decomposition
gadget gets written, and the bound alone silences the diagnostic.

## One weak assertion covers a whole chain

The checker's own comment on `arguments_intersect` says:

> We want to avoid using tainted inputs to constrain Brillig outputs. […]
> However if a tainted input has been constrained already, we can use it.

So a hint that counts as constrained may then be used to clear the next hint.
When the first hint was only *weakly* constrained, that licence passes down the
chain:

```noir
unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field) -> pub Field {
    let h1 = unsafe { hint(a) };
    assert(h1 != 0);          // the only weak constraint in the program
    let h2 = unsafe { hint(h1) };
    assert(h2 == h1);
    let h3 = unsafe { hint(h2) };
    assert(h3 == h2);
    h3
}
```

| program | `nargo compile` |
| --- | --- |
| the chain **without** `assert(h1 != 0)` | `bug: Brillig function call isn't properly covered` |
| one hint plus `assert(h1 != 0)` | **silent** |
| three hints, still one `assert(h1 != 0)` | **silent** |

Removing that single line brings the diagnostic back, so it is what silences
the whole chain. Verified on the three-hint version: honest output `5`, forged
output `6` for the same input, `no-violation` on the independent re-check, and
the control with the output restored is rejected at opcode 7. Also silent on
the released 1.0.0-beta.26.

The consequence is that the cost of this class does not scale with how many
weak constraints a program contains. One is enough.

## Where it comes from

`check_for_missing_brillig_constraints.rs`, in the doc comment on
`try_constrain`, lists the exceptions to the rule that a constraint must relate
a call's inputs to its outputs:

> Exceptions to this rule are:
> * if there are no input arguments …
> * **if there is only one constrained value (an output against a constant)**

implemented as `let is_against_const = constrained_values.len() == 1;`, which
then skips the `arguments_intersect` check and clears the output.

The parenthetical assumes that comparing an output against a constant pins it.
`assert(h != 0)` and `assert(h < 100)` are comparisons against a constant that
pin nothing. The gap is the conflation of *compared to a constant* with
*determined by a constant*. This reading of the source is offered as the
explanation; the causal evidence above is the three-way table, which does not
depend on it.

## Verification

| | |
| --- | --- |
| compiler | `nargo compile --force` → exit 0, zero `bug:` lines |
| honest run | `a = 5` → output `0x05` |
| forged | same `a = 5` → output `6` |
| independent re-check | `feasible --propagate-only` on `forged_witness.json` → `no-violation` |
| control | the same witness with the output put back to `5` → `rejected` at opcode 3 |
| third engine | `noir-picus-adapter scan` (SMT uniqueness query, independent of both the mutation search and constant propagation) → `3 targets — 0 verified, 3 unsafe` |

Three engines with different failure modes agree: a forward mutation search
finds the second witness, constant propagation accepts it, and the SMT
uniqueness query proves the output is not unique.

## Reproduce

```bash
nargo compile --force     # exit 0, no diagnostics
nargo execute --force     # output 0x05
noir-picus-adapter mutate target/*.json --witness target/*.gz --attempts 8
```

## Versions

Reproduced on both 1.0.0-beta.26 (release, git 40d6574) and 1.0.0-beta.26+e088a9e (a build after that release). The nightly reports the same version
string as the release, so the git hash is the only reliable identifier.

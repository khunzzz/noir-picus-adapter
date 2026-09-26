# Correctly constrained program reported as under-constrained

The mirror image of `../array-output-length-threshold/`. There the checker went
silent on an unsound program; here it raises `bug:` on a sound one.

```noir
unconstrained fn hint(x: Field) -> Field { x }

fn main(a: Field) {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    let mut t = h;
    let mut r = a;
    t = t * a + a;   r = r * a + a;   // repeated K times
    assert(t == r);
}
```

`t` and `r` are built by identical chains from `h` and `a`, so `assert(t == r)`
constrains `h == a` exactly. The hint is fully determined at every K.

## Transition at 10 instructions

| K (chain steps) | instructions | `nargo compile` |
| ---: | ---: | --- |
| 0, 1, 2, 4, **5** | 0 … **10** | silent |
| **6**, 8, 10, 12, 16, 24 | **12** … 48 | `bug: Brillig function call isn't properly covered by a manual constraint` |

Each step is two instructions, so the flip lands between 10 and 12 —
`DEFAULT_MAX_ANCESTOR_DISTANCE = 10`.

## Causal proof

Same K=6 program, only the checker's BFS depth changed:

```
nargo compile --force --brillig-constraints-check-max-ancestor-distance N
```

| N | result |
| ---: | --- |
| 10 (default) | **FLAGGED** |
| 14, 20, 40 | silent |

So the constraint is reachable; the BFS simply stops before it. Root cause is
the depth cutoff in `check_for_missing_brillig_constraints.rs`, whose comment
states the intent: *"Limit how far back the BFS traverses"*.

## Why it matters

The first finding shows the checker can be escaped. This one shows it can also
cry wolf: twelve ordinary arithmetic instructions between a hint and its
constraint are enough to produce a soundness warning on correct code. A user
who trusts the checker gets both failure directions at the default settings,
and the two are hard to tell apart from the message alone.

## Baseline

`assert(h == a)` with no chain compiles silently, confirming the harness
produces silent cases and that the diagnostic here tracks chain length alone.

## Versions

Identical on the released 1.0.0-beta.26 (git 40d6574) and on
1.0.0-beta.26+e088a9e: silent at chain 4, flagged at chains 6, 10, 16 and 24 on
both. Not a regression — the behaviour is the same in the release.

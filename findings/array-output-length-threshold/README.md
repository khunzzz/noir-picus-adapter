# Unconstrained public output accepted silently, above an array-length threshold

`nargo compile` reports nothing for this program on 1.0.0-beta.26+e088a9e (a build after that release), and its
public output is a Brillig result that no constraint ties to anything.

```noir
unconstrained fn hint(x: Field) -> [Field; 65] {
    [x; 65]
}

fn main(a: Field) -> pub Field {
    // Safety: demonstration
    let h = unsafe { hint(a) };
    assert(h[0] == a);   // only element 0 is constrained
    h[1]                 // returned, and free
}
```

A prover may return any value for `h[1]`.

## The threshold is exactly 64

| array length | `nargo compile` | our search |
| ---: | --- | --- |
| 4 | `bug: Brillig function call isn't properly covered by a manual constraint` | finds it |
| 64 | same diagnostic | finds it |
| **65** | **silent, exit 0** | finds it |
| 128 | **silent, exit 0** | finds it |

64 is `DEFAULT_MAX_ARRAY_OUTPUT_LENGTH` in
`compiler/noirc_evaluator/src/ssa/checks/check_for_missing_brillig_constraints.rs`,
where the trade-off is stated outright:

> Arrays longer than this value will be considered constrained if any item we
> get from them gets constrained.
>
> The higher this value the longer it will take to check them all, which can
> slow down the compilation of larger rollup circuits.

So the limit is deliberate and documented. What the demonstration adds is that
it is reachable from six lines of ordinary Noir, and that what gets through is
not a subtle partial weakness but a *completely* free public output.

## Verification

| | |
| --- | --- |
| compiler | `nargo compile --force` → exit 0, zero `bug:` lines, zero errors |
| honest run | `nargo execute` → output `0x05` for `a = 5` |
| forged | output `6` for the same `a = 5` |
| independent re-check | `feasible --propagate-only` on `forged_witness.json` → `no-violation` (constant propagation, a different evaluator from the certificate's opcode walk) |
| control | the same witness with the output put back to `5` → `rejected` at opcode 2 |

## Reproduce

```bash
nargo compile --force            # exit 0, no diagnostics
nargo execute --force            # output 0x05
noir-picus-adapter mutate target/*.json --witness target/*.gz --attempts 8
```

## Causal proof, not just a coincident threshold

The limit is tunable through a hidden driver flag, so the same 65-element
program can be compiled against different limits with nothing else changed:

```
nargo compile --force --brillig-constraints-check-max-array-output-length N
```

| N | result |
| ---: | --- |
| 64 (default) | **SILENT** |
| 65 | `bug: Brillig function call isn't properly covered by a manual constraint` |
| 128 | same diagnostic |

The checker *can* see this program. Only the length cutoff suppresses it, at
`check_for_missing_brillig_constraints.rs:177`:

```rust
Some(length) if length.0 > 0 && length.0 <= max_array_output_length => {
```

That pins the root cause to one comparison, and rules out any other
explanation for the diagnostic disappearing.

## Status: a documented trade-off, reached from six lines

This is not an accident in the checker. The constant carries a comment
explaining the compile-time reason for it, and the flag exists to raise it.
What the demonstration establishes is how cheap the escape is and how total
the resulting hole is — one array literal past the cutoff, and a public output
is left entirely free, with the default configuration silent.

## Versions

Reproduced on both 1.0.0-beta.26 (release, git 40d6574) and 1.0.0-beta.26+e088a9e (a build after that release). The nightly reports the same version
string as the release, so the git hash is the only reliable identifier.

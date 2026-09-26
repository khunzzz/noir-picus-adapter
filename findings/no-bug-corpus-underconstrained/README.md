# A program in Noir's own "no bug" corpus is under-constrained

`test_programs/compile_success_no_bug/regression_11490` is part of the corpus
that asserts the under-constrainedness checker stays silent. It does stay
silent. The program is nevertheless unsound: the circuit accepts statements the
program itself rejects.

```noir
unconstrained fn f(input: u32) -> [u8; 2] {
    [input as u8; 2]
}

fn main(input: u32, expected_sum: pub u32) {
    // safety: test
    let data = unsafe { f(input) };
    let mut sum: u32 = 0;
    for i in 0..2 {
        sum += data[i] as u32;
    }
    assert(sum == expected_sum);
    assert(sum < 1000000);
}
```

## The input reaches nothing

The whole compiled circuit is four lines:

```
private parameters: [w0]              // input
public parameters: [w1]               // expected_sum
BRILLIG CALL func: 0, inputs: [w0], outputs: [[w2, w3]]
BLACKBOX::RANGE input: w2, bits: 8
BLACKBOX::RANGE input: w3, bits: 8
ASSERT w3 = w1 - w2                   // the only link
```

`w2` and `w3` are the two bytes. The only constraint on them is
`w2 + w3 = expected_sum`, with each held to eight bits. **`w0` appears in no
constraint at all.** Honestly, `f` returns `[input as u8; 2]`, so
`expected_sum` must be `2 * (input as u8)`; the circuit asks for nothing of the
kind.

## A prover can prove a statement the program refuses

`input = 1` gives `data = [1, 1]` and `sum = 2`.

| | |
| --- | --- |
| `nargo execute` with `input = 1, expected_sum = 2` | succeeds |
| `nargo execute` with `input = 1, expected_sum = 100` | **`Cannot satisfy constraint`** — the program rejects |
| the circuit with `w0 = 1, w1 = 100, w2 = 50, w3 = 50` | **`no-violation`** — the circuit accepts |

## Controls

The re-check is not passing vacuously, and the input really is irrelevant:

| assignment | result |
| --- | --- |
| `w2 = 50, w3 = 49` (sum ≠ `expected_sum`) | **rejected** at opcode 5 |
| `w0 = 1, w1 = 2, w2 = 1, w3 = 1` (honest) | accepted |
| `w0 = 77777, w1 = 100, w2 = 50, w3 = 50` | **accepted** — changing the private input changes nothing |

The last row is the point: whatever `input` a prover commits to, it can satisfy
the circuit for any `expected_sum` below 512 by splitting it across two bytes.

## What the test's own comments say

The file explains why the checker is quiet:

> This constraint does not connect the inputs and outputs of the call to `f`
> above, so `check_for_missing_brillig_constraints` does not consider it
> sufficient.

> This constraint on the output against a constant would be considered
> sufficient by `check_for_missing_brillig_constraints`, however the 'Constant
> Folding using constraints' pass turned this into
> `assert(expected_sum < 1000000)` due to the previous constraint.

So the authors knew the first assertion does not connect inputs to outputs, and
that the second one only looked sufficient because of the exception for
constraints against a constant — the same exception documented in
`../non-pinning-constraint-silences-checker/`. What the test then fixes in place
is the silence, in a corpus whose name asserts there is no bug to report.

## How it was found

By the static pass, on a corpus that ships no `Prover.toml` and so was out of
reach of the witness-driven search:

```
noir-picus-adapter unpinned target/regression_11490.json
```

## Versions

Both the released 1.0.0-beta.26 (git 40d6574) and 1.0.0-beta.26+e088a9e:
zero `bug:` lines on each, two candidates from the static pass on each.

# `to_le_bits` in an unconstrained function crashes the compiler

Three lines of ordinary Noir make `nargo compile` panic. The compiler says so
itself.

```noir
unconstrained fn main(x: Field) -> pub [bool; 255] {
    x.to_le_bits()
}
```

```
The application panicked (crashed).
Message:  ToRadix num_limbs (255) exceeds the maximum useful number of limbs (254) for this field
Location: compiler/noirc_evaluator/src/brillig/brillig_ir/codegen_intrinsic.rs:78

This is a bug. We may have already fixed this in newer versions of Nargo so try
searching for similar issues at https://github.com/noir-lang/noir/issues/.
```

## The threshold is 255

| `N` | result |
| ---: | --- |
| 253, 254 | compiles |
| **255, 256, 300** | **panic** |

254 is the bit width of the field, so any request for more bits than the field
has trips the assertion at `codegen_intrinsic.rs:78`:

```rust
assert!(
    target_array.size.0 <= F::max_num_bits(),
    "ToRadix num_limbs ({}) exceeds the maximum useful number of limbs ({}) for this field",
    ...
);
```

## Only the unconstrained path, and only the bit variants

| program | result |
| --- | --- |
| `unconstrained fn main(...) -> [bool; 255] { x.to_le_bits() }` | **panic** |
| `unconstrained fn main(...) -> [bool; 255] { x.to_be_bits() }` | **panic** |
| `fn main(...) -> [bool; 255] { x.to_le_bits() }` (constrained) | compiles |
| `unconstrained fn main(...) -> [u8; 255] { x.to_le_bytes() }` | `error: N must be less than or equal to modulus_le_bytes` |

The last row is the point: the neighbouring method rejects the same oversized
`N` with a proper diagnostic. The clean path exists; the bit variants do not
reach it, and an internal assertion fires instead. A constrained function is
also fine, so only Brillig codegen is affected.

## Versions

Panics on both the released **1.0.0-beta.26** (git `40d6574`) and
**1.0.0-beta.26+e088a9e**.

## Severity

A crash, not a soundness defect: nothing unsound is produced, the compiler stops.
It is still a compiler bug by the project's own definition — the panic handler
prints "This is a bug" and asks for an issue — and it is reachable from three
lines a user could plausibly write, for instance when parameterising a
decomposition by a generic that is not clamped to the field width.

## Prior art in the tracker

The "This is a bug" line is the project's generic panic handler; it fires on any
crash and says nothing about this one in particular. Searching the tracker:

* the exact assertion text, `exceeds the maximum useful number of limbs`, returns
  **no issues**;
* a search for `to_le_bits` + panic turns up nothing matching this case.

Two neighbours are worth noting, both closed:

* **#12736** — *ICE: `nargo execute` panics with `This is a bug` when calling
  `field.to_le_bytes::<0>()` (or `to_be_bytes`) on a non-zero field.* The same
  family from the other end: `N` too **small**, and the byte variant. It was
  filed and fixed, so the project treats this class as a defect worth closing.
* **#1129** — *std::merkle functions break for path array of length >254.* The
  same 254 threshold in a different function.

So this variant — `N` too large, bit variant, unconstrained only — appears
unreported. GitHub's search is not exhaustive and an issue phrased differently
could exist, but the exact assertion text appears nowhere.

## Reproducing

```bash
nargo compile --force     # panics
```

`panic.txt` holds the full output.

## How it was found

Not by hand. Noir's own `tooling/ssa_fuzzer` has five comparison modes, four of
them marked `#[allow(dead_code)]` and never enabled. Running them (see
`../ssa-fuzzer-constant-mode-broken/`) surfaced this assertion among the
crashes, and it turned out to be reachable from ordinary source rather than only
from the fuzzer's hand-built SSA.

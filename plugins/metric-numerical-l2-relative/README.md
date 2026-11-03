# metric-numerical-l2-relative

A **`SemanticEquivalent` metric** (spec §7.5) for numerical workloads — matrix
products, simulations, anything whose replicas agree up to floating-point
noise: the **relative L2 distance** between two numeric vectors.

* Implements `entangle:integrity/metric@0.1.0` — `compare(a, b) -> f64` — in
  the `metric-plugin` world. Not a `run` plugin.
* **Tier 2**, `runtime = "wasm"`, no capabilities. Runs only on the submitter,
  once per replica pair.

## Input encoding

Each replica output is **UTF-8 text holding a flat list of numbers**:

* separated by commas (optionally padded with whitespace) or by whitespace:
  `1, 2, 3`, `1 2 3` and `1,2\n3` are the same vector;
* optionally wrapped in one pair of square brackets, so a flat JSON array such
  as `[1.5, -2, 3e-4]` works unchanged;
* each number in Rust `f64` syntax and finite (`NaN` / `inf` are refused);
* `""` and `[]` are the empty vector.

Invalid UTF-8, empty fields (`1,,2`), unbalanced brackets, nested arrays or
non-numbers make an output **unparseable**.

## Distance

```text
d(a, b) = ‖a − b‖₂ / max(‖a‖₂, ‖b‖₂)
```

Symmetric, scale-invariant, in `[0, 2]`; two zero (or empty) vectors are at
distance 0. Values are pre-scaled by the largest magnitude, so inputs near
`f64::MAX` do not overflow. Vectors of **different lengths** or an
**unparseable** output are incomparable: the distance is `+inf`, which never
agrees with anything (the metric contract's "incomparable"). The result is
never `NaN` or negative.

| a | b | distance |
|---|---|---|
| `[1, 2, 3]` | `1 2 3` | 0 |
| `[3, 4]` | `[3, 4.1]` | ≈ 0.0197 |
| `[1, 0]` | `[0, 1]` | √2 |
| `[1, 2]` | `[1, 2, 3]` | +inf |

A threshold of `1e-6` accepts replicas that agree to about six significant
digits.

## Tests

`cargo test` runs the parser and the math natively (`src/l2.rs`).

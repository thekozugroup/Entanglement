# metric-bleu-4

A **`SemanticEquivalent` metric** (spec §7.5): the distance between two text
outputs is `1 − BLEU-4`. Use it to replicate a non-deterministic text workload
(LLM inference, translation, summarisation) on several peers and accept the
answer only when enough replicas say essentially the same thing.

* Implements `entangle:integrity/metric@0.1.0` — `compare(a, b) -> f64` — in
  the `metric-plugin` world (`crates/entangle-wit/wit-integrity/metric.wit`).
  It is **not** a `run` plugin: `entangle plugins invoke` cannot call it.
* **Tier 2**, `runtime = "wasm"`, no capabilities. It runs only on the
  **submitter**, once per replica pair; workers never load it.
* Never fails: every pair of byte strings gets a distance in `[0, 1]`.

## Definition

* **Tokens** — UTF-8 (invalid bytes become U+FFFD), split on whitespace. Case
  and punctuation are kept: `Hello,` is one token.
* **Modified n-gram precision** `p_n` for `n = 1..4`, candidate counts clipped
  by reference counts. `a` is the candidate, `b` the reference.
* **Smoothing** — add-one for `n ≥ 2` (Lin & Och 2004): identical short
  answers (fewer than 4 tokens) still score BLEU 1. `p_1 = 0` gives BLEU 0.
* **Brevity penalty** — `1` if the candidate is longer than the reference,
  else `exp(1 − r/c)`.
* `BLEU = BP · (p_1 p_2 p_3 p_4)^(1/4)`; two empty outputs score 1, one empty
  output scores 0.
* **distance = 1 − BLEU**.

BLEU is asymmetric; the scheduler always compares replica pairs in a fixed
canonical order (by output BLAKE3), so verification is reproducible.

| a | b | distance |
|---|---|---|
| `Hello, world!` | `Hello,   world!` | 0 |
| `the cat sat on the mat` | `the cat is on the mat` | 1 − (1/18)^¼ ≈ 0.514 |
| `the cat` | `the cat sat on the mat` | 1 − e⁻² ≈ 0.865 |
| `a b c` | `x y z` | 1 |

## Using it

```bash
entangle plugins build plugins/metric-bleu-4 --out ~/.entangle/plugins/metric-bleu-4
entangle compute dispatch <plugin-id> --input '…' \
  --integrity semantic-equivalent \
  --metric <your-fingerprint>/metric-bleu-4@0.1.0 \
  --replicas 3 --quorum 2 --threshold 0.15
```

The metric's publisher key must be on the **submitter's** keyring (§7.5 Rule
2); a metric signed by anyone else is refused before anything is dispatched.

## Tests

`cargo test` runs the math natively (`src/bleu.rs`); the built component is
exercised end to end by `crates/entangle-scheduler/tests/integrity_atc.rs`
(fixture rebuilt with `crates/entangle-scheduler/tests/fixtures/build.sh`).

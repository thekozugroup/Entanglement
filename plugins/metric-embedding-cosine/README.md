# metric-embedding-cosine

A **`SemanticEquivalent` metric** (spec §7.5) for free-text outputs — LLM
answers, summaries, translations, anything whose replicas say the same thing
in different words: **one minus the cosine similarity** of the two outputs'
embeddings.

* Implements `entangle:integrity/metric@0.1.0` — `compare(a, b) -> f64` — in
  the `metric-plugin` world. Not a `run` plugin.
* **Tier 2**, `runtime = "wasm"`, no capabilities. Runs only on the submitter,
  once per replica pair.

## Embedding

* An output that is **a flat list of finite numbers** (comma- or
  whitespace-separated, optionally one pair of square brackets — a JSON array
  such as `[0.12, -0.5, 3e-2]`) is taken as its own embedding: a workload that
  returns embeddings from its own model is compared directly.
* Any other **UTF-8 text** is embedded with a pinned **feature-hashing**
  model: lower-cased words (runs of alphanumeric characters) at weight 1.0 and
  their space-padded character trigrams at weight 0.5, each hashed (64-bit
  FNV-1a, defined in the source) to one of 512 signed buckets. No model
  weights, no randomness: the same bytes embed identically on every node.

This is **not a neural sentence-embedding model** (spec §7.5 names "a pinned
sentence-embedding model"): shipping one inside a tier-2 metric component is
out of scope for this build. Bag-of-words-and-trigrams similarity catches
rewording, inflection, case and punctuation, but not synonyms; for those,
return embeddings from the workload itself (the vector form above).

## Distance

```text
d(a, b) = 1 − cos(e(a), e(b)),  in [0, 2]
```

| a | b | distance |
|---|---|---|
| `The cat sat on the mat.` | `the cats sat on a mat` | ≈ 0.2 |
| `The cat sat on the mat.` | `Quarterly revenue grew by four percent.` | ≈ 1 |
| `Hello, World!` | `hello world` | 0 |
| `[3, 4]` | `[4, 3]` | 0.04 |
| `[1, 2]` | `[1, 2, 3]` | +inf |

Two outputs without a single word (or two empty vectors) are at distance 0;
one empty and one not, at 1. **Incomparable** outputs — not UTF-8, a vector
against text, vectors of different lengths — are at `+inf`, which never
agrees. The result is never `NaN` or negative.

A threshold around `0.3` accepts paraphrases of one answer and refuses
different answers; tune it for the workload.

## Tests

`cargo test` runs the embedding and the math natively (`src/cosine.rs`).

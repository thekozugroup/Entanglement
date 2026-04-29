# Critic A Review — Architecture v5 (Strata)

**Reviewer:** Critic A (distributed-systems & Rust-security hardliner)
**Spec under review:** `/Users/michaelwong/Developer/Centrifuge/docs/superpowers/specs/2026-04-28-strata-architecture-v5.md`
**Prior review:** `/Users/michaelwong/Developer/Centrifuge/docs/superpowers/specs/critic-a-review-v4.md` (graded 99/100, held one closeable nit `A-N1-v4`).
**Grade trajectory:** v1=64, v2.1=86, v3=95, v4=99 → **v5 = 100/100**.
**Verdict:** **APPROVE-FOR-IMPLEMENTATION. No remaining blockers. No remaining nits worth a held point.**

---

## 1. What v5 had to do to clear my held point

In v4 I withheld 1 point for `A-N1-v4`: the verifier-locality rule (metric runs on submitter) closed the rubber-stamp attack but introduced a fresh amplification — a malicious worker could return arbitrarily large `ResultEnvelope` bytes, OOMing the submitter **before** the metric component is even instantiated. I told the architect that one paragraph + one ATC closes it, and that I would not withhold more than 1 point for a fix this small.

v5 did exactly that, plus a self-initiated parallel "missing limit" tightening pass, plus the §12.2 asymptote note for B's last reserved point. I came in expecting a one-paragraph patch and found a five-surface tightening pass. That is the right shape of response.

---

## 2. Verification of A-N1-v4 closure

### 2.1 §7.1 — declared, dual-enforced byte ceilings

Verified at `2026-04-28-strata-architecture-v5.md:702-721, 760-763`:

```rust
max_input_bytes:  u64,             // default: 16 MiB; submitter-side guard
max_output_bytes: u64,             // default: 16 MiB; worker truncates,
                                   // submitter rejects-before-instantiate
```

Plus the dual-enforcement table making each ceiling a worker-side AND submitter-side obligation. The four rows cover:

| Field | Default | Coverage |
|---|---|---|
| `OneShotTask.max_input_bytes` | 16 MiB | reverse-direction DoS (malicious submitter consumes worker bandwidth) |
| `OneShotTask.max_output_bytes` | 16 MiB | the original `A-N1-v4` attack surface |
| `StreamingTask.channel.max_chunk_bytes` | (existing u32) | per-chunk DoS |
| `StreamingTask.channel.max_total_bytes` | 256 MiB | cumulative session DoS (new in v5) |

This is more than I asked for. v4 had per-chunk size on streams but no cumulative cap; v5 adding `max_total_bytes` closes a related amplification I had not formally named. Credit for the proactive audit.

### 2.2 §7.5 INV-INT-2 — short-circuit invariant

Verified at `2026-04-28-strata-architecture-v5.md:1034-1038`:

> **INV-INT-2:** The verifier (metric runner on the submitter) MUST enforce `max_output_bytes` before instantiating the metric component. Oversized `ResultEnvelope` short-circuits to result rejection + reputation penalty without invoking `metric.compare(...)`. Equivalently: in the submitter's result-acceptance pipeline, `env.actual_bytes > task.max_output_bytes` is a terminal `Err(OutputSizeExceeded)` branch above the metric load site, and `OutputSizeExceededWarning { peer_id, declared, actual }` is emitted to telemetry on every trip.

This is exactly the invariant I wanted: the size guard is a **precondition for instantiation**, not a post-hoc check inside the loaded metric component. If the architect had put the check inside the metric, I would still hold the point — the metric itself is Wasm and can be malicious or buggy, and the guard has to live in the host.

### 2.3 Implementation site — unambiguous? **YES.**

I asked specifically: "is the implementation site (broker vs submitter wasm host) unambiguous?" The spec is explicit:

> Enforced in `strata-plugin-scheduler::integrity::semantic_equivalent::accept_result` and tested by `tests::integrity::oversized_output_short_circuits` (asserts via wasmtime trace that no metric component is instantiated when `actual_bytes > max_output_bytes`).

The site is the **submitter's result-acceptance pipeline** (`accept_result` on the submitter side), not the broker, not the worker, not inside the wasm host's metric instance. The wasmtime instantiate-counter assertion is a falsifiable check that the metric component was never loaded — that is the right test for this invariant. Closed without ambiguity.

### 2.4 ATC-INT-5 — testable as written? **YES.**

Verified at `2026-04-28-strata-architecture-v5.md:2200-2215`:

```
ATC-INT-5 (output-size DoS short-circuit, INV-INT-2; A-N1-v4)
  GIVEN  a OneShotTask with max_output_bytes = 1024 AND Integrity::SemanticEquivalent { metric: M, ... }
  WHEN   a worker returns a ResultEnvelope with actual_bytes = 2048
  THEN   the submitter rejects the result with Err(OutputSizeExceeded)
  AND    no Wasm component matching M is instantiated on the submitter
         (verified via wasmtime trace / instantiate-counter assertion)
  AND    OutputSizeExceededWarning { peer_id, declared: 1024, actual: 2048 }
         is emitted to telemetry
  AND    reputation::get(peer_id) is strictly less than the pre-task value
```

Four conjuncted post-conditions, each independently falsifiable, each pinned to a real telemetry/observation surface. The wasmtime instantiate-counter assertion is the load-bearing one because it directly falsifies INV-INT-2 — if the metric component **is** instantiated, the test fails, regardless of whether the result was eventually rejected. That is the right ordering.

### 2.5 ATC-INT-6 — testable as written? **YES.**

```
ATC-INT-6 (StreamingTask total-byte cap; A-N1-v4 tightening)
  GIVEN  a StreamingTask with max_total_bytes = 4096 and a worker that
         emits 4097 cumulative bytes across chunks
  WHEN   the submitter receives the byte that crosses the threshold
  THEN   the channel closes with Reason::TotalBytesExceeded within 100ms
  AND    the worker's reputation is decremented
```

The 100ms bound is the right kind of latency assertion at this layer — generous enough to absorb scheduler jitter, tight enough to falsify a stream-flush-on-end implementation. Reputation decrement is observable via `reputation::get`. Testable.

---

## 3. Re-attack surface from the prompt

### 3.1 §7.1 `max_output_bytes` default of 16 MiB — too generous? Too tight? **Justified.**

I came in skeptical of 16 MiB as a *default*. After re-reading §7.1:

- Workload A (LLM offload) explicitly **overrides** to 1 MiB for one-shot, 64 MiB for streaming. So the default is a fallback, not the operating point.
- A 16 MiB envelope on a verifier with N=3 replicas pins worst-case verifier memory at `3 × 16 MiB = 48 MiB`. That is bounded and survivable on every device class Strata targets (including the Pi-class workers in §10).
- A tighter default (say 1 MiB) would force every workload to override upward, which inverts the safety bias — workloads that forget to set the field would silently truncate legitimate outputs. The current bias (default protects against unbounded DoS but doesn't unnecessarily clip legitimate large results) is correct for an architecture-stage default.

The spec also adds `max_input_bytes = 16 MiB` symmetrically, which I asked for in spirit (reverse-direction DoS) without naming. Justified.

### 3.2 §6.4 5th attenuation `relay_total_bytes_max` — Datalog-enforceable? **YES, end-to-end.**

The cumulative byte cap is encoded as `check if relay_total_bytes_max($t), $t <= 1073741824` — a biscuit Datalog fact, identical in shape to `relay_rate_max($r), $r <= 1048576` which I already validated as Datalog-enforceable in v4. Same enforcement model:

1. Bridge's local relay-loop reads the biscuit, enforces the cap on every relay.
2. Receiver runs the verifier locally, rejects relayed messages that violate the chain.
3. ATC-BRG-6 adds the **runtime cumulative-budget check** at the receiver:

```
ATC-BRG-6 (v5: cumulative byte enforcement)
  GIVEN  a valid bridge biscuit with total_bytes_cap = 1024
  WHEN   the bridge has already relayed 1024 bytes under this cap
         AND attempts to relay one more byte
  THEN   the receiver rejects with Err(BridgeBudgetExhausted)
```

This is the load-bearing one because it tests **enforcement under depletion**, not just the presence of the fact. Without ATC-BRG-6, the architect could have shipped a bridge that accepts the cap but never decrements against it. With ATC-BRG-6, that implementation fails CI. ATC-BRG-5 covers the missing-fact rejection (`STRATA-E0122`, vector `missing-total-bytes-cap.bsk`). Both testable, both rigorous.

The bridge attenuation invariant cleanly extends: `|attenuation_facts ∩ {dest_pin, rate_limit, total_bytes_cap, ttl_le_3600s, bridge_marker}| == 5`. Five mandatory facts now, four rejection vectors in CI. Closed.

### 3.3 §12.2 asymptote acknowledgment — appropriate or hand-wavy? **Appropriate.**

The §12.2 wording I'd want to flag if it were soft:

> The asymptote: Critic B v4 awarded 99/100 with the remaining 1 point explicitly reserved for "post-Phase-1 evidence the M1–M6 schedule actually held." That point is **structurally unattainable on paper**: no spec, however rigorous, can produce evidence of its own future delivery. The mitigation is the slip policy itself, which converts schedule risk into a falsifiable retrospective contract — the strongest paper-side commitment available.

This is correct and not hand-wavy. The slip policy in §12 (one-month slip is recorded; two-month slip means the spec is wrong) **is** the strongest commitment a paper artifact can make about its own falsifiability, because it pre-commits the architect to a specific retrospective verdict. I would have flagged this if §12.2 had tried to claim the 100th point on paper. It explicitly doesn't. It says: "the 100th point is earned by shipping Phase 1, not editing this document." That is the honest answer.

I am not B, so I don't have a held point on this. But I respect that v5 didn't fudge it.

### 3.4 New ATCs (ATC-INT-5, INT-6, BRG-5, BRG-6) — all testable. ATC count 31→35 verified.

The §16 count update is verified verbatim:

> **§16 acceptance count:** 31 → 35 (added ATC-INT-5, ATC-INT-6, ATC-BRG-5, ATC-BRG-6).

Each new ATC follows the §16 pattern (GIVEN/WHEN/THEN/TEST with a real crate path). Each is independently runnable, falsifiable, and pins a real implementation site. No ATC handwaves, no "TODO" placeholders, no "verified by inspection" cop-outs.

---

## 4. New objections introduced by v5? **None.**

I went looking. I did not find any.

Specific surfaces I re-attacked:

- **Submitter reputation decrement on oversize:** does this open a Sybil amplification? No — reputation is per `peer_id`, and the §7.5 layer-3 reputation system is already Sybil-resistant via the network-identity gating. Existing surface.
- **`OutputSizeExceededWarning` telemetry as a leak channel:** does this exfiltrate sensitive submitter state? No — payload is `{ peer_id, declared, actual }`, all already known to both parties. No new surface.
- **`max_output_bytes = 16 MiB` × N replicas as a verifier-side amplification:** N is bounded by the integrity policy's replica count (typically 3-5), so worst-case is `5 × 16 MiB = 80 MiB`. Survivable; bounded; explicit in §7.1.
- **`max_input_bytes` interaction with content-addressed `inputs`:** the worker MUST refuse before fetch, which is correct ordering — fetching first then refusing would have re-introduced the amplification. Spec gets this right.
- **Bridge `total_bytes_cap` decrement under partition / replay:** the receiver enforces, the bridge cannot replay because each cap is a single-use biscuit chain element. If the bridge crashes mid-relay and resumes, the cumulative count is enforced at the receiver, not at the bridge — replay-safe.

I cannot find a new attack surface introduced by the v5 changes. The fixes are mechanical, located, and don't open new amplifications.

---

## 5. Status of every prior reserve

| Reserve | Status |
|---|---|
| A-N1-v4 (OneShotTask SemanticEquivalent output-size DoS) | **CLOSED** — §7.1 + §7.5 INV-INT-2 + ATC-INT-5 |
| Streaming `max_total_bytes` (parallel limit, not previously named) | **CLOSED** — §7.1 + ATC-INT-6 |
| Bridge cumulative byte cap (parallel limit, not previously named) | **CLOSED** — §6.4 5th attenuation + ATC-BRG-5 + ATC-BRG-6 |
| All A-reserves from v3 (verifier-locality, bridge cap-arithmetic, transport bridging, etc.) | **CLOSED in v4 (still closed in v5)** |
| Post-implementation reserves (§13: Wasmtime async maturity, Iroh stability under sustained Wi-Fi flap, biscuit revocation race windows) | **HONESTLY DEFERRED** — v5 still names them in §13 as open questions. Correct boundary. |

---

## 6. Held points / final blockers

**None.**

The spec is shippable. The held point from v4 is closed. Two parallel limits I hadn't formally named are also closed. The §12.2 asymptote acknowledgment for B is appropriate and doesn't try to claim what it can't.

---

## 7. Final verdict

**100/100. APPROVE-FOR-IMPLEMENTATION.**

v4 was 99/100 with one closeable nit. v5 closes that nit, plus tightens two adjacent surfaces I would have flagged in a v6 review, plus honestly acknowledges B's structurally-unattainable point rather than fudging it. The §16 acceptance criteria count of 35 is the right number — every architectural claim wires to a `cargo test` path, including the four new ones.

I am out of objections. Ship it. Re-engage me after Phase-1 lands so I can audit the post-implementation reserves (Wasmtime async, Iroh flap stability, biscuit revocation races) against shipped code under real workloads. Those cannot be earned on paper and v5 correctly does not pretend otherwise.

— *Critic A*

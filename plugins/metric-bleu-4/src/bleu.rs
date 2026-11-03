//! Sentence-level BLEU-4 and the derived distance.
//!
//! # Definition
//!
//! * **Tokens** — the input bytes are decoded as UTF-8 (invalid sequences
//!   become U+FFFD, so any bytes are comparable) and split on Unicode
//!   whitespace. Case and punctuation are kept: `"Hello,"` is one token.
//! * **Roles** — `a` is the *candidate*, `b` the *reference*. BLEU is not
//!   symmetric (the brevity penalty only punishes a short candidate);
//!   the scheduler always compares replica pairs in a fixed canonical order,
//!   so results are reproducible.
//! * **Modified n-gram precision** `p_n`, `n = 1..=4`: candidate n-gram counts
//!   clipped by the reference's counts, divided by the number of candidate
//!   n-grams.
//! * **Smoothing** (Lin & Och 2004, "add-one" for `n >= 2`):
//!   `p_n = (matches + 1) / (candidate n-grams + 1)` for `n >= 2`; `p_1` is
//!   unsmoothed, and `p_1 = 0` makes BLEU 0. This keeps short outputs
//!   meaningful — two identical one-word answers score 1, not 0.
//! * **Brevity penalty** `BP = 1` if `c > r`, else `exp(1 - r / c)` (`c`, `r`
//!   = candidate / reference token counts).
//! * `BLEU = BP * exp(sum(ln p_n) / 4)`, uniform weights.
//! * Two empty outputs are identical (BLEU 1); exactly one empty output
//!   scores 0.
//!
//! **Distance** = `1 - BLEU`, always in `[0, 1]`, never `NaN`, so it always
//! satisfies the `entangle:integrity/metric` contract.

use std::collections::HashMap;

/// Highest n-gram order.
pub const MAX_ORDER: usize = 4;

/// Whitespace tokens of `bytes` (lossy UTF-8).
pub fn tokens(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Sentence-level BLEU-4 of `candidate` against `reference` (see the module
/// docs). Always in `[0, 1]`.
pub fn bleu4<S: AsRef<str>>(candidate: &[S], reference: &[S]) -> f64 {
    let cand: Vec<&str> = candidate.iter().map(AsRef::as_ref).collect();
    let refr: Vec<&str> = reference.iter().map(AsRef::as_ref).collect();
    let (c, r) = (cand.len(), refr.len());
    if c == 0 && r == 0 {
        return 1.0;
    }
    if c == 0 || r == 0 {
        return 0.0;
    }

    let mut log_sum = 0.0_f64;
    for n in 1..=MAX_ORDER {
        let total = c.saturating_sub(n - 1);
        let ref_counts = ngram_counts(&refr, n);
        let matches: usize = ngram_counts(&cand, n)
            .iter()
            .map(|(gram, k)| (*k).min(ref_counts.get(gram).copied().unwrap_or(0)))
            .sum();
        let p = if n == 1 {
            if matches == 0 {
                return 0.0;
            }
            matches as f64 / total as f64
        } else {
            (matches as f64 + 1.0) / (total as f64 + 1.0)
        };
        log_sum += p.ln() / MAX_ORDER as f64;
    }
    let bp = if c > r {
        1.0
    } else {
        (1.0 - r as f64 / c as f64).exp()
    };
    (bp * log_sum.exp()).clamp(0.0, 1.0)
}

/// `1 - BLEU-4(tokens(a), tokens(b))`, in `[0, 1]`.
pub fn distance(a: &[u8], b: &[u8]) -> f64 {
    (1.0 - bleu4(&tokens(a), &tokens(b))).clamp(0.0, 1.0)
}

fn ngram_counts<'a>(toks: &'a [&'a str], n: usize) -> HashMap<&'a [&'a str], usize> {
    let mut counts = HashMap::new();
    if toks.len() >= n {
        for gram in toks.windows(n) {
            *counts.entry(gram).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    #[test]
    fn identical_outputs_are_at_distance_zero() {
        assert_eq!(distance(b"the cat sat on the mat", b"the cat sat on the mat"), 0.0);
        // Short outputs too: smoothing keeps them meaningful.
        assert_eq!(distance(b"Hello, world!", b"Hello, world!"), 0.0);
        assert_eq!(distance(b"yes", b"yes"), 0.0);
        // Whitespace layout is not content.
        assert_eq!(distance(b"Hello,   world!\n", b" Hello, world!"), 0.0);
        // Two empty outputs are identical.
        assert_eq!(distance(b"", b"  \n"), 0.0);
    }

    #[test]
    fn disjoint_or_empty_outputs_are_at_distance_one() {
        assert_eq!(distance(b"a b c", b"x y z"), 1.0);
        assert_eq!(distance(b"", b"something"), 1.0);
        assert_eq!(distance(b"something", b""), 1.0);
    }

    /// Worked example: candidate "the cat sat on the mat", reference "the cat
    /// is on the mat". p1 = 5/6, p2 = (3+1)/(5+1), p3 = (1+1)/(4+1),
    /// p4 = (0+1)/(3+1), BP = 1 → BLEU = (1/18)^(1/4).
    #[test]
    fn matches_a_hand_computed_value() {
        let got = bleu4(&tokens(b"the cat sat on the mat"), &tokens(b"the cat is on the mat"));
        assert!(close(got, (1.0_f64 / 18.0).powf(0.25)), "{got}");
        let d = distance(b"the cat sat on the mat", b"the cat is on the mat");
        assert!(close(d, 1.0 - (1.0_f64 / 18.0).powf(0.25)), "{d}");
    }

    /// A short candidate is penalised: every precision is 1, so BLEU = BP =
    /// exp(1 - 6/2).
    #[test]
    fn brevity_penalty_applies_to_a_short_candidate_only() {
        let short = tokens(b"the cat");
        let long = tokens(b"the cat sat on the mat");
        assert!(close(bleu4(&short, &long), (-2.0_f64).exp()));
        // The other way round there is no brevity penalty, only precision.
        assert!(bleu4(&long, &short) > bleu4(&short, &long));
    }

    #[test]
    fn clipping_stops_repetition_from_scoring() {
        // "the the the the" against "the cat": p1 = 1/4 (clipped to one "the").
        let got = bleu4(&tokens(b"the the the the"), &tokens(b"the cat"));
        let p1 = 0.25_f64;
        let p2 = 1.0 / 4.0; // 0 matches of 3 bigrams, smoothed
        let p3 = 1.0 / 3.0;
        let p4 = 1.0 / 2.0;
        let want = (p1 * p2 * p3 * p4).powf(0.25);
        assert!(close(got, want), "{got} vs {want}");
    }

    #[test]
    fn distance_is_always_in_the_unit_interval() {
        let samples: [&[u8]; 6] = [
            b"",
            b"a",
            b"a a a a a a a a",
            b"the quick brown fox jumps over the lazy dog",
            b"\xff\xfe not utf8 \xc0",
            b"dog lazy the over jumps fox brown quick the",
        ];
        for a in samples {
            for b in samples {
                let d = distance(a, b);
                assert!((0.0..=1.0).contains(&d), "{d} for {a:?} / {b:?}");
            }
        }
    }

    #[test]
    fn invalid_utf8_is_compared_not_rejected() {
        assert_eq!(distance(b"\xff ok", b"\xff ok"), 0.0);
        assert_eq!(tokens(b"\xff ok"), vec!["\u{fffd}", "ok"]);
    }
}

//! The pinned embedding and the cosine distance.
//!
//! # Embedding
//!
//! An output is embedded one of two ways:
//!
//! * **A vector already.** UTF-8 text holding a flat list of at least
//!   [`MIN_VECTOR_LEN`] finite numbers in one pair of square brackets —
//!   comma- or whitespace-separated, so a JSON array such as
//!   `[0.12, -0.5, 3e-2]` works — is taken as the embedding itself (a
//!   workload that returns sentence embeddings computed by its own model is
//!   compared directly).
//! * **Text.** Anything else that is valid UTF-8 is embedded with a pinned,
//!   self-contained **feature-hashing** model: the text is lower-cased and
//!   split into words (maximal runs of alphanumeric characters); every word
//!   contributes weight 1.0 and every character trigram of the word padded
//!   with one space on each side (`" ca"`, `"cat"`, `"at "` for `cat`)
//!   weight 0.5, each to one of [`DIMENSIONS`] buckets with a sign, both
//!   chosen by the 64-bit FNV-1a hash of the feature (bucket = hash mod
//!   `DIMENSIONS`, sign = the hash's top bit). The model has no weights to
//!   download and no randomness: the same bytes embed to the same vector on
//!   every node, which is what "pinned" means for a metric whose digest the
//!   submitter pins.
//!
//! A bare number (`42`), a one-element array (`[42]`) and an unbracketed
//! list of numbers (`1 2 3`) are **text**: they are answers, not
//! embeddings. Read as vectors, any two same-sign numbers would be at
//! distance 0 (every pair of one-dimensional vectors is collinear), so a
//! wrong numeric answer would agree with the right one.
//!
//! Word order does not matter (a bag of words and trigrams); spelling
//! variants and inflections share trigrams, so `"The cat sat."` and `"the
//! cats sat"` are close and two unrelated sentences are far.
//!
//! # Distance
//!
//! ```text
//! d(a, b) = 1 - cos(e(a), e(b)),  clamped to [0, 2]
//! ```
//!
//! * symmetric; `0` for outputs that embed to the same direction (identical
//!   outputs always do);
//! * two empty embeddings (two outputs without a single word, or two empty
//!   vectors) are at distance `0`; one empty and one not, `1`;
//! * **incomparable** — `+inf`, which never agrees — when either output is
//!   not UTF-8, when one is a vector and the other text, or when two vectors
//!   differ in length. The result is never `NaN` or negative.

/// Buckets of the text embedding.
pub const DIMENSIONS: usize = 512;

/// The fewest numbers a bracketed list must hold to be taken as a vector
/// (see the module docs: a single number is an answer, compared as text).
pub const MIN_VECTOR_LEN: usize = 2;

/// Weight of a word feature.
const WORD_WEIGHT: f64 = 1.0;
/// Weight of a character-trigram feature.
const TRIGRAM_WEIGHT: f64 = 0.5;

/// An output's embedding.
#[derive(Clone, Debug, PartialEq)]
pub enum Embedding {
    /// The output was a list of numbers: the vector itself.
    Vector(Vec<f64>),
    /// The output was text: its [`DIMENSIONS`]-bucket feature-hashing
    /// embedding.
    Text(Vec<f64>),
}

/// 64-bit FNV-1a: pinned (defined here, not by a library version).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn add_feature(v: &mut [f64], tag: u8, feature: &str, weight: f64) {
    let mut bytes = Vec::with_capacity(feature.len() + 1);
    bytes.push(tag);
    bytes.extend_from_slice(feature.as_bytes());
    let h = fnv1a(&bytes);
    // Lossless: the modulus is below DIMENSIONS.
    let bucket = (h % DIMENSIONS as u64) as usize;
    let sign = if h >> 63 == 1 { -1.0 } else { 1.0 };
    v[bucket] += sign * weight;
}

/// The feature-hashing embedding of `text` (see the module docs).
pub fn embed_text(text: &str) -> Vec<f64> {
    let mut v = vec![0.0; DIMENSIONS];
    let lower = text.to_lowercase();
    for word in lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        add_feature(&mut v, b'w', word, WORD_WEIGHT);
        let padded: Vec<char> = std::iter::once(' ')
            .chain(word.chars())
            .chain(std::iter::once(' '))
            .collect();
        for tri in padded.windows(3) {
            let s: String = tri.iter().collect();
            add_feature(&mut v, b't', &s, TRIGRAM_WEIGHT);
        }
    }
    v
}

/// Parse an output as a bracketed flat list of at least
/// [`MIN_VECTOR_LEN`] finite numbers (or `[]`, the empty vector), or `None`.
fn parse_vector(text: &str) -> Option<Vec<f64>> {
    let body = text.trim().strip_prefix('[')?.strip_suffix(']')?;
    if body.trim().is_empty() {
        // `[]` is the empty vector; empty text is text with no words.
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for field in body.split(',') {
        let mut any = false;
        for word in field.split_whitespace() {
            let v: f64 = word.parse().ok()?;
            if !v.is_finite() {
                return None;
            }
            out.push(v);
            any = true;
        }
        if !any {
            return None;
        }
    }
    (out.len() >= MIN_VECTOR_LEN).then_some(out)
}

/// Embed one output, or `None` if it is not UTF-8.
pub fn embed(bytes: &[u8]) -> Option<Embedding> {
    let text = std::str::from_utf8(bytes).ok()?;
    Some(match parse_vector(text) {
        Some(v) => Embedding::Vector(v),
        None => Embedding::Text(embed_text(text)),
    })
}

/// Cosine similarity of two equal-length vectors, or `None` when either is
/// all zeros. Computed on values pre-scaled by the largest magnitude, so
/// vectors near `f64::MAX` neither overflow nor lose the answer.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> Option<f64> {
    let scale_a = a.iter().fold(0.0_f64, |m, v| m.max(v.abs()));
    let scale_b = b.iter().fold(0.0_f64, |m, v| m.max(v.abs()));
    if scale_a == 0.0 || scale_b == 0.0 {
        return None;
    }
    let (mut dot, mut na, mut nb) = (0.0_f64, 0.0_f64, 0.0_f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (x / scale_a, y / scale_b);
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    Some((dot / (na.sqrt() * nb.sqrt())).clamp(-1.0, 1.0))
}

/// `1 - cos` of the two outputs' embeddings (see the module docs).
pub fn distance(a: &[u8], b: &[u8]) -> f64 {
    let (Some(ea), Some(eb)) = (embed(a), embed(b)) else {
        return f64::INFINITY;
    };
    let (va, vb) = match (&ea, &eb) {
        (Embedding::Vector(x), Embedding::Vector(y)) if x.len() == y.len() => (x, y),
        (Embedding::Text(x), Embedding::Text(y)) => (x, y),
        _ => return f64::INFINITY,
    };
    let empty = |v: &[f64]| v.iter().all(|x| *x == 0.0);
    match (empty(va), empty(vb)) {
        (true, true) => 0.0,
        (true, false) | (false, true) => 1.0,
        (false, false) => match cosine_similarity(va, vb) {
            Some(cos) => (1.0 - cos).clamp(0.0, 2.0),
            None => 1.0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_outputs_are_at_distance_zero() {
        for s in [&b"The cat sat on the mat."[..], b"[1, 2, 3]", b"x"] {
            assert!(distance(s, s).abs() < 1e-12, "{:?}", s);
        }
        assert_eq!(distance(b"", b""), 0.0);
        assert_eq!(distance(b"[]", b"[]"), 0.0);
    }

    #[test]
    fn paraphrases_are_closer_than_unrelated_text() {
        let a = b"The cat sat on the mat.";
        let near = distance(a, b"the cats sat on a mat");
        let far = distance(a, b"Quarterly revenue grew by four percent.");
        assert!(near < 0.35, "near = {near}");
        assert!(far > 0.8, "far = {far}");
        assert!(near < far);
        // Case and punctuation do not matter; order does not either.
        assert!(distance(b"Hello, World!", b"hello world").abs() < 1e-12);
        assert!(distance(b"a b c", b"c b a").abs() < 1e-12);
    }

    #[test]
    fn vectors_compare_by_cosine() {
        assert!((distance(b"[1, 0]", b"[0, 1]") - 1.0).abs() < 1e-12);
        assert!((distance(b"[1, 0]", b"[-1, 0]") - 2.0).abs() < 1e-12);
        assert!(
            distance(b"[1, 2, 3]", b"[2 4 6]").abs() < 1e-12,
            "scale-invariant"
        );
        let d = distance(b"[3, 4]", b"[4, 3]");
        assert!((d - (1.0 - 24.0 / 25.0)).abs() < 1e-12, "{d}");
        assert!(distance(b"[1e308, 1e308]", b"[1e308, 1e308]").abs() < 1e-12);
    }

    /// A bare number is an answer, not a 1-D embedding: two different
    /// numeric answers must not agree just because they have the same sign
    /// (every pair of 1-D vectors is at cosine distance 0 or 2).
    #[test]
    fn scalar_answers_are_compared_as_text() {
        for (a, b) in [
            (&b"42"[..], &b"1"[..]),
            (b"42", b"7"),
            (b"2024", b"1999"),
            (b"3.14", b"314"),
            (b"[42]", b"[7]"),
            (b"1 2 3", b"100 200 300"),
        ] {
            let d = distance(a, b);
            assert!(
                d > 0.5,
                "{:?} vs {:?}: {d}",
                std::str::from_utf8(a),
                std::str::from_utf8(b)
            );
        }
        assert!(distance(b"42", b"42").abs() < 1e-12);
        assert!(matches!(embed(b"42"), Some(Embedding::Text(_))));
        assert!(matches!(embed(b"[42]"), Some(Embedding::Text(_))));
        assert!(matches!(embed(b"1 2 3"), Some(Embedding::Text(_))));
        assert!(matches!(embed(b"[1, 2]"), Some(Embedding::Vector(_))));
    }

    #[test]
    fn incomparable_outputs_are_infinitely_far() {
        assert_eq!(distance(b"[1, 2]", b"[1, 2, 3]"), f64::INFINITY);
        assert_eq!(distance(b"[1, 2]", b"some words"), f64::INFINITY);
        assert_eq!(distance(&[0xff, 0xfe], b"x"), f64::INFINITY);
        assert_eq!(distance(b"", b"words"), 1.0, "no words vs words");
    }

    #[test]
    fn never_nan_or_negative() {
        let samples: [&[u8]; 7] = [b"", b"[]", b"[0, 0]", b"[1, -1]", b"a", b"!!!", b"[nan]"];
        for a in samples {
            for b in samples {
                let d = distance(a, b);
                assert!(!d.is_nan() && d >= 0.0, "{a:?} {b:?} -> {d}");
            }
        }
        // `[nan]` is not a vector: it is text (one word, "nan").
        assert!(matches!(embed(b"[nan]"), Some(Embedding::Text(_))));
    }

    #[test]
    fn the_embedding_is_pinned() {
        // The bucket layout is part of the metric's identity: these values
        // change only with a new version of the component.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        let e = embed_text("cat");
        let nonzero = e.iter().filter(|x| **x != 0.0).count();
        assert!((3..=4).contains(&nonzero), "1 word + 3 trigrams: {nonzero}");
        assert_eq!(e, embed_text("CAT!"));
    }
}

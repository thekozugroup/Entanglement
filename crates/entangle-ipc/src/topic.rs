//! Topic identifiers for the IPC bus.

/// Topic identifier for the bus.  Stable, dot-separated, lowercase.
///
/// Examples: `"broker.audit"`, `"runtime.plugin.lifecycle"`, `"host.plugin.log"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Topic(String);

impl Topic {
    /// Construct a new `Topic`, returning an error if the string contains
    /// characters outside `[a-z0-9._-]`, is empty, or contains an empty
    /// segment (e.g. `"broker..audit"`, `".broker"`, `"broker."`).
    ///
    /// Empty segments are rejected rather than merely discouraged: allowing
    /// them lets otherwise-distinct topics collide under glob matching (an
    /// empty segment would silently satisfy a `*` wildcard), so they are
    /// invalid at construction time instead of being a matching footgun.
    pub fn new<S: Into<String>>(s: S) -> Result<Self, crate::IpcError> {
        let s = s.into();
        if s.is_empty()
            || s.split('.').any(|seg| seg.is_empty())
            || !s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
            })
        {
            return Err(crate::IpcError::InvalidTopic(s));
        }
        Ok(Self(s))
    }

    /// Return the topic as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test whether this topic matches a glob-style `pattern`.
    ///
    /// Rules:
    /// - `"**"` anywhere as the whole pattern matches everything.
    /// - A trailing `"**"` segment matches any number of additional segments.
    /// - A `"*"` segment matches exactly one segment.
    /// - Any other segment must match literally.
    ///
    /// This runs once per filtered subscriber per published envelope, so it
    /// allocates nothing: a wildcard-free pattern reduces to a byte
    /// comparison, and anything else walks both sides as iterators rather
    /// than collecting them into `Vec<&str>`.
    pub fn matches(&self, pattern: &str) -> bool {
        if pattern == "**" {
            return true;
        }

        // A trailing `"**"` segment means "and any number of further
        // segments". `pattern == "**"` was already handled above, so the only
        // other way for the final segment to be `"**"` is a `".**"` suffix.
        let (prefix, open_ended) = match pattern.strip_suffix(".**") {
            Some(prefix) => (prefix, true),
            None => (pattern, false),
        };

        // Fast path — a wildcard-free `prefix` needs no segment walk at all.
        // Splitting on `'.'` is injective, so "same segment list" is exactly
        // "same bytes"; the only extra rule is that an open-ended pattern may
        // stop at a segment boundary.
        if !prefix.as_bytes().contains(&b'*') {
            return match self.0.strip_prefix(prefix) {
                // Same segments, nothing left over.
                Some("") => true,
                // Leftover segments are only allowed by a trailing `**`, and
                // only at a segment boundary — `a.**` matches `a.b`, not `ab`.
                Some(rest) => open_ended && rest.starts_with('.'),
                None => false,
            };
        }

        let mut top = self.0.as_bytes().split(|&b| b == b'.');
        for p in prefix.as_bytes().split(|&b| b == b'.') {
            match top.next() {
                Some(t) if p == b"*" || p == t => {}
                // The topic ran out of segments, or this one did not match.
                _ => return false,
            }
        }
        // Without a trailing `**` the topic must be fully consumed.
        open_ended || top.next().is_none()
    }

    /// Validate a subscriber glob `pattern` (as passed to
    /// [`crate::Bus::subscribe_topic`] / [`crate::Bus::try_subscribe_topic`]
    /// and checked by [`Topic::matches`]).
    ///
    /// A pattern is valid glob syntax, not necessarily one that matches any
    /// topic currently in use — this catches structural mistakes, not
    /// semantic typos.
    ///
    /// Rejects:
    /// - an empty pattern,
    /// - any empty segment (e.g. `"broker..audit"`, `".broker"`, `"broker."`),
    /// - characters outside `[a-z0-9._-]` plus the `*` wildcard,
    /// - a `"**"` segment that is not the final segment of the pattern
    ///   (e.g. `"a.**.c"`) — [`Topic::matches`] only treats a *trailing*
    ///   `"**"` as a multi-segment wildcard, so anywhere else it is silently
    ///   treated as a literal segment that can never match a real topic.
    pub fn validate_pattern(pattern: &str) -> Result<(), crate::IpcError> {
        if pattern.is_empty() {
            return Err(crate::IpcError::InvalidTopic(pattern.to_string()));
        }
        if !pattern.chars().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == '.'
                || c == '-'
                || c == '_'
                || c == '*'
        }) {
            return Err(crate::IpcError::InvalidTopic(pattern.to_string()));
        }

        let segs: Vec<&str> = pattern.split('.').collect();
        if segs.iter().any(|seg| seg.is_empty()) {
            return Err(crate::IpcError::InvalidTopic(pattern.to_string()));
        }

        if let Some(pos) = segs.iter().position(|seg| *seg == "**") {
            if pos != segs.len() - 1 {
                return Err(crate::IpcError::InvalidTopic(pattern.to_string()));
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_segments() {
        // Previously accepted; empty segments used to alias under glob
        // matching (e.g. "broker.*.audit" would match "broker..audit").
        assert!(Topic::new("broker..audit").is_err());
        assert!(Topic::new(".broker").is_err());
        assert!(Topic::new("broker.").is_err());
        assert!(Topic::new("..").is_err());
    }

    #[test]
    fn new_still_accepts_valid_topics() {
        assert!(Topic::new("broker.audit").is_ok());
        assert!(Topic::new("a.b.c").is_ok());
        assert!(Topic::new("ent_runtime.plugin-lifecycle").is_ok());
    }

    /// `"**"` is only a multi-segment wildcard when it is a *whole* trailing
    /// segment. A segment that merely ends in `**` is a literal that can never
    /// match a real topic (topics cannot contain `*`).
    #[test]
    fn double_star_is_only_special_as_a_whole_trailing_segment() {
        let t = Topic::new("a.b.c").unwrap();
        assert!(t.matches("a.**"));
        assert!(t.matches("a.b.**"));
        assert!(t.matches("a.b.c.**"), "`**` may absorb zero segments");
        assert!(!t.matches("a.b**"), "`b**` is a literal segment");
        assert!(!t.matches("x**"));
        // Non-trailing `**` is a literal segment too (validate_pattern rejects
        // it up front, but `matches` must not silently reinterpret it).
        assert!(!t.matches("a.**.c"));
    }

    /// A pattern longer than the topic must not match, and a topic longer than
    /// a non-`**` pattern must not match either.
    #[test]
    fn arity_mismatch_never_matches_without_double_star() {
        let t = Topic::new("a.b").unwrap();
        assert!(!t.matches("a.b.c"), "pattern longer than topic");
        assert!(!t.matches("a"), "pattern shorter than topic");
        assert!(!t.matches("a.b.c.**"), "`**` prefix longer than topic");
        assert!(t.matches("a.*"));
        assert!(t.matches("*.*"));
    }

    #[test]
    fn validate_pattern_rejects_empty_pattern() {
        assert!(Topic::validate_pattern("").is_err());
    }

    #[test]
    fn validate_pattern_rejects_empty_segments() {
        assert!(Topic::validate_pattern("broker..audit").is_err());
        assert!(Topic::validate_pattern(".broker").is_err());
        assert!(Topic::validate_pattern("broker.").is_err());
    }

    #[test]
    fn validate_pattern_rejects_disallowed_characters() {
        assert!(Topic::validate_pattern("Broker.*").is_err(), "uppercase");
        assert!(Topic::validate_pattern("broker.#").is_err(), "hash");
        assert!(
            Topic::validate_pattern("broker audit").is_err(),
            "whitespace"
        );
        assert!(
            Topic::validate_pattern("broker.?").is_err(),
            "question mark"
        );
    }

    #[test]
    fn validate_pattern_rejects_non_trailing_double_star() {
        assert!(Topic::validate_pattern("a.**.c").is_err());
        assert!(Topic::validate_pattern("**.a").is_err());
        assert!(Topic::validate_pattern("a.**.**").is_err());
    }

    #[test]
    fn validate_pattern_accepts_valid_patterns() {
        assert!(Topic::validate_pattern("broker.audit").is_ok());
        assert!(Topic::validate_pattern("broker.*").is_ok());
        assert!(Topic::validate_pattern("broker.**").is_ok());
        assert!(Topic::validate_pattern("**").is_ok());
        assert!(Topic::validate_pattern("*").is_ok());
        assert!(Topic::validate_pattern("a.*.c").is_ok());
    }
}

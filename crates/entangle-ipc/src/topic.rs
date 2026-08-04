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
    pub fn matches(&self, pattern: &str) -> bool {
        if pattern == "**" {
            return true;
        }
        let pat_segs: Vec<&str> = pattern.split('.').collect();
        let top_segs: Vec<&str> = self.0.split('.').collect();

        if pat_segs.last() == Some(&"**") {
            let prefix = &pat_segs[..pat_segs.len() - 1];
            return top_segs.len() >= prefix.len()
                && prefix
                    .iter()
                    .enumerate()
                    .all(|(i, p)| *p == "*" || *p == top_segs[i]);
        }

        if pat_segs.len() != top_segs.len() {
            return false;
        }
        pat_segs
            .iter()
            .zip(top_segs.iter())
            .all(|(p, t)| *p == "*" || p == t)
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

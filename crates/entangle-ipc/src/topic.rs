//! Topic identifiers for the IPC bus.

/// Topic identifier for the bus.  Stable, dot-separated, lowercase.
///
/// Examples: `"broker.audit"`, `"runtime.plugin.lifecycle"`, `"host.plugin.log"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Topic(String);

impl Topic {
    /// Construct a new `Topic`, returning an error if the string contains
    /// characters outside `[a-z0-9._-]` or is empty.
    pub fn new<S: Into<String>>(s: S) -> Result<Self, crate::IpcError> {
        let s = s.into();
        if s.is_empty()
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
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

//! The `[lifecycle]` table of `entangle.toml` (spec §3.3, §4.4).
//!
//! ```toml
//! [lifecycle]
//! activation = "lazy"        # "eager" (default) | "lazy"
//! idle-timeout-secs = 300    # optional: drop the instance after this long idle
//! ```
//!
//! - `eager` (the default — the spec leaves it open, and it is how every
//!   plugin loaded before this table existed behaves): the plugin is
//!   instantiated when it loads.
//! - `lazy`: the plugin is verified (signature, keyring, tier ceiling,
//!   runtime kind, a compile of the component) when it loads, but only
//!   instantiated on its first invocation.
//! - `idle-timeout-secs`: once no call or stream has used the plugin for this
//!   long, its instance is dropped; the next invocation instantiates it
//!   again. Absent: never dropped.
//!
//! Both apply to wasm plugins only. A native plugin runs a fresh sandboxed
//! process per call and has no resident instance to defer or drop, so a
//! native manifest asking for `lazy` or an idle timeout is refused rather
//! than accepted and ignored.
//!
//! The raw [`crate::Manifest`] does not carry this table (so existing code
//! building a `Manifest` by hand is unaffected); it is read from the same
//! manifest text with [`parse`].

use crate::schema::Runtime;
use crate::validate::ValidationError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Longest accepted `idle-timeout-secs`: 7 days.
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// When a plugin is instantiated.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Activation {
    /// At load.
    #[default]
    Eager,
    /// On first invocation.
    Lazy,
}

/// The raw `[lifecycle]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct LifecycleSection {
    /// `activation`.
    pub activation: Activation,
    /// `idle-timeout-secs`.
    pub idle_timeout_secs: Option<u64>,
}

/// A validated `[lifecycle]`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Lifecycle {
    /// When the plugin is instantiated.
    pub activation: Activation,
    /// Drop the instance after this long without a call or stream.
    pub idle_timeout: Option<Duration>,
}

impl Lifecycle {
    /// Whether the plugin's instance may be absent while it is loaded
    /// (lazy, or an idle timeout), so the runtime must be able to
    /// instantiate it again.
    pub fn can_be_torn_down(&self) -> bool {
        self.activation == Activation::Lazy || self.idle_timeout.is_some()
    }
}

/// Only the `[lifecycle]` table of a manifest; every other key is ignored
/// here (the rest of the manifest is parsed into [`crate::Manifest`]).
#[derive(Deserialize)]
struct LifecycleOnly {
    #[serde(default)]
    lifecycle: Option<LifecycleSection>,
}

/// Read and validate the `[lifecycle]` table of the manifest `text`, for a
/// plugin of `runtime`. An absent table is the default (eager, no idle
/// timeout).
pub fn parse(text: &str, runtime: Runtime) -> Result<Lifecycle, ValidationError> {
    let raw: LifecycleOnly = toml::from_str(text)?;
    validate(raw.lifecycle.unwrap_or_default(), runtime)
}

/// Validate a raw `[lifecycle]` table (`ENTANGLE-E0780` on a bad value).
pub fn validate(section: LifecycleSection, runtime: Runtime) -> Result<Lifecycle, ValidationError> {
    let idle_timeout = match section.idle_timeout_secs {
        None => None,
        Some(0) => {
            return Err(ValidationError::InvalidLifecycle(
                "idle-timeout-secs must be at least 1".into(),
            ))
        }
        Some(s) if s > MAX_IDLE_TIMEOUT_SECS => {
            return Err(ValidationError::InvalidLifecycle(format!(
                "idle-timeout-secs {s} is above the maximum {MAX_IDLE_TIMEOUT_SECS} (7 days)"
            )))
        }
        Some(s) => Some(Duration::from_secs(s)),
    };
    let lifecycle = Lifecycle {
        activation: section.activation,
        idle_timeout,
    };
    if runtime == Runtime::Native && lifecycle.can_be_torn_down() {
        return Err(ValidationError::InvalidLifecycle(
            "activation = \"lazy\" and idle-timeout-secs apply to wasm plugins only; a native \
             plugin runs a fresh sandboxed process per call"
                .into(),
        ));
    }
    Ok(lifecycle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "[plugin]\nid = \"x\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n";

    #[test]
    fn absent_table_is_eager_without_timeout() {
        let l = parse(HEAD, Runtime::Wasm).unwrap();
        assert_eq!(l, Lifecycle::default());
        assert_eq!(l.activation, Activation::Eager);
        assert!(!l.can_be_torn_down());
    }

    #[test]
    fn spec_example_parses() {
        let text = format!("{HEAD}[lifecycle]\nactivation = \"lazy\"\nidle-timeout-secs = 300\n");
        let l = parse(&text, Runtime::Wasm).unwrap();
        assert_eq!(l.activation, Activation::Lazy);
        assert_eq!(l.idle_timeout, Some(Duration::from_secs(300)));
        assert!(l.can_be_torn_down());
        let eager = format!("{HEAD}[lifecycle]\nactivation = \"eager\"\nidle-timeout-secs = 5\n");
        let l = parse(&eager, Runtime::Wasm).unwrap();
        assert_eq!(l.activation, Activation::Eager);
        assert!(l.can_be_torn_down());
    }

    #[test]
    fn bad_values_are_refused() {
        for bad in [
            "[lifecycle]\nactivation = \"sometimes\"\n",
            "[lifecycle]\nidle_timeout_secs = 5\n",
            "[lifecycle]\nidle-timeout-secs = -1\n",
            "[lifecycle]\nwarmup = true\n",
        ] {
            assert!(
                matches!(
                    parse(&format!("{HEAD}{bad}"), Runtime::Wasm),
                    Err(ValidationError::Toml(_))
                ),
                "{bad}"
            );
        }
        for bad in [
            "[lifecycle]\nidle-timeout-secs = 0\n",
            "[lifecycle]\nidle-timeout-secs = 604801\n",
        ] {
            let err = parse(&format!("{HEAD}{bad}"), Runtime::Wasm).unwrap_err();
            assert!(err.to_string().starts_with("ENTANGLE-E0780"), "{err}");
        }
    }

    #[test]
    fn native_plugins_cannot_be_lazy_or_idle() {
        for t in [
            "[lifecycle]\nactivation = \"lazy\"\n",
            "[lifecycle]\nidle-timeout-secs = 60\n",
        ] {
            let err = parse(&format!("{HEAD}{t}"), Runtime::Native).unwrap_err();
            assert!(err.to_string().contains("wasm plugins only"), "{err}");
        }
        let eager = format!("{HEAD}[lifecycle]\nactivation = \"eager\"\n");
        assert!(parse(&eager, Runtime::Native).is_ok());
    }
}

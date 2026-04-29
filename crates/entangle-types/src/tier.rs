//! Tier enum representing the privilege level of a plugin.
//!
//! Tiers are ordered from least privileged (`Pure`, tier 1) to most
//! privileged (`Native`, tier 5). Each tier is a strict superset of the
//! capabilities available at lower tiers.
//!
//! # Specification reference
//! §4.2 of the Entanglement Architecture specification.

use std::fmt;

/// The five capability tiers defined by the Entanglement architecture.
///
/// Tiers form a total order: `Pure < Sandboxed < Networked < Privileged < Native`.
///
/// # Serialization
/// Serialized as the numeric value (1–5). Deserialization rejects values
/// outside that range.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u8", into = "u8")]
pub enum Tier {
    /// Tier 1 — pure computation; no I/O of any kind.
    Pure = 1,
    /// Tier 2 — sandboxed execution with scoped local storage.
    Sandboxed = 2,
    /// Tier 3 — network-capable; may open outbound connections to declared hosts.
    Networked = 3,
    /// Tier 4 — privileged; may access shared volumes and inter-plugin messaging.
    Privileged = 4,
    /// Tier 5 — native; full host access including Docker socket and subprocess execution.
    Native = 5,
}

impl Tier {
    /// Returns the one-line description from specification §4.2.
    pub fn description(&self) -> &'static str {
        match self {
            Tier::Pure => "Pure computation; no I/O of any kind.",
            Tier::Sandboxed => "Sandboxed execution with scoped local storage access.",
            Tier::Networked => "Network-capable; outbound connections to declared hosts.",
            Tier::Privileged => "Privileged; shared volumes and inter-plugin messaging.",
            Tier::Native => "Native; full host access including Docker socket.",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tier-{}", *self as u8)
    }
}

impl TryFrom<u8> for Tier {
    type Error = crate::errors::EntangleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Tier::Pure),
            2 => Ok(Tier::Sandboxed),
            3 => Ok(Tier::Networked),
            4 => Ok(Tier::Privileged),
            5 => Ok(Tier::Native),
            other => Err(crate::errors::EntangleError::Internal(format!(
                "invalid tier value: {other}; expected 1..=5"
            ))),
        }
    }
}

impl From<Tier> for u8 {
    fn from(t: Tier) -> u8 {
        t as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(Tier::Pure < Tier::Native);
        assert!(Tier::Pure < Tier::Sandboxed);
        assert!(Tier::Sandboxed < Tier::Networked);
        assert!(Tier::Networked < Tier::Privileged);
        assert!(Tier::Privileged < Tier::Native);
    }

    #[test]
    fn try_from_valid() {
        assert_eq!(Tier::try_from(1).unwrap(), Tier::Pure);
        assert_eq!(Tier::try_from(3).unwrap(), Tier::Networked);
        assert_eq!(Tier::try_from(5).unwrap(), Tier::Native);
    }

    #[test]
    fn try_from_zero_errors() {
        assert!(Tier::try_from(0).is_err());
    }

    #[test]
    fn try_from_six_errors() {
        assert!(Tier::try_from(6).is_err());
    }

    #[test]
    fn display() {
        assert_eq!(Tier::Pure.to_string(), "tier-1");
        assert_eq!(Tier::Native.to_string(), "tier-5");
    }

    #[test]
    fn round_trip_u8() {
        for n in 1u8..=5 {
            let t = Tier::try_from(n).unwrap();
            assert_eq!(u8::from(t), n);
        }
    }
}

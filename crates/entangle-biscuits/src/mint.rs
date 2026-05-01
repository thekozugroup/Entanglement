//! Biscuit minting and attenuation helpers (spec §6).
//!
//! [`mint`] creates a new root biscuit from a `biscuit_auth::KeyPair` and an initial [`ClaimSet`].
//! [`attenuate_biscuit`] appends an attenuation block signed by a fresh ephemeral key.

use biscuit_auth::{builder::BlockBuilder, Biscuit, PublicKey};

use crate::{claims::ClaimSet, errors::BiscuitError};

/// Mint a new biscuit token from `root_keypair` with the given claim set as the
/// authority block.
pub fn mint(
    root_keypair: &biscuit_auth::KeyPair,
    claims: &ClaimSet,
) -> Result<Vec<u8>, BiscuitError> {
    let mut builder = Biscuit::builder();
    for claim in &claims.claims {
        let fact_str = claim.as_datalog();
        builder = builder
            .fact(fact_str.as_str())
            .map_err(|e| BiscuitError::Build(e.to_string()))?;
    }
    let biscuit = builder
        .build(root_keypair)
        .map_err(|e| BiscuitError::Build(e.to_string()))?;
    biscuit
        .to_vec()
        .map_err(|e| BiscuitError::Build(e.to_string()))
}

/// Append an attenuation block to an existing biscuit.
///
/// The new block is signed by a fresh ephemeral key (biscuit-auth default).
pub fn attenuate_biscuit(
    biscuit_bytes: &[u8],
    root_pubkey: &PublicKey,
    extra_claims: &ClaimSet,
) -> Result<Vec<u8>, BiscuitError> {
    let biscuit = Biscuit::from(biscuit_bytes, root_pubkey)
        .map_err(|e| BiscuitError::Parse(e.to_string()))?;

    let mut block = BlockBuilder::new();
    for claim in &extra_claims.claims {
        let fact_str = claim.as_datalog();
        block = block
            .fact(fact_str.as_str())
            .map_err(|e| BiscuitError::Build(e.to_string()))?;
    }

    let attenuated = biscuit
        .append(block)
        .map_err(|e| BiscuitError::Build(e.to_string()))?;
    attenuated
        .to_vec()
        .map_err(|e| BiscuitError::Build(e.to_string()))
}

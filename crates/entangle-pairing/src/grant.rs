//! The `mesh.peer` capability tokens a pairing exchanges (spec §6.3 step 4:
//! "On accept, both sides mint long-lived biscuit tokens granting
//! `mesh.peer` to each other and persist them").
//!
//! Each side mints a token rooted at **its own** identity key and issued to
//! the other device ([`issue`](crate::grant::issue)), and sends it inside the
//! exchange it already signs: the side that verifies the other's proof of the
//! code first puts its token in its reply, the other side in the frame that
//! answers it. Each side checks the token it receives
//! ([`check`](crate::grant::check)): it must verify under the other device's
//! (transport- or signature-authenticated) key, name this device as its
//! holder, grant `mesh.peer`, carry no expiry it has already passed and
//! nothing but the authority block. That token is what this device presents
//! to the other one with every remote request; the revocation ids of the
//! token it issued are what `entangle peers remove` revokes.
//!
//! A device built before tokens existed sends none. The pairing still
//! completes, without a token in that direction ([`crate::PairedPeer`]'s
//! `capability_token` is `None`); a token that *is* sent but does not check
//! out fails the pairing.
//!
//! The tokens are minted when the cryptographic exchange completes, before
//! the humans have compared fingerprints. A caller that then stops (the
//! fingerprints did not match, or the exchange failed after its token was
//! sent) must revoke what it issued — [`crate::PairedPeer`] and
//! [`crate::net::Dialer::issued_revocation_ids`] say what that is — so a token
//! handed to a device that never became a peer stays dead even if that
//! device is later put on the allowlist by hand.

use entangle_biscuits::templates::{self, MAX_TOKEN_BYTES};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

use crate::PairingError;

pub use entangle_biscuits::templates::MintedToken;

/// Mint the `mesh.peer` token `issuer` gives `holder` while pairing: rooted at
/// `issuer`'s identity key, no expiry (it lives until revoked).
pub fn issue(issuer: &IdentityKeyPair, holder: PeerId) -> Result<MintedToken, PairingError> {
    templates::mint_mesh_peer(issuer, holder, None)
        .map_err(|e| PairingError::Grant(format!("minting the mesh.peer token: {e}")))
}

/// Whether `token` (raw bytes) is a `mesh.peer` grant from the device whose
/// key is `issuer_public_key` to `holder`, checked now.
pub fn verify(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    holder: PeerId,
) -> Result<(), PairingError> {
    templates::verify_mesh_peer_grant(token, issuer_public_key, holder, templates::now_unix_secs())
        .map(|_| ())
        .map_err(|e| PairingError::Grant(format!("the other device's token was refused: {e}")))
}

/// Decode and [`verify`] the hex token the other device sent. Returns the
/// raw token to store.
pub fn check(
    token_hex: &str,
    issuer_public_key: &[u8; 32],
    holder: PeerId,
) -> Result<Vec<u8>, PairingError> {
    // Bounded before decoding: the verifier refuses anything larger anyway.
    if token_hex.len() > 2 * MAX_TOKEN_BYTES {
        return Err(PairingError::Grant(format!(
            "the other device's token is larger than {MAX_TOKEN_BYTES} bytes"
        )));
    }
    let token = hex::decode(token_hex)
        .map_err(|e| PairingError::Grant(format!("the other device's token is not hex: {e}")))?;
    verify(&token, issuer_public_key, holder)?;
    Ok(token)
}

/// [`check`] an optional token: `Ok(None)` when the other device sent none
/// (built before tokens existed).
pub fn check_optional(
    token_hex: Option<&str>,
    issuer_public_key: &[u8; 32],
    holder: PeerId,
) -> Result<Option<Vec<u8>>, PairingError> {
    token_hex
        .map(|t| check(t, issuer_public_key, holder))
        .transpose()
}

/// The wire form of a minted token.
pub fn to_hex(token: &MintedToken) -> String {
    hex::encode(&token.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(k: &IdentityKeyPair) -> PeerId {
        PeerId::from_public_key_bytes(k.public().as_bytes())
    }

    #[test]
    fn an_issued_token_checks_out_only_for_its_issuer_and_holder() {
        let (a, b, c) = (
            IdentityKeyPair::generate(),
            IdentityKeyPair::generate(),
            IdentityKeyPair::generate(),
        );
        let t = issue(&a, id(&b)).unwrap();
        let hex = to_hex(&t);
        assert_eq!(check(&hex, a.public().as_bytes(), id(&b)).unwrap(), t.bytes);
        assert!(
            check(&hex, a.public().as_bytes(), id(&c)).is_err(),
            "holder"
        );
        assert!(
            check(&hex, c.public().as_bytes(), id(&b)).is_err(),
            "issuer"
        );
        assert!(check("zz", a.public().as_bytes(), id(&b)).is_err(), "hex");
        let huge = "00".repeat(MAX_TOKEN_BYTES + 1);
        assert!(check(&huge, a.public().as_bytes(), id(&b)).is_err(), "size");
        assert_eq!(
            check_optional(None, a.public().as_bytes(), id(&b)).unwrap(),
            None
        );
    }
}

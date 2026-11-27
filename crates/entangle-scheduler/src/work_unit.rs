//! The negotiated signed semantic-replica work unit. Its executor runs only the job.
use crate::wire::{decode_request, RemoteErrorCode, RemoteTaskRequest, RemoteTaskResponse};
use entangle_mesh_iroh::MAX_FRAME_BYTES;
use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::{peer_id::PeerId, plugin_id::PluginId};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};

pub(crate) const PROBE: &[u8] = b"\0entangle/signed-semantic/1?";
pub(crate) const WORK: &[u8] = b"\0entangle/signed-semantic/1!";
pub(crate) const MUTATE: &[u8] = b"\0entangle/signed-semantic/1/mutate";
pub(crate) const REPLICAS: usize = 3;
const QUORUM: u8 = 2;

/// Canonical postcard bytes of this ordered tuple of fields are hashed and signed.
#[derive(Serialize, Deserialize)]
pub(crate) struct Policy {
    metric: String,
    cid: [u8; 32],
    publisher: [u8; 32],
    // IEEE 754 binary32 bits in postcard's canonical unsigned-integer encoding.
    threshold_bits: u32,
    replicas: u8,
    quorum: u8,
}

impl Policy {
    pub(crate) fn new(
        metric: &PluginId,
        cid: [u8; 32],
        publisher: [u8; 32],
        threshold: f32,
    ) -> Self {
        Self {
            metric: metric.to_string(),
            cid,
            publisher,
            threshold_bits: threshold.to_bits(),
            replicas: REPLICAS as u8,
            quorum: QUORUM,
        }
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        postcard::to_allocvec(self).map_err(|e| e.to_string())
    }
    fn valid(&self) -> bool {
        self.metric.parse::<PluginId>().is_ok_and(|id| {
            IdentityPublicKey::from_bytes(&self.publisher)
                .is_ok_and(|key| id.publisher == key.fingerprint_hex())
        }) && (0.0..=1.0).contains(&f32::from_bits(self.threshold_bits))
            && self.replicas == REPLICAS as u8
            && self.quorum == QUORUM
    }
}

#[derive(Serialize, Deserialize)]
struct Signed<'a> {
    signer: [u8; 32],
    policy: Policy,
    policy_hash: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    request: &'a [u8],
    #[serde(borrow, with = "serde_bytes")]
    signature: &'a [u8],
}

fn signature_message(policy_hash: &[u8; 32], request: &[u8]) -> Vec<u8> {
    [WORK, policy_hash, &Sha256::digest(request)[..]].concat()
}

pub(crate) fn encode(
    identity: &IdentityKeyPair,
    request: &[u8],
    policy: Policy,
) -> Result<([u8; 32], Vec<u8>), String> {
    let policy_hash = Sha256::digest(policy.bytes()?).into();
    let signature = identity.sign(&signature_message(&policy_hash, request));
    let signed = Signed {
        signer: *identity.public().as_bytes(),
        policy,
        policy_hash,
        request,
        signature: signature.as_bytes(),
    };
    let frame = [
        WORK,
        postcard::to_allocvec(&signed)
            .map_err(|e| e.to_string())?
            .as_slice(),
    ]
    .concat();
    if frame.len() > MAX_FRAME_BYTES {
        return Err("signed work unit exceeds transport cap".into());
    }
    Ok((policy_hash, frame))
}

pub(crate) fn mutation() -> RemoteTaskResponse {
    RemoteTaskResponse::err(
        RemoteErrorCode::PolicyMutation,
        "PolicyMutation: active work-unit policy is immutable",
    )
}

type TaskKey = (PeerId, [u8; 16]);

/// Pin a policy until execution ends, including on cancellation. No completed tasks are retained.
#[derive(Default)]
pub(crate) struct Active(Mutex<HashMap<TaskKey, [u8; 32]>>);
pub(crate) struct Lease {
    active: Arc<Active>,
    key: TaskKey,
    hash: [u8; 32],
    policy: Policy,
}

impl Active {
    pub(crate) fn accept(
        self: &Arc<Self>,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<(RemoteTaskRequest, Lease), RemoteTaskResponse> {
        let malformed = || {
            RemoteTaskResponse::err(
                RemoteErrorCode::MalformedRequest,
                "invalid signed work unit",
            )
        };
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(malformed());
        }
        let (signed, rest): (Signed<'_>, _) =
            postcard::take_from_bytes(bytes).map_err(|_| malformed())?;
        if !rest.is_empty() || !signed.policy.valid() {
            return Err(malformed());
        }
        let computed: [u8; 32] =
            Sha256::digest(signed.policy.bytes().map_err(|_| malformed())?).into();
        if signed.policy_hash != computed {
            return Err(mutation());
        }
        let key = IdentityPublicKey::from_bytes(&signed.signer).map_err(|_| malformed())?;
        let signature = Signature::from_bytes(signed.signature).map_err(|_| malformed())?;
        if PeerId::from_public_key_bytes(key.as_bytes()) != peer
            || key
                .verify(&signature_message(&computed, signed.request), &signature)
                .is_err()
        {
            return Err(RemoteTaskResponse::err(
                RemoteErrorCode::NotAuthorized,
                "invalid submitter signature",
            ));
        }
        let request = decode_request(signed.request).map_err(|_| malformed())?;
        let key = (peer, request.task_id);
        let mut active = self.0.lock();
        match active.entry(key) {
            std::collections::hash_map::Entry::Occupied(_) => return Err(mutation()),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(computed);
            }
        }
        Ok((
            request,
            Lease {
                active: Arc::clone(self),
                key,
                hash: computed,
                policy: signed.policy,
            },
        ))
    }
}

impl Lease {
    pub(crate) fn complete(&self, output: &[u8]) -> Result<Vec<u8>, RemoteTaskResponse> {
        let observed: [u8; 32] =
            Sha256::digest(self.policy.bytes().map_err(|_| mutation())?).into();
        if observed != self.hash || self.active.0.lock().get(&self.key) != Some(&observed) {
            return Err(mutation());
        }
        Ok([self.key.1.as_slice(), observed.as_slice(), output].concat())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.active.0.lock().remove(&self.key);
    }
}

/// Mirrors the v1 transport response but borrows its untrusted payload. Only
/// result bytes that pass both the submitter's size cap and receipt are copied.
#[derive(Deserialize)]
pub(crate) enum BorrowedOutcome<'a> {
    Ok {
        #[serde(borrow, with = "serde_bytes")]
        output: &'a [u8],
    },
    Err {
        code: RemoteErrorCode,
        #[serde(borrow)]
        message: &'a str,
    },
}

pub(crate) const RECEIPT_LEN: usize = 48;

pub(crate) fn check_receipt(bytes: &[u8], id: &[u8; 16], hash: &[u8; 32]) -> bool {
    bytes.len() >= RECEIPT_LEN && bytes[..16] == *id && bytes[16..48] == *hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_request, RemoteOutcome, WIRE_VERSION};

    #[test]
    fn atc_int_3_cannot_mutate_policy_until_replica_returns() {
        let identity = IdentityKeyPair::generate();
        let peer = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let id: PluginId = format!("{}/job@1.0.0", identity.fingerprint_hex())
            .parse()
            .unwrap();
        let request = RemoteTaskRequest {
            v: WIRE_VERSION,
            task_id: [1; 16],
            plugin: id.to_string(),
            input: vec![],
            timeout_ms: 200,
            max_input_bytes: 16,
            max_output_bytes: 16,
        };
        let req = encode_request(&request).unwrap();
        let sign = |threshold| {
            encode(
                &identity,
                &req,
                Policy::new(&id, [3; 32], *identity.public().as_bytes(), threshold),
            )
            .unwrap()
        };
        let (hash, signed) = sign(0.5);
        let active = Arc::new(Active::default());
        let (_, lease) = active.accept(peer, &signed[WORK.len()..]).ok().unwrap();
        let (_, changed) = sign(0.9);
        let failure = active.accept(peer, &changed[WORK.len()..]).err().unwrap();
        assert!(matches!(
            failure.outcome,
            RemoteOutcome::Err {
                code: RemoteErrorCode::PolicyMutation,
                ..
            }
        ));
        let wrong = IdentityKeyPair::generate();
        assert!(active
            .accept(
                PeerId::from_public_key_bytes(wrong.public().as_bytes()),
                &signed[WORK.len()..]
            )
            .is_err());
        let result = lease.complete(b"raw output").unwrap();
        assert!(check_receipt(&result, &request.task_id, &hash));
        drop(lease);
        assert!(active.0.lock().is_empty());
    }
}

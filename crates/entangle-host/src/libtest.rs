//! A selector-only adapter for a signed WASI Rust libtest command.

use serde::{Deserialize, Deserializer, Serialize};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::WasiCtxBuilder;

use crate::{state::HostState, HostError};

/// Manifest world selecting the WASI CLI adapter for a Rust test executable.
pub const LIBTEST_WORLD: &str = "wasi:cli/command@0.2.0";

const CAPTURE_LIMIT: usize = 64 * 1024;
const TEST_NAME_LIMIT: usize = 4096;
const MAX_ATTEMPT: u8 = 11;

/// Digests of the signed component and exact manifest bytes verified by the loader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibtestIdentity {
    #[serde(with = "digest_hex")]
    artifact_blake3: [u8; 32],
    #[serde(with = "digest_hex")]
    manifest_blake3: [u8; 32],
}

impl LibtestIdentity {
    /// Construct the identity from the two digests in a verified signature bundle.
    pub fn from_verified_hashes(artifact_blake3: [u8; 32], manifest_blake3: [u8; 32]) -> Self {
        Self {
            artifact_blake3,
            manifest_blake3,
        }
    }
}

mod digest_hex {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        digest: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(digest))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected a lowercase BLAKE3 digest"));
        }
        let mut digest = [0; 32];
        hex::decode_to_slice(encoded, &mut digest).map_err(D::Error::custom)?;
        Ok(digest)
    }
}

// A missing pin supports older clients; an explicitly null pin is an invalid request.
fn present_identity<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<LibtestIdentity>, D::Error> {
    LibtestIdentity::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    List {
        #[serde(default, deserialize_with = "present_identity")]
        expected_suite_identity: Option<LibtestIdentity>,
        #[serde(default)]
        ignored: bool,
    },
    Test {
        #[serde(default, deserialize_with = "present_identity")]
        expected_suite_identity: Option<LibtestIdentity>,
        name: String,
        #[serde(default)]
        ignored: bool,
        #[serde(default = "first_attempt")]
        attempt: u8,
    },
}

fn first_attempt() -> u8 {
    1
}

pub(crate) struct LibtestCapture {
    stdout: MemoryOutputPipe,
    stderr: MemoryOutputPipe,
}

impl LibtestCapture {
    pub(crate) fn start(
        input: &[u8],
        state: &mut HostState,
        identity: Option<&LibtestIdentity>,
    ) -> Result<Self, HostError> {
        let request: Request = serde_json::from_slice(input).map_err(|error| {
            HostError::PluginReturnedError(format!("invalid libtest request: {error}"))
        })?;
        let expected = match &request {
            Request::List {
                expected_suite_identity,
                ..
            }
            | Request::Test {
                expected_suite_identity,
                ..
            } => expected_suite_identity.as_ref(),
        };
        if expected.is_some() && expected != identity {
            return Err(HostError::PluginReturnedError(
                "libtest suite identity mismatch".into(),
            ));
        }
        let stdout = MemoryOutputPipe::new(CAPTURE_LIMIT);
        let stderr = MemoryOutputPipe::new(CAPTURE_LIMIT);
        let mut wasi = WasiCtxBuilder::new();
        if let Request::Test { attempt, .. } = &request {
            if !(1..=MAX_ATTEMPT).contains(attempt) {
                return Err(HostError::PluginReturnedError(
                    "libtest attempt must be between 1 and 11".into(),
                ));
            }
            wasi.env("ENTANGLE_LIBTEST_ATTEMPT", attempt.to_string());
        }
        wasi.args(&arguments(request)?)
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        state.replace_wasi(wasi.build());
        Ok(Self { stdout, stderr })
    }

    pub(crate) fn result(
        self,
        exit_code: Option<i32>,
        identity: Option<&LibtestIdentity>,
    ) -> Result<Vec<u8>, HostError> {
        serde_json::to_vec(&serde_json::json!({
            "suite_identity": identity,
            "exit_code": exit_code,
            "stdout": String::from_utf8_lossy(&self.stdout.contents()),
            "stderr": String::from_utf8_lossy(&self.stderr.contents()),
        }))
        .map_err(|error| HostError::PluginReturnedError(error.to_string()))
    }
}

fn arguments(request: Request) -> Result<Vec<String>, HostError> {
    let mut args = [
        "entangle-libtest",
        "--format",
        "terse",
        "--test-threads",
        "1",
    ]
    .map(str::to_owned)
    .to_vec();
    match request {
        Request::List { ignored, .. } => {
            args.push("--list".into());
            if ignored {
                args.push("--ignored".into());
            }
        }
        Request::Test { name, ignored, .. } => {
            if name.is_empty() || name.len() > TEST_NAME_LIMIT || name.chars().any(char::is_control)
            {
                return Err(HostError::PluginReturnedError(
                    "invalid libtest name".into(),
                ));
            }
            if ignored {
                args.push("--ignored".into());
            }
            // Stable WASI Rust aborts on panic before libtest can flush its
            // own captures. The host still records raw stdout and stderr.
            args.extend(["--nocapture".into(), "--exact".into(), "--".into(), name]);
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_pins_require_both_canonical_digests() {
        let digest = "ab".repeat(32);
        let valid = serde_json::json!({"artifact_blake3":digest,"manifest_blake3":digest});
        for value in [
            serde_json::Value::Null,
            serde_json::json!({"artifact_blake3":digest}),
            serde_json::json!({"artifact_blake3":digest.to_uppercase(),"manifest_blake3":digest}),
            serde_json::json!({"artifact_blake3":digest,"manifest_blake3":"9"}),
            serde_json::json!({"artifact_blake3":digest,"manifest_blake3":digest,"other":0}),
        ] {
            assert!(serde_json::from_value::<Request>(
                serde_json::json!({"operation":"list","expected_suite_identity":value})
            )
            .is_err());
        }
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"operation":"list","expected_suite_identity":valid})
        )
        .is_ok());
    }

    #[test]
    fn test_name_cannot_supply_a_libtest_option() {
        let args = arguments(Request::Test {
            expected_suite_identity: None,
            name: "--include-ignored".into(),
            ignored: false,
            attempt: 1,
        })
        .unwrap();
        assert_eq!(
            &args[args.len() - 3..],
            ["--exact", "--", "--include-ignored"]
        );
        assert!(serde_json::from_str::<Request>(
            r#"{"operation":"test","name":"x","args":["--list"]}"#
        )
        .is_err());
    }
}

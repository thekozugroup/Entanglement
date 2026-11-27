//! A selector-only adapter for a signed WASI Rust libtest command.

use serde::Deserialize;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::WasiCtxBuilder;

use crate::{state::HostState, HostError};

/// Manifest world selecting the WASI CLI adapter for a Rust test executable.
pub const LIBTEST_WORLD: &str = "wasi:cli/command@0.2.0";

const CAPTURE_LIMIT: usize = 64 * 1024;
const TEST_NAME_LIMIT: usize = 4096;
const MAX_ATTEMPT: u8 = 11;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    List {
        #[serde(default)]
        ignored: bool,
    },
    Test {
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
    pub(crate) fn start(input: &[u8], state: &mut HostState) -> Result<Self, HostError> {
        let request: Request = serde_json::from_slice(input).map_err(|error| {
            HostError::PluginReturnedError(format!("invalid libtest request: {error}"))
        })?;
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

    pub(crate) fn result(self, exit_code: Option<i32>) -> Result<Vec<u8>, HostError> {
        serde_json::to_vec(&serde_json::json!({
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
        Request::List { ignored } => {
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
    fn test_name_cannot_supply_a_libtest_option() {
        let args = arguments(Request::Test {
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

//! Connection authentication for the daemon socket.
//!
//! The socket is mode `0600` and the daemon checks the peer's uid, but any
//! process running as the user can connect — including an AI agent that
//! `entangle agent run` confined with the OS sandbox, which does not
//! mediate `connect()` on path-named Unix sockets. So the daemon also writes
//! a random token, at each start, to a `0600` file next to the socket
//! ([`token_path`]), and the first line of every connection must present it
//! ([`auth_line`]) before any method is dispatched. A process that can read
//! the daemon's directory (the CLI, the gateway's built-in server) passes;
//! a sandboxed agent, whose allowlist never includes `~/.entangle`, does
//! not.

use std::path::{Path, PathBuf};

/// The method name of the authentication line (a JSON-RPC notification:
/// no `id`, no reply on success).
pub const AUTH_METHOD: &str = "auth";

/// JSON-RPC error code of a connection refused for a missing or wrong token.
pub const UNAUTHORIZED: i32 = -32001;

/// The token file of the daemon listening on `socket`: `<socket>.token` in
/// the same directory.
pub fn token_path(socket: &Path) -> PathBuf {
    let mut name = socket
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".token");
    socket.with_file_name(name)
}

/// The first line a client sends on a connection (without the newline).
pub fn auth_line(token: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": AUTH_METHOD,
        "params": { "token": token },
    })
    .to_string()
}

/// Read the token for `socket`, trimmed; `None` when the file is missing or
/// unreadable (an older daemon, or a caller without access).
pub fn read_token(socket: &Path) -> Option<String> {
    let t = std::fs::read_to_string(token_path(socket)).ok()?;
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lives_next_to_the_socket() {
        assert_eq!(
            token_path(Path::new("/home/u/.entangle/sock")),
            PathBuf::from("/home/u/.entangle/sock.token")
        );
        let v: serde_json::Value = serde_json::from_str(&auth_line("abc")).unwrap();
        assert_eq!(v["method"], "auth");
        assert_eq!(v["params"]["token"], "abc");
        assert!(v.get("id").is_none());
    }
}

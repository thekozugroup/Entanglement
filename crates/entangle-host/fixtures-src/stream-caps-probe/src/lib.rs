//! Test fixture: the `stream-plugin`-world counterpart of `caps-probe`. It
//! checks that a streaming invocation gets exactly the capability grants a
//! one-shot invocation gets.
//!
//! `start-stream(input)` runs `input` as a script, one command per line,
//! and yields **one output chunk per command**: `ok`, `ok:<detail>` or
//! `err:<kind>:<message>`. It then reads the input stream and runs every
//! inbound chunk as a further script the same way, until the input ends
//! (`ok(0)`). A test can therefore keep the instance alive between two
//! commands — e.g. hold a connection open while it revokes a grant — by not
//! sending the next chunk yet.
//!
//! | command                 | effect                                             |
//! |-------------------------|----------------------------------------------------|
//! | `write <path> <text>`   | `std::fs::write`                                   |
//! | `read <path>`           | `std::fs::read_to_string` → `ok:<text>`            |
//! | `ls <path>`             | sorted entry names → `ok:a,b,c`                    |
//! | `connect <host:port>`   | TCP connect (resolving names), read the greeting   |
//! | `hold <host:port>`      | as `connect`, and keep the connection open         |
//! | `again`                 | read from the connection `hold` kept → `ok:<text>` |
//! | `listen <ip:port>`      | TCP bind + listen                                  |
//! | `resolve <host>`        | DNS lookup → `ok:<ip>,<ip>`                        |
//! | `fetch <kind> [<name>]` | `capability.fetch` → `ok:<handle>`                 |
//! | `release <handle>`      | `capability.release`                               |
//!
//! Fetch errors are reported as `err:not-granted:<reason>`, `err:revoked:`
//! or `err:invalid-kind:`, exactly as `caps-probe` reports them.

#![allow(unsafe_code, missing_docs)]

wit_bindgen::generate!({
    world: "stream-plugin",
    path: "../../../entangle-wit/wit",
});

use entangle::plugin::capability::{fetch, release, FetchError, Kind};
use entangle::plugin::stream::{next_chunk, yield_chunk, ChunkResult};
use std::io::{Read, Write};

const OUTPUT: u64 = 0;
const INPUT: u64 = 1;

fn io_err(e: std::io::Error) -> String {
    format!("err:{:?}:{e}", e.kind())
}

fn kind(s: &str) -> Option<Kind> {
    Some(match s {
        "compute-cpu" => Kind::ComputeCpu,
        "storage-local" => Kind::StorageLocal,
        "storage-share" => Kind::StorageShare,
        "net-lan" => Kind::NetLan,
        "net-wan" => Kind::NetWan,
        "custom" => Kind::Custom,
        _ => return None,
    })
}

/// Connections opened by `hold`, kept for the rest of the stream.
struct Probe {
    held: Vec<std::net::TcpStream>,
}

fn greeting(s: &mut std::net::TcpStream) -> String {
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) => format!("ok:{}", String::from_utf8_lossy(&buf[..n])),
        Err(e) => io_err(e),
    }
}

impl Probe {
    fn step(&mut self, line: &str) -> String {
        let mut words = line.splitn(3, ' ');
        let cmd = words.next().unwrap_or("");
        let a = words.next().unwrap_or("");
        let b = words.next();
        match cmd {
            "write" => match std::fs::write(a, b.unwrap_or("")) {
                Ok(()) => "ok".into(),
                Err(e) => io_err(e),
            },
            "read" => match std::fs::read_to_string(a) {
                Ok(s) => format!("ok:{s}"),
                Err(e) => io_err(e),
            },
            "ls" => match std::fs::read_dir(a) {
                Ok(rd) => {
                    let mut names: Vec<String> = rd
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    format!("ok:{}", names.join(","))
                }
                Err(e) => io_err(e),
            },
            "connect" | "hold" => match std::net::TcpStream::connect(a) {
                Ok(mut s) => {
                    let _ = s.write_all(b"hi");
                    let out = greeting(&mut s);
                    if cmd == "hold" {
                        self.held.push(s);
                    }
                    out
                }
                Err(e) => io_err(e),
            },
            "again" => match self.held.last_mut() {
                Some(s) => greeting(s),
                None => "err:NotConnected:no held connection".into(),
            },
            "listen" => match std::net::TcpListener::bind(a) {
                Ok(_) => "ok".into(),
                Err(e) => io_err(e),
            },
            "resolve" => {
                use std::net::ToSocketAddrs;
                match (a, 0u16).to_socket_addrs() {
                    Ok(addrs) => {
                        let mut ips: Vec<String> = addrs.map(|s| s.ip().to_string()).collect();
                        ips.sort();
                        ips.dedup();
                        format!("ok:{}", ips.join(","))
                    }
                    Err(e) => io_err(e),
                }
            }
            "fetch" => {
                let Some(k) = kind(a) else {
                    return format!("err:bad-kind-string:{a}");
                };
                match fetch(k, b) {
                    Ok(h) => format!("ok:{h}"),
                    Err(FetchError::NotGranted(why)) => format!("err:not-granted:{why}"),
                    Err(FetchError::Revoked) => "err:revoked:".into(),
                    Err(FetchError::InvalidKind) => "err:invalid-kind:".into(),
                }
            }
            "release" => match a.parse::<u32>() {
                Ok(h) => {
                    release(h);
                    "ok".into()
                }
                Err(e) => format!("err:bad-handle:{e}"),
            },
            other => format!("err:unknown-command:{other}"),
        }
    }

    /// Run `script`, yielding one chunk per command.
    fn script(&mut self, script: &[u8]) -> Result<(), PluginError> {
        let script = std::str::from_utf8(script)
            .map_err(|e| PluginError::InvalidInput(e.to_string()))?;
        for line in script.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let result = self.step(line);
            yield_chunk(OUTPUT, result.as_bytes()).map_err(PluginError::Internal)?;
        }
        Ok(())
    }
}

struct StreamCapsProbe;

impl Guest for StreamCapsProbe {
    fn start_stream(input: Vec<u8>) -> Result<u64, PluginError> {
        let mut probe = Probe { held: Vec::new() };
        probe.script(&input)?;
        loop {
            match next_chunk(INPUT) {
                ChunkResult::Ok(bytes) => probe.script(&bytes)?,
                ChunkResult::End => return Ok(OUTPUT),
                ChunkResult::Error(e) => return Err(PluginError::Internal(e)),
            }
        }
    }
}

export!(StreamCapsProbe);

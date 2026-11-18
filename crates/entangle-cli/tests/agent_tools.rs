//! `entangle agent run --entangle-tools`: the gateway's built-in `entangle`
//! server exposes the daemon's loaded plugins as MCP tools (spec §8.3).
//!
//! Real pieces end to end: a daemon (`entangle_bin` state + its RPC server
//! on a Unix socket) with the signed `hello-pong` example plugin loaded, the
//! real `entangle` binary, and an agent that speaks MCP over HTTP to the
//! gateway URL from its session config. The "agent" is this test binary
//! re-executed (`fake_agent_client`), started through a two-line shell
//! script because the CLI puts the agent's own flags first.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use entangle_bin::{config, server, state::DaemonState};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use serde_json::{json, Value};

const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");

/// One JSON-RPC POST to a gateway route. Returns (status, body).
fn post(url: &str, token: &str, msg: &Value) -> (u16, Value) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (addr, path) = rest.split_once('/').expect("path");
    let body = msg.to_string();
    let mut s = std::net::TcpStream::connect(addr).expect("connect to the gateway");
    write!(
        s,
        "POST /{path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut text = String::new();
    s.read_to_string(&mut text).unwrap();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// The agent side. A no-op in a normal test run; when started by the CLI
/// (`FAKE_AGENT_RESULT` set) it reads the session config, talks MCP to the
/// `entangle` route and records every reply.
#[test]
fn fake_agent_client() {
    let Some(result) = std::env::var_os("FAKE_AGENT_RESULT") else {
        return;
    };
    let cfg_path = std::env::var("FAKE_AGENT_MCP_CONFIG").expect("session config path");
    let token = std::env::var("ENTANGLE_SESSION_TOKEN").expect("session token");
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    let mut out =
        json!({ "servers": cfg["mcpServers"].as_object().unwrap().keys().collect::<Vec<_>>() });
    if let Some(url) = cfg["mcpServers"]["entangle"]["url"].as_str() {
        let call = |id: u64, method: &str, params: Value| {
            post(
                url,
                &token,
                &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
            )
            .1
        };
        out["initialize"] = call(
            1,
            "initialize",
            json!({"protocolVersion":"2025-03-26","capabilities":{}}),
        );
        let list = call(2, "tools/list", json!({}));
        let first = list["result"]["tools"][0]["name"]
            .as_str()
            .map(str::to_owned);
        out["list"] = list;
        let tool = std::env::var("FAKE_AGENT_TOOL").ok().or(first);
        if let Some(tool) = tool {
            out["call"] = call(
                3,
                "tools/call",
                json!({"name": tool, "arguments": {"input": "ping"}}),
            );
        }
        out["oversized"] = json!(
            post(
                url,
                &token,
                &json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                    "params":{"name":"x","arguments":{"input":"a".repeat(5 * 1024 * 1024)}}}),
            )
            .0
        );
    }
    std::fs::write(result, out.to_string()).unwrap();
}

struct Daemon {
    tmp: tempfile::TempDir,
    home: PathBuf,
    plugin_id: String,
    /// The reply to `plugins/load`.
    loaded: Result<String, String>,
    client: entangle_rpc::Client,
}

/// Start a daemon whose config is `config_toml` (`{id}` is replaced by the
/// plugin id) and try to load the signed hello-pong plugin into it.
async fn daemon(config_toml: &str) -> Daemon {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = tmp.path().join("home");
    let config_dir = home.join(".entangle");
    std::fs::create_dir_all(&config_dir).unwrap();
    let kp = IdentityKeyPair::generate();
    let plugin_id = format!("{}/hello-pong@0.1.0", kp.fingerprint_hex());
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let manifest = format!(
        "[plugin]\nid = \"{plugin_id}\"\nversion = \"0.1.0\"\ntier = 2\nruntime = \"wasm\"\n\n[capabilities]\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.wasm"), HELLO).unwrap();
    std::fs::write(
        pkg.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(HELLO, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        config_toml.replace("{id}", &plugin_id),
    )
    .unwrap();
    let cfg = config::load_config(&config_dir.join("config.toml")).unwrap();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "agent-tools".into(),
        added_at: 0,
        note: String::new(),
    });
    let kernel = Arc::new(Kernel::new(config::kernel_config(&cfg, &config_dir), keyring).unwrap());
    let pool = WorkerPool::new();
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let state = Arc::new(DaemonState::new(
        kernel.clone(),
        Arc::new(Dispatcher::new(pool.clone(), kernel, local)),
        pool,
        PeerStore::new(),
        identity,
        "agent-tools".into(),
    ));
    // Where the CLI looks: `$HOME/.entangle/sock`.
    let socket = config_dir.join("sock");
    let sp = socket.clone();
    tokio::spawn(async move {
        let _ = server::serve(sp, state).await;
    });
    let client = entangle_rpc::Client::new(&socket);
    for _ in 0..200 {
        if client.version().await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let loaded = client
        .plugins_load(&pkg)
        .await
        .map(|r| r.plugin_id)
        .map_err(|e| e.to_string());
    Daemon {
        tmp,
        home,
        plugin_id,
        loaded,
        client,
    }
}

struct Run {
    code: Option<i32>,
    stderr: String,
    /// What the fake agent recorded (`Null` if it never ran).
    result: Value,
}

/// `entangle agent run claude-code <extra> --bin <fake agent>` in a fresh
/// project directory, with `$HOME` pointing at the daemon's.
async fn agent_run(d: &Daemon, extra: &[&str], envs: &[(&str, &str)]) -> Run {
    let project = d.tmp.path().join("project");
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let exe = std::env::current_exe().unwrap();
    let script = project.join("fake-agent.sh");
    // `$2` is the --mcp-config path the CLI passes first.
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nFAKE_AGENT_MCP_CONFIG=\"$2\" exec '{}' --exact fake_agent_client --nocapture\n",
            exe.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = project.join("result.json");
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("entangle"));
    cmd.current_dir(&project)
        .env("HOME", &d.home)
        .env("ENTANGLE_SESSIONS_DIR", d.tmp.path().join("sessions"))
        .env("FAKE_AGENT_RESULT", &result)
        .env_remove("ENTANGLE_AGENT_SANDBOX_PROBE")
        .args(["agent", "run", "claude-code", "--config"])
        .arg(project.join("none.json"))
        .arg("--bin")
        .arg(&script)
        // The agent is this test binary: let the sandbox read and run it.
        .arg("--sandbox-read")
        .arg(exe.parent().unwrap())
        .args(extra);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    Run {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        result: std::fs::read_to_string(&result)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null),
    }
}

fn tool_names(r: &Run) -> Vec<String> {
    r.result["list"]["result"]["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn loaded_plugin_is_listed_and_invoked_through_the_gateway() {
    let d = daemon("").await;
    assert_eq!(d.loaded.as_deref(), Ok(d.plugin_id.as_str()));
    // What the plugin answers when the daemon is asked directly.
    let direct = d
        .client
        .plugins_invoke(&d.plugin_id, b"ping".to_vec(), 10_000)
        .await
        .unwrap()
        .output;

    let r = agent_run(&d, &["--entangle-tools"], &[]).await;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("1 loaded plugin(s) exposed"),
        "{}",
        r.stderr
    );
    assert_eq!(r.result["servers"], json!(["entangle"]), "{}", r.result);
    assert_eq!(
        r.result["initialize"]["result"]["serverInfo"]["name"], "entangle",
        "{}",
        r.result
    );
    assert_eq!(tool_names(&r), ["hello-pong"], "{}", r.result);
    let tool = &r.result["list"]["result"]["tools"][0];
    assert!(tool["description"].as_str().unwrap().contains(&d.plugin_id));
    assert!(tool["description"].as_str().unwrap().contains("tier 2"));
    assert_eq!(tool["inputSchema"]["type"], "object");
    assert!(tool["inputSchema"]["properties"]["input"].is_object());

    let call = &r.result["call"]["result"];
    assert_eq!(call["isError"], false, "{}", r.result);
    assert_eq!(
        call["content"][0]["text"].as_str().unwrap().as_bytes(),
        direct,
        "the tool result is the plugin's output"
    );
    // The same request-body cap as every other route (4 MiB).
    assert_eq!(r.result["oversized"], 413, "{}", r.result);
    // Audited like any tool call.
    assert!(r.stderr.contains("\"tool_calls\":1"), "{}", r.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn off_by_default() {
    let d = daemon("").await;
    assert!(d.loaded.is_ok());
    let r = agent_run(&d, &[], &[]).await;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(
        r.result["servers"],
        json!([]),
        "no `entangle` server without the flag"
    );
    assert!(r.result.get("list").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_policy_applies_to_plugin_tools() {
    let d = daemon("").await;
    assert!(d.loaded.is_ok());
    let r = agent_run(
        &d,
        &["--entangle-tools", "--deny", "entangle/hello-pong"],
        &[],
    )
    .await;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    // Listing is not a tool call; the call is refused by policy and audited
    // as denied, and the plugin is not run.
    assert_eq!(tool_names(&r), ["hello-pong"]);
    let msg = r.result["call"]["error"]["message"].as_str().unwrap_or("");
    assert!(msg.starts_with("ENTANGLE-E0661"), "{}", r.result);
    assert!(r.stderr.contains("\"denied\":1"), "{}", r.stderr);
}

/// `[plugins] disabled`: the daemon refuses to load the plugin, so it is
/// neither listed nor callable through the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn disabled_plugin_is_neither_listed_nor_callable() {
    let d = daemon("[plugins]\ndisabled = [\"{id}\"]\n").await;
    assert!(
        d.loaded.is_err(),
        "the daemon must refuse a disabled plugin"
    );
    let r = agent_run(
        &d,
        &["--entangle-tools"],
        &[("FAKE_AGENT_TOOL", "hello-pong")],
    )
    .await;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(tool_names(&r).is_empty(), "{}", r.result);
    let msg = r.result["call"]["error"]["message"].as_str().unwrap_or("");
    assert!(msg.starts_with("ENTANGLE-E0686"), "{}", r.result);
}

/// `[security] max_tier_allowed` below the plugin's tier: same outcome.
#[tokio::test(flavor = "multi_thread")]
async fn plugin_over_the_tier_ceiling_is_neither_listed_nor_callable() {
    let d = daemon("[security]\nmax_tier_allowed = 1\n").await;
    assert!(d.loaded.is_err(), "tier 2 is over a ceiling of 1");
    let r = agent_run(
        &d,
        &["--entangle-tools"],
        &[("FAKE_AGENT_TOOL", "hello-pong")],
    )
    .await;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(tool_names(&r).is_empty(), "{}", r.result);
    assert!(r.result["call"]["error"].is_object(), "{}", r.result);
}

#[tokio::test(flavor = "multi_thread")]
async fn needs_a_running_daemon_and_a_free_server_name() {
    // No daemon at $HOME/.entangle/sock.
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let d = Daemon {
        home: tmp.path().join("nohome"),
        plugin_id: String::new(),
        loaded: Err(String::new()),
        client: entangle_rpc::Client::new(tmp.path().join("none")),
        tmp,
    };
    std::fs::create_dir_all(&d.home).unwrap();
    let r = agent_run(&d, &["--entangle-tools"], &[]).await;
    assert_ne!(r.code, Some(0));
    assert!(r.stderr.contains("ENTANGLE-E0685"), "{}", r.stderr);
    assert!(r.result.is_null(), "the agent was not started");

    // The user's config already has a server called `entangle`.
    let d = daemon("").await;
    let project = d.tmp.path().join("p2");
    std::fs::create_dir_all(&project).unwrap();
    let cfg = project.join("mcp.json");
    std::fs::write(&cfg, r#"{"mcpServers":{"entangle":{"command":"true"}}}"#).unwrap();
    let home = d.home.clone();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(assert_cmd::cargo::cargo_bin("entangle"))
            .current_dir(&project)
            .env("HOME", &home)
            .args([
                "agent",
                "run",
                "claude-code",
                "--entangle-tools",
                "--bin",
                "/bin/true",
                "--config",
            ])
            .arg(&cfg)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("ENTANGLE-E0687"), "{err}");
}

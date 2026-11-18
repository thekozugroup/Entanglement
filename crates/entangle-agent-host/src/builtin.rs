//! Built-in downstream servers: MCP servers the gateway implements itself
//! instead of proxying to a process or a URL.
//!
//! The one shipped here is [`EntangleTools`], the `entangle` server (spec
//! §8.3 "forwards to the actual Entanglement capability"): it exposes the
//! plugins loaded in the daemon as MCP tools. `tools/list` lists them,
//! `tools/call` invokes one through a [`PluginBackend`] (the daemon's
//! `plugins/invoke` RPC in `entangle agent run`).
//!
//! A built-in server is a route like any other: the same bearer
//! authentication, `before_tool` / `after_tool` policy hooks, audit records,
//! request-body cap, per-request timeout and reply-size cap apply, because
//! the gateway dispatches to it at the same point it would write to a stdio
//! server.
//!
//! # What the daemon decides
//! The server lists only what the backend reports as loaded and invokes
//! only through it, so the daemon's own rules hold without being
//! re-implemented here: a plugin over `[security] max_tier_allowed` or named
//! in `[plugins] disabled` is not loaded, hence neither listed nor callable,
//! and a plugin unloaded mid-session stops being callable at once (the name
//! is resolved against a fresh listing on every call).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde_json::{json, Value};

/// A boxed future, as returned by the object-safe traits of this module.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An MCP server implemented in-process. The gateway calls
/// [`handle`](Self::handle) with each JSON-RPC *request* addressed to the
/// route (notifications are dropped: a built-in server keeps no session
/// state), after policy for `tools/call`, under the route's timeout.
pub trait BuiltinServer: Send + Sync + std::fmt::Debug {
    /// Answer one JSON-RPC request with a complete JSON-RPC response (the
    /// `id` echoed). `timeout` is the gateway's per-request budget, for
    /// servers that pass a deadline on.
    fn handle(&self, request: Value, timeout: Duration) -> BoxFuture<'_, Value>;
}

/// One loaded plugin, as the backend reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginTool {
    /// The daemon's plugin id (`<publisher>/<name>@<version>`).
    pub plugin_id: String,
    /// The plugin's effective tier, when the backend knows it.
    pub tier: Option<u8>,
}

/// What [`EntangleTools`] needs from the daemon. Errors are operator-facing
/// text (they reach the agent as a tool error and the audit log).
pub trait PluginBackend: Send + Sync + std::fmt::Debug {
    /// The plugins that are loaded right now.
    fn list(&self) -> BoxFuture<'_, Result<Vec<PluginTool>, String>>;
    /// Invoke `plugin_id` with `input`, waiting at most `timeout`.
    fn invoke(
        &self,
        plugin_id: &str,
        input: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Vec<u8>, String>>;
}

/// Route name of the built-in capability server.
pub const ENTANGLE_SERVER_NAME: &str = "entangle";

/// Longest tool name MCP clients accept (`^[a-zA-Z0-9_-]{1,64}$`).
const TOOL_NAME_MAX: usize = 64;

/// Protocol versions this server answers `initialize` with.
const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// The built-in `entangle` MCP server: loaded plugins as tools.
///
/// Tool names are fixed for the life of the server (one session): the first
/// listing assigns them as [`tool_names`] does, a plugin seen later gets a
/// name that was never used before, and a name never changes its plugin —
/// so a plugin loaded mid-session cannot take over a name the agent and the
/// `--allow`/`--deny` patterns already know as another plugin. The name of
/// a plugin that was unloaded stays reserved.
#[derive(Debug)]
pub struct EntangleTools<B> {
    backend: B,
    /// Tool name → plugin id, every assignment made so far.
    names: parking_lot::Mutex<BTreeMap<String, String>>,
}

/// The tool name for a plugin id: the `<name>` part (or the whole id when
/// it has no publisher prefix) with every character outside
/// `[A-Za-z0-9_-]` replaced by `_`, at most 64 characters.
fn base_tool_name(plugin_id: &str) -> String {
    let name = plugin_id.rsplit_once('/').map_or(plugin_id, |(_, n)| n);
    let name = name.split_once('@').map_or(name, |(n, _)| n);
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(TOOL_NAME_MAX)
        .collect();
    if out.is_empty() {
        out.push_str("plugin");
    }
    out
}

/// Tool name → plugin, for one listing. Deterministic: plugins are taken in
/// id order, and a name already taken (two publishers, or two versions, of
/// one plugin name) gets a numeric suffix.
pub fn tool_names(plugins: &[PluginTool]) -> BTreeMap<String, PluginTool> {
    let mut assigned = BTreeMap::new();
    assign_names(&mut assigned, plugins)
}

/// Extend `assigned` (tool name → plugin id) with names for the plugins of
/// `plugins` that have none yet, never reusing a name, and return the
/// loaded plugins by name.
fn assign_names(
    assigned: &mut BTreeMap<String, String>,
    plugins: &[PluginTool],
) -> BTreeMap<String, PluginTool> {
    let mut sorted: Vec<&PluginTool> = plugins.iter().collect();
    sorted.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
    let mut out: BTreeMap<String, PluginTool> = BTreeMap::new();
    for p in sorted {
        let existing = assigned
            .iter()
            .find(|(_, id)| **id == p.plugin_id)
            .map(|(n, _)| n.clone());
        let name = match existing {
            Some(n) => n,
            None => {
                let base = base_tool_name(&p.plugin_id);
                let mut name = base.clone();
                let mut n = 2;
                while assigned.contains_key(&name) {
                    let suffix = format!("_{n}");
                    let keep = TOOL_NAME_MAX.saturating_sub(suffix.len()).min(base.len());
                    name = format!("{}{suffix}", &base[..keep]);
                    n += 1;
                }
                assigned.insert(name.clone(), p.plugin_id.clone());
                name
            }
        };
        out.insert(name, p.clone());
    }
    out
}

/// The input schema of every plugin tool. Plugin manifests declare no
/// schema of their own (a plugin's entry point takes and returns bytes), so
/// this is the generic bytes/text one.
fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "input": {
                "type": "string",
                "description": "UTF-8 text passed to the plugin as its input bytes."
            },
            "input_base64": {
                "type": "string",
                "description": "Base64 (standard alphabet) input for binary data; use instead of `input`."
            }
        },
        "additionalProperties": false
    })
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

/// A tool-level failure: MCP reports these inside a successful response so
/// the model sees them.
fn tool_error(id: &Value, text: String) -> Value {
    ok(
        id,
        json!({"content": [{"type": "text", "text": text}], "isError": true}),
    )
}

/// Decode standard base64 (padding optional, whitespace ignored).
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u8);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Truncation to the low byte is the point.
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Encode standard base64 with padding.
fn encode_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The plugin input named by a `tools/call`'s `arguments`.
fn input_bytes(arguments: Option<&Value>) -> Result<Vec<u8>, String> {
    let empty = serde_json::Map::new();
    let args = match arguments {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err("arguments must be an object".into()),
    };
    if let Some(unknown) = args.keys().find(|k| *k != "input" && *k != "input_base64") {
        return Err(format!(
            "unknown argument {unknown:?} (expected `input` or `input_base64`)"
        ));
    }
    match (args.get("input"), args.get("input_base64")) {
        (Some(_), Some(_)) => Err("give `input` or `input_base64`, not both".into()),
        (Some(Value::String(s)), None) => Ok(s.clone().into_bytes()),
        (None, Some(Value::String(s))) => {
            decode_base64(s).ok_or_else(|| "`input_base64` is not valid base64".to_owned())
        }
        (None, None) => Ok(Vec::new()),
        _ => Err("`input` and `input_base64` must be strings".into()),
    }
}

impl<B: PluginBackend> EntangleTools<B> {
    /// A server over `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            names: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }

    /// The loaded `plugins` by their (fixed) tool names.
    fn named(&self, plugins: &[PluginTool]) -> BTreeMap<String, PluginTool> {
        assign_names(&mut self.names.lock(), plugins)
    }

    async fn tools_list(&self, id: &Value) -> Value {
        let plugins = match self.backend.list().await {
            Ok(p) => p,
            Err(e) => return err(id, -32603, format!("ENTANGLE-E0685: {e}")),
        };
        let tools: Vec<Value> = self
            .named(&plugins)
            .into_iter()
            .map(|(name, p)| {
                let tier = p.tier.map(|t| format!(" (tier {t})")).unwrap_or_default();
                json!({
                    "name": name,
                    "description": format!(
                        "Entanglement plugin {}{tier}, run by the local daemon. Takes bytes \
                         (`input` as text, or `input_base64`) and returns the plugin's output.",
                        p.plugin_id
                    ),
                    "inputSchema": input_schema(),
                })
            })
            .collect();
        ok(id, json!({"tools": tools}))
    }

    async fn tools_call(&self, id: &Value, params: Option<&Value>, timeout: Duration) -> Value {
        let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
            return err(
                id,
                -32602,
                "ENTANGLE-E0686: tools/call requires params.name",
            );
        };
        let input = match input_bytes(params.and_then(|p| p.get("arguments"))) {
            Ok(i) => i,
            Err(why) => return err(id, -32602, format!("ENTANGLE-E0686: {why}")),
        };
        // Resolved against what is loaded now: an unloaded or disabled
        // plugin is not callable, whatever an earlier listing said.
        let plugins = match self.backend.list().await {
            Ok(p) => p,
            Err(e) => return tool_error(id, format!("ENTANGLE-E0685: {e}")),
        };
        let Some(plugin) = self.named(&plugins).remove(name) else {
            return err(
                id,
                -32602,
                format!(
                    "ENTANGLE-E0686: no loaded plugin is exposed as tool {name:?} (see \
                     tools/list; a plugin that is disabled, unloaded or over the tier ceiling \
                     is not callable)"
                ),
            );
        };
        match self.backend.invoke(&plugin.plugin_id, input, timeout).await {
            Ok(output) => {
                let content = match String::from_utf8(output) {
                    Ok(text) => json!({"type": "text", "text": text}),
                    Err(e) => json!({
                        "type": "resource",
                        "resource": {
                            "uri": format!("entangle://plugin-output/{name}"),
                            "mimeType": "application/octet-stream",
                            "blob": encode_base64(e.as_bytes()),
                        }
                    }),
                };
                ok(id, json!({"content": [content], "isError": false}))
            }
            Err(e) => tool_error(
                id,
                format!("ENTANGLE-E0688: plugin {} failed: {e}", plugin.plugin_id),
            ),
        }
    }
}

impl<B: PluginBackend> BuiltinServer for EntangleTools<B> {
    fn handle(&self, request: Value, timeout: Duration) -> BoxFuture<'_, Value> {
        Box::pin(async move {
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let params = request.get("params");
            match request.get("method").and_then(Value::as_str) {
                Some("initialize") => {
                    let asked = params
                        .and_then(|p| p.get("protocolVersion"))
                        .and_then(Value::as_str);
                    let version = asked
                        .filter(|v| SUPPORTED_PROTOCOLS.contains(v))
                        .unwrap_or(SUPPORTED_PROTOCOLS[1]);
                    ok(
                        &id,
                        json!({
                            "protocolVersion": version,
                            "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": {
                                "name": ENTANGLE_SERVER_NAME,
                                "version": env!("CARGO_PKG_VERSION"),
                            },
                            "instructions": "Tools are the plugins loaded in the local \
                                             Entanglement daemon. Each takes bytes and returns \
                                             bytes; calls are subject to the session's tool \
                                             policy and are audited.",
                        }),
                    )
                }
                Some("ping") => ok(&id, json!({})),
                Some("tools/list") => self.tools_list(&id).await,
                Some("tools/call") => self.tools_call(&id, params, timeout).await,
                Some(other) => err(&id, -32601, format!("method not found: {other}")),
                None => err(&id, -32600, "invalid request"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Debug, Default)]
    struct Fake {
        plugins: Mutex<Vec<PluginTool>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl PluginBackend for &Fake {
        fn list(&self) -> BoxFuture<'_, Result<Vec<PluginTool>, String>> {
            Box::pin(async move { Ok(self.plugins.lock().clone()) })
        }
        fn invoke(
            &self,
            plugin_id: &str,
            input: Vec<u8>,
            _timeout: Duration,
        ) -> BoxFuture<'_, Result<Vec<u8>, String>> {
            let id = plugin_id.to_owned();
            Box::pin(async move {
                self.calls.lock().push((id.clone(), input.clone()));
                if id.contains("fails") {
                    return Err("ENTANGLE-E0300: boom".into());
                }
                if id.contains("binary") {
                    return Ok(vec![0xff, 0x00, 0xfe]);
                }
                let mut out = b"echo:".to_vec();
                out.extend(input);
                Ok(out)
            })
        }
    }

    fn plugin(id: &str) -> PluginTool {
        PluginTool {
            plugin_id: id.into(),
            tier: Some(2),
        }
    }

    async fn call(fake: &'static Fake, msg: Value) -> Value {
        EntangleTools::new(fake)
            .handle(msg, Duration::from_secs(5))
            .await
    }

    fn leak(plugins: &[&str]) -> &'static Fake {
        let f: &'static Fake = Box::leak(Box::default());
        *f.plugins.lock() = plugins.iter().map(|p| plugin(p)).collect();
        f
    }

    #[test]
    fn tool_names_are_valid_unique_and_deterministic() {
        let ps = [
            plugin("bbbb/hash-it@0.1.0"),
            plugin("aaaa/hash-it@0.2.0"),
            plugin("aaaa/weird name!@1.0.0"),
            plugin(&format!("aaaa/{}@1.0.0", "x".repeat(100))),
        ];
        let names = tool_names(&ps);
        assert_eq!(names["hash-it"].plugin_id, "aaaa/hash-it@0.2.0");
        assert_eq!(names["hash-it_2"].plugin_id, "bbbb/hash-it@0.1.0");
        assert!(names.contains_key("weird_name_"));
        for n in names.keys() {
            assert!(n.len() <= 64 && !n.is_empty(), "{n}");
            assert!(n
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        }
        // Order of the listing does not matter.
        let mut rev = ps.to_vec();
        rev.reverse();
        assert_eq!(tool_names(&rev), names);
    }

    /// Review finding 10: a plugin loaded mid-session must not take over a
    /// tool name the agent (and the policy) already know as another plugin.
    #[tokio::test]
    async fn a_plugin_loaded_mid_session_never_takes_over_a_name() {
        let fake = leak(&["bbbb/hash-it@0.1.0"]);
        let server = EntangleTools::new(fake);
        let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let r = server.handle(list.clone(), Duration::from_secs(5)).await;
        assert_eq!(r["result"]["tools"][0]["name"], "hash-it");
        // A plugin whose id sorts first is loaded during the session.
        fake.plugins.lock().push(plugin("aaaa/hash-it@0.2.0"));
        let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "hash-it", "arguments": {"input": "x"}}});
        let r = server.handle(call, Duration::from_secs(5)).await;
        assert_eq!(r["result"]["isError"], false, "{r}");
        assert_eq!(
            fake.calls.lock().last().unwrap().0,
            "bbbb/hash-it@0.1.0",
            "the name keeps its plugin"
        );
        let r = server.handle(list, Duration::from_secs(5)).await;
        let names: Vec<(String, String)> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["name"].as_str().unwrap().to_owned(),
                    t["description"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names[0].0 == "hash-it" && names[0].1.contains("bbbb/hash-it"));
        assert!(names[1].0 == "hash-it_2" && names[1].1.contains("aaaa/hash-it"));
    }

    #[test]
    fn base64_round_trips() {
        for data in [&b""[..], b"a", b"ab", b"abc", b"\xff\x00\xfe\x01"] {
            assert_eq!(decode_base64(&encode_base64(data)).unwrap(), data);
        }
        assert_eq!(encode_base64(b"hello"), "aGVsbG8=");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert!(decode_base64("not base64!").is_none());
    }

    #[tokio::test]
    async fn initialize_list_and_call() {
        let f = leak(&["pub/hello@0.1.0"]);
        let init = call(
            f,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                   "params":{"protocolVersion":"2024-11-05","capabilities":{}}}),
        )
        .await;
        assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(init["result"]["serverInfo"]["name"], "entangle");
        assert!(init["result"]["capabilities"]["tools"].is_object());

        let list = call(f, json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "hello");
        assert!(tools[0]["description"]
            .as_str()
            .unwrap()
            .contains("pub/hello@0.1.0"));
        assert_eq!(tools[0]["inputSchema"]["type"], "object");

        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":"c","method":"tools/call",
                   "params":{"name":"hello","arguments":{"input":"hi"}}}),
        )
        .await;
        assert_eq!(r["id"], "c");
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["content"][0]["text"], "echo:hi");
        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                   "params":{"name":"hello","arguments":{"input_base64":"AAE="}}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(
            *f.calls.lock(),
            vec![
                ("pub/hello@0.1.0".to_owned(), b"hi".to_vec()),
                ("pub/hello@0.1.0".to_owned(), vec![0, 1])
            ]
        );
    }

    #[tokio::test]
    async fn unknown_tools_bad_arguments_and_plugin_failures() {
        let f = leak(&["pub/fails@0.1.0", "pub/binary@0.1.0"]);
        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gone"}}),
        )
        .await;
        assert_eq!(r["error"]["code"], -32602);
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("ENTANGLE-E0686"));
        for args in [
            json!({"input": 5}),
            json!({"input":"a","input_base64":"YQ=="}),
            json!({"nope": "x"}),
            json!({"input_base64": "***"}),
            json!([1]),
        ] {
            let r = call(
                f,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                       "params":{"name":"fails","arguments":args}}),
            )
            .await;
            assert_eq!(r["error"]["code"], -32602, "{r}");
        }
        assert!(f.calls.lock().is_empty(), "nothing was invoked");

        // A plugin failure is a tool error the model can read.
        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fails"}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("ENTANGLE-E0688") && text.contains("E0300"),
            "{text}"
        );

        // Non-UTF-8 output comes back as a base64 blob.
        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"binary"}}),
        )
        .await;
        assert_eq!(r["result"]["content"][0]["resource"]["blob"], "/wD+");

        // A plugin unloaded after a listing is no longer callable.
        f.plugins.lock().clear();
        let r = call(
            f,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"binary"}}),
        )
        .await;
        assert_eq!(r["error"]["code"], -32602);

        let r = call(f, json!({"jsonrpc":"2.0","id":9,"method":"resources/list"})).await;
        assert_eq!(r["error"]["code"], -32601);
    }
}

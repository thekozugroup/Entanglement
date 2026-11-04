//! `entangle config set|get|unset` — schema-checked, format-preserving edits
//! of `~/.entangle/config.toml` (spec §6.1.1, §6.4, §9.2).
//!
//! Keys are dotted paths onto the daemon's schema
//! (`crates/entangle-bin/src/config.rs`, every section `deny_unknown_fields`):
//! `mesh.tailscale.port` is `[mesh.tailscale] port`. The [`KEYS`] registry
//! names every settable key with its value type and when a change takes
//! effect; a unit test pins it against the daemon's own schema so the two
//! cannot drift.
//!
//! The spec's transport switches are spelled as keys too, although they are
//! not tables in the file: `mesh.local.enabled` and `mesh.iroh.enabled` add
//! or remove `"local"` / `"iroh"` in `[mesh] transports`, and
//! `mesh.tailscale.enabled` sets `[mesh.tailscale] enabled` **and** adds or
//! removes `"tailscale"` in `transports` (the daemon runs the transport only
//! with both).
//!
//! Every write is checked before anything touches the disk: the value
//! against the key's type, then the whole edited file exactly as the daemon
//! loads it (its parser and [`entangle_bin::config::Config::validate`]), and
//! the multi-node start-up rule (`[mesh] multi_node = true` needs a paired
//! peer, `ENTANGLE-E0050`). Only then is it written, atomically, keeping the
//! file's mode, comments and key order ([`crate::configedit`]).

use anyhow::{bail, Context as _, Result};
use toml_edit::{Array, Item, Value};

use crate::config;
use crate::configedit::ConfigDoc;

/// When a change of a key takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applies {
    /// `entangle config reload` applies it to the running daemon.
    Reload,
    /// The daemon reads it at start: restart it.
    Restart,
    /// Read by the CLI when a command runs, and by the daemon at start.
    CliNowDaemonRestart,
}

impl Applies {
    /// One line for the operator.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Reload => "applies to a running daemon with `entangle config reload`",
            Self::Restart => "takes effect when the daemon (re)starts",
            Self::CliNowDaemonRestart => {
                "used by `entangle` commands at once; the daemon picks it up when it (re)starts"
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Restart => "restart",
            Self::CliNowDaemonRestart => "now (cli) / restart (daemon)",
        }
    }
}

/// The type a key's value must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `true` / `false`.
    Bool,
    /// An integer in `min..=max`.
    Int {
        /// Smallest accepted value.
        min: i64,
        /// Largest accepted value.
        max: i64,
    },
    /// A floating-point number.
    Float,
    /// Any string.
    Str,
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// A list of strings (`a,b` or a TOML array).
    StrList,
    /// A list of transport names.
    TransportList,
    /// One transport name.
    Transport,
    /// An IP address.
    Ip,
    /// An `ip:port` socket address.
    SocketAddr,
}

impl Kind {
    fn describe(self) -> String {
        match self {
            Self::Bool => "true or false".into(),
            Self::Int { min, max } => format!("an integer from {min} to {max}"),
            Self::Float => "a number".into(),
            Self::Str => "a string".into(),
            Self::Enum(v) => format!("one of {}", v.join(", ")),
            Self::StrList => "a comma-separated list or a TOML array of strings".into(),
            Self::TransportList => {
                format!("a list of transports ({})", TRANSPORTS.join(", "))
            }
            Self::Transport => format!("one of {}", TRANSPORTS.join(", ")),
            Self::Ip => "an IP address".into(),
            Self::SocketAddr => "an ip:port address".into(),
        }
    }
}

/// Transport names `[mesh] transports` understands.
pub const TRANSPORTS: [&str; 3] = ["local", "iroh", "tailscale"];

/// How a key maps onto the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// `[path] name`.
    Plain {
        /// Table path.
        path: &'static [&'static str],
        /// Key in that table.
        name: &'static str,
    },
    /// `mesh.local.enabled` / `mesh.iroh.enabled`: membership of this
    /// transport in `[mesh] transports`.
    TransportMember(&'static str),
    /// `mesh.tailscale.enabled`: `[mesh.tailscale] enabled` and membership
    /// of `"tailscale"` in `[mesh] transports`.
    Tailscale,
}

/// One settable key.
#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    /// Dotted key, as typed on the command line.
    pub key: &'static str,
    /// Where it lives in the file.
    pub target: Target,
    /// Value type.
    pub kind: Kind,
    /// When a change takes effect.
    pub applies: Applies,
    /// When set, `config set` refuses the key and names this command, which
    /// keeps more state than the key in step.
    pub managed_by: Option<&'static str>,
    /// One-line description.
    pub help: &'static str,
}

const fn plain(
    key: &'static str,
    path: &'static [&'static str],
    name: &'static str,
    kind: Kind,
    applies: Applies,
    help: &'static str,
) -> KeySpec {
    KeySpec {
        key,
        target: Target::Plain { path, name },
        kind,
        applies,
        managed_by: None,
        help,
    }
}

const R: Applies = Applies::Restart;

/// Every key `config set|get|unset` knows. `mesh.overrides.<peer-id>` is
/// accepted in addition (one transport or a list, see [`Kind::Transport`]).
pub const KEYS: &[KeySpec] = &[
    plain(
        "node.label",
        &["node"],
        "label",
        Kind::Str,
        Applies::CliNowDaemonRestart,
        "human-readable device label shown when pairing and in mDNS (default: host name)",
    ),
    plain(
        "runtime.bus_capacity",
        &["runtime"],
        "bus_capacity",
        Kind::Int {
            min: 1,
            max: 1 << 20,
        },
        R,
        "lifecycle event bus capacity",
    ),
    plain(
        "mesh.transports",
        &["mesh"],
        "transports",
        Kind::TransportList,
        R,
        "transports this node participates in",
    ),
    plain(
        "mesh.multi_node",
        &["mesh"],
        "multi_node",
        Kind::Bool,
        R,
        "require at least one paired peer before the daemon starts (ENTANGLE-E0050)",
    ),
    plain(
        "mesh.preferred",
        &["mesh"],
        "preferred",
        Kind::Transport,
        R,
        "transport tried first for every peer without an override",
    ),
    KeySpec {
        key: "mesh.local.enabled",
        target: Target::TransportMember("local"),
        kind: Kind::Bool,
        applies: R,
        managed_by: None,
        help: "mesh.local (LAN mDNS discovery): \"local\" in [mesh] transports",
    },
    KeySpec {
        key: "mesh.iroh.enabled",
        target: Target::TransportMember("iroh"),
        kind: Kind::Bool,
        applies: R,
        managed_by: None,
        help: "mesh.iroh (QUIC over the internet): \"iroh\" in [mesh] transports",
    },
    KeySpec {
        key: "mesh.tailscale.enabled",
        target: Target::Tailscale,
        kind: Kind::Bool,
        applies: R,
        managed_by: None,
        help: "mesh.tailscale: [mesh.tailscale] enabled and \"tailscale\" in [mesh] transports",
    },
    plain(
        "mesh.tailscale.port",
        &["mesh", "tailscale"],
        "port",
        Kind::Int { min: 0, max: 65535 },
        R,
        "TCP port for Entanglement traffic over the tailnet",
    ),
    plain(
        "mesh.tailscale.acl-mode",
        &["mesh", "tailscale"],
        "acl-mode",
        Kind::Enum(&["entangle-on-top", "trust-tailnet", "tailscale-only"]),
        R,
        "entangle-on-top (default: peer allowlist on top of tailnet ACLs) or trust-tailnet",
    ),
    plain(
        "mesh.tailscale.tailscale-cli",
        &["mesh", "tailscale"],
        "tailscale-cli",
        Kind::Str,
        R,
        "path to the tailscale CLI (empty: look it up on $PATH)",
    ),
    plain(
        "mesh.tailscale.bind-ip",
        &["mesh", "tailscale"],
        "bind-ip",
        Kind::Ip,
        R,
        "local address for the tailnet listener (unset: all interfaces)",
    ),
    plain(
        "security.max_tier_allowed",
        &["security"],
        "max_tier_allowed",
        Kind::Int { min: 1, max: 5 },
        Applies::Reload,
        "ceiling on plugin tiers (lowering over loaded plugins: `entangle security set-max-tier`)",
    ),
    plain(
        "security.allow_unsandboxed_native",
        &["security"],
        "allow_unsandboxed_native",
        Kind::Bool,
        R,
        "run native plugins on a host without an OS sandbox",
    ),
    plain(
        "security.deny_capabilities",
        &["security"],
        "deny_capabilities",
        Kind::StrList,
        R,
        "capabilities never granted to any plugin, e.g. net.wan,storage.share.*",
    ),
    plain(
        "scheduler.bind",
        &["scheduler"],
        "bind",
        Kind::SocketAddr,
        R,
        "UDP address of the mesh.iroh endpoint (:0 picks a port)",
    ),
    plain(
        "scheduler.peers",
        &["scheduler"],
        "peers",
        Kind::StrList,
        R,
        "<pubkey-hex>@host:port addresses of peers to dispatch work to over mesh.iroh",
    ),
    plain(
        "scheduler.relay",
        &["scheduler"],
        "relay",
        Kind::Bool,
        R,
        "allow iroh relay fallback when hole-punching fails",
    ),
    plain(
        "scheduler.spot_check_probability",
        &["scheduler"],
        "spot_check_probability",
        Kind::Float,
        R,
        "Layer-2 spot-check rate, 0..=1",
    ),
    plain(
        "scheduler.spot_check_max_concurrent",
        &["scheduler"],
        "spot_check_max_concurrent",
        Kind::Int { min: 1, max: 1024 },
        R,
        "most spot-checks at once",
    ),
    KeySpec {
        key: "wrappers.install",
        target: Target::Plain {
            path: &["wrappers"],
            name: "install",
        },
        kind: Kind::Bool,
        applies: Applies::CliNowDaemonRestart,
        managed_by: Some("entangle wrapper enable|disable"),
        help: "the opt-in shell shim (spec §8.3)",
    },
    KeySpec {
        key: "plugins.disabled",
        target: Target::Plain {
            path: &["plugins"],
            name: "disabled",
        },
        kind: Kind::StrList,
        applies: R,
        managed_by: Some("entangle plugins disable|enable <id>"),
        help: "plugin ids that are not loaded",
    },
    plain(
        "metrics.enabled",
        &["metrics"],
        "enabled",
        Kind::Bool,
        R,
        "serve GET /metrics",
    ),
    plain(
        "metrics.listen",
        &["metrics"],
        "listen",
        Kind::SocketAddr,
        R,
        "ip:port of /metrics",
    ),
    plain(
        "metrics.allow_non_loopback",
        &["metrics"],
        "allow_non_loopback",
        Kind::Bool,
        R,
        "permit a non-loopback metrics address",
    ),
    plain(
        "telemetry.otlp.enabled",
        &["telemetry", "otlp"],
        "enabled",
        Kind::Bool,
        R,
        "export traces over OTLP/HTTP",
    ),
    plain(
        "telemetry.otlp.endpoint",
        &["telemetry", "otlp"],
        "endpoint",
        Kind::Str,
        R,
        "OTLP/HTTP base endpoint",
    ),
    plain(
        "telemetry.otlp.service_name",
        &["telemetry", "otlp"],
        "service_name",
        Kind::Str,
        R,
        "service.name resource attribute",
    ),
    plain(
        "trust.require_capability_tokens",
        &["trust"],
        "require_capability_tokens",
        Kind::Bool,
        R,
        "refuse remote requests without a capability token",
    ),
];

/// Prefix of the per-peer transport override keys.
const OVERRIDES_PREFIX: &str = "mesh.overrides.";

/// A key resolved against the registry.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The key as typed (trimmed).
    pub key: String,
    /// The registry entry (a synthetic one for `mesh.overrides.<peer>`).
    pub spec: KeySpec,
    /// For `mesh.overrides.<peer>`, the peer id.
    pub override_peer: Option<String>,
}

/// Look up `key`. Unknown keys fail with `ENTANGLE-E0780`, naming the keys
/// of the same section.
pub fn resolve(key: &str) -> Result<Resolved> {
    let key = key.trim();
    if let Some(spec) = KEYS.iter().find(|k| k.key == key) {
        return Ok(Resolved {
            key: key.to_owned(),
            spec: *spec,
            override_peer: None,
        });
    }
    if let Some(peer) = key.strip_prefix(OVERRIDES_PREFIX) {
        if peer.is_empty() || peer.contains('.') {
            bail!("ENTANGLE-E0780: `{key}`: expected mesh.overrides.<peer-id-hex>");
        }
        return Ok(Resolved {
            key: key.to_owned(),
            spec: KeySpec {
                key: "mesh.overrides.<peer-id>",
                target: Target::Plain {
                    path: &["mesh", "overrides"],
                    name: "",
                },
                kind: Kind::TransportList,
                applies: Applies::Restart,
                managed_by: None,
                help: "transports for one peer, in order (no fallback outside them)",
            },
            override_peer: Some(peer.to_owned()),
        });
    }
    let section = key.split('.').next().unwrap_or("");
    let near: Vec<&str> = KEYS
        .iter()
        .map(|k| k.key)
        .filter(|k| k.split('.').next() == Some(section))
        .collect();
    let hint = if near.is_empty() {
        "run `entangle config get` to list every key".to_owned()
    } else {
        format!("keys in [{section}]: {}", near.join(", "))
    };
    bail!("ENTANGLE-E0780: unknown config key `{key}`; {hint}")
}

impl Resolved {
    fn path_and_name(&self) -> Option<(&'static [&'static str], String)> {
        match (self.spec.target, &self.override_peer) {
            (Target::Plain { path, .. }, Some(peer)) => Some((path, peer.clone())),
            (Target::Plain { path, name }, None) => Some((path, name.to_owned())),
            _ => None,
        }
    }
}

fn bad_value(key: &str, raw: &str, kind: Kind, why: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "ENTANGLE-E0781: `{raw}` is not a valid value for {key}: {why} (expected {})",
        kind.describe()
    )
}

fn split_list(raw: &str) -> Result<Vec<String>, String> {
    let t = raw.trim();
    if t.starts_with('[') {
        let parsed: toml::Value =
            toml::from_str(&format!("v = {t}")).map_err(|e| format!("not a TOML array: {e}"))?;
        let arr = parsed
            .get("v")
            .and_then(toml::Value::as_array)
            .ok_or("not a TOML array")?;
        return arr
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("array element {v} is not a string"))
            })
            .collect();
    }
    Ok(t.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect())
}

fn check_transport(name: &str) -> Result<(), String> {
    if TRANSPORTS.contains(&name) {
        Ok(())
    } else {
        Err(format!("unknown transport `{name}`"))
    }
}

/// Parse `raw` as a value of `kind`.
pub fn parse_value(key: &str, kind: Kind, raw: &str) -> Result<Value> {
    let bad = |why: &dyn std::fmt::Display| bad_value(key, raw, kind, why);
    let t = raw.trim();
    Ok(match kind {
        Kind::Bool => match t {
            "true" => Value::from(true),
            "false" => Value::from(false),
            _ => return Err(bad(&"not a boolean")),
        },
        Kind::Int { min, max } => {
            let n: i64 = t.parse().map_err(|e| bad(&e))?;
            if !(min..=max).contains(&n) {
                return Err(bad(&"out of range"));
            }
            Value::from(n)
        }
        Kind::Float => {
            let x: f64 = t.parse().map_err(|e| bad(&e))?;
            if !x.is_finite() {
                return Err(bad(&"not a finite number"));
            }
            Value::from(x)
        }
        Kind::Str => Value::from(raw),
        Kind::Enum(options) => {
            if !options.contains(&t) {
                return Err(bad(&"not one of the accepted values"));
            }
            Value::from(t)
        }
        Kind::StrList | Kind::TransportList => {
            let items = split_list(raw).map_err(|e| bad(&e))?;
            if kind == Kind::TransportList {
                for i in &items {
                    check_transport(i).map_err(|e| bad(&e))?;
                }
                let mut seen = std::collections::HashSet::new();
                if let Some(d) = items.iter().find(|i| !seen.insert(i.as_str())) {
                    return Err(bad(&format!("`{d}` is listed twice")));
                }
            }
            let mut arr = Array::new();
            for i in items {
                arr.push(i);
            }
            Value::Array(arr)
        }
        Kind::Transport => {
            check_transport(t).map_err(|e| bad(&e))?;
            Value::from(t)
        }
        Kind::Ip => {
            t.parse::<std::net::IpAddr>().map_err(|e| bad(&e))?;
            Value::from(t)
        }
        Kind::SocketAddr => {
            t.parse::<std::net::SocketAddr>().map_err(|e| bad(&e))?;
            Value::from(t)
        }
    })
}

// ---------------------------------------------------------------------------
// Reading values
// ---------------------------------------------------------------------------

/// A key's value and where it came from.
#[derive(Clone, Debug, PartialEq)]
pub struct Shown {
    /// Value as TOML (strings unquoted when printed alone).
    pub value: toml::Value,
    /// Set in the file (`false`: the daemon default).
    pub explicit: bool,
}

fn default_table() -> Result<toml::Table> {
    let text = toml::to_string(&entangle_bin::config::Config::default())
        .context("serialising the default config")?;
    Ok(text.parse::<toml::Table>()?)
}

fn lookup<'a>(table: &'a toml::Table, path: &[&str], name: &str) -> Option<&'a toml::Value> {
    let mut cur = table;
    for p in path {
        cur = cur.get(*p)?.as_table()?;
    }
    cur.get(name)
}

fn transports_of(table: &toml::Table) -> Vec<String> {
    lookup(table, &["mesh"], "transports")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The value of `key` in `file` (a parsed config.toml), or the daemon
/// default. `None` for an optional key that is unset and has no default.
pub fn current(file: &toml::Table, r: &Resolved) -> Result<Option<Shown>> {
    let listed = |t: &str| transports_of(file).iter().any(|x| x == t);
    match r.spec.target {
        Target::TransportMember(t) => Ok(Some(Shown {
            value: toml::Value::Boolean(listed(t)),
            explicit: lookup(file, &["mesh"], "transports").is_some(),
        })),
        Target::Tailscale => {
            let enabled = lookup(file, &["mesh", "tailscale"], "enabled")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            Ok(Some(Shown {
                value: toml::Value::Boolean(enabled && listed("tailscale")),
                explicit: lookup(file, &["mesh", "tailscale"], "enabled").is_some()
                    || lookup(file, &["mesh"], "transports").is_some(),
            }))
        }
        Target::Plain { .. } => {
            let (path, name) = r
                .path_and_name()
                .context("a plain key always has a path and a name")?;
            if let Some(v) = lookup(file, path, &name) {
                return Ok(Some(Shown {
                    value: v.clone(),
                    explicit: true,
                }));
            }
            let defaults = default_table()?;
            Ok(lookup(&defaults, path, &name).map(|v| Shown {
                value: v.clone(),
                explicit: false,
            }))
        }
    }
}

/// Print a value the way `config get <key>` does: strings bare, the rest as
/// TOML.
pub fn render(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------

/// What a set/unset did to the document.
#[derive(Debug, Default)]
pub struct Edit {
    /// Human-readable notes about related state (printed after the change).
    pub notes: Vec<String>,
}

/// Apply `key = raw` to `doc`.
pub fn apply_set(doc: &mut ConfigDoc, r: &Resolved, raw: &str) -> Result<Edit> {
    let mut edit = Edit::default();
    if let Some(cmd) = r.spec.managed_by {
        bail!(
            "ENTANGLE-E0780: {} is managed by `{cmd}`, which keeps the rest of its state in \
             step; use that instead",
            r.key
        );
    }
    if r.spec.key == "node.label" {
        entangle_bin::config::check_label(raw)
            .map_err(|e| bad_value(&r.key, raw, r.spec.kind, e))?;
    }
    match r.spec.target {
        Target::TransportMember(t) => {
            let on = parse_value(&r.key, Kind::Bool, raw)?.as_bool() == Some(true);
            set_member(doc, t, on)?;
        }
        Target::Tailscale => {
            let on = parse_value(&r.key, Kind::Bool, raw)?.as_bool() == Some(true);
            doc.set_at(&["mesh", "tailscale"], "enabled", Value::from(on))?;
            set_member(doc, "tailscale", on)?;
        }
        Target::Plain { .. } => {
            let (path, name) = r
                .path_and_name()
                .context("a plain key always has a path and a name")?;
            let v = if r.override_peer.is_some() {
                let v = parse_value(&r.key, Kind::TransportList, raw)?;
                // One transport is written as a string, as the docs show it.
                match v.as_array().map(|a| a.len()) {
                    Some(1) => {
                        let one = v
                            .as_array()
                            .and_then(|a| a.get(0))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        Value::from(one)
                    }
                    _ => v,
                }
            } else {
                parse_value(&r.key, r.spec.kind, raw)?
            };
            doc.set_at(path, &name, v)?;
            if r.spec.key == "mesh.transports" {
                let listed = doc
                    .get_str_array_at(&["mesh"], "transports")
                    .iter()
                    .any(|t| t == "tailscale");
                let enabled = doc
                    .get_at(&["mesh", "tailscale"], "enabled")
                    .and_then(Item::as_bool)
                    .unwrap_or(false);
                if listed && !enabled {
                    edit.notes.push(
                        "\"tailscale\" is listed but [mesh.tailscale] enabled is not true, so \
                         the daemon will not run it; use `entangle config set \
                         mesh.tailscale.enabled true`"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(edit)
}

fn set_member(doc: &mut ConfigDoc, transport: &str, on: bool) -> Result<()> {
    if on {
        doc.add_to_str_array_at(&["mesh"], "transports", transport)?;
    } else {
        doc.remove_from_str_array_at(&["mesh"], "transports", transport)?;
    }
    Ok(())
}

/// Remove `key` from `doc` (it falls back to the daemon default).
pub fn apply_unset(doc: &mut ConfigDoc, r: &Resolved) -> Result<Edit> {
    if let Some(cmd) = r.spec.managed_by {
        bail!(
            "ENTANGLE-E0780: {} is managed by `{cmd}`; use that instead",
            r.key
        );
    }
    match r.spec.target {
        Target::TransportMember(t) => set_member(doc, t, false)?,
        Target::Tailscale => {
            doc.remove_at(&["mesh", "tailscale"], "enabled")?;
            set_member(doc, "tailscale", false)?;
        }
        Target::Plain { .. } => {
            let (path, name) = r
                .path_and_name()
                .context("a plain key always has a path and a name")?;
            doc.remove_at(path, &name)?;
        }
    }
    Ok(Edit::default())
}

/// Check `text` exactly as the daemon loads it, plus the multi-node rule
/// against the peer store at `peers`. Returns the parsed config.
pub fn validate_as_daemon(
    text: &str,
    peers: &std::path::Path,
) -> Result<entangle_bin::config::Config> {
    let cfg: entangle_bin::config::Config = toml::from_str(text).map_err(|e| {
        anyhow::anyhow!(
            "ENTANGLE-E0782: the daemon would refuse this config.toml: {}",
            e.to_string().trim_end()
        )
    })?;
    cfg.validate().map_err(|e| {
        anyhow::anyhow!("ENTANGLE-E0782: the daemon would refuse this config.toml: {e:#}")
    })?;
    if cfg.mesh.multi_node && !has_trusted_peer(peers) {
        bail!(
            "ENTANGLE-E0782: [mesh] multi_node = true needs at least one paired peer, and \
             {} has none: the daemon would refuse to start (ENTANGLE-E0050). Pair a device \
             first (`entangle pair --print-code` here, `entangle pair <code>` there), then set it",
            peers.display()
        );
    }
    Ok(cfg)
}

fn has_trusted_peer(peers: &std::path::Path) -> bool {
    entangle_peers::PeerStore::open(peers)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

fn peers_path() -> std::path::PathBuf {
    config::entangle_dir().join("peers.toml")
}

/// Edit, validate and write config.toml. `None` for `raw` unsets the key.
fn write(key: &str, raw: Option<&str>) -> Result<i32> {
    let r = resolve(key)?;
    let path = config::config_path();
    let mut doc = ConfigDoc::load(&path)?;
    let before = doc.to_text();
    let edit = match raw {
        Some(raw) => apply_set(&mut doc, &r, raw)?,
        None => apply_unset(&mut doc, &r)?,
    };
    let text = doc.to_text();
    let cfg = validate_as_daemon(&text, &peers_path())?;
    let file: toml::Table = text.parse().context("re-reading the edited config")?;
    let shown = current(&file, &r)?;
    let display = shown
        .as_ref()
        .map(|s| render(&s.value))
        .unwrap_or_else(|| "(unset)".into());
    if text == before {
        println!(
            "{key} = {display} (already so; {} unchanged)",
            path.display()
        );
        return Ok(0);
    }
    doc.save(&path)?;
    match raw {
        Some(_) => println!("set {key} = {display} in {}", path.display()),
        None => println!(
            "unset {key} in {} (now {display}{})",
            path.display(),
            if shown.as_ref().is_some_and(|s| !s.explicit) {
                ", the default"
            } else {
                ""
            }
        ),
    }
    println!("  {}", r.spec.applies.describe());
    for note in edit.notes {
        println!("note: {note}");
    }
    follow_up_hints(&r, &cfg);
    Ok(0)
}

/// After enabling a multi-node transport, say how to pair (spec §9.2 step 4:
/// "re-runs the wizard's pairing prompt").
fn follow_up_hints(r: &Resolved, cfg: &entangle_bin::config::Config) {
    let enabling = matches!(
        r.spec.target,
        Target::TransportMember(_) | Target::Tailscale
    ) || r.spec.key == "mesh.transports";
    if !enabling || cfg.mesh.transports.is_empty() || has_trusted_peer(&peers_path()) {
        return;
    }
    println!(
        "No device is paired yet. Pair one: `entangle pair --print-code` on this device, \
         `entangle pair <code>` on the other."
    );
}

/// `entangle config set <key> <value>`.
pub fn set(key: &str, raw: &str) -> Result<i32> {
    write(key, Some(raw))
}

/// `entangle config unset <key>`.
pub fn unset(key: &str) -> Result<i32> {
    write(key, None)
}

/// `entangle config get [<key>]`.
pub fn get(key: Option<&str>, json: bool) -> Result<i32> {
    let path = config::config_path();
    let file: toml::Table = match std::fs::read_to_string(&path) {
        Ok(t) => t.parse().map_err(|e| {
            anyhow::anyhow!("ENTANGLE-E0754: {} is not valid TOML: {e}", path.display())
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if let Some(key) = key {
        let r = resolve(key)?;
        let shown = current(&file, &r)?;
        if json {
            let v = serde_json::json!({
                "key": key,
                "value": shown.as_ref().map(|s| &s.value),
                "explicit": shown.as_ref().is_some_and(|s| s.explicit),
                "applies": r.spec.applies.label(),
            });
            println!("{v}");
        } else {
            match shown {
                Some(s) => println!("{}", render(&s.value)),
                None => println!("(unset)"),
            }
        }
        return Ok(0);
    }
    let mut rows = Vec::new();
    for spec in KEYS {
        let r = Resolved {
            key: spec.key.to_owned(),
            spec: *spec,
            override_peer: None,
        };
        let shown = current(&file, &r)?;
        rows.push((spec, shown));
    }
    if json {
        let v: Vec<_> = rows
            .iter()
            .map(|(spec, shown)| {
                serde_json::json!({
                    "key": spec.key,
                    "value": shown.as_ref().map(|s| &s.value),
                    "explicit": shown.as_ref().is_some_and(|s| s.explicit),
                    "applies": spec.applies.label(),
                    "managed_by": spec.managed_by,
                    "help": spec.help,
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "path": path, "keys": v }));
        return Ok(0);
    }
    println!("{} (keys marked * are set in the file)", path.display());
    let w = KEYS.iter().map(|k| k.key.len()).max().unwrap_or(0);
    for (spec, shown) in rows {
        let (mark, value) = match &shown {
            Some(s) => (if s.explicit { "*" } else { " " }, render(&s.value)),
            None => (" ", "(unset)".to_owned()),
        };
        let applies = match spec.managed_by {
            Some(cmd) => format!("via `{cmd}`"),
            None => spec.applies.label().to_owned(),
        };
        println!("{mark} {:<w$}  {value}   [{applies}]", spec.key);
    }
    println!(
        "\nAlso: mesh.overrides.<peer-id> (transports for one peer). Change a key with \
         `entangle config set <key> <value>`, drop it with `entangle config unset <key>`."
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_text(text: &str, key: &str, raw: &str) -> Result<String> {
        let mut doc = ConfigDoc::parse(text)?;
        apply_set(&mut doc, &resolve(key)?, raw)?;
        Ok(doc.to_text())
    }

    /// Every leaf key of the daemon's default config is in the registry, so
    /// a new daemon setting cannot ship without `config set` support.
    #[test]
    fn registry_covers_every_key_of_the_daemon_schema() {
        fn leaves(prefix: &str, t: &toml::Table, out: &mut Vec<String>) {
            for (k, v) in t {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match v {
                    toml::Value::Table(sub) => leaves(&key, sub, out),
                    _ => out.push(key),
                }
            }
        }
        let mut found = Vec::new();
        leaves("", &default_table().unwrap(), &mut found);
        assert!(found.len() > 20, "{found:?}");
        for k in found {
            assert!(KEYS.iter().any(|s| s.key == k), "{k} is not in KEYS");
        }
    }

    /// Every registry key, set to a sample value, yields a file the daemon
    /// loads with that value in place (so each maps onto a real schema key).
    #[test]
    fn every_registry_key_round_trips_through_the_daemon_parser() {
        let sample = |k: &KeySpec| -> &str {
            match (k.key, k.kind) {
                ("node.label", _) => "alice-laptop",
                ("mesh.transports", _) => "local,iroh",
                ("security.deny_capabilities", _) => "net.wan",
                ("scheduler.peers", _) => "[]",
                ("telemetry.otlp.endpoint", _) => "http://localhost:4318",
                (_, Kind::Bool) => "true",
                (_, Kind::Int { min, .. }) if min > 0 => "1",
                (_, Kind::Int { .. }) => "7",
                (_, Kind::Float) => "0.5",
                (_, Kind::Enum(v)) => v[0],
                (_, Kind::Transport) => "iroh",
                (_, Kind::Ip) => "100.64.0.1",
                (_, Kind::SocketAddr) => "127.0.0.1:9464",
                (_, Kind::StrList | Kind::TransportList) => "a,b",
                (_, Kind::Str) => "x",
            }
        };
        for k in KEYS.iter().filter(|k| k.managed_by.is_none()) {
            let raw = sample(k);
            let text = set_text("", k.key, raw).unwrap_or_else(|e| panic!("{}: {e:#}", k.key));
            let parsed: entangle_bin::config::Config = toml::from_str(&text)
                .unwrap_or_else(|e| panic!("{} = {raw}: daemon refused:\n{text}\n{e}", k.key));
            let file: toml::Table = text.parse().unwrap();
            let shown = current(&file, &resolve(k.key).unwrap()).unwrap().unwrap();
            assert!(shown.explicit, "{}", k.key);
            drop(parsed);
        }
    }

    #[test]
    fn transport_switches_edit_the_transports_list_and_the_tailscale_table() {
        let base = "# keep\n[mesh]\ntransports = [\"local\"] # lan\n";
        let on = set_text(base, "mesh.tailscale.enabled", "true").unwrap();
        assert!(
            on.starts_with("# keep\n[mesh]\ntransports = [\"local\", \"tailscale\"] # lan\n"),
            "{on}"
        );
        assert!(on.contains("[mesh.tailscale]\nenabled = true\n"), "{on}");
        let cfg: entangle_bin::config::Config = toml::from_str(&on).unwrap();
        assert!(entangle_bin::tailscale::enabled(&cfg.mesh));

        let off = set_text(&on, "mesh.tailscale.enabled", "false").unwrap();
        let cfg: entangle_bin::config::Config = toml::from_str(&off).unwrap();
        assert_eq!(cfg.mesh.transports, ["local"]);
        assert!(!cfg.mesh.tailscale.enabled);

        let iroh = set_text(base, "mesh.iroh.enabled", "true").unwrap();
        let no_local = set_text(&iroh, "mesh.local.enabled", "false").unwrap();
        let cfg: entangle_bin::config::Config = toml::from_str(&no_local).unwrap();
        assert_eq!(cfg.mesh.transports, ["iroh"]);
        let file: toml::Table = no_local.parse().unwrap();
        let shown = current(&file, &resolve("mesh.local.enabled").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(shown.value, toml::Value::Boolean(false));
    }

    #[test]
    fn values_are_type_checked_against_the_key() {
        for (key, raw) in [
            ("mesh.tailscale.port", "70000"),
            ("mesh.tailscale.port", "abc"),
            ("security.max_tier_allowed", "6"),
            ("mesh.multi_node", "yes"),
            ("mesh.transports", "local,wifi"),
            ("mesh.transports", "local,local"),
            ("mesh.preferred", "udp"),
            ("mesh.tailscale.acl-mode", "open"),
            ("mesh.tailscale.bind-ip", "tailnet"),
            ("scheduler.spot_check_probability", "nan"),
            ("node.label", "  "),
        ] {
            let err = set_text("", key, raw).unwrap_err().to_string();
            assert!(err.contains("ENTANGLE-E0781"), "{key}={raw}: {err}");
        }
        let err = resolve("mesh.tailscale.prot").unwrap_err().to_string();
        assert!(
            err.contains("ENTANGLE-E0780") && err.contains("mesh.tailscale.port"),
            "{err}"
        );
        let err = set_text("", "wrappers.install", "true")
            .unwrap_err()
            .to_string();
        assert!(err.contains("entangle wrapper enable|disable"), "{err}");
    }

    #[test]
    fn overrides_take_one_transport_or_an_ordered_list() {
        let peer = "7a21c0de7a21c0de7a21c0de7a21c0de";
        let one = set_text("", &format!("mesh.overrides.{peer}"), "iroh").unwrap();
        assert!(one.contains(&format!("{peer} = \"iroh\"")), "{one}");
        let cfg: entangle_bin::config::Config = toml::from_str(&one).unwrap();
        assert_eq!(
            cfg.mesh.overrides.get(peer),
            Some(&entangle_bin::config::TransportOverride::One("iroh".into()))
        );
        let two = set_text(&one, &format!("mesh.overrides.{peer}"), "tailscale,iroh").unwrap();
        let cfg: entangle_bin::config::Config = toml::from_str(&two).unwrap();
        assert_eq!(cfg.mesh.overrides.len(), 1);
        // A bad peer id is refused by the daemon's own validation.
        let bad = set_text("", "mesh.overrides.bob", "iroh").unwrap();
        let err = validate_as_daemon(&bad, std::path::Path::new("/nonexistent/peers.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ENTANGLE-E0782") && err.contains("E0435"),
            "{err}"
        );
    }

    #[test]
    fn multi_node_without_a_peer_is_refused_like_the_daemon_start() {
        let text = set_text("", "mesh.multi_node", "true").unwrap();
        let err = validate_as_daemon(&text, std::path::Path::new("/nonexistent/peers.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("E0050") && err.contains("entangle pair --print-code"),
            "{err}"
        );
    }

    #[test]
    fn unset_falls_back_to_the_default() {
        let mut doc =
            ConfigDoc::parse("[mesh.tailscale]\nport = 9 # mine\nenabled = true\n").unwrap();
        apply_unset(&mut doc, &resolve("mesh.tailscale.port").unwrap()).unwrap();
        let file: toml::Table = doc.to_text().parse().unwrap();
        let shown = current(&file, &resolve("mesh.tailscale.port").unwrap())
            .unwrap()
            .unwrap();
        assert!(!shown.explicit);
        assert_eq!(
            shown.value,
            toml::Value::Integer(i64::from(entangle_mesh_tailscale::DEFAULT_PORT))
        );
        assert!(doc.to_text().contains("enabled = true"));
    }
}

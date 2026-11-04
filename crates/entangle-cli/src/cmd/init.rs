//! `entangle init` — set up `~/.entangle` (spec §9.2, §9.1.1, §11 #16–17).
//!
//! Interactive by default: a line-based wizard (no cursor movement, plain
//! `question [default]:` lines, see [`crate::cmd::ui`]) that asks for the
//! device label, whether this daemon will ever talk to another node, which
//! transports to use (detecting a Tailscale tailnet with `tailscale status
//! --json`), the tier ceiling and how to get the identity key; then writes
//! the files, prints what to open in a firewall (it never changes one), and
//! offers to pair a device now.
//!
//! `--headless` (or the older `--non-interactive`) asks nothing: every
//! choice comes from flags (`--single-node`, `--transport`, `--label`,
//! `--max-tier`, `--tailscale-profile`) or defaults.
//!
//! Multi-node is never written with an empty allowlist: `[mesh] multi_node`
//! stays `false` until a device is paired (the daemon would refuse to start
//! otherwise, `ENTANGLE-E0050`), and the node's own key is never put on its
//! allowlist. The wizard pairs now, or prints the `entangle pair` commands.
//!
//! Choosing `mesh.tailscale` runs the §9.1.1 checks, each failure with its
//! message and exit code: binary missing (64), older than 1.62.0 (69,
//! `ENTANGLE-E0891`; the CLI's version and tailscaled's are both checked),
//! version unknown (69, `ENTANGLE-E0893`), not logged in or stopped (65),
//! running but offline (75), several login profiles not confirmed (64).

use crate::cmd::ui::{Prompter, Style};
use crate::config::{self, entangle_dir};
use crate::configedit::ConfigDoc;
use crate::identity::ensure_identity;
use anyhow::Context;
use clap::Args;
use entangle_mesh_tailscale::{
    CliStatusSource, MeshTailscaleError, StatusSource as _, TailnetState, TailscaleProfile,
    TailscaleStatus, TailscaleVersion,
};
use entangle_signing::{IdentityKeyPair, Keyring};
use std::path::{Path, PathBuf};
use toml_edit::{Array, Value};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

/// `entangle init` arguments.
#[derive(Args, Debug, Default, Clone)]
pub struct InitArgs {
    /// Ask nothing; use flags and defaults. Older spelling of --headless.
    #[arg(long)]
    pub non_interactive: bool,

    /// Ask nothing: every choice comes from the flags below or defaults
    /// (label = host name, transports = local, max tier = 5, new identity).
    /// Existing files are left in place; an existing config.toml gets only
    /// what the flags set.
    #[arg(long)]
    pub headless: bool,

    /// This daemon never talks to another node: no transports.
    #[arg(long, conflicts_with = "transport")]
    pub single_node: bool,

    /// Transports to enable, comma-separated: local, iroh, tailscale.
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub transport: Vec<String>,

    /// Human-readable device label shown to paired devices (default: host name).
    #[arg(long, alias = "identity-label", value_name = "LABEL")]
    pub label: Option<String>,

    /// The Tailscale profile (tailnet, account or id) you expect to be
    /// active; required with --headless when several profiles exist.
    #[arg(long, value_name = "NAME")]
    pub tailscale_profile: Option<String>,

    /// `[security] max_tier_allowed`, 1..=5 (default 5).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=5))]
    pub max_tier: Option<u8>,
}

impl InitArgs {
    fn headless(&self) -> bool {
        self.headless || self.non_interactive
    }
}

/// A failure that ends `init` with a specific exit code (spec §9.1.1).
#[derive(Debug)]
pub struct InitFailure {
    /// Process exit code.
    pub code: i32,
    /// The message (may span lines).
    pub message: String,
}

impl std::fmt::Display for InitFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InitFailure {}

/// `EX_USAGE`.
const EXIT_USAGE: i32 = 64;
/// `EX_DATAERR`: the tailnet is not usable as it is.
const EXIT_TAILNET: i32 = 65;
/// `EX_UNAVAILABLE`: the host `tailscale` is too old.
const EXIT_UNAVAILABLE: i32 = 69;
/// `EX_TEMPFAIL`: retry shortly.
const EXIT_TEMPFAIL: i32 = 75;

fn fail(code: i32, message: impl Into<String>) -> anyhow::Error {
    InitFailure {
        code,
        message: message.into(),
    }
    .into()
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

enum IdentityAction {
    Generate,
    Import(String),
}

/// What to write. A `None` setting was not chosen (no flag, and no question
/// asked because config.toml already exists): the file keeps its value, and
/// a new file gets the default.
struct WizardAnswers {
    /// `[node] label`.
    label: Option<String>,
    /// `[mesh] transports` (and `[mesh.tailscale]` to match).
    transports: Option<Vec<String>>,
    /// `[security] max_tier_allowed`.
    max_tier: Option<u8>,
    action: IdentityAction,
    /// Detection result, when tailscale was chosen.
    tailscale: Option<TsReport>,
    /// Ask to pair at the end (interactive only).
    offer_pairing: bool,
}

/// Defaults for a new config.toml (spec §9.2 headless defaults).
const DEFAULT_TRANSPORTS: &[&str] = &["local"];
const DEFAULT_MAX_TIER: u8 = 5;

fn check_label(label: &str) -> anyhow::Result<()> {
    entangle_bin::config::check_label(label)
        .map_err(|e| fail(EXIT_USAGE, format!("ENTANGLE-E0884: invalid --label: {e}")))
}

fn parse_transports(raw: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for t in raw.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let t = t.strip_prefix("mesh.").unwrap_or(t);
        if !crate::cmd::configset::TRANSPORTS.contains(&t) {
            return Err(fail(
                EXIT_USAGE,
                format!(
                    "ENTANGLE-E0884: unknown transport `{t}` in --transport (expected local, iroh \
                     or tailscale)"
                ),
            ));
        }
        if !out.iter().any(|x| x == t) {
            out.push(t.to_owned());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tailscale detection (spec §9.2 step 5, §9.1.1, §11 #17)
// ---------------------------------------------------------------------------

/// What `tailscale` on this host says.
pub(crate) struct TsReport {
    /// The command run (`tailscale` or a configured path).
    pub cli: String,
    /// Where `cli` resolves on `$PATH`, when it is a bare name.
    pub resolved: Option<PathBuf>,
    /// `tailscale version`, or why it could not be read.
    pub version: Result<TailscaleVersion, String>,
    /// Classified liveness state.
    pub state: TailnetState,
    /// The parsed status, when there was one.
    pub status: Option<TailscaleStatus>,
    /// Login profiles (`tailscale switch --list`); empty when unknown.
    pub profiles: Vec<TailscaleProfile>,
}

/// Find `cmd` on `$PATH` (a path with a `/` is returned as is when it
/// exists).
pub(crate) fn which(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        return p.is_file().then_some(p);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(cmd))
        .find(|p| p.is_file())
}

/// Probe the host's `tailscale` (status, version, profiles).
pub(crate) async fn detect_tailscale(cli: &str) -> TsReport {
    let source = CliStatusSource::new(cli);
    let obs = source.observe().await;
    let version = match source.fetch_version().await {
        Ok(v) => Ok(v),
        Err(MeshTailscaleError::NotInstalled) => Err("not installed".to_owned()),
        Err(e) => Err(e.to_string()),
    };
    let profiles = source.list_profiles().await.unwrap_or_default();
    TsReport {
        cli: cli.to_owned(),
        resolved: which(cli),
        version,
        state: obs.state,
        status: obs.status,
        profiles,
    }
}

impl TsReport {
    /// The tailnet is up and this node is online in it.
    pub fn active(&self) -> bool {
        self.state == TailnetState::Active
    }

    fn tailnet(&self) -> String {
        self.profiles
            .iter()
            .find(|p| p.active)
            .map(|p| p.tailnet.clone())
            .filter(|t| !t.is_empty())
            .or_else(|| self.status.as_ref().and_then(|s| s.tailnet_name.clone()))
            .unwrap_or_else(|| "(unnamed tailnet)".to_owned())
    }

    fn binary(&self) -> String {
        self.resolved
            .as_ref()
            .map_or_else(|| self.cli.clone(), |p| p.display().to_string())
    }

    /// tailscaled's version, from the status JSON.
    fn daemon_version(&self) -> Option<TailscaleVersion> {
        self.status
            .as_ref()
            .and_then(TailscaleStatus::parsed_version)
    }

    /// The version to show: the CLI's, else tailscaled's.
    fn known_version(&self) -> Option<TailscaleVersion> {
        self.version
            .as_ref()
            .ok()
            .copied()
            .or_else(|| self.daemon_version())
    }

    /// One line: version, binary and state.
    pub fn summary(&self) -> String {
        let version = match self.known_version() {
            Some(v) => format!("tailscale {v}"),
            None => "tailscale".to_owned(),
        };
        match &self.state {
            TailnetState::Active => format!(
                "{version} at {}: tailnet '{}' is active",
                self.binary(),
                self.tailnet()
            ),
            TailnetState::Stopped { reason } => {
                format!("{version} at {}: not active ({reason})", self.binary())
            }
            TailnetState::Uninstalled => "tailscale: not installed".to_owned(),
        }
    }

    /// The §9.1.1 failure for using `mesh.tailscale` on this host, if any.
    pub fn failure(&self) -> Option<anyhow::Error> {
        const SKIP: &str = "If you intended to skip Tailscale: rerun with --transport local,iroh";
        if self.state == TailnetState::Uninstalled
            || self.version.as_ref().is_err_and(|e| e == "not installed")
        {
            return Some(fail(
                EXIT_USAGE,
                "ENTANGLE-E0889: tailscale binary not found.\n  Install: \
                 https://tailscale.com/download\n  Or: rerun with --transport local,iroh",
            ));
        }
        // Spec §11 #17, failing closed: the CLI's version and tailscaled's
        // are both held to the floor, and an unknown one is refused.
        if let Err(e) =
            entangle_mesh_tailscale::check_versions(self.version.clone(), self.daemon_version())
        {
            return Some(fail(EXIT_UNAVAILABLE, e.to_string()));
        }
        match &self.state {
            TailnetState::Active | TailnetState::Uninstalled => None,
            TailnetState::Stopped { reason } if reason == "NeedsLogin" => Some(fail(
                EXIT_TAILNET,
                format!(
                    "ENTANGLE-E0889: tailnet not authenticated.\n  Run 'tailscale up' then \
                     retry.\n  {SKIP}"
                ),
            )),
            TailnetState::Stopped { reason } if reason == "Self offline" => Some(fail(
                EXIT_TEMPFAIL,
                "ENTANGLE-E0889: tailnet authenticated but offline. Wait a few seconds and \
                 retry, or check 'tailscale netcheck'.",
            )),
            TailnetState::Stopped { reason } => Some(fail(
                EXIT_TAILNET,
                format!(
                    "ENTANGLE-E0889: tailnet stopped ({reason}). Run 'tailscale up' to \
                     resume.\n  {SKIP}"
                ),
            )),
        }
    }
}

/// Several login profiles: the active one must be the one meant (spec
/// §9.1.1). `--tailscale-profile` names it; otherwise ask (interactive) or
/// refuse (headless).
fn confirm_profile(
    report: &TsReport,
    expected: Option<&str>,
    prompter: Option<&mut Prompter>,
) -> anyhow::Result<()> {
    let active = report.profiles.iter().find(|p| p.active);
    if let Some(want) = expected {
        return match active {
            Some(p) if p.matches(want) => Ok(()),
            Some(p) => Err(fail(
                EXIT_USAGE,
                format!(
                    "ENTANGLE-E0884: the active Tailscale profile is '{}' ({}), not '{want}'. \
                     Run 'tailscale switch {want}' and retry.",
                    p.tailnet, p.account
                ),
            )),
            // No profile list (an older CLI): nothing to compare against.
            None => Ok(()),
        };
    }
    if report.profiles.len() < 2 {
        return Ok(());
    }
    let Some(p) = active else {
        return Ok(());
    };
    let warn = format!(
        "{} multiple tailnets/profiles detected. Active profile: '{}' ({}).\n  If this is \
         wrong, run 'tailscale switch <profile>' or pass --tailscale-profile <name> and retry.",
        Style::stdout().warning(),
        p.tailnet,
        p.account
    );
    match prompter {
        Some(prompter) => {
            println!("{warn}");
            if prompter.confirm(&format!("Continue with '{}'?", p.tailnet), false)? {
                Ok(())
            } else {
                Err(fail(
                    EXIT_USAGE,
                    "ENTANGLE-E0884: stopped: the active Tailscale profile was not confirmed",
                ))
            }
        }
        None => Err(fail(
            EXIT_USAGE,
            format!(
                "ENTANGLE-E0884: multiple Tailscale profiles; active: '{}' ({}). Pass \
                 --tailscale-profile {} to confirm it (or 'tailscale switch <profile>' first).",
                p.tailnet, p.account, p.tailnet
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Interactive wizard
// ---------------------------------------------------------------------------

/// Transports from `--single-node` / `--transport`, if either was given.
fn flagged_transports(args: &InitArgs) -> anyhow::Result<Option<Vec<String>>> {
    if args.single_node {
        Ok(Some(Vec::new()))
    } else if !args.transport.is_empty() {
        parse_transports(&args.transport).map(Some)
    } else {
        Ok(None)
    }
}

/// `existing`: config.toml is already there. Its questions are then not
/// asked — the file keeps its settings, flags still apply — and only the
/// identity question remains.
async fn run_wizard(args: &InitArgs, existing: bool) -> anyhow::Result<WizardAnswers> {
    let st = Style::stdout();
    let mut p = Prompter::new();
    let hostname = config::host_name();

    println!("Welcome to Entanglement.");
    println!(
        "This sets up {}: a device identity, config.toml, peers.toml and keyring.toml.",
        entangle_dir().display()
    );
    println!("Each question shows its default in brackets; press Enter to accept it.");

    let mut tailscale = None;
    let (label, transports, max_tier) = if existing {
        println!(
            "\n{} already exists, so init keeps its settings and does not ask about them; \
             --label, --transport, --single-node and --max-tier are applied to it. Change a \
             setting with `entangle config set <key> <value>` (`entangle config get` lists them).",
            config::config_path().display()
        );
        let label = args.label.clone();
        if let Some(l) = &label {
            check_label(l)?;
        }
        (label, flagged_transports(args)?, args.max_tier)
    } else {
        // [1/5] label
        println!("\n{}", st.bold("[1/5] Device label"));
        println!("Shown to the devices you pair with, next to this device's fingerprint.");
        let label = match &args.label {
            Some(l) => l.clone(),
            None => loop {
                let l = p.text("Label", &hostname)?;
                match entangle_bin::config::check_label(&l) {
                    Ok(()) => break l,
                    Err(e) => println!("  {e}"),
                }
            },
        };
        check_label(&label)?;

        // [2/5] single-node or not, and transports
        println!("\n{}", st.bold("[2/5] Other devices"));
        let transports = if let Some(t) = flagged_transports(args)? {
            if t.is_empty() {
                println!("Single-node (--single-node): no transports.");
            } else {
                println!("Transports (--transport): {}", t.join(", "));
            }
            t
        } else if !p.confirm(
            "Will this daemon ever talk to another Entanglement node?",
            false,
        )? {
            println!(
                "Single-node: no transports. Later: `entangle config set mesh.local.enabled \
                 true` (or mesh.iroh / mesh.tailscale), then pair with `entangle pair`."
            );
            Vec::new()
        } else {
            println!("\n{}", st.bold("[3/5] Transports"));
            println!("Checking for Tailscale (`tailscale status --json`)...");
            let report = detect_tailscale("tailscale").await;
            println!("  {}", report.summary());
            let mut chosen = Vec::new();
            if report.state != TailnetState::Uninstalled
                && p.confirm(
                    "Use mesh.tailscale (reach your devices over your tailnet)?",
                    report.active(),
                )?
            {
                // The §9.1.1 checks right away, while the tailnet is the topic.
                if let Some(e) = report.failure() {
                    return Err(e);
                }
                confirm_profile(&report, args.tailscale_profile.as_deref(), Some(&mut p))?;
                chosen.push("tailscale".to_owned());
                tailscale = Some(report);
            }
            if p.confirm("Use mesh.local (find devices on this LAN over mDNS)?", true)? {
                chosen.push("local".to_owned());
            }
            if p.confirm(
                "Use mesh.iroh (QUIC across networks with NAT traversal; also carries work to \
                 LAN peers found by mesh.local)?",
                chosen.iter().any(|t| t == "local"),
            )? {
                chosen.push("iroh".to_owned());
            }
            if chosen.is_empty() {
                println!("No transport chosen: this node is single-node.");
            }
            chosen
        };

        // [4/5] tier ceiling
        println!("\n{}", st.bold("[4/5] Plugin tier ceiling"));
        println!("1-5; 5 allows native subprocess plugins, 3 forbids every native plugin.");
        let max_tier = match args.max_tier {
            Some(t) => t,
            None => loop {
                let raw = p.text("max_tier_allowed", "5")?;
                match raw.parse::<u8>() {
                    Ok(n) if (1..=5).contains(&n) => break n,
                    _ => println!("  Please answer a number from 1 to 5."),
                }
            },
        };
        (Some(label), Some(transports), Some(max_tier))
    };
    let chosen_tailscale = transports
        .as_ref()
        .is_some_and(|t| t.iter().any(|x| x == "tailscale"));
    if tailscale.is_none() && chosen_tailscale {
        // Chosen with --transport: check it the same way.
        let report = detect_tailscale("tailscale").await;
        println!("  {}", report.summary());
        if let Some(e) = report.failure() {
            return Err(e);
        }
        confirm_profile(&report, args.tailscale_profile.as_deref(), Some(&mut p))?;
        tailscale = Some(report);
    }

    // [5/5] identity
    println!(
        "\n{}",
        st.bold(if existing {
            "Identity key"
        } else {
            "[5/5] Identity key"
        })
    );
    let action = if config::identity_path().exists() {
        println!(
            "An identity already exists at {}.",
            config::identity_path().display()
        );
        println!(
            "k: keep it; i: import a PEM file instead (asks before replacing it, and backs the \
             old key up first)."
        );
        match p.choose("Identity", &["k", "i"], "k")?.as_str() {
            "i" => IdentityAction::Import(p.text("PEM file path", "")?),
            // `ensure_identity` keeps the key on disk.
            _ => IdentityAction::Generate,
        }
    } else {
        println!("g: generate a fresh Ed25519 key (new device); i: import a PEM file.");
        match p.choose("Identity", &["g", "i"], "g")?.as_str() {
            "i" => IdentityAction::Import(p.text("PEM file path", "")?),
            _ => IdentityAction::Generate,
        }
    };

    Ok(WizardAnswers {
        label,
        offer_pairing: true,
        transports,
        max_tier,
        action,
        tailscale,
    })
}

/// `existing`: config.toml is already there, so only what a flag sets is
/// written; otherwise every setting gets its default.
async fn headless_answers(args: &InitArgs, existing: bool) -> anyhow::Result<WizardAnswers> {
    let label = match &args.label {
        Some(l) => Some(l.clone()),
        None if existing => None,
        None => Some(config::host_name()),
    };
    if let Some(l) = &label {
        check_label(l)?;
    }
    let transports = match flagged_transports(args)? {
        Some(t) => Some(t),
        None if existing => None,
        None => Some(DEFAULT_TRANSPORTS.iter().map(|t| (*t).to_owned()).collect()),
    };
    let tailscale = if transports
        .as_ref()
        .is_some_and(|t| t.iter().any(|x| x == "tailscale"))
    {
        let report = detect_tailscale("tailscale").await;
        if let Some(e) = report.failure() {
            return Err(e);
        }
        confirm_profile(&report, args.tailscale_profile.as_deref(), None)?;
        Some(report)
    } else {
        None
    };
    Ok(WizardAnswers {
        label,
        transports,
        max_tier: args.max_tier.or((!existing).then_some(DEFAULT_MAX_TIER)),
        action: IdentityAction::Generate,
        tailscale,
        offer_pairing: false,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Write the chosen settings into `doc`; returns the keys set.
fn apply_answers(doc: &mut ConfigDoc, a: &WizardAnswers) -> anyhow::Result<Vec<&'static str>> {
    let mut keys = Vec::new();
    if let Some(label) = &a.label {
        doc.set_at(&["node"], "label", Value::from(label.as_str()))?;
        keys.push("node.label");
    }
    if let Some(transports) = &a.transports {
        let mut list = Array::new();
        for t in transports {
            list.push(t.as_str());
        }
        doc.set_at(&["mesh"], "transports", Value::Array(list))?;
        keys.push("mesh.transports");
        if transports.iter().any(|t| t == "tailscale") {
            doc.set_at(&["mesh", "tailscale"], "enabled", Value::from(true))?;
            // A mode already chosen in the file stays.
            if doc.get_at(&["mesh", "tailscale"], "acl-mode").is_none() {
                doc.set_at(
                    &["mesh", "tailscale"],
                    "acl-mode",
                    Value::from("entangle-on-top"),
                )?;
            }
            keys.push("mesh.tailscale.enabled");
        } else if doc
            .get_at(&["mesh", "tailscale"], "enabled")
            .and_then(toml_edit::Item::as_bool)
            == Some(true)
        {
            // Off with the transport, as `config set mesh.tailscale.enabled
            // false` does: an enabled table outside `transports` is inert.
            doc.set_at(&["mesh", "tailscale"], "enabled", Value::from(false))?;
            keys.push("mesh.tailscale.enabled");
        }
    }
    if let Some(tier) = a.max_tier {
        doc.set_at(
            &["security"],
            "max_tier_allowed",
            Value::from(i64::from(tier)),
        )?;
        keys.push("security.max_tier_allowed");
    }
    Ok(keys)
}

/// The config.toml `init` writes, validated as the daemon loads it.
fn initial_config(a: &WizardAnswers, peers: &Path) -> anyhow::Result<ConfigDoc> {
    let mut doc = ConfigDoc::parse(
        "# Entanglement configuration, written by `entangle init`.\n\
         # Change it with `entangle config set <key> <value>` (`entangle config get` lists the keys).\n\n",
    )?;
    apply_answers(&mut doc, a)?;
    // Never multi-node with an empty allowlist (spec §9.2, §11 #16): it is
    // switched on only once a device is paired.
    doc.set_at(&["mesh"], "multi_node", Value::from(false))?;
    crate::cmd::configset::validate_as_daemon(&doc.to_text(), peers)
        .context("the config.toml init would write")?;
    Ok(doc)
}

/// The settings chosen with flags, applied to an existing config.toml and
/// validated as the daemon loads it. `None` when there is nothing to change.
fn edited_config(
    a: &WizardAnswers,
    cfg_path: &Path,
    peers: &Path,
) -> anyhow::Result<Option<(ConfigDoc, Vec<&'static str>)>> {
    if a.label.is_none() && a.transports.is_none() && a.max_tier.is_none() {
        return Ok(None);
    }
    let mut doc = ConfigDoc::load(cfg_path)?;
    let before = doc.to_text();
    let keys = apply_answers(&mut doc, a)?;
    crate::cmd::configset::validate_as_daemon(&doc.to_text(), peers)
        .with_context(|| format!("the changes init would make to {}", cfg_path.display()))?;
    Ok((doc.to_text() != before).then_some((doc, keys)))
}

/// The transports the daemon would run from config.toml as it is on disk
/// (`tailscale` only when `[mesh.tailscale] enabled` too); `None` when the
/// daemon could not read the file.
fn configured_transports(cfg_path: &Path) -> Option<Vec<String>> {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return None,
    };
    let cfg: entangle_bin::config::Config = toml::from_str(&text).ok()?;
    let tailscale_on = cfg.mesh.tailscale.enabled;
    Some(
        cfg.mesh
            .transports
            .into_iter()
            .filter(|t| t != "tailscale" || tailscale_on)
            .collect(),
    )
}

/// What to open in a host firewall, per transport. Init never changes a
/// firewall (deviation from spec §1 / §9.2 step 6).
fn print_firewall_notes(transports: &[String]) {
    if transports.is_empty() {
        return;
    }
    let st = Style::stdout();
    println!("\n{}", st.bold("Firewall"));
    println!("init does not change your firewall. If one is on, allow:");
    for t in transports {
        match t.as_str() {
            "local" => println!("  mesh.local      UDP 5353 (mDNS multicast) on the LAN interface"),
            "iroh" => println!(
                "  mesh.iroh       the UDP port of [scheduler] bind (default: a random port; fix \
                 one with `entangle config set scheduler.bind 0.0.0.0:41641`, then allow UDP 41641)"
            ),
            "tailscale" => println!(
                "  mesh.tailscale  nothing on the host firewall: TCP {} arrives over the tailnet \
                 (restrict it with a Tailscale ACL, below)",
                entangle_mesh_tailscale::DEFAULT_PORT
            ),
            _ => {}
        }
    }
    println!(
        "  pairing         a random UDP port, shown by `entangle pair --print-code` (fix it with \
         --bind 0.0.0.0:<port>)"
    );
}

/// The spec §9.1.1 shared-tailnet note, the trust dependency of §11 #17 and
/// the sample ACL of §11 #16.
fn print_tailscale_notes(report: &TsReport) {
    let st = Style::stdout();
    let tailnet = report.tailnet();
    println!("\n{}", st.bold("Tailscale"));
    let version = report
        .known_version()
        .map_or_else(|| "unknown version".to_owned(), |v| v.to_string());
    println!(
        "Entanglement trusts the local Tailscale binary ({}, version {version}) for peer \
         discovery.",
        report.binary()
    );
    println!(
        "{} tailnet '{tailnet}' may be shared with other Entanglement users.",
        st.note()
    );
    println!(
        "  Default: [mesh.tailscale] acl-mode = \"entangle-on-top\" — Entanglement enforces its \
         own peer allowlist regardless of tailnet ACLs."
    );
    if report.status.as_ref().is_some_and(|s| s.users.len() > 1) {
        println!(
            "  This tailnet has {} accounts: keep acl-mode = \"entangle-on-top\".",
            report.status.as_ref().map_or(0, |s| s.users.len())
        );
    }
    println!("  Run 'entangle peers list' to see trusted peers (initially: none; pair one first).");
    println!(
        "  Sample Tailscale ACL limiting the Entanglement port to tagged devices:\n    \
         {{\"acls\": [{{\"action\": \"accept\", \"src\": [\"tag:entangle\"], \"dst\": \
         [\"tag:entangle:{}\"]}}]}}",
        entangle_mesh_tailscale::DEFAULT_PORT
    );
}

fn print_pair_later() {
    println!("Daemon configured as single-node until a device is paired. Pair one:");
    println!("  entangle pair --print-code     # on this device");
    println!("  entangle pair <code>           # on the other device");
    println!(
        "Then make the daemon require a paired peer at start: entangle config set mesh.multi_node true"
    );
}

/// After a successful pairing: the allowlist is populated, so multi-node can
/// be recorded (the daemon's start-up rule now holds).
fn enable_multi_node(cfg_path: &Path, peers: &Path) -> anyhow::Result<()> {
    let mut doc = ConfigDoc::load(cfg_path)?;
    doc.set_at(&["mesh"], "multi_node", Value::from(true))?;
    crate::cmd::configset::validate_as_daemon(&doc.to_text(), peers)?;
    doc.save(cfg_path)?;
    println!("Set [mesh] multi_node = true (a paired device is on the allowlist).");
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// `entangle init`; returns the process exit code (spec §9.1.1 codes).
pub async fn run(args: InitArgs) -> anyhow::Result<i32> {
    match ensure_initialised(args, true).await {
        Ok(()) => Ok(0),
        Err(e) => match e.downcast_ref::<InitFailure>() {
            Some(f) => {
                eprintln!("{} {}", Style::stderr().error(), f.message);
                Ok(f.code)
            }
            None => Err(e),
        },
    }
}

/// The body of `entangle init`, reusable by other commands.
///
/// `entangle quickstart` and `entangle install` need exactly this —
/// create-or-keep the identity, config, peer store, and keyring — but print
/// their own closing banner, so `print_next_steps` suppresses `init`'s.
///
/// Idempotent: with all four files present this returns early without touching
/// anything. A failure with a specific exit code is an [`InitFailure`].
pub(crate) async fn ensure_initialised(
    args: InitArgs,
    print_next_steps: bool,
) -> anyhow::Result<()> {
    let dir = entangle_dir();
    let id_path = config::identity_path();
    let cfg_path = config::config_path();
    let kr_path = config::keyring_path();
    let peers_path = dir.join("peers.toml");

    // Idempotency check: all four files already present → nothing to do.
    if id_path.exists() && cfg_path.exists() && kr_path.exists() && peers_path.exists() {
        println!("Already initialized at {}.", dir.display());
        return Ok(());
    }

    // Every question (and every tailnet check), and the config.toml to
    // write checked as the daemon loads it, before anything is written. An
    // existing config.toml gets only what was chosen with flags.
    let existing = cfg_path.exists();
    let answers = if args.headless() {
        headless_answers(&args, existing).await?
    } else {
        run_wizard(&args, existing).await?
    };
    let doc = if existing {
        edited_config(&answers, &cfg_path, &peers_path)?.map(|(doc, keys)| (doc, Some(keys)))
    } else {
        Some((initial_config(&answers, &peers_path)?, None))
    };

    create_entangle_dir(&dir)?;
    println!();
    match &answers.action {
        IdentityAction::Generate => println!("Setting up identity..."),
        IdentityAction::Import(_) => println!("Importing identity..."),
    }

    // --- identity.key ---
    let kp = match &answers.action {
        IdentityAction::Generate => {
            let kp = ensure_identity(&id_path)?;
            println!("  Identity ready at {} (mode 0600)", id_path.display());
            kp
        }
        IdentityAction::Import(pem_path) => import_identity(pem_path, &id_path, &peers_path)?,
    };

    let fingerprint = fmt_fingerprint(&kp.fingerprint_hex());
    println!("  Fingerprint: {fingerprint}");
    println!(
        "  Write the fingerprint down: it identifies this device. Back the key up with \
         `entangle backup`."
    );

    // --- config.toml ---
    match doc {
        Some((doc, None)) => {
            doc.save(&cfg_path)?;
            println!("  Wrote {}", cfg_path.display());
        }
        Some((doc, Some(keys))) => {
            doc.save(&cfg_path)?;
            println!("  Updated {} ({})", cfg_path.display(), keys.join(", "));
        }
        None => println!("  Kept existing {}", cfg_path.display()),
    }

    // --- peers.toml ---
    if !peers_path.exists() {
        write_peers_stub(&peers_path)?;
        println!("  Wrote {} (empty)", peers_path.display());
    } else {
        println!("  Kept existing {}", peers_path.display());
    }

    // --- keyring.toml ---
    if !kr_path.exists() {
        Keyring::new().save(&kr_path)?;
        println!("  Wrote {} (empty)", kr_path.display());
    } else {
        println!("  Kept existing {}", kr_path.display());
    }

    // The notes are about what config.toml now holds, not what was asked.
    let transports = configured_transports(&cfg_path).unwrap_or_else(|| {
        println!(
            "{} the daemon cannot read {}; check it with `entangle config validate`",
            Style::stdout().warning(),
            cfg_path.display()
        );
        Vec::new()
    });
    if let Some(report) = &answers.tailscale {
        print_tailscale_notes(report);
    }
    print_firewall_notes(&transports);

    if !transports.is_empty() {
        println!("\n{}", Style::stdout().bold("Pairing"));
        let has_peer = entangle_peers::PeerStore::open(&peers_path)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_peer {
            println!("A paired device is already on the allowlist.");
        } else if answers.offer_pairing
            && Prompter::new().confirm("Pair another device now?", true)?
        {
            match crate::cmd::pair::pair_from_wizard(&config::device_label()).await {
                Ok(()) => enable_multi_node(&cfg_path, &peers_path)?,
                Err(e) => {
                    println!(
                        "{} pairing did not complete: {e:#}",
                        Style::stdout().warning()
                    );
                    print_pair_later();
                }
            }
        } else {
            print_pair_later();
        }
    }

    if print_next_steps {
        println!();
        println!("Next steps:");
        println!("  - Start the daemon:        entangled run");
        println!("  - Pair another device:     entangle pair --print-code");
        println!("  - Install a plugin:        entangle plugins install <NAME>");
        println!("  - See what is available:   entangle plugins available");
        println!("  - Change a setting:        entangle config set <key> <value>");
        println!("  - Run diagnostics:         entangle doctor");
    }

    Ok(())
}

/// The import arm: write `pem_path` as this device's identity, asking before
/// replacing a different existing key.
fn import_identity(
    pem_path: &str,
    id_path: &Path,
    peers_path: &Path,
) -> anyhow::Result<IdentityKeyPair> {
    let pem =
        std::fs::read_to_string(pem_path).with_context(|| format!("read PEM from {pem_path}"))?;
    let kp = IdentityKeyPair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid PEM: {e}"))?;
    let new_fp = kp.fingerprint_hex();

    match decide_import_at(id_path, &new_fp) {
        ImportDecision::Write => {
            write_identity_pem(id_path, &pem)?;
            println!("  Wrote {} (mode 0600)", id_path.display());
        }
        ImportDecision::Skip => {
            println!(
                "  Imported key already matches {} — left in place.",
                id_path.display()
            );
        }
        ImportDecision::ConfirmReplace {
            existing_fp,
            new_fp,
        } => {
            println!();
            println!("  An identity already exists at {}.", id_path.display());
            match &existing_fp {
                Some(fp) => println!("     existing fingerprint: {}", fmt_fingerprint(fp)),
                None => {
                    println!("     existing key is present but could NOT be parsed (corrupt?).")
                }
            }
            println!("     imported fingerprint: {}", fmt_fingerprint(&new_fp));
            println!();
            println!("  WARNING: overwriting REPLACES this device's Ed25519 identity.");
            println!("           Every existing pairing breaks (peer_id derives from the");
            println!("           public key) and the old private key is UNRECOVERABLE.");

            let proceed =
                Prompter::new().confirm("  Overwrite the existing identity.key?", false)?;
            if !proceed {
                anyhow::bail!(
                    "aborted: kept existing identity.key at {}",
                    id_path.display()
                );
            }

            let bak = backup_identity(id_path)?;
            println!("  Backed up existing key to {} (mode 0600)", bak.display());
            write_identity_pem(id_path, &pem)?;
            println!("  Wrote {} (mode 0600)", id_path.display());

            // Identity changed → any trusted peers are now stale.
            warn_and_maybe_clear_stale_peers(peers_path)?;
        }
    }
    Ok(kp)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Empty peer store.  Trusted peers are persisted as a `[[peer]]`
/// array-of-tables (see the `entangle-peers` crate); a brand-new store is just
/// a header comment, which parses to zero peers.  The previous stub emitted a
/// bogus `[peers]` table that does not match the real schema.
const PEERS_STUB: &str = "# Entanglement peer store — managed by `entangle`.\n\
# Trusted peers are recorded as [[peer]] array-of-tables; this file starts empty.\n";

/// Write the empty peer-store stub at mode 0600.
///
/// `PeerStore::save` creates the file 0600, so a store written by the daemon or
/// by `entangle mesh trust` is owner-only. Writing the stub with a plain
/// `fs::write` would instead leave it at the process umask (0644 in a default
/// container), so a freshly-`init`ed host had a world-readable trust file until
/// its first mutation. This keeps the permission story consistent from the very
/// first write.
fn write_peers_stub(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::File::create(path)?
        }
    };
    f.write_all(PEERS_STUB.as_bytes())?;
    // `mode` only applies at creation; tighten an existing file too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Import-overwrite decision (pure, unit-testable — no stdin, no I/O)
// ---------------------------------------------------------------------------

/// What the Import arm should do about an identity that may already be on disk.
///
/// Computed purely from the existing and incoming fingerprints so the
/// data-loss-relevant logic can be unit-tested without a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImportDecision {
    /// No identity.key on disk yet — write the imported key unconditionally.
    Write,
    /// An identity.key already exists whose fingerprint matches the imported
    /// key, so writing would be a no-op.  Leave the file untouched.
    Skip,
    /// An identity.key already exists that *differs* from the imported key (or
    /// could not be parsed).  Overwriting destroys the old Ed25519 key and
    /// breaks every existing pairing (`peer_id` derives from the public key),
    /// so this requires explicit confirmation and a backup first.
    ConfirmReplace {
        /// Fingerprint of the existing on-disk key, or `None` if it could not
        /// be parsed.
        existing_fp: Option<String>,
        /// Fingerprint of the imported key.
        new_fp: String,
    },
}

/// Decide, purely from fingerprints, what the Import arm should do.
///
/// * `None`            → no key on disk                → [`ImportDecision::Write`]
/// * `Some(Ok(fp))`    → parsed key, `fp == new_fp`    → [`ImportDecision::Skip`]
/// * `Some(Ok(fp))`    → parsed key, `fp != new_fp`    → [`ImportDecision::ConfirmReplace`]
/// * `Some(Err(()))`   → present but unparseable       → [`ImportDecision::ConfirmReplace`]
fn decide_import(existing: Option<Result<String, ()>>, new_fp: &str) -> ImportDecision {
    match existing {
        None => ImportDecision::Write,
        Some(Ok(fp)) if fp == new_fp => ImportDecision::Skip,
        Some(Ok(fp)) => ImportDecision::ConfirmReplace {
            existing_fp: Some(fp),
            new_fp: new_fp.to_string(),
        },
        Some(Err(())) => ImportDecision::ConfirmReplace {
            existing_fp: None,
            new_fp: new_fp.to_string(),
        },
    }
}

/// Read the fingerprint of the identity currently at `id_path`, if any.
///
/// Returns `None` when no file exists, `Some(Ok(fp))` when it parses to
/// fingerprint `fp`, and `Some(Err(()))` when a file is present but is not a
/// valid PEM keypair — the latter is treated as "differs" so a corrupt key is
/// never silently overwritten.
fn read_existing_fingerprint(id_path: &Path) -> Option<Result<String, ()>> {
    if !id_path.exists() {
        return None;
    }
    match std::fs::read_to_string(id_path) {
        Ok(pem) => match IdentityKeyPair::from_pem(&pem) {
            Ok(kp) => Some(Ok(kp.fingerprint_hex())),
            Err(_) => Some(Err(())),
        },
        Err(_) => Some(Err(())),
    }
}

/// Convenience: read the on-disk key at `id_path` and [`decide_import`].
fn decide_import_at(id_path: &Path, new_fp: &str) -> ImportDecision {
    decide_import(read_existing_fingerprint(id_path), new_fp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a raw fingerprint_hex string as `xxxx-xxxx-xxxx-xxxx` (groups of 4).
fn fmt_fingerprint(raw: &str) -> String {
    raw.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Create `~/.entangle` at mode 0700 on Unix — it holds the private identity
/// key and must not be group/world accessible.
fn create_entangle_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        // Another command (`entangle config set`, `wrapper enable`) may have
        // created it at the umask: it holds the private key, so tighten it.
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & !0o077))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write PEM to `id_path`, restricting it to mode 0600 on Unix.
fn write_identity_pem(id_path: &Path, pem: &str) -> anyhow::Result<()> {
    std::fs::write(id_path, pem).with_context(|| format!("write {}", id_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(id_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Back up the existing identity to `identity.key.bak-<unix_ts>` (mode 0600)
/// before it is overwritten, so a mistaken import is at least recoverable.
/// The original file is copied, never moved.
fn backup_identity(id_path: &Path) -> anyhow::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let mut name = id_path.as_os_str().to_owned();
    name.push(format!(".bak-{ts}"));
    let bak = PathBuf::from(name);
    std::fs::copy(id_path, &bak)
        .with_context(|| format!("back up {} to {}", id_path.display(), bak.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
    }
    Ok(bak)
}

/// A changed identity invalidates every existing pairing (the peer relationship
/// was authenticated against our *old* public key).  If the store actually
/// holds peers, warn and offer to clear it.  Only reachable from the wizard's
/// confirmed-overwrite branch, so prompting here is safe.
fn warn_and_maybe_clear_stale_peers(peers_path: &Path) -> anyhow::Result<()> {
    let has_peers = std::fs::read_to_string(peers_path)
        .map(|s| s.contains("[[peer]]"))
        .unwrap_or(false);
    if !has_peers {
        return Ok(());
    }
    println!();
    println!(
        "  WARNING: your identity changed, so the pairings in {} are now stale",
        peers_path.display()
    );
    println!("           and will no longer authenticate.");
    let clear =
        Prompter::new().confirm("  Clear peers.toml now (you will need to re-pair)?", false)?;
    if clear {
        write_peers_stub(peers_path).with_context(|| format!("clear {}", peers_path.display()))?;
        println!(
            "  Cleared {}. Re-pair your devices with `entangle pair`.",
            peers_path.display()
        );
    } else {
        println!(
            "  Left {} in place — its entries should be re-paired before use.",
            peers_path.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_signing::IdentityKeyPair;

    /// Deterministic keypair PEM + fingerprint for a given seed byte.
    fn seed_pem(seed: u8) -> (String, String) {
        let kp = IdentityKeyPair::from_seed(&[seed; 32]);
        (kp.to_pem(), kp.fingerprint_hex())
    }

    #[test]
    fn decide_import_no_existing_writes() {
        let (_, fp) = seed_pem(1);
        assert_eq!(decide_import(None, &fp), ImportDecision::Write);
    }

    #[test]
    fn decide_import_identical_key_is_skip() {
        let (_, fp) = seed_pem(7);
        assert_eq!(
            decide_import(Some(Ok(fp.clone())), &fp),
            ImportDecision::Skip
        );
    }

    #[test]
    fn decide_import_differing_key_requires_confirmation() {
        let (_, existing) = seed_pem(2);
        let (_, incoming) = seed_pem(3);
        assert_ne!(existing, incoming);
        assert_eq!(
            decide_import(Some(Ok(existing.clone())), &incoming),
            ImportDecision::ConfirmReplace {
                existing_fp: Some(existing),
                new_fp: incoming,
            }
        );
    }

    #[test]
    fn decide_import_unparseable_existing_requires_confirmation() {
        let (_, incoming) = seed_pem(4);
        assert_eq!(
            decide_import(Some(Err(())), &incoming),
            ImportDecision::ConfirmReplace {
                existing_fp: None,
                new_fp: incoming,
            }
        );
    }

    /// Pre-seed identity.key with a DIFFERENT key and assert the on-disk
    /// decision does NOT clobber it silently: it must land on the
    /// confirmation path, and taking a backup must preserve the old bytes
    /// (leaving the original intact).
    #[test]
    fn preseeded_differing_identity_is_not_clobbered_without_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");

        let (existing_pem, existing_fp) = seed_pem(10);
        std::fs::write(&id_path, &existing_pem).unwrap();

        let (_incoming_pem, incoming_fp) = seed_pem(11);
        assert_ne!(existing_fp, incoming_fp);

        // The pure decision must require confirmation — never a silent Write.
        let decision = decide_import_at(&id_path, &incoming_fp);
        assert_eq!(
            decision,
            ImportDecision::ConfirmReplace {
                existing_fp: Some(existing_fp.clone()),
                new_fp: incoming_fp,
            }
        );

        // The write path must back up the old key before any overwrite, and the
        // backup must preserve the original bytes byte-for-byte.
        let bak = backup_identity(&id_path).unwrap();
        assert!(bak.exists(), "backup not created");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), existing_pem);
        // The original is untouched — backup copies, never moves.
        assert_eq!(std::fs::read_to_string(&id_path).unwrap(), existing_pem);
    }

    /// Importing a byte-identical key over an existing identity is a no-op.
    #[test]
    fn preseeded_identical_identity_is_skip() {
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");

        let (pem, fp) = seed_pem(21);
        std::fs::write(&id_path, &pem).unwrap();

        assert_eq!(decide_import_at(&id_path, &fp), ImportDecision::Skip);
    }

    #[cfg(unix)]
    #[test]
    fn backup_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id_path = dir.path().join("identity.key");
        let (pem, _) = seed_pem(30);
        std::fs::write(&id_path, &pem).unwrap();

        let bak = backup_identity(&id_path).unwrap();
        let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

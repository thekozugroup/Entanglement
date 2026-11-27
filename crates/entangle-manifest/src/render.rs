//! Render and validate the manifest included in a signed plugin package.

use anyhow::{bail, Context, Result};

/// A `dist/entangle.toml` rendered from an author's source manifest.
#[derive(Debug, Clone)]
pub struct RenderedManifest {
    /// Exact bytes written to `dist/entangle.toml` (and covered by the signature).
    pub toml: String,
    /// Fully-qualified `<publisher>/<name>@<version>` plugin id.
    pub plugin_id: String,
    /// Effective tier after validation (`max(declared, implied)`).
    pub effective_tier: u8,
}

/// Split an `entangle.toml` `plugin.id` into its bare `<name>` segment.
///
/// Accepts every shape an author might plausibly write:
/// `PUBLISHER_PLACEHOLDER/my-plugin@0.1.0`, `<fingerprint>/my-plugin`, or a
/// bare `my-plugin`. Only the name survives — the publisher always comes from
/// the signing key and the version always comes from `plugin.version`, so a
/// stale or hand-edited id can never leak into the signed artifact.
pub fn plugin_name_from_id(id: &str) -> &str {
    let after_slash = match id.rfind('/') {
        Some(i) => &id[i + 1..],
        None => id,
    };
    match after_slash.rfind('@') {
        Some(i) => &after_slash[..i],
        None => after_slash,
    }
}

/// Rewrite an author's `entangle.toml` into the signed `dist/entangle.toml`.
///
/// * `source` — the author's manifest text.
/// * `fingerprint_hex` — 32 lowercase hex chars from `IdentityKeyPair::fingerprint_hex`.
///
/// The returned manifest is guaranteed to have passed
/// [`crate::validate()`], so tier/capability violations
/// (`ENTANGLE-E0042`) and malformed ids (`ENTANGLE-E0201`) surface at build
/// time rather than at load time on someone else's machine.
pub fn render_dist_manifest(source: &str, fingerprint_hex: &str) -> Result<RenderedManifest> {
    let mut doc: toml::Value =
        toml::from_str(source).context("parsing entangle.toml (source manifest)")?;

    let table = doc
        .as_table_mut()
        .context("entangle.toml must be a TOML table")?;

    let plugin = table
        .get_mut("plugin")
        .context("entangle.toml is missing the required [plugin] section")?
        .as_table_mut()
        .context("[plugin] must be a TOML table")?;

    let version = plugin
        .get("version")
        .and_then(|v| v.as_str())
        .context("[plugin] is missing a `version` string (e.g. version = \"0.1.0\")")?
        .to_owned();

    let raw_id = plugin
        .get("id")
        .and_then(|v| v.as_str())
        .context("[plugin] is missing an `id` string (e.g. id = \"PUBLISHER_PLACEHOLDER/my-plugin@0.1.0\")")?
        .to_owned();

    let name = plugin_name_from_id(&raw_id).to_owned();
    if name.is_empty() {
        bail!("could not derive a plugin name from id {raw_id:?}");
    }

    // The fully-qualified form. Both `/` and `@<version>` are mandatory.
    let plugin_id = format!("{fingerprint_hex}/{name}@{version}");
    plugin.insert("id".into(), toml::Value::String(plugin_id.clone()));

    // An optional `[signature]` section pins the expected signer. It is NOT
    // rewritten the way `id` is: it exists to narrow trust, so silently
    // retargeting it at whatever key happens to be signing would defeat its
    // only purpose. Disagreement is the author's mistake, and the kernel would
    // reject the load anyway (ENTANGLE-E0105) — say so now instead.
    if let Some(declared) = table
        .get("signature")
        .and_then(|s| s.get("publisher"))
        .and_then(|p| p.as_str())
    {
        if !declared.eq_ignore_ascii_case(fingerprint_hex) {
            bail!(
                "[signature] publisher = {declared:?} does not match the signing key \
                 ({fingerprint_hex}).\n\
                 Either remove the [signature] section or sign with that key (--key <PEM>)."
            );
        }
    }

    let rendered = toml::to_string_pretty(&doc).context("serializing dist/entangle.toml")?;

    // Validate the exact bytes we are about to sign.
    let parsed: crate::Manifest =
        toml::from_str(&rendered).context("re-parsing the rendered plugin manifest")?;
    let validated = crate::validate::validate(parsed)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the rendered entangle.toml is not a valid plugin manifest")?;

    // Belt and braces: the kernel parses the id back out of the manifest, so a
    // regression here is a load-time ENTANGLE-E0201 for every consumer.
    let validated_id = validated.plugin_id.to_string();
    if validated_id != plugin_id {
        bail!(
            "internal error: rendered id {plugin_id:?} did not round-trip (got {validated_id:?})"
        );
    }

    Ok(RenderedManifest {
        toml: rendered,
        plugin_id,
        effective_tier: validated.effective_tier as u8,
    })
}

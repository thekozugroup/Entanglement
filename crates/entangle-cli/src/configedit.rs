//! Format-preserving edits of `~/.entangle/config.toml`.
//!
//! The CLI's typed [`crate::config::Config`] knows only a few sections;
//! re-serialising it would drop comments, reorder keys and delete sections it
//! does not model (`[mesh.tailscale]`, `[metrics]`, `[telemetry]`, ...). Every
//! operator-facing write (`entangle wrapper`, `entangle security`,
//! `entangle config reload|set|unset`, `entangle init`) therefore goes through
//! [`toml_edit`], which keeps all bytes it was not asked to change. The write
//! itself is atomic and keeps the file's permissions
//! ([`crate::fsutil::atomic_write`]).
//!
//! Tables are addressed by path (`["mesh", "tailscale"]`); a path may run
//! through standard tables (`[mesh.tailscale]`) or inline ones
//! (`mesh = { tailscale = { ... } }`), and missing tables are created as
//! standard tables (the parents of a new nested table stay implicit, so no
//! empty `[mesh]` header appears).

use std::path::Path;

use anyhow::{Context as _, Result};
use toml_edit::{value, Array, DocumentMut, Item, Table, TableLike, Value};

/// An editable, format-preserving view of a TOML document.
pub struct ConfigDoc {
    doc: DocumentMut,
    /// The input used CRLF line endings; `toml_edit` normalises them to LF
    /// when printing, so they are restored in [`ConfigDoc::to_text`].
    crlf: bool,
}

impl ConfigDoc {
    /// Parse `text`.
    pub fn parse(text: &str) -> Result<Self> {
        let doc = text
            .parse::<DocumentMut>()
            .map_err(|e| anyhow::anyhow!("ENTANGLE-E0754: config.toml is not valid TOML: {e}"))?;
        Ok(Self {
            doc,
            crlf: text.contains("\r\n"),
        })
    }

    /// Load `path`; an absent file is an empty document.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(t) => Self::parse(&t).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::parse(""),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The document text, byte-identical outside the edited keys.
    pub fn to_text(&self) -> String {
        let text = self.doc.to_string();
        if self.crlf {
            text.replace("\r\n", "\n").replace('\n', "\r\n")
        } else {
            text
        }
    }

    /// Write atomically to `path` (see [`crate::fsutil::atomic_write`]).
    pub fn save(&self, path: &Path) -> Result<()> {
        crate::fsutil::atomic_write(path, self.to_text().as_bytes(), 0o644)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// The table at `path`, created (with implicit parents) when missing.
    fn table_at_mut(&mut self, path: &[&str]) -> Result<&mut dyn TableLike> {
        let mut cur: &mut dyn TableLike = self.doc.as_table_mut();
        for (depth, name) in path.iter().enumerate() {
            let shown = path[..=depth].join(".");
            let last = depth + 1 == path.len();
            let item = cur.entry(name).or_insert_with(|| {
                let mut t = Table::new();
                // A parent created only to hold a nested table prints no
                // header of its own.
                t.set_implicit(!last);
                Item::Table(t)
            });
            cur = item.as_table_like_mut().ok_or_else(|| {
                anyhow::anyhow!(
                    "ENTANGLE-E0754: [{shown}] in config.toml is not a table; fix it by hand"
                )
            })?;
        }
        Ok(cur)
    }

    /// The table at `path`, if every part of it exists and is a table.
    fn table_at(&self, path: &[&str]) -> Option<&dyn TableLike> {
        let mut cur: &dyn TableLike = self.doc.as_table();
        for name in path {
            cur = cur.get(name)?.as_table_like()?;
        }
        Some(cur)
    }

    /// The item at `path.key`, if present.
    pub fn get_at(&self, path: &[&str], key: &str) -> Option<&Item> {
        self.table_at(path)?.get(key)
    }

    /// Set `path.key` to `new`, keeping the key's position and any trailing
    /// comment when it already exists.
    pub fn set_at(&mut self, path: &[&str], key: &str, new: Value) -> Result<()> {
        let shown = path.join(".");
        let table = self.table_at_mut(path)?;
        match table.get_mut(key) {
            Some(Item::Value(old)) => {
                let mut v = new;
                *v.decor_mut() = old.decor().clone();
                *old = v;
            }
            Some(Item::None) | None => {
                table.insert(key, value(new));
            }
            Some(_) => anyhow::bail!(
                "ENTANGLE-E0754: [{shown}] {key} in config.toml is a table, not a value; fix it \
                 by hand"
            ),
        }
        Ok(())
    }

    /// Remove `path.key`; returns whether it was there. Comments and other
    /// keys of the table are kept, and so is a table left empty.
    pub fn remove_at(&mut self, path: &[&str], key: &str) -> Result<bool> {
        if self.table_at(path).is_none() {
            return Ok(false);
        }
        Ok(self.table_at_mut(path)?.remove(key).is_some())
    }

    /// Set `section.key` to `new`, keeping the key's position and any
    /// trailing comment when it already exists.
    pub fn set(&mut self, section: &str, key: &str, new: Value) -> Result<()> {
        self.set_at(&[section], key, new)
    }

    /// Set `section.key` to a boolean.
    pub fn set_bool(&mut self, section: &str, key: &str, b: bool) -> Result<()> {
        self.set(section, key, Value::from(b))
    }

    /// Set `section.key` to an integer.
    pub fn set_int(&mut self, section: &str, key: &str, n: i64) -> Result<()> {
        self.set(section, key, Value::from(n))
    }

    /// Read `section.key` as a boolean.
    #[cfg(test)]
    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        self.doc.get(section)?.get(key)?.as_bool()
    }

    /// Read `section.key` as an integer.
    #[cfg(test)]
    pub fn get_int(&self, section: &str, key: &str) -> Option<i64> {
        self.doc.get(section)?.get(key)?.as_integer()
    }

    /// Strings in the array `section.key` (empty when absent).
    pub fn get_str_array(&self, section: &str, key: &str) -> Vec<String> {
        self.get_str_array_at(&[section], key)
    }

    /// Strings in the array `path.key` (empty when absent).
    pub fn get_str_array_at(&self, path: &[&str], key: &str) -> Vec<String> {
        self.get_at(path, key)
            .and_then(Item::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Add `item` to the string array `section.key` unless already there.
    pub fn add_to_str_array(&mut self, section: &str, key: &str, item: &str) -> Result<()> {
        self.add_to_str_array_at(&[section], key, item).map(|_| ())
    }

    /// Add `item` to the string array `path.key` unless already there;
    /// returns whether it was added.
    pub fn add_to_str_array_at(&mut self, path: &[&str], key: &str, item: &str) -> Result<bool> {
        let shown = path.join(".");
        let table = self.table_at_mut(path)?;
        let arr = table
            .entry(key)
            .or_insert_with(|| value(Array::new()))
            .as_array_mut()
            .ok_or_else(|| {
                anyhow::anyhow!("ENTANGLE-E0754: [{shown}] {key} in config.toml is not an array")
            })?;
        if arr.iter().any(|v| v.as_str() == Some(item)) {
            return Ok(false);
        }
        arr.push(item);
        Ok(true)
    }

    /// Remove `item` from the string array `section.key`; returns whether it
    /// was there. Other elements, comments and an empty leftover array are
    /// kept as they are.
    pub fn remove_from_str_array(&mut self, section: &str, key: &str, item: &str) -> Result<bool> {
        self.remove_from_str_array_at(&[section], key, item)
    }

    /// [`Self::remove_from_str_array`] for the array at `path.key`.
    pub fn remove_from_str_array_at(
        &mut self,
        path: &[&str],
        key: &str,
        item: &str,
    ) -> Result<bool> {
        let shown = path.join(".");
        if self.get_at(path, key).is_none() {
            return Ok(false);
        }
        let table = self.table_at_mut(path)?;
        let Some(item_ref) = table.get_mut(key) else {
            return Ok(false);
        };
        let arr = item_ref.as_array_mut().ok_or_else(|| {
            anyhow::anyhow!("ENTANGLE-E0754: [{shown}] {key} in config.toml is not an array")
        })?;
        let before = arr.len();
        arr.retain(|v| v.as_str() != Some(item));
        Ok(arr.len() != before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# operator notes: keep me
[mesh]
transports = ["local", "tailscale"]   # both
multi_node = false

[mesh.tailscale]
enabled = true
acl-mode = "trust-tailnet"

[security]
allow_unsandboxed_native = false # careful
max_tier_allowed = 5 # ceiling

[metrics]
listen = "127.0.0.1:9100"

[telemetry]
opt_in = false
"#;

    #[test]
    fn unknown_sections_comments_and_order_survive_a_tier_edit() {
        let mut d = ConfigDoc::parse(SAMPLE).unwrap();
        d.set_int("security", "max_tier_allowed", 3).unwrap();
        let out = d.to_text();
        assert_eq!(
            out,
            SAMPLE.replace(
                "max_tier_allowed = 5 # ceiling",
                "max_tier_allowed = 3 # ceiling"
            )
        );
        // Sections the typed CLI Config does not know are still there.
        assert!(out.contains("[mesh.tailscale]") && out.contains("[metrics]"));
        assert!(out.contains("[telemetry]") && out.contains("# operator notes: keep me"));
    }

    #[test]
    fn adding_new_sections_leaves_existing_text_untouched() {
        let mut d = ConfigDoc::parse(SAMPLE).unwrap();
        d.set_bool("wrappers", "install", true).unwrap();
        d.add_to_str_array("plugins", "disabled", "ab/x@0.1.0")
            .unwrap();
        d.add_to_str_array("plugins", "disabled", "ab/x@0.1.0")
            .unwrap();
        let out = d.to_text();
        assert!(out.starts_with(SAMPLE));
        let again = ConfigDoc::parse(&out).unwrap();
        assert_eq!(again.get_bool("wrappers", "install"), Some(true));
        assert_eq!(again.get_str_array("plugins", "disabled"), ["ab/x@0.1.0"]);
    }

    #[test]
    fn empty_and_missing_files_work_and_crlf_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/config.toml");
        let mut doc = ConfigDoc::load(&p).unwrap();
        doc.set_int("security", "max_tier_allowed", 4).unwrap();
        doc.save(&p).unwrap();
        assert_eq!(
            ConfigDoc::load(&p)
                .unwrap()
                .get_int("security", "max_tier_allowed"),
            Some(4)
        );
        let crlf = "[security]\r\nmax_tier_allowed = 5\r\n";
        let mut doc = ConfigDoc::parse(crlf).unwrap();
        doc.set_int("security", "max_tier_allowed", 2).unwrap();
        assert_eq!(doc.to_text(), "[security]\r\nmax_tier_allowed = 2\r\n");
    }

    #[test]
    fn nested_tables_are_edited_in_place_or_created_without_empty_parents() {
        let mut d = ConfigDoc::parse(SAMPLE).unwrap();
        d.set_at(&["mesh", "tailscale"], "port", Value::from(9))
            .unwrap();
        d.set_at(&["telemetry", "otlp"], "enabled", Value::from(true))
            .unwrap();
        let out = d.to_text();
        assert!(
            out.contains(
                "[mesh.tailscale]\nenabled = true\nacl-mode = \"trust-tailnet\"\nport = 9\n"
            ),
            "{out}"
        );
        assert!(out.contains("[telemetry.otlp]\nenabled = true\n"), "{out}");
        assert!(
            out.starts_with("# operator notes: keep me\n[mesh]\n"),
            "{out}"
        );

        // A fresh document: no empty `[mesh]` header above `[mesh.tailscale]`.
        let mut d = ConfigDoc::parse("").unwrap();
        d.set_at(&["mesh", "tailscale"], "enabled", Value::from(true))
            .unwrap();
        assert_eq!(d.to_text(), "[mesh.tailscale]\nenabled = true\n");
        assert_eq!(
            d.get_at(&["mesh", "tailscale"], "enabled")
                .and_then(Item::as_bool),
            Some(true)
        );

        // Inline tables are edited where they are.
        let mut d = ConfigDoc::parse("mesh = { transports = [\"local\"] }\n").unwrap();
        assert!(d
            .add_to_str_array_at(&["mesh"], "transports", "iroh")
            .unwrap());
        assert!(!d
            .add_to_str_array_at(&["mesh"], "transports", "iroh")
            .unwrap());
        assert_eq!(
            d.get_str_array_at(&["mesh"], "transports"),
            ["local", "iroh"]
        );
        assert!(d.remove_at(&["mesh"], "transports").unwrap());
        assert!(!d.remove_at(&["nope"], "x").unwrap());
    }

    #[test]
    fn malformed_toml_and_wrong_shapes_are_reported_not_clobbered() {
        assert!(ConfigDoc::parse("[security\n")
            .err()
            .unwrap()
            .to_string()
            .contains("ENTANGLE-E0754"));
        let mut d = ConfigDoc::parse("security = 3\n").unwrap();
        assert!(d.set_int("security", "max_tier_allowed", 3).is_err());
    }
}

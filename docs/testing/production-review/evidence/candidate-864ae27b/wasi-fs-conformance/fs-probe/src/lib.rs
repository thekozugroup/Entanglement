use entangle_sdk::{entangle_plugin, PluginError};
use std::path::Path;
fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
    let root = std::str::from_utf8(&input).map_err(|_| PluginError::InvalidInput("utf8".into()))?;
    let preopens = wasip2::filesystem::preopens::get_directories();
    let p = Path::new(root);
    let cases = [
        ("root_metadata", std::fs::metadata(p).is_ok()),
        ("root_read_dir", std::fs::read_dir(p).is_ok()),
        ("file_metadata", std::fs::metadata(p.join("fixture.txt")).is_ok()),
        ("file_read", std::fs::read(p.join("fixture.txt")).is_ok()),
        ("link_metadata", std::fs::symlink_metadata(p.join("fixture-link")).is_ok()),
        ("link_read", std::fs::read_link(p.join("fixture-link")).is_ok()),
        ("trailing_slash_metadata", std::fs::metadata(format!("{root}/")).is_ok()),
    ];
    let mut out = format!("preopen_count={}\n", preopens.len());
    for (_, name) in &preopens { out.push_str(&format!("preopen={name}\n")); }
    for (name, ok) in cases { out.push_str(&format!("{name}={ok}\n")); }
    Ok(out.into_bytes())
}
entangle_plugin!(run);

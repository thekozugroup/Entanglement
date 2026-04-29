//! Hello-world plugin — the §9.3 walkthrough.

use entangle_sdk::{entangle_plugin, log};

fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    let name = std::str::from_utf8(&input)
        .map_err(|e| entangle_sdk::PluginError::InvalidInput(e.to_string()))?;
    log::info(&format!("hello-world plugin received name: {name}"));
    let greeting = format!("Hello, {name}!");
    Ok(greeting.into_bytes())
}

entangle_plugin!(run);

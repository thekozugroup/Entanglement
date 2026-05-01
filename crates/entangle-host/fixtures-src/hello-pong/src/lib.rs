use entangle_sdk::entangle_plugin;

fn run(input: Vec<u8>) -> Result<Vec<u8>, entangle_sdk::PluginError> {
    if input.is_empty() {
        return Ok(b"pong".to_vec());
    }
    let s = std::str::from_utf8(&input)
        .map_err(|e| entangle_sdk::PluginError::InvalidInput(e.to_string()))?;
    Ok(format!("Hello, {s}!").into_bytes())
}

entangle_plugin!(run);

//! The plugin's logic, free of wasm-only types so it is tested natively.

/// Split `text` into chunks of one line each, every line keeping its
/// trailing `\n`; a final line without one is a chunk of its own. Empty text
/// is no chunks.
pub fn split(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

/// Decode one chunk of input as UTF-8, naming the chunk in the error.
pub fn decode(bytes: &[u8], what: &str) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("{what} is not UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_keep_their_newlines() {
        assert_eq!(
            split("alpha\nbeta\ngamma").collect::<Vec<_>>(),
            ["alpha\n", "beta\n", "gamma"]
        );
        assert_eq!(split("one\n").collect::<Vec<_>>(), ["one\n"]);
        assert_eq!(split("\n\n").collect::<Vec<_>>(), ["\n", "\n"]);
        assert_eq!(split("").count(), 0);
    }

    #[test]
    fn invalid_utf8_is_an_error_naming_the_chunk() {
        let err = decode(&[0xff, 0xfe], "input chunk 3").unwrap_err();
        assert!(err.contains("input chunk 3"), "{err}");
        assert_eq!(decode("ok".as_bytes(), "x").unwrap(), "ok");
    }
}

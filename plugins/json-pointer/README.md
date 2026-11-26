# json-pointer

Resolve JSON Pointers against a JSON document. The plugin runs as a tier-1 WASI component with zero declared capabilities. [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)

## Input and output

Pass a UTF-8 JSON object containing `pointer`, a string, and `data`, any JSON value. The plugin returns the selected JSON value as written in `data`, preserving number precision, escape sequences, and formatting within that value.

| Pointer | Selection |
| --- | --- |
| `""` or `"#"` | The whole document |
| `"/items/0/name"` | The `name` of the first item |
| `"/"` | The member whose name is the empty string |
| `"/a~1b/m~0n"` | Member `m~n` inside member `a/b` |
| `"#/summary%20text"` | The member `summary text` using the URI fragment form |

Object names are matched exactly. Array indices start at zero and omit leading zeros. A malformed pointer, missing value, out-of-range array index, or duplicate occurrence of a referenced object member returns `InvalidInput`.

## Try it

Build and sign the plugin.

```sh
entangle plugins build plugins/json-pointer
```

For a new publisher key, run the `entangle keyring add` command printed by the build. With `entangled` running, load the package.

```sh
entangle plugins load plugins/json-pointer/dist
```

Use the plugin ID printed by `plugins build`. This example extracts a response description from an OpenAPI `paths` object.

```sh
entangle plugins invoke '<publisher>/json-pointer@0.1.0' \
  --input '{"pointer":"#/paths/~1health/get/responses/200/description","data":{"paths":{"/health":{"get":{"responses":{"200":{"description":"Healthy"}}}}}}}'
```

The result is `"Healthy"`. Use `--input-file` to pass a larger envelope from disk.

## Development

```sh
cd plugins/json-pointer
cargo test --locked
cargo build --locked --release --target wasm32-wasip2
```

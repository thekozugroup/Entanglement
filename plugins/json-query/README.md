# json-query

Pull values out of a JSON document with dotted paths, array indexing and wildcards —
then get the result back as JSON.

* **Tier 1**, `runtime = "wasm"`, **zero declared capabilities**. Pure compute: no
  filesystem, no network, no capability handles. The only host import it uses is logging.
* Never panics. Every bad input becomes `PluginError::InvalidInput` with a message
  that names the problem.

## Input format

A single UTF-8 JSON **object** (the "envelope"):

```json
{
  "query": "items[*].name",
  "data":  { "items": [ { "name": "a" }, { "name": "b" } ] },
  "pretty": false
}
```

| Field    | Required | Type    | Meaning                                                        |
| -------- | -------- | ------- | -------------------------------------------------------------- |
| `query`  | yes      | string  | The path to evaluate (grammar below). `""` or `"$"` = the whole document. |
| `data`   | yes      | any     | The document to query. Explicit `null` is allowed; *omitting* the field is an error. |
| `pretty` | no       | boolean | `true` → indented output plus a trailing newline. Default `false`. |

Any other top-level field is rejected, so a typo like `"quary"` fails loudly instead of
silently returning the whole document.

### Query grammar

```
path     := '$'? first? rest*
first    := name | bracket
rest     := '.' name | '.' bracket | bracket
bracket  := '[' ( integer | '*' | '"key"' | '\'key\'' ) ']'
name     := any run of characters except '.' and '['     ("*" means wildcard)
```

| Query               | Meaning                                                   |
| ------------------- | --------------------------------------------------------- |
| `$` or `` (empty)   | the whole document                                        |
| `user.name`         | field selection by dotted path                            |
| `items[2]`          | array index (0-based); `items.2` also works               |
| `items[*]`          | every element of the array; `items.*` also works          |
| `items[*].name`     | the `name` of every element                               |
| `*`                 | on an object: every **value**, in key order               |
| `rows[*][*]`        | nested wildcards flatten                                  |
| `["a.b"].c`         | quoted key, for keys that themselves contain `.` or `[`   |

Selection semantics:

* A path with **no** wildcard selects exactly one value. A missing key or an
  out-of-range index is an **error** — you asked for something specific and it wasn't
  there. The error message lists the keys that *are* available.
* A path **with** a wildcard always produces a JSON **array**. After fanning out,
  elements that lack the requested key/index are skipped rather than failing the whole
  query, so `items[*].name` over `[{"name":"a"},{}]` yields `["a"]`.

## Output format

The selected JSON value, serialised. Compact and with no trailing newline by default;
indented with a trailing newline when `"pretty": true`.

```
input:  {"query":"user.name","data":{"user":{"name":"Ada"}}}
output: "Ada"

input:  {"query":"items[*].id","data":{"items":[{"id":1},{"id":2}]}}
output: [1,2]
```

Array order is always preserved. Object keys come out alphabetically — that is
`serde_json`'s default map ordering — so `{"z":1,"a":2}` is echoed as `{"a":2,"z":1}`.
This also means a `*` wildcard over an object yields its values in *sorted key* order.

On failure nothing is written to stdout; the invocation fails with
`InvalidInput`, e.g.:

```
query matched nothing: $.user has no key "nickname" (available keys: age, name)
```

## Try it

```bash
# build + sign + load
entangle plugins build plugins/json-query
entangle plugins load plugins/json-query/dist/

# field selection
entangle plugins invoke <publisher>/json-query@0.1.0 \
  --input '{"query":"user.name","data":{"user":{"name":"Ada","age":36}}}'
# → "Ada"

# array index
entangle plugins invoke <publisher>/json-query@0.1.0 \
  --input '{"query":"items[1]","data":{"items":["a","b","c"]}}'
# → "b"

# wildcard + pretty
entangle plugins invoke <publisher>/json-query@0.1.0 \
  --input '{"query":"items[*].name","data":{"items":[{"name":"a"},{"name":"b"}]},"pretty":true}'
# → [
#     "a",
#     "b"
#   ]

# large documents: keep the envelope in a file
entangle plugins invoke <publisher>/json-query@0.1.0 --input-file ./query.json
```

Replace `<publisher>` with the fingerprint printed by `entangle plugins build`
(it substitutes `PUBLISHER_PLACEHOLDER` in `entangle.toml`).

## Errors

| Situation                              | Message starts with          |
| -------------------------------------- | ---------------------------- |
| empty / whitespace-only input          | `bad input envelope: input is empty` |
| non-UTF-8 bytes                        | `input is not valid UTF-8`   |
| unparseable JSON                       | `input is not valid JSON`    |
| envelope isn't an object, or a field is missing/mistyped/unknown | `bad input envelope` |
| unparseable `query`                    | `bad query`                  |
| path found nothing / wrong type        | `query matched nothing`      |

## Development

The whole plugin is a pure function, `transform(&[u8]) -> Result<Vec<u8>, Error>`, plus
a path engine in `src/path.rs`. Both are tested on the **host** target — no wasm runtime
needed:

```bash
cd plugins/json-query
cargo test                                   # 50 tests
cargo build --release --target wasm32-wasip2 # component build
```

## Files

* `src/lib.rs` — envelope parsing, `transform`, wasm entrypoint, integration tests
* `src/path.rs` — path grammar + evaluator, with its own unit tests
* `entangle.toml` — tier-1 manifest, zero capabilities
* `dist/` — produced by `entangle plugins build` (gitignored)

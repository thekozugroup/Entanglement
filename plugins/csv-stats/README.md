# csv-stats

Point it at a CSV and get a per-column profile back as JSON: how many values, how many
blanks, and either min/max/mean/sum (numeric columns) or a distinct-value count (text
columns).

* **Tier 1**, `runtime = "wasm"`, **zero declared capabilities**. Pure compute: no
  filesystem, no network, no capability handles. The only host import it uses is logging.
* Never panics. Ragged rows, bad UTF-8, unterminated quotes and empty input all come
  back as `PluginError::InvalidInput` with a message naming the line involved.

## Input format

Raw UTF-8 **CSV bytes** — no envelope, the bytes are the document.

* The **first row is always the header**. Column names are taken from it and trimmed.
* RFC-4180 quoting is honoured: `"a,b"`, `""` for an embedded double quote, and
  newlines inside quoted fields.
* Delimiter is `,`. Line endings may be `\n` or `\r\n`. A trailing newline is optional.
* A leading UTF-8 BOM is stripped, so `\u{feff}name` is the column `name`.
* Every data row must have **exactly** as many fields as the header. A ragged row is an
  error, not a guess.
* A line containing no characters at all is skipped (standard `csv` behaviour) and does
  not count as a row.

## Output format

Pretty-printed JSON with a trailing newline. For the input
`name,age,note` / `Ada,36,` / `Grace,45,` / `Alan,41,`:

```json
{
  "columns": [
    {
      "count": 3,
      "distinct": 3,
      "name": "name",
      "nulls": 0,
      "type": "text"
    },
    {
      "count": 3,
      "max": 45.0,
      "mean": 40.666666666666664,
      "min": 36.0,
      "name": "age",
      "nulls": 0,
      "sum": 122.0,
      "type": "numeric"
    },
    {
      "count": 0,
      "name": "note",
      "nulls": 3,
      "type": "empty"
    }
  ],
  "rows": 3
}
```

(Object keys come out alphabetically — that is `serde_json`'s default map ordering, and
it makes the output stable and diffable. The `columns` **array** stays in header order.)

| Field      | Present for | Meaning                                                            |
| ---------- | ----------- | ------------------------------------------------------------------ |
| `rows`     | top level   | number of **data** rows; the header is not counted                 |
| `name`     | every col   | the header cell, trimmed                                           |
| `type`     | every col   | `numeric`, `text`, or `empty`                                      |
| `count`    | every col   | non-empty values seen                                              |
| `nulls`    | every col   | empty or whitespace-only values seen                               |
| `min` `max` `mean` `sum` | `numeric` only | over the non-empty values; `mean = sum / count`      |
| `distinct` | `text` only | number of distinct non-empty values (compared after trimming)      |

`columns` is in header order, and duplicate header names stay as separate columns.

### How a column's type is decided

* `numeric` — the column has at least one non-empty value and **every** non-empty value
  parses as a finite decimal number. Surrounding whitespace is tolerated (`" 42 "`), as
  are signs and exponents (`-1.5`, `+0.5`, `2e3`), and quoted numbers (`"42"`).
  `inf`, `-inf`, `NaN` and hex are deliberately **not** numeric — they have no JSON
  representation, so a column containing them is `text`.
* `empty` — no non-empty values at all (a header-only file, or an all-blank column).
  Carries only `count` (always 0) and `nulls`.
* `text` — anything else.

Blank cells never contribute to numeric statistics: `1, , 3` gives
`count: 2, nulls: 1, sum: 4, mean: 2`.

## Try it

```bash
# build + sign + load
entangle plugins build plugins/csv-stats
entangle plugins load plugins/csv-stats/dist/

entangle plugins invoke <publisher>/csv-stats@0.1.0 \
  --input 'name,age,city
Ada,36,London
Grace,45,New York
Alan,41,London'
# → {"rows":3,"columns":[ ... ]}

# quoted fields containing the delimiter
entangle plugins invoke <publisher>/csv-stats@0.1.0 \
  --input 'name,note
Ada,"math, engines"
Grace,"compilers"'

# real files
entangle plugins invoke <publisher>/csv-stats@0.1.0 --input-file ./sales.csv
```

Replace `<publisher>` with the fingerprint printed by `entangle plugins build`
(it substitutes `PUBLISHER_PLACEHOLDER` in `entangle.toml`).

## Errors

| Situation                        | Message                                                        |
| -------------------------------- | -------------------------------------------------------------- |
| empty / whitespace-only input    | `input is empty; expected CSV text whose first row is a header…` |
| non-UTF-8 bytes                  | `input is not valid UTF-8: …`                                  |
| a row with the wrong field count | `ragged CSV: line 3 has 4 field(s) but the header declares 3…`  |
| unterminated quote, stray quote  | `could not parse CSV: …`                                       |

## Development

The whole plugin is a pure function, `transform(&[u8]) -> Result<Vec<u8>, Error>`, tested
on the **host** target — no wasm runtime needed:

```bash
cd plugins/csv-stats
cargo test                                   # 31 tests
cargo build --release --target wasm32-wasip2 # component build
```

## Files

* `src/lib.rs` — `transform`, the per-column accumulator, wasm entrypoint, tests
* `entangle.toml` — tier-1 manifest, zero capabilities
* `dist/` — produced by `entangle plugins build` (gitignored)

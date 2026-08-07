# markdown-html

Render Markdown to an HTML fragment with [`pulldown-cmark`](https://docs.rs/pulldown-cmark),
hardened so it is safe to point at Markdown you did not write.

* **Tier 1**, `runtime = "wasm"`, **zero declared capabilities**. Pure compute: no
  filesystem, no network, no capability handles. The only host import it uses is logging.
* Never panics. The only possible error is non-UTF-8 input, reported as
  `PluginError::InvalidInput`.

## Input format

Raw UTF-8 **Markdown bytes** — no envelope, no options, the bytes are the document.

CommonMark, plus four extensions:

* tables (`| a | b |`)
* footnotes (`Text[^1]` / `[^1]: note`)
* strikethrough (`~~gone~~`)
* task lists (`- [x] done`)

Deliberately **not** enabled: heading attribute blocks (`# Title {#id .class}`), because
they let the source inject arbitrary `id`/`class` attributes; and smart punctuation,
because silently rewriting quotes and dashes is lossy.

## Output format

A UTF-8 **HTML fragment**: the rendered body content, with no `<!doctype>`, `<html>`,
`<head>` or `<body>` wrapper. Drop it into a container element and bring your own CSS.

```
input:  # Title
output: <h1>Title</h1>

input:  Hello *world*
output: <p>Hello <em>world</em></p>

input:  - [x] done
output: <ul>\n<li><input disabled="" type="checkbox" checked=""/>\ndone</li>\n</ul>
```

Empty (or whitespace-only) input produces empty output — that is a success, not an error.

## Safety: embedded HTML is escaped, not passed through

This is the one place where this plugin differs from a stock `pulldown-cmark` pipeline,
and it is the point of the plugin. Markdown is a format people paste from the internet,
so the input is treated as hostile.

**Raw HTML in the source is escaped.** `<script>alert(1)</script>` in the Markdown
renders as the literal text `&lt;script&gt;alert(1)&lt;/script&gt;` — a browser displays
those characters instead of executing them. The same applies to inline raw HTML
(`<b>`, `<img …>`), HTML comments, `<iframe>` and `<style>`. Stock `pulldown-cmark`
forwards all of that verbatim; this plugin demotes every `Html`/`InlineHtml` event to a
`Text` event so the HTML writer escapes it.

**Link and image URLs are scheme-filtered.** Only these survive:

* `http`, `https`, `mailto`, `tel`, `ftp`, `ftps`
* protocol-relative (`//cdn.example/x`), root-relative (`/a`), relative (`./a`),
  fragment (`#a`) and query-only (`?q=1`) URLs
* the empty URL

Everything else — notably `javascript:` and `data:` — is replaced with `#`. ASCII
whitespace and control characters are stripped from the URL *before* the scheme is
examined, so `java\tscript:alert(1)`, `jav\nascript:…` and `JaVaScRiPt:…` are all caught
the way a browser would resolve them.

**Heading attribute injection is off**, as noted above.

What this plugin does **not** claim: it is not a CSS sanitiser, it does not vet the
`class` on fenced code blocks beyond HTML-escaping it, and it cannot save you if you
insert the fragment into a page that has its own XSS bugs. If you need a full
allowlisting sanitiser for arbitrary HTML, escape-by-default (what this does) is the
stronger position anyway — there is no HTML to allowlist.

## Try it

```bash
# build + sign + load
entangle plugins build plugins/markdown-html
entangle plugins load plugins/markdown-html/dist/

entangle plugins invoke <publisher>/markdown-html@0.1.0 \
  --input '# Release notes

- **fixed** the thing
- ~~removed~~ the other thing

See [the docs](https://example.com/docs).'
# → <h1>Release notes</h1>
#   <ul>
#   <li><strong>fixed</strong> the thing</li>
#   <li><del>removed</del> the other thing</li>
#   </ul>
#   <p>See <a href="https://example.com/docs">the docs</a>.</p>

# escaping in action
entangle plugins invoke <publisher>/markdown-html@0.1.0 \
  --input 'Careful: <script>alert(1)</script> and [click](javascript:alert(1))'
# → <p>Careful: &lt;script&gt;alert(1)&lt;/script&gt; and <a href="#">click</a></p>

# real files
entangle plugins invoke <publisher>/markdown-html@0.1.0 --input-file ./README.md
```

Replace `<publisher>` with the fingerprint printed by `entangle plugins build`
(it substitutes `PUBLISHER_PLACEHOLDER` in `entangle.toml`).

## Errors

| Situation        | Message                                                              |
| ---------------- | -------------------------------------------------------------------- |
| non-UTF-8 bytes  | `input is not valid UTF-8 Markdown: …; pass the document as UTF-8 text` |

There is no other failure mode: malformed Markdown is not a thing, so an unterminated
code fence, a dangling footnote or a truncated table renders as best it can.

## Development

The rendering pipeline is two pure functions — `transform(&[u8]) -> Result<Vec<u8>, Error>`
and `render(&str) -> String` — plus `sanitize_url(&str) -> Option<String>`, all tested on
the **host** target with no wasm runtime needed:

```bash
cd plugins/markdown-html
cargo test                                   # 34 tests
cargo build --release --target wasm32-wasip2 # component build
```

## Files

* `src/lib.rs` — `render`/`transform`, the event-hardening pass, `sanitize_url`, wasm
  entrypoint, tests
* `entangle.toml` — tier-1 manifest, zero capabilities
* `dist/` — produced by `entangle plugins build` (gitignored)

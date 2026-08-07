//! `markdown-html` — render Markdown to an HTML fragment, safely.
//!
//! Tier 1, zero declared capabilities: pure byte-in/byte-out compute.
//!
//! # Input
//!
//! Raw UTF-8 Markdown bytes. No envelope, no options — the bytes *are* the document.
//! CommonMark plus four extensions: tables, footnotes, strikethrough and task lists.
//!
//! # Output
//!
//! An HTML **fragment** (UTF-8): the rendered body content, with no `<!doctype>`,
//! `<html>`, `<head>` or `<body>` wrapper. Drop it into a container element.
//!
//! # Safety
//!
//! Markdown is a format people paste from the internet, so this plugin assumes the
//! input is hostile:
//!
//! * **Raw HTML in the source is escaped, not passed through.** `<script>x</script>`
//!   in the Markdown renders as the literal text `&lt;script&gt;x&lt;/script&gt;`.
//!   This is the single most important difference from a stock `pulldown-cmark`
//!   pipeline, which forwards raw HTML verbatim.
//! * **Link and image URLs are scheme-filtered.** Only `http`, `https`, `mailto`,
//!   `tel`, `ftp`, `ftps` and scheme-relative/relative/fragment URLs survive;
//!   anything else (notably `javascript:` and `data:`) is replaced with `#`.
//!   ASCII whitespace and control characters are stripped from URLs first, so
//!   `java\tscript:` cannot smuggle a scheme past the filter.
//! * **Heading attribute blocks are not enabled**, so the source cannot inject
//!   arbitrary `id`/`class` attributes.
//!
//! What this plugin does *not* claim: it is not a CSS sanitiser and it does not
//! stop you from rendering the fragment inside a page that has its own XSS bugs.
//!
//! All the real work lives in [`transform`], a plain function over `&[u8]` covered by
//! the host-target test suite (`cargo test`). It never panics on any input.

#![forbid(unsafe_code)]

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag, TagEnd};

/// Everything that can go wrong. Surfaced to the caller as
/// `PluginError::InvalidInput` using the `Display` text below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input bytes were not valid UTF-8.
    NotUtf8(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotUtf8(m) => write!(
                f,
                "input is not valid UTF-8 Markdown: {m}; \
                 pass the document as UTF-8 text"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// URL schemes a link or image is allowed to use.
const SAFE_SCHEMES: [&str; 6] = ["http", "https", "mailto", "tel", "ftp", "ftps"];

/// What a rejected URL is rewritten to.
const INERT_URL: &str = "#";

/// Markdown extensions enabled. Deliberately excludes
/// `ENABLE_HEADING_ATTRIBUTES` (attribute injection) and
/// `ENABLE_SMART_PUNCTUATION` (surprising, lossy character substitution).
fn options() -> Options {
    let mut o = Options::empty();
    o.insert(Options::ENABLE_TABLES);
    o.insert(Options::ENABLE_FOOTNOTES);
    o.insert(Options::ENABLE_STRIKETHROUGH);
    o.insert(Options::ENABLE_TASKLISTS);
    o
}

/// Strip ASCII whitespace and control characters, then decide whether the URL's
/// scheme is on the allowlist.
///
/// Returns the cleaned URL if acceptable, or [`None`] if it must be neutralised.
pub fn sanitize_url(url: &str) -> Option<String> {
    let cleaned: String = url
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();

    if cleaned.is_empty() {
        // An empty href is inert already; keep it empty rather than inventing "#".
        return Some(String::new());
    }

    // Find the scheme delimiter, if this is even an absolute URL. A '/', '?', '#'
    // or '\' before the first ':' means there is no scheme.
    let mut scheme_end = None;
    for (i, c) in cleaned.char_indices() {
        match c {
            ':' => {
                scheme_end = Some(i);
                break;
            }
            '/' | '?' | '#' | '\\' => break,
            _ => {}
        }
    }

    match scheme_end {
        // Relative, root-relative, protocol-relative or fragment URL: fine.
        None => Some(cleaned),
        Some(i) => {
            let scheme = cleaned[..i].to_ascii_lowercase();
            if SAFE_SCHEMES.contains(&scheme.as_str()) {
                Some(cleaned)
            } else {
                None
            }
        }
    }
}

fn safe_dest(url: &CowStr<'_>) -> CowStr<'static> {
    match sanitize_url(url) {
        Some(u) => CowStr::from(u),
        None => CowStr::from(INERT_URL),
    }
}

/// Rewrite one parser event into its safe form.
///
/// * `Html` / `InlineHtml` become `Text`, which the HTML writer escapes.
/// * Link and image destinations pass through [`sanitize_url`].
fn harden(event: Event<'_>) -> Event<'static> {
    match event {
        // Raw HTML blocks and inline raw HTML: demote to text so they get escaped.
        Event::Html(s) => Event::Text(CowStr::from(s.to_string())),
        Event::InlineHtml(s) => Event::Text(CowStr::from(s.to_string())),

        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: safe_dest(&dest_url),
            title: CowStr::from(title.to_string()),
            id: CowStr::from(id.to_string()),
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: safe_dest(&dest_url),
            title: CowStr::from(title.to_string()),
            id: CowStr::from(id.to_string()),
        }),

        // Everything else is structural or already-escaped text; just re-own it.
        other => reown(other),
    }
}

/// Convert a borrowed event into an owned one without changing its meaning.
fn reown(event: Event<'_>) -> Event<'static> {
    match event {
        Event::Text(s) => Event::Text(CowStr::from(s.to_string())),
        Event::Code(s) => Event::Code(CowStr::from(s.to_string())),
        Event::FootnoteReference(s) => Event::FootnoteReference(CowStr::from(s.to_string())),
        Event::SoftBreak => Event::SoftBreak,
        Event::HardBreak => Event::HardBreak,
        Event::Rule => Event::Rule,
        Event::TaskListMarker(b) => Event::TaskListMarker(b),
        Event::End(t) => Event::End(reown_end(t)),
        Event::Start(t) => Event::Start(reown_tag(t)),
        // Math and other future variants: render their source as escaped text so we
        // never silently emit unvetted markup.
        other => Event::Text(CowStr::from(format!("{other:?}"))),
    }
}

fn reown_end(t: TagEnd) -> TagEnd {
    t
}

fn reown_tag(t: Tag<'_>) -> Tag<'static> {
    use pulldown_cmark::CodeBlockKind;
    match t {
        Tag::Paragraph => Tag::Paragraph,
        Tag::Heading {
            level,
            id,
            classes,
            attrs,
        } => Tag::Heading {
            level,
            id: id.map(|s| CowStr::from(s.to_string())),
            classes: classes
                .into_iter()
                .map(|s| CowStr::from(s.to_string()))
                .collect(),
            attrs: attrs
                .into_iter()
                .map(|(k, v)| {
                    (
                        CowStr::from(k.to_string()),
                        v.map(|v| CowStr::from(v.to_string())),
                    )
                })
                .collect(),
        },
        Tag::BlockQuote(kind) => Tag::BlockQuote(kind),
        Tag::CodeBlock(CodeBlockKind::Indented) => Tag::CodeBlock(CodeBlockKind::Indented),
        Tag::CodeBlock(CodeBlockKind::Fenced(info)) => {
            Tag::CodeBlock(CodeBlockKind::Fenced(CowStr::from(info.to_string())))
        }
        Tag::HtmlBlock => Tag::HtmlBlock,
        Tag::List(start) => Tag::List(start),
        Tag::Item => Tag::Item,
        Tag::FootnoteDefinition(s) => Tag::FootnoteDefinition(CowStr::from(s.to_string())),
        Tag::Table(alignments) => Tag::Table(alignments),
        Tag::TableHead => Tag::TableHead,
        Tag::TableRow => Tag::TableRow,
        Tag::TableCell => Tag::TableCell,
        Tag::Emphasis => Tag::Emphasis,
        Tag::Strong => Tag::Strong,
        Tag::Strikethrough => Tag::Strikethrough,
        Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        } => Tag::Link {
            link_type,
            dest_url: safe_dest(&dest_url),
            title: CowStr::from(title.to_string()),
            id: CowStr::from(id.to_string()),
        },
        Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        } => Tag::Image {
            link_type,
            dest_url: safe_dest(&dest_url),
            title: CowStr::from(title.to_string()),
            id: CowStr::from(id.to_string()),
        },
        Tag::MetadataBlock(kind) => Tag::MetadataBlock(kind),
        Tag::DefinitionList => Tag::DefinitionList,
        Tag::DefinitionListTitle => Tag::DefinitionListTitle,
        Tag::DefinitionListDefinition => Tag::DefinitionListDefinition,
        Tag::Superscript => Tag::Superscript,
        Tag::Subscript => Tag::Subscript,
    }
}

/// The whole plugin, as a pure function. Never panics on any input.
pub fn transform(input: &[u8]) -> Result<Vec<u8>, Error> {
    let markdown = core::str::from_utf8(input).map_err(|e| Error::NotUtf8(e.to_string()))?;
    Ok(render(markdown).into_bytes())
}

/// Render Markdown text to a safe HTML fragment.
pub fn render(markdown: &str) -> String {
    let parser = Parser::new_ext(markdown, options()).map(harden);
    // Rough heuristic: HTML is usually a bit larger than its Markdown source.
    let mut out = String::with_capacity(markdown.len() + markdown.len() / 2 + 16);
    html::push_html(&mut out, parser);
    out
}

// ------------------------------------------------------------------
// wasm entrypoint — thin wrapper, no logic
// ------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm_entry {
    use entangle_sdk::{entangle_plugin, log, PluginError};

    fn run(input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        log::info(&format!("markdown-html: {} input bytes", input.len()));
        match crate::transform(&input) {
            Ok(out) => Ok(out),
            Err(e) => {
                let msg = e.to_string();
                log::warn(&format!("markdown-html: {msg}"));
                Err(PluginError::InvalidInput(msg))
            }
        }
    }

    entangle_plugin!(run);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(md: &str) -> String {
        String::from_utf8(transform(md.as_bytes()).expect("should succeed")).unwrap()
    }

    // ---------------- happy paths ----------------

    #[test]
    fn renders_headings() {
        assert_eq!(h("# Title"), "<h1>Title</h1>\n");
        assert_eq!(h("### Deep"), "<h3>Deep</h3>\n");
    }

    #[test]
    fn renders_paragraph_and_inline_emphasis() {
        assert_eq!(
            h("Hello *world* and **bold**."),
            "<p>Hello <em>world</em> and <strong>bold</strong>.</p>\n"
        );
    }

    #[test]
    fn renders_lists() {
        assert_eq!(h("- a\n- b"), "<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n");
        assert_eq!(
            h("1. one\n2. two"),
            "<ol>\n<li>one</li>\n<li>two</li>\n</ol>\n"
        );
    }

    #[test]
    fn renders_fenced_code_with_language_class() {
        let out = h("```rust\nfn main() {}\n```");
        assert!(
            out.contains(r#"<pre><code class="language-rust">"#),
            "{out}"
        );
        assert!(out.contains("fn main() {}"), "{out}");
    }

    #[test]
    fn renders_inline_code_escaped() {
        assert_eq!(
            h("use `a < b` here"),
            "<p>use <code>a &lt; b</code> here</p>\n"
        );
    }

    #[test]
    fn renders_blockquote_and_rule() {
        assert!(h("> quoted").contains("<blockquote>"));
        assert!(h("---").contains("<hr />"));
    }

    #[test]
    fn renders_tables_extension() {
        let out = h("| a | b |\n|---|---|\n| 1 | 2 |");
        assert!(out.contains("<table>"), "{out}");
        assert!(out.contains("<th>a</th>"), "{out}");
        assert!(out.contains("<td>1</td>"), "{out}");
    }

    #[test]
    fn renders_strikethrough_extension() {
        assert_eq!(h("~~gone~~"), "<p><del>gone</del></p>\n");
    }

    #[test]
    fn renders_task_lists_extension() {
        let out = h("- [x] done\n- [ ] todo");
        assert!(out.contains("checked"), "{out}");
        assert!(out.contains(r#"type="checkbox""#), "{out}");
    }

    #[test]
    fn renders_footnotes_extension() {
        let out = h("Text[^1]\n\n[^1]: The note");
        assert!(out.contains("footnote"), "{out}");
        assert!(out.contains("The note"), "{out}");
    }

    #[test]
    fn renders_safe_links_and_images() {
        assert_eq!(
            h("[site](https://example.com)"),
            "<p><a href=\"https://example.com\">site</a></p>\n"
        );
        assert_eq!(
            h("![alt](/img/logo.png)"),
            "<p><img src=\"/img/logo.png\" alt=\"alt\" /></p>\n"
        );
        assert!(h("[mail](mailto:a@b.com)").contains("mailto:a@b.com"));
        assert!(h("[rel](./docs/x.html)").contains("./docs/x.html"));
        assert!(h("[frag](#section)").contains("href=\"#section\""));
    }

    // ---------------- HTML escaping (the security contract) ----------------

    #[test]
    fn raw_html_block_is_escaped_not_passed_through() {
        let out = h("<script>alert(1)</script>");
        assert!(!out.contains("<script>"), "raw script survived: {out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
        assert!(out.contains("alert(1)"), "{out}");
    }

    #[test]
    fn inline_raw_html_is_escaped() {
        let out = h("hello <b>there</b>");
        assert!(!out.contains("<b>"), "{out}");
        assert!(out.contains("&lt;b&gt;there&lt;/b&gt;"), "{out}");
    }

    #[test]
    fn img_onerror_payload_is_escaped() {
        let out = h(r#"<img src=x onerror="alert(1)">"#);
        // No real tag is emitted; the payload survives only as escaped text, which
        // a browser renders as characters rather than executing.
        assert!(!out.contains("<img"), "{out}");
        assert!(out.starts_with("&lt;img"), "{out}");
    }

    #[test]
    fn html_comment_is_escaped() {
        let out = h("<!-- secret -->");
        assert!(!out.contains("<!--"), "{out}");
        assert!(out.contains("&lt;!--"), "{out}");
    }

    #[test]
    fn iframe_and_style_are_escaped() {
        for md in [
            "<iframe src=\"//evil\"></iframe>",
            "<style>body{display:none}</style>",
        ] {
            let out = h(md);
            assert!(!out.contains("<iframe"), "{out}");
            assert!(!out.contains("<style"), "{out}");
        }
    }

    #[test]
    fn ampersands_and_angle_brackets_in_text_are_escaped() {
        assert_eq!(h("a & b < c"), "<p>a &amp; b &lt; c</p>\n");
    }

    // ---------------- URL filtering ----------------

    #[test]
    fn javascript_urls_are_neutralised() {
        let out = h("[click](javascript:alert(1))");
        assert!(!out.to_lowercase().contains("javascript:"), "{out}");
        assert!(out.contains("href=\"#\""), "{out}");
    }

    #[test]
    fn javascript_url_with_embedded_whitespace_is_neutralised() {
        // Browsers strip control characters before resolving the scheme, so we must too.
        for md in [
            "[x](java\tscript:alert(1))",
            "[x](  javascript:alert(1))",
            "[x](JaVaScRiPt:alert(1))",
        ] {
            let out = h(md);
            assert!(!out.to_lowercase().contains("javascript"), "{md} -> {out}");
        }
    }

    #[test]
    fn data_urls_are_neutralised_for_links_and_images() {
        let a = h("[x](data:text/html;base64,PHNjcmlwdD4=)");
        assert!(!a.contains("data:"), "{a}");
        assert!(a.contains("href=\"#\""), "{a}");

        let i = h("![x](data:image/png;base64,iVBORw0KGgo=)");
        assert!(!i.contains("data:"), "{i}");
        assert!(i.contains("src=\"#\""), "{i}");

        // An SVG data URL with raw angle brackets is not even parsed as a link by
        // CommonMark; it must still not produce markup.
        let s = h("![x](data:image/svg+xml,<svg onload=alert(1)>)");
        assert!(!s.contains("<svg"), "{s}");
        assert!(!s.contains("<img"), "{s}");
    }

    #[test]
    fn vbscript_and_file_urls_are_neutralised() {
        assert!(!h("[x](vbscript:msgbox)").contains("vbscript"));
        assert!(!h("[x](file:///etc/passwd)").contains("file:"));
    }

    #[test]
    fn autolinks_are_also_filtered() {
        let out = h("<https://example.com>");
        assert!(out.contains("https://example.com"), "{out}");
    }

    #[test]
    fn sanitize_url_unit_cases() {
        assert_eq!(sanitize_url("https://a.b/c"), Some("https://a.b/c".into()));
        assert_eq!(
            sanitize_url("//cdn.example/x"),
            Some("//cdn.example/x".into())
        );
        assert_eq!(sanitize_url("/abs"), Some("/abs".into()));
        assert_eq!(sanitize_url("rel/path"), Some("rel/path".into()));
        assert_eq!(sanitize_url("#frag"), Some("#frag".into()));
        assert_eq!(sanitize_url("?q=1"), Some("?q=1".into()));
        assert_eq!(sanitize_url(""), Some(String::new()));
        assert_eq!(sanitize_url("MAILTO:a@b"), Some("MAILTO:a@b".into()));
        assert_eq!(sanitize_url("javascript:x"), None);
        assert_eq!(sanitize_url("JAVASCRIPT:x"), None);
        assert_eq!(sanitize_url("data:text/html,x"), None);
        assert_eq!(sanitize_url("vbscript:x"), None);
        // Control characters removed before the scheme check.
        assert_eq!(sanitize_url("java\u{0}script:x"), None);
        assert_eq!(sanitize_url("jav\nascript:x"), None);
    }

    // ---------------- unicode ----------------

    #[test]
    fn unicode_text_passes_through_unchanged() {
        assert_eq!(h("héllo wörld"), "<p>héllo wörld</p>\n");
        assert_eq!(h("# 東京タワー"), "<h1>東京タワー</h1>\n");
        assert_eq!(h("Emoji: 🎉✨🌍"), "<p>Emoji: 🎉✨🌍</p>\n");
    }

    #[test]
    fn unicode_in_link_text_and_url() {
        let out = h("[café](https://example.com/café)");
        assert!(out.contains("café"), "{out}");
        assert!(out.contains("https://example.com/caf"), "{out}");
    }

    #[test]
    fn rtl_and_combining_marks_survive() {
        assert_eq!(h("مرحبا"), "<p>مرحبا</p>\n");
        assert_eq!(h("e\u{301}"), "<p>e\u{301}</p>\n");
    }

    #[test]
    fn zero_width_and_bidi_control_chars_are_not_dropped_from_text() {
        // We only strip control characters from *URLs*, never from body text.
        let out = h("a\u{200b}b");
        assert!(out.contains('\u{200b}'), "{out:?}");
    }

    // ---------------- edge cases ----------------

    #[test]
    fn empty_input_produces_empty_output() {
        assert_eq!(transform(b"").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn whitespace_only_input_produces_empty_output() {
        assert_eq!(h("   \n\n\t "), "");
    }

    #[test]
    fn invalid_utf8_is_reported_not_panicked() {
        let e = transform(&[b'#', b' ', 0xff, 0xfe])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not valid UTF-8"), "{e}");
        assert!(matches!(transform(&[0x80]), Err(Error::NotUtf8(_))));
    }

    #[test]
    fn unterminated_constructs_do_not_panic() {
        for md in [
            "```rust\nfn main() {",
            "[unclosed](",
            "| a | b\n|---",
            "> > > > deep",
            "*",
            "[^1]: dangling footnote",
            "<div",
            "&#x",
            "\u{0}\u{1}\u{2}",
        ] {
            let out = h(md);
            // Contract: it returns *something* and never panics.
            let _ = out.len();
        }
    }

    #[test]
    fn deeply_nested_lists_do_not_blow_the_stack() {
        let mut md = String::new();
        for i in 0..200 {
            md.push_str(&" ".repeat(i * 2));
            md.push_str("- item\n");
        }
        let out = h(&md);
        assert!(out.contains("<ul>"), "{out}");
    }

    #[test]
    fn long_document_renders() {
        let md = "para\n\n".repeat(5_000);
        let out = h(&md);
        assert_eq!(out.matches("<p>para</p>").count(), 5_000);
    }

    #[test]
    fn output_is_valid_utf8_for_all_tested_inputs() {
        for md in ["# a", "`b`", "[c](https://d)", "🎉", "<b>x</b>"] {
            let bytes = transform(md.as_bytes()).unwrap();
            core::str::from_utf8(&bytes).expect("utf-8 out");
        }
    }
}

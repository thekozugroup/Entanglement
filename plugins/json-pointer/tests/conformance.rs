use entangle_json_pointer::transform;

const RFC_DOCUMENT: &str =
    r#"{"foo":["bar","baz"],"":0,"a/b":1,"c%d":2,"e^f":3,"g|h":4,"i\\j":5,"k\"l":6," ":7,"m~n":8}"#;

fn resolve(pointer: &str, document: &str) -> Result<String, String> {
    let pointer = serde_json::to_string(pointer).unwrap();
    let input = format!(r#"{{"pointer":{pointer},"data":{document}}}"#);
    transform(input.as_bytes()).map(|out| String::from_utf8(out).unwrap())
}

#[test]
fn resolves_rfc_6901_string_examples() {
    for (pointer, expected) in [
        ("", RFC_DOCUMENT),
        ("/foo", r#"["bar","baz"]"#),
        ("/foo/0", r#""bar""#),
        ("/", "0"),
        ("/a~1b", "1"),
        ("/c%d", "2"),
        ("/e^f", "3"),
        ("/g|h", "4"),
        ("/i\\j", "5"),
        ("/k\"l", "6"),
        ("/ ", "7"),
        ("/m~0n", "8"),
    ] {
        assert_eq!(
            resolve(pointer, RFC_DOCUMENT),
            Ok(expected.into()),
            "{pointer:?}"
        );
    }
}

#[test]
fn resolves_rfc_6901_uri_fragment_examples() {
    for (pointer, expected) in [
        ("#", RFC_DOCUMENT),
        ("#/foo", r#"["bar","baz"]"#),
        ("#/foo/0", r#""bar""#),
        ("#/", "0"),
        ("#/a~1b", "1"),
        ("#/c%25d", "2"),
        ("#/e%5Ef", "3"),
        ("#/g%7Ch", "4"),
        ("#/i%5Cj", "5"),
        ("#/k%22l", "6"),
        ("#/%20", "7"),
        ("#/m~0n", "8"),
    ] {
        assert_eq!(
            resolve(pointer, RFC_DOCUMENT),
            Ok(expected.into()),
            "{pointer:?}"
        );
    }
}

#[test]
fn decodes_escapes_once_and_matches_keys_exactly() {
    let data = r#"{"~1":"tilde one","/":"slash","é":1,"e\u0301":2,"a%20b":3,"\u0000":4,"": {"": 5},"*":6}"#;
    for (pointer, expected) in [
        ("/~01", r#""tilde one""#),
        ("/~1", r#""slash""#),
        ("#%2f%7E01", r#""tilde one""#),
        ("#/%C3%A9", "1"),
        ("/e\u{0301}", "2"),
        ("#/%65%cc%81", "2"),
        ("/a%20b", "3"),
        ("#/a%2520b", "3"),
        ("/\0", "4"),
        ("#/%00", "4"),
        ("//", "5"),
        ("/*", "6"),
    ] {
        assert_eq!(resolve(pointer, data), Ok(expected.into()), "{pointer:?}");
    }
}

#[test]
fn rejects_invalid_pointer_syntax() {
    for pointer in [
        "foo",
        " /foo",
        "/~",
        "/~2",
        "/missing/~x",
        "#foo",
        "#/~3",
        "#/%7E3",
        "#/%",
        "#/%8",
        "#/%GH",
        "#/%FF",
        "#/a#b",
        "#/a b",
        "#/é",
    ] {
        let error = resolve(pointer, RFC_DOCUMENT).unwrap_err();
        assert!(
            error.starts_with("invalid pointer:"),
            "{pointer:?}: {error}"
        );
    }
}

#[test]
fn applies_index_rules_only_to_arrays() {
    assert_eq!(resolve("/0/1", r#"[[false, true]]"#), Ok("true".into()));
    for pointer in ["/", "/-", "/01", "/+1", "/-1", "/ 1", "/１"] {
        let error = resolve(pointer, "[0,1]").unwrap_err();
        assert!(
            error.contains("invalid array index"),
            "{pointer:?}: {error}"
        );
    }
    for pointer in ["/2", "/184467440737095516160"] {
        assert!(resolve(pointer, "[0,1]")
            .unwrap_err()
            .contains("out of range"));
    }
    for key in ["", "-", "01", "+1", "-1", " 1", "１"] {
        let document = serde_json::json!({ key: 7 }).to_string();
        assert_eq!(
            resolve(&format!("/{key}"), &document),
            Ok("7".into()),
            "{key:?}"
        );
    }
}

#[test]
fn reports_missing_and_ambiguous_members() {
    let data = r#"{"items":[{"name":null,"other":1,"other":2}],"duplicate":1,"\u0064uplicate":2}"#;
    assert_eq!(resolve("/items/0/name", data), Ok("null".into()));
    assert!(resolve("/duplicate", data)
        .unwrap_err()
        .contains("ambiguous"));
    assert!(resolve("/items/0/other", data)
        .unwrap_err()
        .contains("ambiguous"));
    assert!(resolve("/items/0/missing", data)
        .unwrap_err()
        .contains("no member"));
    assert!(resolve("/items/0/name/x", data)
        .unwrap_err()
        .contains("object or array"));
}

#[test]
fn preserves_value_bytes_and_numeric_precision() {
    let value =
        r#"{ "number": 123456789012345678901234567890, "escaped": "\u00e9", "extreme": 1e1000 }"#;
    let data = format!(r#"{{ "value": {value} }}"#);
    assert_eq!(resolve("/value", &data), Ok(value.into()));
    assert_eq!(
        resolve("/value/number", &data),
        Ok("123456789012345678901234567890".into())
    );
    assert_eq!(resolve("/value/extreme", &data), Ok("1e1000".into()));
    assert_eq!(resolve("", "null"), Ok("null".into()));
}

#[test]
fn rejects_invalid_envelopes_and_trailing_garbage() {
    for input in [
        "",
        r#"["",0]"#,
        r#"{"data":0}"#,
        r#"{"pointer":""}"#,
        r#"{"pointer":0,"data":0}"#,
        r#"{"pointer":"","data":0,"pretty":true}"#,
        r#"{"pointer":"","pointer":"/x","data":0}"#,
        r#"{"pointer":"","data":0,"data":1}"#,
        r#"{"pointer":"","data":{"invalid":[] false}}"#,
        r#"{"pointer":"","data":null} null"#,
    ] {
        let error = transform(input.as_bytes()).unwrap_err();
        assert!(
            error.starts_with("invalid input envelope:"),
            "{input:?}: {error}"
        );
    }
    assert!(transform(b"\xff").unwrap_err().contains("UTF-8"));
}

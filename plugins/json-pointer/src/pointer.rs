use std::borrow::Cow;
use std::fmt;

use serde::de::{DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

pub(crate) fn parse(pointer: &str) -> Result<Vec<String>, &'static str> {
    let pointer = match pointer.strip_prefix('#') {
        Some(fragment) => Cow::Owned(decode_fragment(fragment)?),
        None => Cow::Borrowed(pointer),
    };
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    pointer
        .strip_prefix('/')
        .ok_or("a nonempty pointer must start with '/'")?
        .split('/')
        .map(decode_token)
        .collect()
}

fn decode_token(token: &str) -> Result<String, &'static str> {
    let mut decoded = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        decoded.push(match ch {
            '~' => match chars.next() {
                Some('0') => '~',
                Some('1') => '/',
                _ => return Err("a '~' escape must be '~0' or '~1'"),
            },
            ch => ch,
        });
    }
    Ok(decoded)
}

fn decode_fragment(fragment: &str) -> Result<String, &'static str> {
    let mut decoded = Vec::with_capacity(fragment.len());
    let mut bytes = fragment.bytes();
    while let Some(byte) = bytes.next() {
        // RFC 3986 allows pchar, '/' and '?' unescaped in a fragment.
        decoded.push(match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or("invalid percent escape")?;
                let low = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or("invalid percent escape")?;
                high * 16 + low
            }
            byte if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte) => byte,
            _ => return Err("invalid character in URI fragment; percent-encode it"),
        });
    }
    String::from_utf8(decoded).map_err(|_| "URI fragment must decode to UTF-8")
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn resolve<'de>(
    data: &'de RawValue,
    tokens: &[String],
) -> Result<&'de RawValue, String> {
    if tokens.is_empty() {
        return Ok(data);
    }
    let mut deserializer = serde_json::Deserializer::from_str(data.get());
    Selection { tokens }
        .deserialize(&mut deserializer)
        .map_err(|error| format!("pointer could not be evaluated: {error}"))
}

struct Selection<'a> {
    tokens: &'a [String],
}

impl<'de> DeserializeSeed<'de> for Selection<'_> {
    type Value = &'de RawValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        match self.tokens.split_first() {
            Some((token, tail)) => deserializer.deserialize_any(Children { token, tail }),
            None => <&RawValue>::deserialize(deserializer),
        }
    }
}

// Scan the current container while descending only through matching children.
// Continue scanning object keys after finding a match to detect duplicates.
struct Children<'a> {
    token: &'a str,
    tail: &'a [String],
}

impl<'de> Visitor<'de> for Children<'_> {
    type Value = &'de RawValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "an object or array for reference token {:?}",
            self.token
        )
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut selected = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == self.token {
                if selected.is_some() {
                    return Err(M::Error::custom(format_args!(
                        "object member {key:?} is ambiguous"
                    )));
                }
                selected = Some(map.next_value_seed(Selection { tokens: self.tail })?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        selected
            .ok_or_else(|| M::Error::custom(format_args!("object has no member {:?}", self.token)))
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        if !is_array_index(self.token) {
            return Err(S::Error::custom(format_args!(
                "invalid array index {:?}",
                self.token
            )));
        }
        let out_of_range =
            || S::Error::custom(format_args!("array index {} is out of range", self.token));
        let index = self.token.parse::<usize>().map_err(|_| out_of_range())?;
        let mut selected = None;
        for current in 0.. {
            if current == index {
                match seq.next_element_seed(Selection { tokens: self.tail })? {
                    Some(value) => selected = Some(value),
                    None => break,
                }
            } else if seq.next_element::<IgnoredAny>()?.is_none() {
                break;
            }
        }
        selected.ok_or_else(out_of_range)
    }
}

fn is_array_index(token: &str) -> bool {
    match token.as_bytes() {
        b"0" => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

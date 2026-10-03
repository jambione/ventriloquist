//! Strict, bounded JSON reader used for every message decode (README §5.1).
//!
//! This is deliberately our own code rather than a general-purpose JSON
//! library, so that the accept/reject boundary is fully specified by the
//! README and does not depend on any library's internals. It validates the
//! **whole document**, including members that the message layer later
//! ignores, and fails with [`Error::InvalidJson`] when:
//!
//! 1. the input is not valid UTF-8, or is not exactly one RFC 8259 value
//!    surrounded by optional JSON whitespace (space, tab, LF, CR);
//! 2. objects and arrays nest more than [`crate::MAX_JSON_DEPTH`] deep (the
//!    outermost container is depth 1);
//! 3. any number, converted to IEEE 754 binary64 with round-to-nearest-even,
//!    is not finite (for example `1e400`);
//! 4. any string (key or value) contains a `\u` escape for a lone surrogate:
//!    a high surrogate (`D800`–`DBFF`) not immediately followed by a `\u`
//!    escape of a low surrogate (`DC00`–`DFFF`), or a low surrogate that does
//!    not complete such a pair;
//! 5. any object, at any depth, has two members whose keys are equal after
//!    unescaping.
//!
//! Only the members of a top-level object are returned, as [`Scalar`]s;
//! nested containers are validated and then discarded, so memory use is
//! bounded by the input size.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::MAX_JSON_DEPTH;

/// A top-level member value. Nested containers are reported only by kind.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Scalar<'a> {
    /// A string, unescaped.
    Str(String),
    /// A number, as its raw (grammar-checked, finite) source text.
    Num(&'a str),
    /// `true` / `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// An object (contents validated, not kept).
    Object,
    /// An array (contents validated, not kept).
    Array,
}

/// A parsed document.
#[derive(Debug)]
pub(crate) enum Document<'a> {
    /// The top-level value is an object; its members in source order (keys are unique).
    Object(Vec<(String, Scalar<'a>)>),
    /// The top-level value is valid JSON but not an object.
    NotObject,
}

/// Parse and fully validate `bytes`.
pub(crate) fn parse(bytes: &[u8]) -> Result<Document<'_>> {
    let text = std::str::from_utf8(bytes).map_err(|_| bad("input is not valid UTF-8"))?;
    let mut p = Parser {
        s: text,
        b: bytes,
        i: 0,
    };
    p.ws();
    let doc = if p.peek() == Some(b'{') {
        Document::Object(p.object(1, true)?.unwrap_or_default())
    } else {
        p.value(0)?;
        Document::NotObject
    };
    p.ws();
    if p.i != p.b.len() {
        return Err(bad("trailing characters after the JSON value"));
    }
    Ok(doc)
}

fn bad(why: &'static str) -> Error {
    Error::InvalidJson(why.to_owned())
}

struct Parser<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(bad("unexpected character"))
        }
    }

    /// Parse one value. `depth` is the nesting depth of the enclosing
    /// container (0 at top level).
    fn value(&mut self, depth: usize) -> Result<Scalar<'a>> {
        match self.peek() {
            Some(b'{') => {
                self.object(depth + 1, false)?;
                Ok(Scalar::Object)
            }
            Some(b'[') => {
                self.array(depth + 1)?;
                Ok(Scalar::Array)
            }
            Some(b'"') => Ok(Scalar::Str(self.string()?)),
            Some(b't') => self.literal("true", Scalar::Bool(true)),
            Some(b'f') => self.literal("false", Scalar::Bool(false)),
            Some(b'n') => self.literal("null", Scalar::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(bad("expected a JSON value")),
        }
    }

    fn literal(&mut self, word: &'static str, v: Scalar<'a>) -> Result<Scalar<'a>> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(bad("invalid literal"))
        }
    }

    fn check_depth(depth: usize) -> Result<()> {
        if depth > MAX_JSON_DEPTH {
            Err(bad("nesting deeper than 32 levels"))
        } else {
            Ok(())
        }
    }

    /// Parse an object at nesting `depth` (1 = outermost). With `keep`, the
    /// members are returned.
    fn object(&mut self, depth: usize, keep: bool) -> Result<Option<Vec<(String, Scalar<'a>)>>> {
        Self::check_depth(depth)?;
        self.eat(b'{')?;
        let mut seen: HashSet<String> = HashSet::new();
        let mut members = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(keep.then_some(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(bad("expected an object key"));
            }
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(depth)?;
            if !seen.insert(key.clone()) {
                return Err(bad("duplicate object key"));
            }
            if keep {
                members.push((key, v));
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(keep.then_some(members));
                }
                _ => return Err(bad("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<()> {
        Self::check_depth(depth)?;
        self.eat(b'[')?;
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            self.value(depth)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(bad("expected ',' or ']'")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Scalar<'a>> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(bad("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(bad("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(bad("invalid number"));
            }
        }
        let raw = &self.s[start..self.i];
        // Rust's float parsing is correctly rounded (round-to-nearest-even)
        // and yields ±inf on overflow.
        let f: f64 = raw.parse().map_err(|_| bad("invalid number"))?;
        if !f.is_finite() {
            return Err(bad("number is not finite as a binary64 double"));
        }
        Ok(Scalar::Num(raw))
    }

    fn hex4(&mut self) -> Result<u32> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| bad("truncated \\u escape"))?;
        let mut v = 0u32;
        for &c in h {
            let d = (c as char)
                .to_digit(16)
                .ok_or_else(|| bad("invalid \\u escape"))?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or_else(|| bad("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| bad("unterminated string"))?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = match hi {
                                0xD800..=0xDBFF => {
                                    if !self.b[self.i..].starts_with(b"\\u") {
                                        return Err(bad("lone surrogate escape"));
                                    }
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(bad("lone surrogate escape"));
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                }
                                0xDC00..=0xDFFF => return Err(bad("lone surrogate escape")),
                                cp => cp,
                            };
                            char::from_u32(cp).ok_or_else(|| bad("invalid \\u escape"))?
                        }
                        _ => return Err(bad("invalid escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1F => return Err(bad("unescaped control character in string")),
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        // The input was validated as UTF-8 and escapes are encoded as UTF-8,
        // so this cannot fail; map defensively anyway.
        String::from_utf8(out).map_err(|_| bad("input is not valid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Document<'_> {
        parse(s.as_bytes()).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }
    fn err(s: &str) {
        assert_eq!(
            parse(s.as_bytes()).map(|_| ()).unwrap_err().code(),
            "invalid_json",
            "{s:?}"
        );
    }

    #[test]
    fn grammar() {
        for s in [
            "{}",
            "[]",
            "0",
            "-0",
            "1.5e-3",
            "\"x\"",
            "null",
            " {\"a\" : [1, {\"b\": true}] } ",
            "1e308",
            "-1e-400",
            "123456789012345678901234567890",
        ] {
            ok(s);
        }
        for s in [
            "",
            " ",
            "{",
            "}",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "+1",
            ".5",
            "1.",
            "1e",
            "-",
            "NaN",
            "Infinity",
            "tru",
            "nul",
            "{\"a\" 1}",
            "{a:1}",
            "'x'",
            "\"\\x\"",
            "\"\\u12\"",
            "\"a\nb\"",
            "{} {}",
            "\u{feff}{}",
            "\u{a0}{}",
            "\"\\u00G0\"",
        ] {
            err(s);
        }
    }

    #[test]
    fn r1_rules() {
        // depth
        let d = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        ok(&d(32));
        err(&d(33));
        ok(&format!("{{\"x\":{}}}", d(31)));
        err(&format!("{{\"x\":{}}}", d(32)));
        err(&"[".repeat(100_000));
        // finiteness
        err("1e400");
        err("-1e400");
        err("1e309");
        ok("1.7976931348623157e308");
        err("1.7976931348623159e308");
        ok(&"9".repeat(300));
        err(&"9".repeat(400));
        // surrogates
        ok(r#""\ud83d\ude00""#);
        for s in [
            r#""\ud800""#,
            r#""\udfff""#,
            r#""\ud800A""#,
            r#""\udc00\ud800""#,
            r#""\ud800\u0041""#,
            r#""\ud800\ud800""#,
        ] {
            err(s);
        }
        err(r#"{"\ud800":1}"#);
        // duplicates (after unescaping), at any depth
        err(r#"{"a":1,"a":2}"#);
        err(r#"{"t":1,"\u0074":2}"#);
        err(r#"{"x":[{"k":1,"k":1}]}"#);
        ok(r#"{"a":{"a":1},"b":{"a":1}}"#);
    }

    #[test]
    fn top_level_members() {
        let Document::Object(m) =
            ok(r#"{"t":"p\u0069ng","n":-0,"o":{"x":[1]},"a":[],"b":false,"z":null}"#)
        else {
            panic!()
        };
        assert_eq!(
            m,
            vec![
                ("t".into(), Scalar::Str("ping".into())),
                ("n".into(), Scalar::Num("-0")),
                ("o".into(), Scalar::Object),
                ("a".into(), Scalar::Array),
                ("b".into(), Scalar::Bool(false)),
                ("z".into(), Scalar::Null),
            ]
        );
        assert!(matches!(ok("[1]"), Document::NotObject));
    }
}

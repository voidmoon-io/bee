//! combq tokens.

use super::{ParseError, Span};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// A bare word: a namespace, field, operator, keyword or `true`/`false`.
    Word(String),
    Str(String),
    Int(i64),
    /// A relative time, `-<n><s|m|h|d>`, kept as written.
    RelTime(String),
    Dot,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Eof,
}

impl Tok {
    pub fn describe(&self) -> String {
        match self {
            Tok::Word(w) => format!("`{w}`"),
            Tok::Str(_) => "a string".into(),
            Tok::Int(_) => "a number".into(),
            Tok::RelTime(t) => format!("`{t}`"),
            Tok::Dot => "`.`".into(),
            Tok::LBracket => "`[`".into(),
            Tok::RBracket => "`]`".into(),
            Tok::LParen => "`(`".into(),
            Tok::RParen => "`)`".into(),
            Tok::Eof => "the end of the query".into(),
        }
    }
}

pub fn lex(src: &str) -> Result<Vec<(Tok, Span)>, ParseError> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        let span = |end: usize| Span { start, end };
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'#' => i = line_end(b, i),
            b'/' if b.get(i + 1) == Some(&b'/') => i = line_end(b, i),
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let close = src[i + 2..]
                    .find("*/")
                    .ok_or_else(|| ParseError::at(span(b.len()), "unclosed `/*` comment"))?;
                i = i + 2 + close + 2;
            }
            b'.' => {
                out.push((Tok::Dot, span(i + 1)));
                i += 1;
            }
            b'[' => {
                out.push((Tok::LBracket, span(i + 1)));
                i += 1;
            }
            b']' => {
                out.push((Tok::RBracket, span(i + 1)));
                i += 1;
            }
            b'(' => {
                out.push((Tok::LParen, span(i + 1)));
                i += 1;
            }
            b')' => {
                out.push((Tok::RParen, span(i + 1)));
                i += 1;
            }
            b'"' | b'\'' => {
                let (s, end) = string(src, i)?;
                out.push((Tok::Str(s), span(end)));
                i = end;
            }
            b'-' if b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j < b.len()
                    && matches!(b[j], b's' | b'm' | b'h' | b'd')
                    && !word_byte(b.get(j + 1))
                {
                    out.push((Tok::RelTime(src[i..=j].to_string()), span(j + 1)));
                    i = j + 1;
                } else {
                    let n = src[i..j]
                        .parse()
                        .map_err(|_| ParseError::at(span(j), "number out of range"))?;
                    out.push((Tok::Int(n), span(j)));
                    i = j;
                }
            }
            b'0'..=b'9' => {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if word_byte(b.get(j)) {
                    return Err(ParseError::at(
                        span(j + 1),
                        "a number runs into a word; quote the value",
                    ));
                }
                let n = src[i..j]
                    .parse()
                    .map_err(|_| ParseError::at(span(j), "number out of range"))?;
                out.push((Tok::Int(n), span(j)));
                i = j;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let mut j = i;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                out.push((Tok::Word(src[i..j].to_string()), span(j)));
                i = j;
            }
            _ => {
                let ch = src[i..].chars().next().unwrap_or('?');
                return Err(ParseError::at(
                    span(i + ch.len_utf8()),
                    format!("unexpected `{}`", ch.escape_debug()),
                ));
            }
        }
    }
    out.push((
        Tok::Eof,
        Span {
            start: b.len(),
            end: b.len(),
        },
    ));
    Ok(out)
}

fn word_byte(b: Option<&u8>) -> bool {
    b.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn line_end(b: &[u8], i: usize) -> usize {
    b[i..]
        .iter()
        .position(|&c| c == b'\n')
        .map_or(b.len(), |p| i + p)
}

/// A quoted string starting at `start`: `\"`, `\'`, `\\`, `\n`, `\r`, `\t` and `\u{…}` escapes.
fn string(src: &str, start: usize) -> Result<(String, usize), ParseError> {
    let quote = src.as_bytes()[start] as char;
    let mut out = String::new();
    let mut chars = src[start + 1..].char_indices();
    while let Some((off, c)) = chars.next() {
        let at = start + 1 + off;
        match c {
            c if c == quote => return Ok((out, at + 1)),
            '\\' => {
                let (_, e) = chars.next().ok_or_else(|| {
                    ParseError::at(
                        Span {
                            start,
                            end: src.len(),
                        },
                        "unclosed string",
                    )
                })?;
                match e {
                    '"' | '\'' | '\\' => out.push(e),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let rest = &src[at + 2..];
                        let close = rest
                            .strip_prefix('{')
                            .and_then(|r| r.find('}'))
                            .ok_or_else(|| {
                                ParseError::at(
                                    Span {
                                        start: at,
                                        end: at + 2,
                                    },
                                    "write \\u{hex}",
                                )
                            })?;
                        let hex = &rest[1..=close];
                        let ch = u32::from_str_radix(hex, 16)
                            .ok()
                            .and_then(char::from_u32)
                            .ok_or_else(|| {
                                ParseError::at(
                                    Span {
                                        start: at,
                                        end: at + 3 + close,
                                    },
                                    "not a Unicode scalar",
                                )
                            })?;
                        out.push(ch);
                        for _ in 0..close + 2 {
                            chars.next();
                        }
                    }
                    other => {
                        return Err(ParseError::at(
                            Span {
                                start: at,
                                end: at + 1 + other.len_utf8(),
                            },
                            format!("unknown escape `\\{other}`"),
                        ))
                    }
                }
            }
            c => out.push(c),
        }
    }
    Err(ParseError::at(
        Span {
            start,
            end: src.len(),
        },
        "unclosed string",
    ))
}

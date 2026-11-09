//! combq — a query language over recorded exchanges (.scratch/comb, issues 04–07).
//!
//! ```text
//! req.host eq "api.example.com" and resp.code gte 500
//! req.method eq "POST" and (req.header["content-type"] cont "json" or req.body regex "\"role\"")
//! origin eq "fuzz" and resp.len gt 10000 and not tag eq "baseline"
//! req.created_at gt -10m and resp.roundtrip gt 2000
//! "Authorization"            // a bare string: req.raw or resp.raw contains it
//! ```
//!
//! A clause is `namespace.field op value` (`origin`, `call`, `tag`, … take no field). Clauses join
//! with `and`, `or` and `not` — `not` binds tightest, then `and`, then `or` — and parentheses.
//! `//` and `#` start a line comment, `/* */` a block comment. Keywords and operators are
//! case-insensitive; string values are case-sensitive except under `cont`/`ncont`.
//!
//! [`parse`] type-checks as it goes: a field only accepts the operators and values its type allows,
//! a regex must compile, and the query is bounded in length, depth and clause count. A query that
//! parses is one every backend can run.

pub mod eval;
mod lex;
mod parse;

#[cfg(test)]
mod tests;

pub use parse::parse;

/// Longest query accepted, in bytes.
pub const MAX_QUERY_LEN: usize = 8 * 1024;
/// Deepest nesting of parentheses and `not`.
pub const MAX_DEPTH: usize = 32;
/// Most clauses in one query.
pub const MAX_CLAUSES: usize = 64;
/// Compiled-size limit for a `regex` value.
pub const MAX_REGEX_BYTES: usize = 1 << 20;

/// A byte range of the query text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A parsed query.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Clause(Clause),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Clause {
    pub field: Field,
    pub op: Op,
    pub value: Value,
    pub span: Span,
}

/// What a clause looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Req(ReqField),
    Resp(RespField),
    /// `tool`, `replay`, `fuzz` or `forwarded`.
    Origin,
    /// The tool call the exchange is attributed to.
    Call,
    Tag,
    /// `completed`, `refused`, `failed` or `truncated`.
    Outcome,
    /// The fuzz run an exchange belongs to.
    Fuzz,
    /// The exchange id.
    Id,
    Session,
    Turn,
    /// A bare string's field: `req.raw` or `resp.raw`. Not writable as `namespace.field`.
    AnyRaw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReqField {
    Method,
    Host,
    Port,
    Path,
    /// The query string, without its `?`.
    Query,
    /// The path's extension, with its `.`.
    Ext,
    Tls,
    Len,
    CreatedAt,
    /// Any header line (`name: value`), or the named header's value.
    Header(Option<String>),
    Body,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespField {
    Code,
    Len,
    /// Total time in milliseconds.
    Roundtrip,
    /// Time to first byte in milliseconds.
    Ttfb,
    Header(Option<String>),
    Body,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    /// Contains, ignoring ASCII case.
    Cont,
    Ncont,
    /// SQL `LIKE`: `%` any run, `_` one character.
    Like,
    Nlike,
    Regex,
    Nregex,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "eq",
            Op::Ne => "ne",
            Op::Gt => "gt",
            Op::Gte => "gte",
            Op::Lt => "lt",
            Op::Lte => "lte",
            Op::Cont => "cont",
            Op::Ncont => "ncont",
            Op::Like => "like",
            Op::Nlike => "nlike",
            Op::Regex => "regex",
            Op::Nregex => "nregex",
        }
    }

    /// The operator that matches exactly what this one does not.
    pub fn negated(self) -> bool {
        matches!(self, Op::Ne | Op::Ncont | Op::Nlike | Op::Nregex)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    /// A point in time, in the store's fixed-width UTC text format.
    Time(String),
    /// A compiled, size-limited regex (for `regex`/`nregex`).
    Regex(Regex),
}

/// A regex value: its source and the compiled form.
#[derive(Debug, Clone)]
pub struct Regex {
    pub source: String,
    pub compiled: regex::Regex,
}

impl PartialEq for Regex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

/// The value type a field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Str,
    Int,
    Bool,
    Time,
}

impl Field {
    pub fn kind(&self) -> Kind {
        match self {
            Field::Req(ReqField::Port | ReqField::Len) => Kind::Int,
            Field::Req(ReqField::Tls) => Kind::Bool,
            Field::Req(ReqField::CreatedAt) => Kind::Time,
            Field::Resp(
                RespField::Code | RespField::Len | RespField::Roundtrip | RespField::Ttfb,
            ) => Kind::Int,
            Field::Turn => Kind::Int,
            _ => Kind::Str,
        }
    }

    /// Whether the field needs the response (and so cannot be decided before it exists — a
    /// request-phase intercept rule refuses it).
    pub fn needs_response(&self) -> bool {
        matches!(self, Field::Resp(_) | Field::AnyRaw)
    }
}

/// Why a query did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub span: Span,
    pub message: String,
}

impl ParseError {
    pub(crate) fn at(span: Span, message: impl Into<String>) -> Self {
        ParseError {
            span,
            message: message.into(),
        }
    }

    /// The error with the query's offending line and a caret under the span.
    pub fn render(&self, query: &str) -> String {
        let start = self.span.start.min(query.len());
        let line_start = query[..start].rfind('\n').map_or(0, |i| i + 1);
        let line_end = query[start..].find('\n').map_or(query.len(), |i| start + i);
        let line = &query[line_start..line_end];
        let col = query[line_start..start].chars().count();
        let width = query[start..self.span.end.clamp(start, line_end)]
            .chars()
            .count()
            .max(1);
        format!(
            "{}\n  {line}\n  {}{}",
            self.message,
            " ".repeat(col),
            "^".repeat(width)
        )
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.span.start)
    }
}

impl std::error::Error for ParseError {}

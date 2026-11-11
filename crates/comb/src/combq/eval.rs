//! Running a combq [`Expr`] against the store: an SQL prefilter and an exact Rust evaluator.
//!
//! [`plan`] turns the expression into a parameterised SQL condition that every match satisfies —
//! exact when every clause is a column comparison, an over-approximation otherwise (a clause on
//! headers, bodies, raw bytes, `query`, `ext`, or any regex counts as `TRUE` there). When it is not
//! exact, [`eval`] decides each candidate in Rust. Both backends give a clause on a missing value
//! (a failed exchange's status) the same answer: false, so its negation is true. No value is ever
//! spliced into SQL text.

use rusqlite::types::Value as SqlValue;

use super::{Clause, Expr, Field, Op, ParseError, ReqField, RespField, Value};
use crate::store::{Store, StoredExchange};

/// Largest decoded body a clause reads; beyond it, the prefix.
pub const BODY_CAP: usize = 1 << 20;

/// A parameterised SQL condition over `exchanges`.
#[derive(Debug, Clone, PartialEq)]
pub struct Sql {
    pub text: String,
    pub params: Vec<SqlValue>,
}

/// How a query runs: a prefilter, and whether it alone is the answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// `None` constrains nothing.
    pub prefilter: Option<Sql>,
    /// The prefilter is the query exactly: no row needs [`eval`].
    pub exact: bool,
}

pub fn plan(e: &Expr) -> Plan {
    let (prefilter, exact) = sql(e);
    Plan { prefilter, exact }
}

fn sql(e: &Expr) -> (Option<Sql>, bool) {
    match e {
        Expr::Clause(c) => match clause_sql(c) {
            Some(s) => (Some(s), true),
            None => (None, false),
        },
        Expr::And(a, b) => {
            let ((sa, ea), (sb, eb)) = (sql(a), sql(b));
            let s = match (sa, sb) {
                (Some(a), Some(b)) => Some(join(a, "AND", b)),
                (a, b) => a.or(b),
            };
            (s, ea && eb)
        }
        Expr::Or(a, b) => {
            let ((sa, ea), (sb, eb)) = (sql(a), sql(b));
            match (sa, sb) {
                (Some(a), Some(b)) => (Some(join(a, "OR", b)), ea && eb),
                // One side is unconstrained in SQL, so the disjunction is too.
                _ => (None, false),
            }
        }
        Expr::Not(x) => match sql(x) {
            (Some(s), true) => (
                Some(Sql {
                    text: format!("NOT ({})", s.text),
                    params: s.params,
                }),
                true,
            ),
            // The negation of an over-approximation is not one.
            _ => (None, false),
        },
    }
}

fn join(a: Sql, op: &str, b: Sql) -> Sql {
    let mut params = a.params;
    params.extend(b.params);
    Sql {
        text: format!("({}) {op} ({})", a.text, b.text),
        params,
    }
}

/// A column comparison for `c`, or `None` when only [`eval`] can decide it.
fn clause_sql(c: &Clause) -> Option<Sql> {
    if matches!(c.op, Op::Regex | Op::Nregex) {
        return None;
    }
    let col = match &c.field {
        Field::Req(ReqField::Method) => "method",
        Field::Req(ReqField::Host) => "lower(host)",
        Field::Req(ReqField::Port) => "port",
        Field::Req(ReqField::Path) => "path",
        Field::Req(ReqField::Tls) => "(COALESCE(scheme, '') = 'https')",
        Field::Req(ReqField::Len) => "req_bytes",
        Field::Req(ReqField::CreatedAt) => "started",
        Field::Resp(RespField::Code) => "status",
        Field::Resp(RespField::Len) => "resp_bytes",
        Field::Resp(RespField::Roundtrip) => "total_ms",
        Field::Resp(RespField::Ttfb) => "ttfb_ms",
        Field::Origin => "origin_kind",
        Field::Call => "call_id",
        Field::Fuzz => "fuzz_run",
        Field::Id => "id",
        Field::Session => "session_id",
        Field::Turn => "turn",
        Field::Outcome => "outcome_kind",
        // Tags are a JSON array: only whole-tag equality is a column test.
        Field::Tag => return tag_sql(c),
        _ => return None,
    };
    let col = if col == "outcome_kind" {
        // `failed: <reason>` → `failed`.
        "CASE WHEN instr(outcome, ':') > 0 THEN substr(outcome, 1, instr(outcome, ':') - 1) \
         ELSE outcome END"
    } else {
        col
    };
    let param = match &c.value {
        Value::Str(s) if matches!(c.field, Field::Req(ReqField::Host)) => {
            SqlValue::Text(bee_core::pattern::normalize_host(s))
        }
        Value::Str(s) | Value::Time(s) => SqlValue::Text(s.clone()),
        Value::Int(n) => SqlValue::Integer(*n),
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Regex(_) => return None,
    };
    let positive = match positive(c.op) {
        Op::Eq => format!("{col} = ?"),
        Op::Gt => format!("{col} > ?"),
        Op::Gte => format!("{col} >= ?"),
        Op::Lt => format!("{col} < ?"),
        Op::Lte => format!("{col} <= ?"),
        Op::Cont => format!("instr(lower({col}), lower(?)) > 0"),
        Op::Like => format!("{col} LIKE ?"),
        _ => return None,
    };
    Some(wrap(positive, c.op.negated(), vec![param]))
}

fn tag_sql(c: &Clause) -> Option<Sql> {
    let (Op::Eq | Op::Ne, Value::Str(s)) = (c.op, &c.value) else {
        return None;
    };
    let quoted = serde_json::to_string(s).ok()?;
    Some(wrap(
        "instr(tags, ?) > 0".into(),
        c.op.negated(),
        vec![SqlValue::Text(quoted)],
    ))
}

/// Two-valued: a NULL column makes the positive test false, so its negation is true — as in
/// [`eval`].
fn wrap(positive: String, negated: bool, params: Vec<SqlValue>) -> Sql {
    let text = if negated {
        format!("NOT COALESCE(({positive}), 0)")
    } else {
        format!("COALESCE(({positive}), 0)")
    };
    Sql { text, params }
}

/// The positive operator behind a negated one.
fn positive(op: Op) -> Op {
    match op {
        Op::Ne => Op::Eq,
        Op::Ncont => Op::Cont,
        Op::Nlike => Op::Like,
        Op::Nregex => Op::Regex,
        o => o,
    }
}

/// One exchange as [`eval`] reads it; bodies are read and decoded on first use.
pub struct View<'a> {
    pub ex: &'a StoredExchange,
    store: &'a Store,
    req_body: Option<Vec<u8>>,
    resp_body: Option<Vec<u8>>,
}

impl<'a> View<'a> {
    pub fn new(ex: &'a StoredExchange, store: &'a Store) -> Self {
        View {
            ex,
            store,
            req_body: None,
            resp_body: None,
        }
    }

    /// The stored (still-encoded) body bytes of one side.
    fn raw_body(&self, sha: Option<&String>) -> Vec<u8> {
        sha.and_then(|s| self.store.read_blob(s).ok().flatten())
            .map(|mut b| {
                b.truncate(BODY_CAP);
                b
            })
            .unwrap_or_default()
    }

    fn body(&mut self, resp: bool) -> &[u8] {
        let (slot, sha, head) = if resp {
            (
                &mut self.resp_body,
                self.ex.resp_body.as_ref(),
                &self.ex.resp_head,
            )
        } else {
            (
                &mut self.req_body,
                self.ex.req_body.as_ref(),
                &self.ex.req_head,
            )
        };
        if slot.is_none() {
            let raw = sha
                .and_then(|s| self.store.read_blob(s).ok().flatten())
                .unwrap_or_default();
            let enc = crate::store::content_encoding(head);
            let decoded = crate::slice::decode(&raw, &enc, BODY_CAP)
                .map(|d| d.bytes)
                .unwrap_or(raw);
            *slot = Some(decoded);
        }
        slot.as_deref().unwrap_or_default()
    }
}

/// The values a field holds for one exchange: none (missing), one or more strings, or a number.
pub enum Got {
    Missing,
    Strs(Vec<String>),
    Int(i64),
}

impl Got {
    fn one(s: impl Into<String>) -> Got {
        Got::Strs(vec![s.into()])
    }

    fn opt(s: &Option<String>) -> Got {
        s.as_ref().map_or(Got::Missing, |x| Got::one(x.clone()))
    }

    fn num(n: Option<u64>) -> Got {
        n.map_or(Got::Missing, |x| Got::Int(x as i64))
    }
}

/// Where [`eval`] reads a field's values from.
pub trait Fields {
    fn get(&mut self, f: &Field) -> Got;
}

/// Decide `e` for one exchange.
pub fn eval<F: Fields + ?Sized>(e: &Expr, v: &mut F) -> bool {
    match e {
        Expr::And(a, b) => eval(a, v) && eval(b, v),
        Expr::Or(a, b) => eval(a, v) || eval(b, v),
        Expr::Not(x) => !eval(x, v),
        Expr::Clause(c) => {
            let hit = match &c.field {
                Field::AnyRaw => {
                    let req = Clause {
                        field: Field::Req(ReqField::Raw),
                        ..c.clone()
                    };
                    let resp = Clause {
                        field: Field::Resp(RespField::Raw),
                        ..c.clone()
                    };
                    positive_hit(&req, v) || positive_hit(&resp, v)
                }
                _ => positive_hit(c, v),
            };
            hit != c.op.negated()
        }
    }
}

/// Whether the clause's positive form holds for any of the field's values.
fn positive_hit<F: Fields + ?Sized>(c: &Clause, v: &mut F) -> bool {
    let got = v.get(&c.field);
    let op = positive(c.op);
    match (got, &c.value) {
        (Got::Missing, _) => false,
        (Got::Int(n), Value::Int(want)) => cmp(op, n.cmp(want)),
        (Got::Int(n), Value::Bool(b)) => (n != 0) == *b,
        (Got::Strs(vals), value) => vals.iter().any(|s| str_hit(&c.field, op, s, value)),
        _ => false,
    }
}

fn cmp(op: Op, o: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::*;
    match op {
        Op::Eq => o == Equal,
        Op::Gt => o == Greater,
        Op::Gte => o != Less,
        Op::Lt => o == Less,
        Op::Lte => o != Greater,
        _ => false,
    }
}

fn str_hit(field: &Field, op: Op, s: &str, value: &Value) -> bool {
    match (op, value) {
        (Op::Regex, Value::Regex(r)) => r.compiled.is_match(s),
        (_, Value::Time(t)) => cmp(op, s.cmp(t.as_str())),
        (Op::Eq, Value::Str(w)) => match field {
            Field::Req(ReqField::Host) => {
                bee_core::pattern::normalize_host(s) == bee_core::pattern::normalize_host(w)
            }
            _ => s == w,
        },
        (Op::Cont, Value::Str(w)) => s.to_ascii_lowercase().contains(&w.to_ascii_lowercase()),
        (Op::Like, Value::Str(w)) => like(s.as_bytes(), w.as_bytes()),
        _ => false,
    }
}

impl Fields for View<'_> {
    fn get(&mut self, f: &Field) -> Got {
        let ex = self.ex;
        match f {
            Field::Req(r) => match r {
                ReqField::Method => Got::opt(&ex.method),
                ReqField::Host => Got::one(ex.host.clone()),
                ReqField::Port => Got::Int(ex.port.into()),
                ReqField::Path => Got::opt(&ex.path),
                ReqField::Query => match ex.target.as_deref().and_then(query_of) {
                    Some(q) => Got::one(q.to_string()),
                    None => Got::Missing,
                },
                ReqField::Ext => match ex.path.as_deref().and_then(ext_of) {
                    Some(e) => Got::one(e.to_string()),
                    None => Got::Missing,
                },
                ReqField::Tls => Got::Int((ex.scheme.as_deref() == Some("https")) as i64),
                ReqField::Len => Got::num(ex.req_bytes),
                ReqField::CreatedAt => Got::one(ex.started.clone()),
                ReqField::Header(name) => headers(&ex.req_head, name.as_deref()),
                ReqField::Body => Got::one(String::from_utf8_lossy(self.body(false)).into_owned()),
                ReqField::Raw => {
                    let mut raw = ex.req_head.clone();
                    raw.extend(self.raw_body(ex.req_body.as_ref()));
                    Got::one(String::from_utf8_lossy(&raw).into_owned())
                }
            },
            Field::Resp(r) => match r {
                RespField::Code => Got::num(ex.status.map(u64::from)),
                RespField::Len => Got::num(ex.resp_bytes),
                RespField::Roundtrip => Got::num(ex.total_ms),
                RespField::Ttfb => Got::num(ex.ttfb_ms),
                RespField::Header(name) => headers(&ex.resp_head, name.as_deref()),
                RespField::Body => Got::one(String::from_utf8_lossy(self.body(true)).into_owned()),
                RespField::Raw => {
                    let mut raw = ex.resp_head.clone();
                    raw.extend(self.raw_body(ex.resp_body.as_ref()));
                    Got::one(String::from_utf8_lossy(&raw).into_owned())
                }
            },
            Field::Origin => Got::one(ex.origin_kind.clone()),
            Field::Call => Got::opt(&ex.call_id),
            Field::Fuzz => Got::opt(&ex.fuzz_run),
            Field::Id => Got::one(ex.id.clone()),
            Field::Session => Got::one(ex.session_id.clone()),
            Field::Turn => ex.turn.map_or(Got::Missing, |t| Got::Int(t.into())),
            Field::Outcome => {
                let kind = ex.outcome.split(':').next().unwrap_or("");
                Got::one(kind.to_string())
            }
            Field::Tag => Got::Strs(ex.tags.clone()),
            Field::AnyRaw => Got::Missing,
        }
    }
}

/// A request on its way upstream, as an intercept rule sees it: nothing about the response, and
/// nothing the store adds later. [`request_only`] keeps a rule's query to these fields.
pub struct Request<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    /// The request target as sent (path and query).
    pub target: &'a str,
    pub head: &'a [u8],
    pub body: &'a [u8],
}

impl Fields for Request<'_> {
    fn get(&mut self, f: &Field) -> Got {
        let Field::Req(r) = f else {
            return Got::Missing;
        };
        let path = crate::store::path_of(self.target);
        match r {
            ReqField::Method => Got::one(self.method),
            ReqField::Host => Got::one(self.host),
            ReqField::Port => Got::Int(self.port.into()),
            ReqField::Path => Got::one(path),
            ReqField::Query => query_of(self.target).map_or(Got::Missing, Got::one),
            ReqField::Ext => ext_of(&path).map_or(Got::Missing, Got::one),
            ReqField::Tls => Got::Int((self.scheme == "https") as i64),
            ReqField::Len => Got::Int(self.body.len() as i64),
            ReqField::Header(name) => headers(self.head, name.as_deref()),
            ReqField::Body => {
                let enc = crate::store::content_encoding(self.head);
                let decoded = crate::slice::decode(self.body, &enc, BODY_CAP)
                    .map(|d| d.bytes)
                    .unwrap_or_else(|_| self.body.to_vec());
                Got::one(String::from_utf8_lossy(&decoded))
            }
            ReqField::Raw => {
                let mut raw = self.head.to_vec();
                raw.extend_from_slice(&self.body[..self.body.len().min(BODY_CAP)]);
                Got::one(String::from_utf8_lossy(&raw))
            }
            ReqField::CreatedAt => Got::Missing,
        }
    }
}

/// Refuse a query a request-phase rule cannot decide: anything about the response, or what only
/// the store knows (origin, call, tags, time, …).
pub fn request_only(e: &Expr) -> Result<(), ParseError> {
    match e {
        Expr::And(a, b) | Expr::Or(a, b) => request_only(a).and(request_only(b)),
        Expr::Not(x) => request_only(x),
        Expr::Clause(c) => match &c.field {
            Field::Req(ReqField::CreatedAt) => Err(ParseError::at(
                c.span,
                "a rule decides a request before it is recorded; req.created_at is not known yet",
            )),
            Field::Req(_) => Ok(()),
            Field::AnyRaw => Err(ParseError::at(
                c.span,
                "a bare string also searches the response, which a rule does not have; use \
                 req.raw cont \"…\"",
            )),
            _ => Err(ParseError::at(
                c.span,
                "a rule decides a request before it is sent: only req.* fields (not \
                 req.created_at) are known",
            )),
        },
    }
}

/// Header lines of a head (`name: value`), or the values of headers named `name`.
fn headers(head: &[u8], name: Option<&str>) -> Got {
    let text = String::from_utf8_lossy(head);
    let mut out = Vec::new();
    for line in text.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        match name {
            None => out.push(line.to_string()),
            Some(n) => {
                if let Some((k, val)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case(n) {
                        out.push(val.trim().to_string());
                    }
                }
            }
        }
    }
    if out.is_empty() {
        Got::Missing
    } else {
        Got::Strs(out)
    }
}

/// The query string of a request target, without `?` or a fragment.
fn query_of(target: &str) -> Option<&str> {
    let q = &target[target.find('?')? + 1..];
    Some(q.split('#').next().unwrap_or(q))
}

/// The extension of a path's last segment, with its `.`.
fn ext_of(path: &str) -> Option<&str> {
    let seg = path.rsplit('/').next()?;
    let dot = seg.rfind('.')?;
    (dot > 0).then(|| &seg[dot..])
}

/// SQLite `LIKE`: `%` any run, `_` one character, ASCII case-insensitive.
fn like(s: &[u8], p: &[u8]) -> bool {
    let (mut si, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'_' || p[pi].eq_ignore_ascii_case(&s[si])) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'%' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'%')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_matches_sqlite() {
        assert!(like(b"/api/users", b"/api/%"));
        assert!(like(b"/API/x", b"/api/_"));
        assert!(!like(b"/api/xy", b"/api/_"));
        assert!(like(b"", b"%"));
        assert!(like(b"abc", b"%b%"));
        assert!(!like(b"abc", b"%d%"));
    }

    #[test]
    fn ext_and_query() {
        assert_eq!(ext_of("/a/b.min.js"), Some(".js"));
        assert_eq!(ext_of("/a/.env"), None);
        assert_eq!(ext_of("/a/b"), None);
        assert_eq!(query_of("/p?a=1&b=2#f"), Some("a=1&b=2"));
        assert_eq!(query_of("/p"), None);
    }

    #[test]
    fn plans_are_exact_only_over_columns() {
        let p = |q: &str| plan(&super::super::parse(q).unwrap().unwrap());
        assert!(p(r#"req.host eq "a" and resp.code gte 500"#).exact);
        assert!(p(r#"not (origin eq "fuzz" or turn eq 2)"#).exact);
        let mixed = p(r#"req.host eq "a" and resp.body cont "x""#);
        assert!(!mixed.exact);
        assert!(mixed.prefilter.is_some(), "the column half still narrows");
        let or = p(r#"req.host eq "a" or resp.body cont "x""#);
        assert!(!or.exact && or.prefilter.is_none());
        let not = p(r#"not resp.body cont "x""#);
        assert!(!not.exact && not.prefilter.is_none());
        assert!(!p(r#"req.path regex "^/a""#).exact);
    }
}

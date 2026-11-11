//! combq's recursive-descent parser, type-checking each clause as it is read.

use super::lex::{lex, Tok};
use super::{
    Clause, Expr, Field, Kind, Op, ParseError, Regex, ReqField, RespField, Span, Value,
    MAX_CLAUSES, MAX_DEPTH, MAX_QUERY_LEN, MAX_REGEX_BYTES,
};

const ORIGINS: &[&str] = &["tool", "replay", "fuzz", "forwarded"];
const OUTCOMES: &[&str] = &["completed", "refused", "failed", "truncated"];

/// Parse and type-check `query`. An empty query (only whitespace or comments) is `Ok(None)`:
/// it matches everything.
pub fn parse(query: &str) -> Result<Option<Expr>, ParseError> {
    if query.len() > MAX_QUERY_LEN {
        return Err(ParseError::at(
            Span {
                start: MAX_QUERY_LEN,
                end: query.len(),
            },
            format!("the query is longer than {MAX_QUERY_LEN} bytes"),
        ));
    }
    let toks = lex(query)?;
    let mut p = Parser {
        toks,
        pos: 0,
        depth: 0,
        clauses: 0,
    };
    if p.peek() == &Tok::Eof {
        return Ok(None);
    }
    let e = p.or()?;
    match p.peek() {
        Tok::Eof => Ok(Some(e)),
        Tok::RParen => Err(p.err_here("unmatched `)`")),
        t => {
            let msg = format!(
                "expected `and`, `or` or the end of the query, found {}",
                t.describe()
            );
            Err(p.err_here(msg))
        }
    }
}

struct Parser {
    toks: Vec<(Tok, Span)>,
    pos: usize,
    depth: usize,
    clauses: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos].0
    }

    fn span(&self) -> Span {
        self.toks[self.pos].1
    }

    fn bump(&mut self) -> (Tok, Span) {
        let t = self.toks[self.pos].clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn err_here(&self, msg: impl Into<String>) -> ParseError {
        ParseError::at(self.span(), msg)
    }

    fn keyword(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Word(w) if w.eq_ignore_ascii_case(kw))
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and()?;
        while self.keyword("or") {
            self.bump();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        while self.keyword("and") {
            self.bump();
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err_here(format!("nested deeper than {MAX_DEPTH}")));
        }
        let e = if self.keyword("not") {
            self.bump();
            Expr::Not(Box::new(self.unary()?))
        } else if self.peek() == &Tok::LParen {
            self.bump();
            let inner = self.or()?;
            if self.peek() != &Tok::RParen {
                let msg = format!("expected `)`, found {}", self.peek().describe());
                return Err(self.err_here(msg));
            }
            self.bump();
            inner
        } else {
            Expr::Clause(self.clause()?)
        };
        self.depth -= 1;
        Ok(e)
    }

    fn clause(&mut self) -> Result<Clause, ParseError> {
        self.clauses += 1;
        if self.clauses > MAX_CLAUSES {
            return Err(self.err_here(format!("more than {MAX_CLAUSES} clauses")));
        }
        let start = self.span().start;
        // A bare string: either raw side contains it.
        if let Tok::Str(s) = self.peek().clone() {
            let (_, sp) = self.bump();
            return Ok(Clause {
                field: Field::AnyRaw,
                op: Op::Cont,
                value: Value::Str(s),
                span: Span { start, end: sp.end },
            });
        }
        let field = self.field()?;
        let (op, op_span) = self.op()?;
        let value = self.value(&field, op, op_span)?;
        let end = self.toks[self.pos.saturating_sub(1)].1.end;
        Ok(Clause {
            field,
            op,
            value,
            span: Span { start, end },
        })
    }

    fn word(&mut self, what: &str) -> Result<(String, Span), ParseError> {
        match self.bump() {
            (Tok::Word(w), sp) => Ok((w.to_ascii_lowercase(), sp)),
            (t, sp) => Err(ParseError::at(
                sp,
                format!("expected {what}, found {}", t.describe()),
            )),
        }
    }

    fn field(&mut self) -> Result<Field, ParseError> {
        let (ns, ns_span) = self.word("a namespace (req, resp, origin, call, tag, …)")?;
        let direct = match ns.as_str() {
            "origin" => Some(Field::Origin),
            "call" => Some(Field::Call),
            "tag" => Some(Field::Tag),
            "outcome" => Some(Field::Outcome),
            "fuzz" => Some(Field::Fuzz),
            "id" => Some(Field::Id),
            "session" => Some(Field::Session),
            "turn" => Some(Field::Turn),
            _ => None,
        };
        if let Some(f) = direct {
            if self.peek() == &Tok::Dot {
                return Err(self.err_here(format!("`{ns}` takes a value directly, not a field")));
            }
            return Ok(f);
        }
        if ns != "req" && ns != "resp" {
            return Err(ParseError::at(
                ns_span,
                format!(
                    "unknown namespace `{ns}`; expected req, resp, origin, call, tag, outcome, \
                     fuzz, id, session or turn"
                ),
            ));
        }
        if self.peek() != &Tok::Dot {
            let msg = format!(
                "expected `.` after `{ns}`, found {}",
                self.peek().describe()
            );
            return Err(self.err_here(msg));
        }
        self.bump();
        let (name, name_span) = self.word("a field")?;
        let header = |p: &mut Parser| -> Result<Option<String>, ParseError> {
            if p.peek() != &Tok::LBracket {
                return Ok(None);
            }
            p.bump();
            let h = match p.bump() {
                (Tok::Str(s), _) if !s.is_empty() => s,
                (_, sp) => return Err(ParseError::at(sp, "expected a quoted header name")),
            };
            if p.peek() != &Tok::RBracket {
                return Err(p.err_here("expected `]`"));
            }
            p.bump();
            Ok(Some(h))
        };
        let unknown = |list: &str| {
            ParseError::at(
                name_span,
                format!("unknown field `{ns}.{name}`; {ns} has {list}"),
            )
        };
        Ok(if ns == "req" {
            Field::Req(match name.as_str() {
                "method" => ReqField::Method,
                "host" => ReqField::Host,
                "port" => ReqField::Port,
                "path" => ReqField::Path,
                "query" => ReqField::Query,
                "ext" => ReqField::Ext,
                "tls" => ReqField::Tls,
                "len" => ReqField::Len,
                "created_at" => ReqField::CreatedAt,
                "header" => ReqField::Header(header(self)?),
                "body" => ReqField::Body,
                "raw" => ReqField::Raw,
                _ => {
                    return Err(unknown(
                        "method, host, port, path, query, ext, tls, len, created_at, header, \
                         body, raw",
                    ))
                }
            })
        } else {
            Field::Resp(match name.as_str() {
                "code" => RespField::Code,
                "len" => RespField::Len,
                "roundtrip" => RespField::Roundtrip,
                "ttfb" => RespField::Ttfb,
                "header" => RespField::Header(header(self)?),
                "body" => RespField::Body,
                "raw" => RespField::Raw,
                _ => return Err(unknown("code, len, roundtrip, ttfb, header, body, raw")),
            })
        })
    }

    fn op(&mut self) -> Result<(Op, Span), ParseError> {
        let (w, sp) = self.word("an operator (eq, ne, gt, gte, lt, lte, cont, like, regex, …)")?;
        let op = match w.as_str() {
            "eq" => Op::Eq,
            "ne" => Op::Ne,
            "gt" => Op::Gt,
            "gte" => Op::Gte,
            "lt" => Op::Lt,
            "lte" => Op::Lte,
            "cont" => Op::Cont,
            "ncont" => Op::Ncont,
            "like" => Op::Like,
            "nlike" => Op::Nlike,
            "regex" => Op::Regex,
            "nregex" => Op::Nregex,
            _ => {
                return Err(ParseError::at(
                    sp,
                    format!(
                        "unknown operator `{w}`; expected eq, ne, gt, gte, lt, lte, cont, ncont, \
                         like, nlike, regex or nregex"
                    ),
                ))
            }
        };
        Ok((op, sp))
    }

    fn value(&mut self, field: &Field, op: Op, op_span: Span) -> Result<Value, ParseError> {
        let kind = field.kind();
        let allowed: &[Op] = match kind {
            Kind::Str => &[
                Op::Eq,
                Op::Ne,
                Op::Cont,
                Op::Ncont,
                Op::Like,
                Op::Nlike,
                Op::Regex,
                Op::Nregex,
            ],
            Kind::Int | Kind::Time => &[Op::Eq, Op::Ne, Op::Gt, Op::Gte, Op::Lt, Op::Lte],
            Kind::Bool => &[Op::Eq, Op::Ne],
        };
        if !allowed.contains(&op) {
            let names: Vec<&str> = allowed.iter().map(|o| o.as_str()).collect();
            return Err(ParseError::at(
                op_span,
                format!(
                    "`{}` does not apply to a {} field; use {}",
                    op.as_str(),
                    kind_name(kind),
                    names.join(", ")
                ),
            ));
        }
        let (tok, sp) = self.bump();
        let mismatch =
            |want: &str| ParseError::at(sp, format!("expected {want}, found {}", tok.describe()));
        match kind {
            Kind::Int => match tok {
                Tok::Int(n) => Ok(Value::Int(n)),
                _ => Err(mismatch("a number")),
            },
            Kind::Bool => match &tok {
                Tok::Word(w) if w.eq_ignore_ascii_case("true") => Ok(Value::Bool(true)),
                Tok::Word(w) if w.eq_ignore_ascii_case("false") => Ok(Value::Bool(false)),
                _ => Err(mismatch("true or false")),
            },
            Kind::Time => {
                let text = match &tok {
                    Tok::RelTime(t) | Tok::Str(t) => t.clone(),
                    _ => {
                        return Err(mismatch(
                            "a time: RFC 3339 in quotes, or relative like -10m",
                        ))
                    }
                };
                crate::query::parse_time(&text)
                    .map(Value::Time)
                    .map_err(|e| ParseError::at(sp, e.to_string()))
            }
            Kind::Str => {
                let Tok::Str(s) = tok else {
                    return Err(mismatch("a quoted string"));
                };
                if matches!(op, Op::Regex | Op::Nregex) {
                    let compiled = regex::RegexBuilder::new(&s)
                        .size_limit(MAX_REGEX_BYTES)
                        .build()
                        .map_err(|e| ParseError::at(sp, format!("regex: {e}")))?;
                    return Ok(Value::Regex(Regex {
                        source: s,
                        compiled,
                    }));
                }
                check_str(field, op, &s).map_err(|m| ParseError::at(sp, m))?;
                Ok(Value::Str(s))
            }
        }
    }
}

/// Values a field cannot hold are errors, not empty results.
fn check_str(field: &Field, op: Op, s: &str) -> Result<(), String> {
    let exact = matches!(op, Op::Eq | Op::Ne);
    match field {
        Field::Req(ReqField::Ext) if exact && !s.starts_with('.') => {
            Err(format!("an extension starts with `.`: \".{s}\""))
        }
        Field::Origin if exact && !ORIGINS.contains(&s) => {
            Err(format!("origin is one of {}", ORIGINS.join(", ")))
        }
        Field::Outcome if exact && !OUTCOMES.contains(&s) => {
            Err(format!("outcome is one of {}", OUTCOMES.join(", ")))
        }
        _ => Ok(()),
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Str => "text",
        Kind::Int => "number",
        Kind::Bool => "true/false",
        Kind::Time => "time",
    }
}

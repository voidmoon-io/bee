use super::*;

fn ok(q: &str) -> Expr {
    parse(q)
        .unwrap_or_else(|e| panic!("{q:?}: {}", e.render(q)))
        .expect("non-empty")
}

fn err(q: &str) -> ParseError {
    match parse(q) {
        Err(e) => e,
        Ok(e) => panic!("{q:?} parsed: {e:?}"),
    }
}

fn clause(e: &Expr) -> &Clause {
    match e {
        Expr::Clause(c) => c,
        other => panic!("not a clause: {other:?}"),
    }
}

#[test]
fn a_clause_parses_with_its_types() {
    let c = ok(r#"req.host eq "api.example.com""#);
    let c = clause(&c);
    assert_eq!(c.field, Field::Req(ReqField::Host));
    assert_eq!(c.op, Op::Eq);
    assert_eq!(c.value, Value::Str("api.example.com".into()));
    assert_eq!(c.span, Span { start: 0, end: 29 });

    assert_eq!(clause(&ok("resp.code gte 500")).value, Value::Int(500));
    assert_eq!(clause(&ok("req.tls eq TRUE")).value, Value::Bool(true));
    assert_eq!(clause(&ok("turn eq 3")).field, Field::Turn);
}

#[test]
fn and_binds_tighter_than_or_and_not_tightest() {
    // a or b and not c  ==  a or (b and (not c))
    let e = ok(r#"origin eq "tool" or resp.code eq 200 and not tag eq "x""#);
    let Expr::Or(a, rest) = e else {
        panic!("top is not or")
    };
    assert_eq!(clause(&a).field, Field::Origin);
    let Expr::And(b, c) = *rest else {
        panic!("rhs is not and")
    };
    assert_eq!(clause(&b).field, Field::Resp(RespField::Code));
    assert!(matches!(*c, Expr::Not(_)));
}

#[test]
fn parentheses_and_keyword_case() {
    let e = ok(r#"(origin eq "fuzz" OR origin eq "replay") AnD resp.len GT 10"#);
    assert!(matches!(e, Expr::And(..)));
}

#[test]
fn headers_by_name_or_any() {
    let c = ok(r#"req.header["Content-Type"] cont "json""#);
    assert_eq!(
        clause(&c).field,
        Field::Req(ReqField::Header(Some("Content-Type".into())))
    );
    let c = ok(r#"resp.header cont "set-cookie""#);
    assert_eq!(clause(&c).field, Field::Resp(RespField::Header(None)));
    assert!(err(r#"req.header[] cont "x""#)
        .message
        .contains("header name"));
}

#[test]
fn a_bare_string_searches_both_raw_sides() {
    let c = ok(r#""Authorization""#);
    let c = clause(&c);
    assert_eq!(c.field, Field::AnyRaw);
    assert_eq!(c.op, Op::Cont);
    assert!(c.field.needs_response());
}

#[test]
fn comments_are_ignored() {
    let e = ok("// recent errors\nresp.code gte 500 /* server side */ and # and slow\n resp.roundtrip gt 2000");
    assert!(matches!(e, Expr::And(..)));
    assert!(parse("  // nothing here\n").unwrap().is_none());
    assert!(parse("").unwrap().is_none());
}

#[test]
fn strings_unescape() {
    let c = ok(r#"req.body cont "a\"b\\c\n\u{1F41D}""#);
    assert_eq!(clause(&c).value, Value::Str("a\"b\\c\n🐝".into()));
    let c = ok("req.path eq '/it'");
    assert_eq!(clause(&c).value, Value::Str("/it".into()));
    assert!(err(r#"req.body cont "\q""#)
        .message
        .contains("unknown escape"));
    assert!(err(r#"req.body cont "open"#).message.contains("unclosed"));
}

#[test]
fn times_are_relative_or_rfc3339() {
    assert!(matches!(
        clause(&ok("req.created_at gt -10m")).value,
        Value::Time(_)
    ));
    let c = ok(r#"req.created_at lte "2026-11-09T12:00:00+02:00""#);
    assert_eq!(
        clause(&c).value,
        Value::Time("2026-11-09T10:00:00.000000Z".into())
    );
    assert!(err(r#"req.created_at gt "yesterday""#)
        .message
        .contains("time"));
}

#[test]
fn regexes_compile_at_parse_time() {
    let c = ok(r#"req.body regex "\"role\"\\s*:""#);
    let Value::Regex(r) = &clause(&c).value else {
        panic!("not a regex")
    };
    assert!(r.compiled.is_match(r#"{"role" : "admin"}"#));
    assert!(err(r#"req.body regex "(unclosed""#)
        .message
        .starts_with("regex:"));
    // Over the size limit.
    assert!(err(r#"req.body regex "(\\w{1000}){1000}""#)
        .message
        .starts_with("regex:"));
}

#[test]
fn operators_must_fit_the_field_type() {
    let e = err(r#"resp.code cont "50""#);
    assert!(
        e.message.contains("does not apply to a number field"),
        "{}",
        e.message
    );
    assert!(err("req.host gt 3")
        .message
        .contains("does not apply to a text field"));
    assert!(err("req.tls cont true").message.contains("true/false"));
    assert!(err("resp.code eq \"500\"")
        .message
        .contains("expected a number"));
    assert!(err("req.host eq api")
        .message
        .contains("expected a quoted string"));
}

#[test]
fn closed_value_sets_are_checked() {
    assert!(err(r#"req.ext eq "php""#)
        .message
        .contains("starts with `.`"));
    ok(r#"req.ext eq ".php""#);
    ok(r#"req.ext cont "ph""#);
    assert!(err(r#"origin eq "tools""#)
        .message
        .contains("origin is one of"));
    assert!(err(r#"outcome eq "ok""#)
        .message
        .contains("outcome is one of"));
}

#[test]
fn unknown_names_say_what_exists() {
    let e = err(r#"request.host eq "x""#);
    assert!(
        e.message.contains("unknown namespace `request`"),
        "{}",
        e.message
    );
    let e = err(r#"req.hots eq "x""#);
    assert!(
        e.message.contains("unknown field `req.hots`"),
        "{}",
        e.message
    );
    assert!(e.message.contains("host"));
    assert_eq!(e.span, Span { start: 4, end: 8 });
    assert!(err(r#"req.host equals "x""#)
        .message
        .contains("unknown operator"));
    assert!(err(r#"origin.kind eq "tool""#)
        .message
        .contains("takes a value directly"));
}

#[test]
fn structure_errors_point_at_the_problem() {
    let q = r#"req.host eq "a" req.port eq 1"#;
    let e = err(q);
    assert!(e.message.contains("expected `and`, `or`"), "{}", e.message);
    assert_eq!(e.span.start, 16);
    assert!(
        e.render(q).ends_with(&format!("{}^^^", " ".repeat(18))),
        "{}",
        e.render(q)
    );
    assert!(err(r#"(req.host eq "a""#).message.contains("expected `)`"));
    assert!(err(r#"req.host eq "a")"#).message.contains("unmatched `)`"));
    assert!(err("req.host eq").message.contains("the end of the query"));
    assert!(err(r#"req.port eq 80x"#)
        .message
        .contains("quote the value"));
}

#[test]
fn queries_are_bounded() {
    let long = format!(r#"req.body cont "{}""#, "a".repeat(MAX_QUERY_LEN));
    assert!(err(&long).message.contains("longer than"));
    let deep = format!(
        "{}turn eq 1{}",
        "(".repeat(MAX_DEPTH + 1),
        ")".repeat(MAX_DEPTH + 1)
    );
    assert!(err(&deep).message.contains("nested deeper"));
    let nots = format!("{}turn eq 1", "not ".repeat(MAX_DEPTH + 1));
    assert!(err(&nots).message.contains("nested deeper"));
    let many = vec!["turn eq 1"; MAX_CLAUSES + 1].join(" and ");
    assert!(err(&many).message.contains("clauses"));
    let fine = vec!["turn eq 1"; MAX_CLAUSES].join(" or ");
    ok(&fine);
}

#[test]
fn every_field_is_reachable() {
    for q in [
        r#"req.method eq "GET""#,
        r#"req.host eq "a""#,
        "req.port eq 443",
        r#"req.path like "/api/%""#,
        r#"req.query cont "id=""#,
        r#"req.ext eq ".js""#,
        "req.tls eq false",
        "req.len lt 100",
        "req.created_at gte -1d",
        r#"req.header cont "x""#,
        r#"req.body ncont "x""#,
        r#"req.raw nlike "%x%""#,
        "resp.code ne 200",
        "resp.len gt 0",
        "resp.roundtrip gt 1",
        "resp.ttfb lte 5",
        r#"resp.header["server"] eq "nginx""#,
        r#"resp.body nregex "^\\s*$""#,
        r#"resp.raw cont "x""#,
        r#"origin eq "forwarded""#,
        r#"call eq "toolu_01""#,
        r#"tag cont "base""#,
        r#"outcome eq "refused""#,
        r#"fuzz eq "F1""#,
        r#"id eq "E1""#,
        r#"session eq "s""#,
        "turn gt 2",
    ] {
        ok(q);
    }
}

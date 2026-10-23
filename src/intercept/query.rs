//! `http_history` filters → parameterised SQL over the store's indexes (019 T057, research R11).
//!
//! Every field is optional and the fields AND together; a list field ORs its values. Unknown keys
//! are an error naming the key (`deny_unknown_fields`) — a typo'd filter must not silently match
//! everything. No value is ever spliced into the SQL text: every one is a bound parameter.

use rusqlite::types::Value as SqlValue;
use serde::Deserialize;

use super::control::format_ts;
use super::store::{Store, StoreError};

/// Most rows one query returns.
pub const MAX_LIMIT: u32 = 200;

/// A single value or a list of them.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// The `http_history` argument (contracts/http-tools.md#http_history).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryFilter {
    pub host: Option<OneOrMany<String>>,
    pub method: Option<OneOrMany<String>>,
    pub path_prefix: Option<String>,
    pub status: Option<OneOrMany<u16>>,
    pub status_range: Option<[u16; 2]>,
    pub min_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    /// RFC 3339, or relative: `-30s`, `-10m`, `-2h`, `-1d`.
    pub since: Option<String>,
    pub until: Option<String>,
    pub call_id: Option<String>,
    pub turn: Option<u32>,
    /// `tool`, `replay`, `fuzz`, `forwarded`.
    pub origin: Option<OneOrMany<String>>,
    pub tags: Option<OneOrMany<String>>,
    /// `completed`, `refused`, `failed`, `truncated`.
    pub outcome: Option<OneOrMany<String>>,
    pub limit: Option<u32>,
    /// `newest` (default) or `oldest`.
    pub order: Option<String>,
    /// Include earlier sessions' exchanges in this project's store (default: this session only).
    pub all_sessions: Option<bool>,
}

/// One compact row.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Row {
    pub id: String,
    pub t: String,
    pub method: Option<String>,
    pub host: String,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub resp_bytes: Option<u64>,
    pub ms: Option<u64>,
    pub origin: String,
    pub call_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HistoryResult {
    pub total_matched: u64,
    pub returned: usize,
    pub rows: Vec<Row>,
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid filter: {0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for QueryError {
    fn from(e: rusqlite::Error) -> Self {
        QueryError::Store(e.into())
    }
}

/// Run `f` against the store.
pub fn history(store: &Store, f: &HistoryFilter) -> Result<HistoryResult, QueryError> {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();
    let mut push = |clause: String, mut values: Vec<SqlValue>, params: &mut Vec<SqlValue>| {
        clauses.push(clause);
        params.append(&mut values);
    };
    let list = |n: usize| vec!["?"; n].join(", ");

    if !f.all_sessions.unwrap_or(false) {
        push(
            "session_id = ?".into(),
            vec![SqlValue::Text(store.session_id().to_string())],
            &mut params,
        );
    }
    if let Some(h) = &f.host {
        let v = h.to_vec();
        push(
            format!("lower(host) IN ({})", list(v.len())),
            v.into_iter()
                .map(|x| SqlValue::Text(bee_core::pattern::normalize_host(&x)))
                .collect(),
            &mut params,
        );
    }
    if let Some(m) = &f.method {
        let v = m.to_vec();
        push(
            format!("upper(method) IN ({})", list(v.len())),
            v.into_iter()
                .map(|x| SqlValue::Text(x.to_ascii_uppercase()))
                .collect(),
            &mut params,
        );
    }
    if let Some(p) = &f.path_prefix {
        push(
            "substr(path, 1, ?) = ?".into(),
            vec![SqlValue::Integer(p.len() as i64), SqlValue::Text(p.clone())],
            &mut params,
        );
    }
    if let Some(s) = &f.status {
        let v = s.to_vec();
        push(
            format!("status IN ({})", list(v.len())),
            v.into_iter().map(|x| SqlValue::Integer(x.into())).collect(),
            &mut params,
        );
    }
    if let Some([lo, hi]) = f.status_range {
        if lo > hi {
            return Err(QueryError::Invalid("status_range low > high".into()));
        }
        push(
            "status BETWEEN ? AND ?".into(),
            vec![SqlValue::Integer(lo.into()), SqlValue::Integer(hi.into())],
            &mut params,
        );
    }
    if let Some(n) = f.min_bytes {
        push(
            "resp_bytes >= ?".into(),
            vec![SqlValue::Integer(n as i64)],
            &mut params,
        );
    }
    if let Some(n) = f.max_bytes {
        push(
            "resp_bytes <= ?".into(),
            vec![SqlValue::Integer(n as i64)],
            &mut params,
        );
    }
    if let Some(s) = &f.since {
        push(
            "started >= ?".into(),
            vec![SqlValue::Text(parse_time(s)?)],
            &mut params,
        );
    }
    if let Some(s) = &f.until {
        push(
            "started <= ?".into(),
            vec![SqlValue::Text(parse_time(s)?)],
            &mut params,
        );
    }
    if let Some(c) = &f.call_id {
        push(
            "call_id = ?".into(),
            vec![SqlValue::Text(c.clone())],
            &mut params,
        );
    }
    if let Some(t) = f.turn {
        push(
            "turn = ?".into(),
            vec![SqlValue::Integer(t.into())],
            &mut params,
        );
    }
    if let Some(o) = &f.origin {
        let v = o.to_vec();
        for x in &v {
            if !["tool", "replay", "fuzz", "forwarded"].contains(&x.as_str()) {
                return Err(QueryError::Invalid(format!("unknown origin `{x}`")));
            }
        }
        push(
            format!("origin_kind IN ({})", list(v.len())),
            v.into_iter().map(SqlValue::Text).collect(),
            &mut params,
        );
    }
    if let Some(t) = &f.tags {
        // Tags are a JSON array of strings; match the quoted element.
        let v = t.to_vec();
        let ors = vec!["instr(tags, ?) > 0"; v.len()].join(" OR ");
        push(
            format!("({ors})"),
            v.into_iter()
                .map(|x| SqlValue::Text(serde_json::to_string(&x).unwrap_or_default()))
                .collect(),
            &mut params,
        );
    }
    if let Some(o) = &f.outcome {
        let v = o.to_vec();
        let mut ors = Vec::new();
        let mut vals = Vec::new();
        for x in v {
            if !["completed", "refused", "failed", "truncated"].contains(&x.as_str()) {
                return Err(QueryError::Invalid(format!("unknown outcome `{x}`")));
            }
            ors.push("substr(outcome, 1, ?) = ?");
            vals.push(SqlValue::Integer(x.len() as i64));
            vals.push(SqlValue::Text(x));
        }
        push(format!("({})", ors.join(" OR ")), vals, &mut params);
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    let order = match f.order.as_deref() {
        None | Some("newest") => "DESC",
        Some("oldest") => "ASC",
        Some(o) => return Err(QueryError::Invalid(format!("unknown order `{o}`"))),
    };
    let limit = f.limit.unwrap_or(50).clamp(1, MAX_LIMIT);

    let conn = store.conn();
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM exchanges {where_sql}"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let sql = format!(
        "SELECT id, started, method, host, path, status, resp_bytes, total_ms, origin_kind,
                call_id, tags, outcome
         FROM exchanges {where_sql}
         ORDER BY started {order}, seq {order} LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(Row {
                id: r.get(0)?,
                t: r.get(1)?,
                method: r.get(2)?,
                host: r.get(3)?,
                path: r.get(4)?,
                status: r.get(5)?,
                resp_bytes: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                ms: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                origin: r.get(8)?,
                call_id: r.get(9)?,
                tags: r
                    .get::<_, Option<String>>(10)?
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default(),
                outcome: r.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HistoryResult {
        total_matched: total as u64,
        returned: rows.len(),
        rows,
    })
}

/// An RFC 3339 time or a relative one (`-30s`, `-10m`, `-2h`, `-1d`), as the store's text format.
pub fn parse_time(s: &str) -> Result<String, QueryError> {
    let now = time::OffsetDateTime::now_utc();
    if let Some(rel) = s.strip_prefix('-') {
        let (num, unit) = rel.split_at(rel.len().saturating_sub(1));
        let n: i64 = num
            .parse()
            .map_err(|_| QueryError::Invalid(format!("bad relative time `{s}`")))?;
        let secs = match unit {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86_400,
            _ => return Err(QueryError::Invalid(format!("bad relative time `{s}`"))),
        };
        return Ok(format_ts(now - time::Duration::seconds(secs)));
    }
    // Absolute: anything RFC 3339; normalised to the store's fixed-width format by hand, since the
    // `time` crate here carries formatting only.
    normalise_rfc3339(s)
        .ok_or_else(|| QueryError::Invalid(format!("bad time `{s}` (RFC 3339 or -N[smhd])")))
}

/// Accept `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`; return it as UTC in the store format.
fn normalise_rfc3339(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    let mut micros = 0i64;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let frac = &s[start..j];
        let six: String = frac.chars().chain(std::iter::repeat('0')).take(6).collect();
        micros = six.parse().ok()?;
        i = j;
    }
    let offset_secs = match b.get(i)? {
        b'Z' | b'z' => 0,
        b'+' | b'-' => {
            let sign = if b[i] == b'-' { -1 } else { 1 };
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    let month = time::Month::try_from(mo as u8).ok()?;
    let date = time::Date::from_calendar_date(y as i32, month, d as u8).ok()?;
    let t = time::Time::from_hms_micro(h as u8, mi as u8, se as u8, micros as u32).ok()?;
    let dt = time::PrimitiveDateTime::new(date, t)
        .assume_utc()
        .checked_sub(time::Duration::seconds(offset_secs))?;
    Some(format_ts(dt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_times_normalise_to_utc() {
        assert_eq!(
            normalise_rfc3339("2026-10-10T12:00:00Z").unwrap(),
            "2026-10-10T12:00:00.000000Z"
        );
        assert_eq!(
            normalise_rfc3339("2026-10-10T12:00:00.5+02:00").unwrap(),
            "2026-10-10T10:00:00.500000Z"
        );
        assert!(normalise_rfc3339("yesterday").is_none());
    }

    #[test]
    fn relative_times_parse() {
        assert!(parse_time("-10m").is_ok());
        assert!(parse_time("-2h").is_ok());
        assert!(parse_time("-3x").is_err());
    }

    #[test]
    fn unknown_filter_keys_are_refused() {
        let e = serde_json::from_value::<HistoryFilter>(serde_json::json!({"hostt": "x"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("hostt"), "{e}");
    }
}

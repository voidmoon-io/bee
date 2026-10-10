//! Fuzz templates, payload sets and clustering (019 US6, research R15).
//!
//! A template is a raw request with positions marked by a delimiter (`§` by default): `§…§` marks a
//! position, and its content is the position's default. Four modes expand it:
//! - `sniper`: one payload set; each position in turn takes each payload, the rest keep defaults;
//! - `battering_ram`: one set; every position takes the same payload at once;
//! - `pitchfork`: one set per position, walked in lock-step;
//! - `cluster_bomb`: one set per position, every combination.
//!
//! The planned count is computed **before** anything is expanded or sent, and a run over the policy's
//! `max_requests_per_run` is refused outright (FR-021). Results come back clustered: the model sees
//! the groups and the outliers, never a thousand rows.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A source of payloads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadSet {
    /// A list bee ships: `sqli-basic`, `xss-basic`, `path-traversal`, `common-paths`.
    Builtin(String),
    Range {
        from: i64,
        to: i64,
        #[serde(default = "one")]
        step: i64,
    },
    Inline(Vec<String>),
    /// A file in the project, read through the tool scope — never by the harness (016 rule).
    ProjectFile(String),
}

fn one() -> i64 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

/// The built-in lists.
pub fn builtin(name: &str) -> Option<&'static str> {
    Some(match name {
        "sqli-basic" => include_str!("payloads/sqli-basic.txt"),
        "xss-basic" => include_str!("payloads/xss-basic.txt"),
        "path-traversal" => include_str!("payloads/path-traversal.txt"),
        "common-paths" => include_str!("payloads/common-paths.txt"),
        _ => return None,
    })
}

/// Largest payload file, in bytes and lines.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_FILE_LINES: usize = 100_000;

/// Lines of a payload file, within the limits (`Err` names the one exceeded).
pub fn file_lines(text: &str) -> Result<Vec<String>, String> {
    if text.len() > MAX_FILE_BYTES {
        return Err(format!("payload file exceeds {MAX_FILE_BYTES} bytes"));
    }
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    if lines.len() > MAX_FILE_LINES {
        return Err(format!("payload file exceeds {MAX_FILE_LINES} lines"));
    }
    Ok(lines)
}

/// The values of a non-file set.
pub fn expand_set(set: &PayloadSet) -> Result<Vec<String>, String> {
    Ok(match set {
        PayloadSet::Builtin(n) => builtin(n)
            .ok_or_else(|| format!("no builtin payload list `{n}` (sqli-basic, xss-basic, path-traversal, common-paths)"))?
            .lines()
            .map(str::to_string)
            .collect(),
        PayloadSet::Range { from, to, step } => {
            if *step == 0 || (to - from).signum() * step.signum() < 0 {
                return Err("range step must move from `from` toward `to`".into());
            }
            let n = (to - from) / step + 1;
            if n > MAX_FILE_LINES as i64 {
                return Err(format!("range of {n} values exceeds {MAX_FILE_LINES}"));
            }
            (0..n).map(|i| (from + i * step).to_string()).collect()
        }
        PayloadSet::Inline(v) => v.clone(),
        PayloadSet::ProjectFile(_) => return Err("project files are read by the caller".into()),
    })
}

/// A template split at its marked positions: `parts[0] pos0 parts[1] pos1 … parts[n]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub parts: Vec<String>,
    pub defaults: Vec<String>,
}

impl Template {
    pub fn parse(text: &str, marker: char) -> Result<Template, String> {
        let pieces: Vec<&str> = text.split(marker).collect();
        if pieces.len() < 3 {
            return Err(format!(
                "the template marks no position (wrap one in {marker}…{marker})"
            ));
        }
        if pieces.len().is_multiple_of(2) {
            return Err(format!("unbalanced {marker} markers in the template"));
        }
        let mut parts = Vec::new();
        let mut defaults = Vec::new();
        for (i, p) in pieces.iter().enumerate() {
            if i % 2 == 0 {
                parts.push((*p).to_string());
            } else {
                defaults.push((*p).to_string());
            }
        }
        Ok(Template { parts, defaults })
    }

    pub fn positions(&self) -> usize {
        self.defaults.len()
    }

    fn render(&self, values: &[&str]) -> String {
        let mut s = String::new();
        for (i, part) in self.parts.iter().enumerate() {
            s.push_str(part);
            if let Some(v) = values.get(i) {
                s.push_str(v);
            }
        }
        s
    }
}

/// How many requests a run would send. Computed before expansion so a huge run is refused cheaply.
pub fn planned(mode: Mode, positions: usize, sets: &[Vec<String>]) -> Result<u64, String> {
    let lens: Vec<u64> = sets.iter().map(|s| s.len() as u64).collect();
    match mode {
        Mode::Sniper | Mode::BatteringRam if sets.len() != 1 => {
            Err(format!("{mode:?} takes exactly one payload set"))
        }
        Mode::Sniper => Ok(lens[0] * positions as u64),
        Mode::BatteringRam => Ok(lens[0]),
        Mode::Pitchfork | Mode::ClusterBomb if sets.len() != positions => Err(format!(
            "{mode:?} takes one payload set per position ({positions} positions, {} sets)",
            sets.len()
        )),
        Mode::Pitchfork => Ok(lens.iter().copied().min().unwrap_or(0)),
        Mode::ClusterBomb => Ok(lens.iter().fold(1u64, |a, b| a.saturating_mul(*b))),
    }
}

/// One variant: its request text and the payload(s) it carries.
pub struct Variant {
    pub text: String,
    pub payloads: Vec<String>,
}

/// Expand. Call only after [`planned`] was checked against the limit.
pub fn expand(t: &Template, mode: Mode, sets: &[Vec<String>]) -> Vec<Variant> {
    let d: Vec<&str> = t.defaults.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    match mode {
        Mode::Sniper => {
            for pos in 0..t.positions() {
                for p in &sets[0] {
                    let mut v = d.clone();
                    v[pos] = p;
                    out.push(Variant {
                        text: t.render(&v),
                        payloads: vec![p.clone()],
                    });
                }
            }
        }
        Mode::BatteringRam => {
            for p in &sets[0] {
                let v = vec![p.as_str(); t.positions()];
                out.push(Variant {
                    text: t.render(&v),
                    payloads: vec![p.clone()],
                });
            }
        }
        Mode::Pitchfork => {
            let n = sets.iter().map(Vec::len).min().unwrap_or(0);
            for i in 0..n {
                let v: Vec<&str> = sets.iter().map(|s| s[i].as_str()).collect();
                out.push(Variant {
                    text: t.render(&v),
                    payloads: v.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
        Mode::ClusterBomb => {
            let mut idx = vec![0usize; sets.len()];
            if sets.iter().any(Vec::is_empty) {
                return out;
            }
            loop {
                let v: Vec<&str> = idx
                    .iter()
                    .enumerate()
                    .map(|(k, &i)| sets[k][i].as_str())
                    .collect();
                out.push(Variant {
                    text: t.render(&v),
                    payloads: v.iter().map(|s| s.to_string()).collect(),
                });
                let mut k = sets.len();
                loop {
                    if k == 0 {
                        return out;
                    }
                    k -= 1;
                    idx[k] += 1;
                    if idx[k] < sets[k].len() {
                        break;
                    }
                    idx[k] = 0;
                }
            }
        }
    }
    out
}

/// Fix `Content-Length` after substitution changed the body's length; a template's head defines the
/// framing, and a payload in the body must not leave it lying.
pub fn fix_length(raw: &str) -> Vec<u8> {
    let (sep, idx) = match (raw.find("\r\n\r\n"), raw.find("\n\n")) {
        (Some(a), Some(b)) if b < a => ("\n\n", b),
        (Some(a), _) => ("\r\n\r\n", a),
        (None, Some(b)) => ("\n\n", b),
        (None, None) => return raw.as_bytes().to_vec(),
    };
    let head = &raw[..idx];
    let body = &raw[idx + sep.len()..];
    let eol = if sep == "\r\n\r\n" { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = head.split(eol).map(str::to_string).collect();
    for l in lines.iter_mut().skip(1) {
        if let Some((k, _)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                *l = format!("{}: {}", k, body.len());
            }
        }
    }
    let mut out = lines.join(eol);
    out.push_str(sep);
    out.push_str(body);
    out.into_bytes()
}

// ── clustering ───────────────────────────────────────────────────────────────────────────────────

/// One variant's response, as clustering sees it.
pub struct Observed {
    pub exchange_id: String,
    pub status: Option<u16>,
    pub body: Vec<u8>,
    pub elapsed_ms: u64,
    pub payloads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GroupKey {
    pub status: Option<u16>,
    pub length_bucket: u64,
    pub word_bucket: u64,
    pub reflected: bool,
    pub slow: bool,
}

/// Group `obs` per research R15 and render the bounded summary.
pub fn cluster(run_id: &str, obs: &[Observed]) -> Value {
    if obs.is_empty() {
        return json!({ "run_id": run_id, "groups": [], "omitted_groups": 0 });
    }
    let median = |mut v: Vec<u64>| -> u64 {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let lens: Vec<u64> = obs.iter().map(|o| o.body.len() as u64).collect();
    let words: Vec<u64> = obs
        .iter()
        .map(|o| String::from_utf8_lossy(&o.body).split_whitespace().count() as u64)
        .collect();
    let times: Vec<u64> = obs.iter().map(|o| o.elapsed_ms).collect();
    let med_len = median(lens.clone());
    let med_words = median(words.clone());
    let med_t = median(times.clone());
    let mad = median(times.iter().map(|t| t.abs_diff(med_t)).collect());
    let len_w = (med_len / 50).max(16);
    let word_w = (med_words / 50).max(1);
    let slow_at = med_t + 3 * mad.max(1);

    let mut groups: BTreeMap<GroupKey, Vec<&Observed>> = BTreeMap::new();
    for (i, o) in obs.iter().enumerate() {
        let text = String::from_utf8_lossy(&o.body);
        let reflected = o.payloads.iter().any(|p| {
            !p.is_empty()
                && (text.contains(p.as_str())
                    || text.contains(&url_decode(p))
                    || text.contains(&html_escape(p)))
        });
        let key = GroupKey {
            status: o.status,
            length_bucket: lens[i] / len_w,
            word_bucket: words[i] / word_w,
            reflected,
            slow: times[i] > slow_at,
        };
        groups.entry(key).or_default().push(o);
    }
    let threshold = ((obs.len() as f64) * 0.005).ceil().max(1.0) as usize;
    let mut list: Vec<(GroupKey, Vec<&Observed>)> = groups.into_iter().collect();
    list.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let render = |(k, g): &(GroupKey, Vec<&Observed>)| {
        json!({
            "key": k,
            "size": g.len(),
            "outlier": g.len() <= threshold,
            "samples": g.iter().take(3).map(|o| json!({
                "id": o.exchange_id,
                "payload": o.payloads.join(" | ").chars().take(80).collect::<String>(),
            })).collect::<Vec<_>>(),
        })
    };
    let outliers: Vec<Value> = list
        .iter()
        .filter(|(_, g)| g.len() <= threshold)
        .map(render)
        .collect();
    let common: Vec<Value> = list
        .iter()
        .filter(|(_, g)| g.len() > threshold)
        .take(5)
        .map(render)
        .collect();
    let shown = outliers.len().min(60) + common.len();
    json!({
        "run_id": run_id,
        "variants": obs.len(),
        "outlier_threshold": threshold,
        "outliers": outliers.into_iter().take(60).collect::<Vec<_>>(),
        "common": common,
        "omitted_groups": list.len().saturating_sub(shown),
    })
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Template {
        Template::parse("GET /item?id=§1§&x=§a§ HTTP/1.1\r\n\r\n", '§').unwrap()
    }

    #[test]
    fn modes_count_and_expand() {
        let set = vec!["p".to_string(), "q".to_string()];
        assert_eq!(
            planned(Mode::Sniper, 2, std::slice::from_ref(&set)).unwrap(),
            4
        );
        assert_eq!(
            planned(Mode::BatteringRam, 2, std::slice::from_ref(&set)).unwrap(),
            2
        );
        assert_eq!(
            planned(Mode::Pitchfork, 2, &[set.clone(), vec!["z".into()]]).unwrap(),
            1
        );
        assert_eq!(
            planned(Mode::ClusterBomb, 2, &[set.clone(), set.clone()]).unwrap(),
            4
        );
        assert!(planned(Mode::Pitchfork, 2, std::slice::from_ref(&set)).is_err());

        let v = expand(&t(), Mode::Sniper, std::slice::from_ref(&set));
        let texts: Vec<&str> = v.iter().map(|v| v.text.as_str()).collect();
        assert!(texts.contains(&"GET /item?id=p&x=a HTTP/1.1\r\n\r\n"));
        assert!(texts.contains(&"GET /item?id=1&x=q HTTP/1.1\r\n\r\n"));
        let cb = expand(&t(), Mode::ClusterBomb, &[set.clone(), set]);
        assert_eq!(cb.len(), 4);
    }

    #[test]
    fn a_template_needs_balanced_markers() {
        assert!(Template::parse("GET / HTTP/1.1", '§').is_err());
        assert!(Template::parse("GET /§a HTTP/1.1", '§').is_err());
    }

    #[test]
    fn substitution_fixes_content_length() {
        let out = fix_length("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nabcdef");
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("Content-Length: 6\r\n"));
    }

    #[test]
    fn the_odd_one_out_is_an_outlier() {
        let mut obs: Vec<Observed> = (0..400)
            .map(|i| Observed {
                exchange_id: format!("E{i}"),
                status: Some(200),
                body: format!("item {i}").into_bytes(),
                elapsed_ms: 5,
                payloads: vec![i.to_string()],
            })
            .collect();
        obs.push(Observed {
            exchange_id: "Ebad".into(),
            status: Some(500),
            body: b"SQL syntax error".to_vec(),
            elapsed_ms: 5,
            payloads: vec!["'".into()],
        });
        let v = cluster("r", &obs);
        let outliers = v["outliers"].as_array().unwrap();
        assert_eq!(outliers.len(), 1, "{v}");
        assert_eq!(outliers[0]["samples"][0]["id"], "Ebad");
    }
}

//! The in-scope file worker behind `read_file`, `edit_file`, `ensure_line`, `write_file` and
//! `list_directory`.
//!
//! Same seam as [`crate::search`]: the harness never opens a file itself (contracts/tool-contracts.md).
//! The tools in [`crate::tools::files`] exec `bee file-worker` through
//! [`crate::tools::exec::run_child`], so every open happens in a process that has joined the scope
//! cgroup and the LSM mediates it. The request travels on **stdin as JSON** ([`FileRequest`]), not
//! argv: the strings are arbitrary model text, possibly large, and argv is neither size-safe nor the
//! place for file contents.
//!
//! **Read** streams the file a line at a time, so a line range of a huge file costs one pass and
//! bounded memory. It stops on a line boundary at `max_bytes` and ends with a note saying which lines
//! were shown and the `offset` to continue from, instead of a mid-line byte cut. A file with a NUL in
//! its first block is refused as binary.
//!
//! **Write** truncates (or creates) the file and writes the content. **List** prints a directory's
//! entries one per line, sorted, with `/` after subdirectories.
//!
//! **Edits converge.** A request describes the state the file should be in, so repeating it is a
//! no-op reported as `unchanged`, never a second change — the property Ansible's `lineinfile` has.
//! [`ensure_line`] is that module's model: a line is present (replacing the last line a pattern
//! matches, or inserted) or absent.
//!
//! **Edit** is [`apply`], a pure function, so its rules are unit-tested without a process:
//! `old_string` must be non-empty, differ from `new_string`, and — unless `replace_all` — match
//! **exactly once**. Zero or several matches is refused with a message saying which, so the model can
//! widen its context and retry instead of silently editing the wrong place.
//!
//! Worker exit codes: 0 done, 1 refused by a rule (the message says which), 2 bad request or I/O
//! (including a kernel denial, which surfaces as `EACCES` from the open).

use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};

/// One worker request, tagged by `op`. Shared by the tools (which serialize it onto the worker's
/// stdin) and the worker (which parses it back).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FileRequest {
    Read(ReadRequest),
    Edit(EditRequest),
    Write(WriteRequest),
    List(ListRequest),
    EnsureLine(EnsureLineRequest),
}

/// Whether [`EnsureLineRequest::line`] (or what its pattern matches) should be in the file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineState {
    #[default]
    Present,
    Absent,
}

/// An `ensure_line` request, after Ansible's `lineinfile`. `regexp` (a regex) or `search_string`
/// (a substring) picks the lines it is about; without either, lines equal to `line` are.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnsureLineRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regexp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_string: Option<String>,
    #[serde(default)]
    pub state: LineState,
    /// Regex, or `EOF` (the default). The line goes after the last line it matches; EOF if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insert_after: Option<String>,
    /// Regex, or `BOF`. The line goes before the last line it matches; EOF if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insert_before: Option<String>,
    /// Create a missing file (`present` only). Without it a missing file is an error.
    #[serde(default)]
    pub create: bool,
}

/// A `write_file` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub path: String,
    #[serde(default)]
    pub content: String,
}

/// A `list_directory` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequest {
    pub path: String,
}

/// A `read_file` request. `offset` is the 1-based first line and `limit` the most lines to show;
/// `max_bytes` is set by the tool (never the model) so the worker cuts on a line boundary before the
/// harness's own byte cap would cut mid-line.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReadRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}

/// An `edit_file` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    pub path: String,
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: bool,
}

/// Why an edit was refused. Each variant renders as one actionable sentence for the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    EmptyOld,
    NoChange,
    /// `crlf`: the file has CRLF line endings but `old_string` spans an LF-only line break — the
    /// usual reason a correct-looking edit misses, so the message says so.
    NotFound {
        crlf: bool,
    },
    Ambiguous {
        count: usize,
    },
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOld => f.write_str("old_string is empty; use write_file to create a file"),
            Self::NoChange => f.write_str("old_string and new_string are identical; nothing to do"),
            Self::NotFound { crlf } => {
                f.write_str(
                    "old_string not found; it must match the file exactly, including whitespace",
                )?;
                if *crlf {
                    f.write_str(
                        " (this file uses CRLF line endings: write line breaks as \\r\\n)",
                    )?;
                }
                Ok(())
            }
            Self::Ambiguous { count } => write!(
                f,
                "old_string matches {count} times; add surrounding context to make it unique, \
                 or set replace_all"
            ),
        }
    }
}

/// What [`apply`] decided. `replaced == 0` means the edit was already applied: nothing to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub content: String,
    pub replaced: usize,
}

/// Apply the edit to `content`, **convergently**: the request describes a desired state, so repeating
/// it is a no-op rather than a second change.
///
/// An occurrence of `old_string` lying inside an occurrence of `new_string` is already converged
/// (`foo` → `foo(bar)` must not become `foo(bar)(bar)` on a repeat), so only the *pending*
/// occurrences count: exactly one is replaced, several are ambiguous unless `replace_all`, and none
/// is "already applied" when `new_string` is present (or empty — the text is already gone) and
/// "not found" otherwise. Uniqueness counts overlapping occurrences: `aa` in `aaa` is two sites, and
/// picking the first would be a silent guess.
pub fn apply(content: &str, req: &EditRequest) -> Result<Applied, EditError> {
    let (old, new) = (req.old_string.as_str(), req.new_string.as_str());
    if old.is_empty() {
        return Err(EditError::EmptyOld);
    }
    if old == new {
        return Err(EditError::NoChange);
    }
    let landed = occurrences(content, new);
    let pending: Vec<usize> = occurrences(content, old)
        .into_iter()
        .filter(|&at| {
            !landed
                .iter()
                .any(|&n| n <= at && at + old.len() <= n + new.len())
        })
        .collect();
    if pending.is_empty() {
        if new.is_empty() || !landed.is_empty() {
            return Ok(Applied {
                content: content.to_string(),
                replaced: 0,
            });
        }
        let crlf = content.contains("\r\n") && old.contains('\n') && !old.contains("\r\n");
        return Err(EditError::NotFound { crlf });
    }
    if !req.replace_all && pending.len() > 1 {
        return Err(EditError::Ambiguous {
            count: pending.len(),
        });
    }
    // Left to right, skipping a site that overlaps the one just replaced.
    let mut out = String::with_capacity(content.len());
    let (mut from, mut replaced) = (0, 0);
    for at in pending {
        if at < from {
            continue;
        }
        out.push_str(&content[from..at]);
        out.push_str(new);
        from = at + old.len();
        replaced += 1;
    }
    out.push_str(&content[from..]);
    Ok(Applied {
        content: out,
        replaced,
    })
}

/// Byte offsets of every occurrence of `needle` in `hay`, overlapping ones included. An empty
/// needle has none.
fn occurrences(hay: &str, needle: &str) -> Vec<usize> {
    let mut found = Vec::new();
    if needle.is_empty() {
        return found;
    }
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let at = from + i;
        found.push(at);
        from = at + hay[at..].chars().next().map_or(1, char::len_utf8);
    }
    found
}

/// The worker body: read the JSON request from `input`, act on it, report on `out` / `err`.
pub fn run(input: &mut impl Read, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let mut raw = String::new();
    if let Err(e) = input.read_to_string(&mut raw) {
        let _ = writeln!(err, "file-worker: reading request: {e}");
        return 2;
    }
    match serde_json::from_str(&raw) {
        Ok(FileRequest::Read(req)) => run_read(&req, out, err),
        Ok(FileRequest::Edit(req)) => run_edit(&req, out, err),
        Ok(FileRequest::Write(req)) => run_write(&req, out, err),
        Ok(FileRequest::List(req)) => run_list(&req, out, err),
        Ok(FileRequest::EnsureLine(req)) => run_ensure_line(&req, out, err),
        Err(e) => {
            let _ = writeln!(err, "file-worker: invalid request: {e}");
            2
        }
    }
}

fn run_read(req: &ReadRequest, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let file = match std::fs::File::open(&req.path) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(err, "read_file: {}: {e}", req.path);
            return 2;
        }
    };
    match read(io::BufReader::new(file), req, out) {
        Ok(()) => 0,
        Err(ReadError::Refused(why)) => {
            let _ = writeln!(err, "read_file: {}: {why}", req.path);
            1
        }
        Err(ReadError::Io(e)) => {
            let _ = writeln!(err, "read_file: {}: {e}", req.path);
            2
        }
    }
}

/// Why a read failed: a rule (bad range, binary file) or the I/O itself.
#[derive(Debug)]
pub enum ReadError {
    Refused(String),
    Io(io::Error),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Stream the requested lines of `reader` to `out` (invalid UTF-8 rendered lossily), then a
/// `[lines a-b of N …]` note whenever less than the whole file was shown. Nothing is written when
/// the request is refused.
pub fn read(
    mut reader: impl BufRead,
    req: &ReadRequest,
    out: &mut impl Write,
) -> Result<(), ReadError> {
    let first = req.offset.unwrap_or(1);
    let limit = req.limit.unwrap_or(usize::MAX);
    let budget = req.max_bytes.unwrap_or(usize::MAX);
    if first == 0 {
        return Err(ReadError::Refused(
            "offset is 1-based; use 1 for the first line".into(),
        ));
    }
    if limit == 0 {
        return Err(ReadError::Refused("limit must be at least 1".into()));
    }
    if fill(&mut reader)?.contains(&0) {
        return Err(ReadError::Refused(
            "binary file (NUL byte near the start); not shown".into(),
        ));
    }

    let mut line = Vec::new();
    let (mut seen, mut shown, mut used) = (0usize, 0usize, 0usize);
    let mut stopped = false;
    let mut ends_in_newline = true;
    // Set when the first wanted line alone exceeds the budget: its full length in bytes.
    let mut cut: Option<usize> = None;
    loop {
        let wanted = !stopped && seen + 1 >= first;
        let keep = if wanted {
            budget.saturating_sub(used).saturating_add(1)
        } else {
            0
        };
        let Some(len) = next_line(&mut reader, keep, &mut line)? else {
            break;
        };
        seen += 1;
        if !wanted {
            continue;
        }
        if shown == limit {
            stopped = true;
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        if len > line.len() || used + text.len() > budget {
            if shown == 0 {
                let mut end = budget.min(text.len());
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                out.write_all(text[..end].as_bytes())?;
                used = end;
                shown = 1;
                ends_in_newline = false;
                cut = Some(len);
            }
            stopped = true;
            continue;
        }
        out.write_all(text.as_bytes())?;
        used += text.len();
        shown += 1;
        ends_in_newline = text.ends_with('\n');
    }

    if shown == 0 {
        if first > 1 {
            return Err(ReadError::Refused(format!(
                "offset {first} is past the end of the file ({seen} lines)"
            )));
        }
        return Ok(());
    }
    let last = first + shown - 1;
    if first == 1 && last == seen && cut.is_none() {
        return Ok(());
    }
    if !ends_in_newline {
        out.write_all(b"\n")?;
    }
    let more = if last < seen {
        format!("; continue with offset={}", last + 1)
    } else {
        String::new()
    };
    match cut {
        Some(len) => writeln!(
            out,
            "[line {first} of {seen} cut: showing {used} of its {len} bytes{more}]"
        )?,
        None => writeln!(out, "[lines {first}-{last} of {seen}{more}]")?,
    }
    Ok(())
}

/// The reader's buffered head, retrying an interrupted fill.
fn fill(reader: &mut impl BufRead) -> io::Result<&[u8]> {
    loop {
        match reader.fill_buf() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Fill again to return: returning the first borrow from inside the loop does not compile.
            Ok(_) => return reader.fill_buf(),
            Err(e) => return Err(e),
        }
    }
}

/// Read one line (through its `\n`) from `reader`, keeping at most `keep` bytes of it in `line`.
/// Returns the line's full length, or `None` at end of file. Memory stays bounded by `keep` however
/// long the line is.
fn next_line(
    reader: &mut impl BufRead,
    keep: usize,
    line: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
    line.clear();
    let mut len = 0;
    loop {
        let chunk = fill(reader)?;
        if chunk.is_empty() {
            return Ok((len > 0).then_some(len));
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        let room = keep.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..take.min(room)]);
        len += take;
        reader.consume(take);
        if done {
            return Ok(Some(len));
        }
    }
}

/// What [`ensure_line`] did, as one line for the model, and the new content when it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineOutcome {
    pub content: Option<String>,
    pub summary: String,
}

/// Bring `content` to the state `req` describes. Lines keep their own terminators; an inserted line
/// takes the file's (`\r\n` if it has any, else `\n`).
///
/// - `present` with a pattern: the **last** matching line becomes `line` (unchanged if it already
///   is). With no match, or no pattern: unchanged if a line equal to `line` exists, else inserted.
/// - `absent`: every line the pattern matches — or, without one, every line equal to `line` — is
///   removed; unchanged if there are none.
pub fn ensure_line(content: &str, req: &EnsureLineRequest) -> Result<LineOutcome, String> {
    let rule = Rule::new(req)?;
    let eol = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut lines: Vec<&str> = content.split_inclusive('\n').collect();
    let text = |l: &str| {
        l.strip_suffix('\n')
            .map_or(l, |l| l.strip_suffix('\r').unwrap_or(l))
            .to_string()
    };
    let unchanged = |summary: String| {
        Ok(LineOutcome {
            content: None,
            summary,
        })
    };
    let changed = |lines: Vec<String>, summary: String| {
        Ok(LineOutcome {
            content: Some(lines.concat()),
            summary,
        })
    };

    if req.state == LineState::Absent {
        let before = lines.len();
        lines.retain(|l| !rule.selects(&text(l)));
        let removed = before - lines.len();
        if removed == 0 {
            return unchanged("no matching line; already absent".into());
        }
        let noun = if removed == 1 { "line" } else { "lines" };
        return changed(
            lines.iter().map(|l| l.to_string()).collect(),
            format!("removed {removed} {noun}"),
        );
    }

    let line = req.line.as_deref().expect("validated: present has a line");
    let last = |pred: &dyn Fn(&str) -> bool| lines.iter().rposition(|l| pred(&text(l)));
    if rule.pattern.is_some() {
        if let Some(i) = last(&|t| rule.matches(t)) {
            if text(lines[i]) == line {
                return unchanged(format!("line {} already matches", i + 1));
            }
            let mut owned: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
            let terminator = &lines[i][text(lines[i]).len()..];
            owned[i] = format!("{line}{terminator}");
            return changed(owned, format!("replaced line {}", i + 1));
        }
    }
    if let Some(i) = last(&|t| t == line) {
        return unchanged(format!("line {} already present", i + 1));
    }
    let at = match &rule.anchor {
        Anchor::Bof => 0,
        Anchor::Eof => lines.len(),
        Anchor::After(re) => last(&|t| re.is_match(t)).map_or(lines.len(), |i| i + 1),
        Anchor::Before(re) => last(&|t| re.is_match(t)).unwrap_or(lines.len()),
    };
    let mut owned: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    if at == owned.len() {
        if let Some(tail) = owned.last_mut().filter(|t| !t.ends_with('\n')) {
            tail.push_str(eol);
        }
    }
    owned.insert(at, format!("{line}{eol}"));
    changed(owned, format!("inserted at line {}", at + 1))
}

enum Pattern {
    Regex(regex::Regex),
    Substring(String),
}

enum Anchor {
    Bof,
    Eof,
    After(regex::Regex),
    Before(regex::Regex),
}

/// A validated [`EnsureLineRequest`]: which lines it is about, and where an insert goes.
struct Rule {
    pattern: Option<Pattern>,
    exact: Option<String>,
    anchor: Anchor,
}

impl Rule {
    fn new(req: &EnsureLineRequest) -> Result<Self, String> {
        let compile = |what: &str, re: &str| {
            regex::Regex::new(re).map_err(|e| format!("{what} is not a valid regex: {e}"))
        };
        if req.regexp.is_some() && req.search_string.is_some() {
            return Err("give regexp or search_string, not both".into());
        }
        if req.insert_after.is_some() && req.insert_before.is_some() {
            return Err("give insert_after or insert_before, not both".into());
        }
        if let Some(line) = &req.line {
            if line.contains(['\n', '\r']) {
                return Err(
                    "line must be a single line (no line breaks); use edit_file for blocks".into(),
                );
            }
        }
        let pattern = match (&req.regexp, &req.search_string) {
            (Some(re), _) => Some(Pattern::Regex(compile("regexp", re)?)),
            (_, Some(s)) if !s.is_empty() => Some(Pattern::Substring(s.clone())),
            (_, Some(_)) => return Err("search_string is empty".into()),
            _ => None,
        };
        match req.state {
            LineState::Present if req.line.is_none() => {
                return Err("state=present needs line".into())
            }
            LineState::Absent if pattern.is_none() && req.line.is_none() => {
                return Err("state=absent needs regexp, search_string or line".into())
            }
            LineState::Absent if req.insert_after.is_some() || req.insert_before.is_some() => {
                return Err("insert_after/insert_before apply only to state=present".into())
            }
            _ => {}
        }
        let anchor = match (&req.insert_after, &req.insert_before) {
            (Some(a), _) if a == "EOF" => Anchor::Eof,
            (Some(a), _) => Anchor::After(compile("insert_after", a)?),
            (_, Some(b)) if b == "BOF" => Anchor::Bof,
            (_, Some(b)) => Anchor::Before(compile("insert_before", b)?),
            _ => Anchor::Eof,
        };
        Ok(Self {
            pattern,
            exact: req.line.clone(),
            anchor,
        })
    }

    fn matches(&self, text: &str) -> bool {
        match &self.pattern {
            Some(Pattern::Regex(re)) => re.is_match(text),
            Some(Pattern::Substring(s)) => text.contains(s.as_str()),
            None => false,
        }
    }

    /// The lines `state=absent` removes: those the pattern matches, else those equal to `line`.
    fn selects(&self, text: &str) -> bool {
        match &self.pattern {
            Some(_) => self.matches(text),
            None => self.exact.as_deref() == Some(text),
        }
    }
}

fn run_ensure_line(req: &EnsureLineRequest, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let (content, exists) = match std::fs::read(&req.path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => (s, true),
            Err(_) => {
                let _ = writeln!(
                    err,
                    "ensure_line: {} is not valid UTF-8; refusing",
                    req.path
                );
                return 2;
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound && req.state == LineState::Absent => {
            let _ = writeln!(out, "unchanged {}: file does not exist", req.path);
            return 0;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && req.create => (String::new(), false),
        Err(e) => {
            let _ = writeln!(err, "ensure_line: {}: {e}", req.path);
            return 2;
        }
    };
    let outcome = match ensure_line(&content, req) {
        Ok(o) => o,
        Err(why) => {
            let _ = writeln!(err, "ensure_line: {why}");
            return 1;
        }
    };
    let Some(updated) = outcome.content else {
        let _ = writeln!(out, "unchanged {}: {}", req.path, outcome.summary);
        return 0;
    };
    let written = if exists {
        write_in_place(&req.path, updated.as_bytes())
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&req.path)
            .and_then(|mut f| f.write_all(updated.as_bytes()))
    };
    if let Err(e) = written {
        let _ = writeln!(err, "ensure_line: writing {}: {e}", req.path);
        return 2;
    }
    let created = if exists { "" } else { " (created the file)" };
    let _ = writeln!(out, "changed {}: {}{created}", req.path, outcome.summary);
    0
}

/// Truncate (or create) the file and write the content, as `tee` did.
fn run_write(req: &WriteRequest, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&req.path)
        .and_then(|mut f| {
            f.write_all(req.content.as_bytes())?;
            f.flush()
        });
    if let Err(e) = written {
        let _ = writeln!(err, "write_file: {}: {e}", req.path);
        return 2;
    }
    let _ = writeln!(out, "wrote {} bytes to {}", req.content.len(), req.path);
    0
}

/// A directory's entries (no `.`/`..`), one per line, byte-sorted, `/` after each subdirectory. A
/// symlink is listed as itself, not as what it points to.
fn run_list(req: &ListRequest, out: &mut impl Write, err: &mut impl Write) -> u8 {
    match list(&req.path) {
        Ok(entries) => {
            for entry in entries {
                let _ = writeln!(out, "{entry}");
            }
            0
        }
        Err(e) => {
            let _ = writeln!(err, "list_directory: {}: {e}", req.path);
            2
        }
    }
}

fn list(path: &str) -> io::Result<Vec<String>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_dir() {
            name.push('/');
        }
        entries.push(name);
    }
    entries.sort();
    Ok(entries)
}

/// Edit one file in place: read it whole (refusing non-UTF-8 rather than rewriting it lossily — an
/// edit must never corrupt bytes it was not asked to touch), [`apply`], write it back.
fn run_edit(req: &EditRequest, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let content = match std::fs::read(&req.path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                let _ = writeln!(err, "edit_file: {} is not valid UTF-8; refusing", req.path);
                return 2;
            }
        },
        Err(e) => {
            let _ = writeln!(err, "edit_file: {}: {e}", req.path);
            return 2;
        }
    };
    let applied = match apply(&content, req) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(err, "edit_file: {e}");
            return 1;
        }
    };
    if applied.replaced == 0 {
        let _ = writeln!(
            out,
            "unchanged {}: already applied (old_string is gone, new_string is in place)",
            req.path
        );
        return 0;
    }
    if let Err(e) = write_in_place(&req.path, applied.content.as_bytes()) {
        let _ = writeln!(err, "edit_file: writing {}: {e}", req.path);
        return 2;
    }
    let n = applied.replaced;
    let noun = if n == 1 {
        "replacement"
    } else {
        "replacements"
    };
    let _ = writeln!(out, "edited {}: {n} {noun}", req.path);
    0
}

/// Truncate-and-write the existing file, like `write_file`'s `tee`. Deliberately not temp+rename: that
/// needs create rights in the directory, which a scope granting only this file's write would deny.
fn write_in_place(path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(old: &str, new: &str, all: bool) -> EditRequest {
        EditRequest {
            path: "f".into(),
            old_string: old.into(),
            new_string: new.into(),
            replace_all: all,
        }
    }

    fn read_str(
        content: &[u8],
        offset: Option<usize>,
        limit: Option<usize>,
        max: Option<usize>,
    ) -> Result<String, String> {
        let req = ReadRequest {
            path: "f".into(),
            offset,
            limit,
            max_bytes: max,
        };
        let mut out = Vec::new();
        match read(content, &req, &mut out) {
            Ok(()) => Ok(String::from_utf8(out).unwrap()),
            Err(ReadError::Refused(why)) => {
                assert!(out.is_empty(), "a refusal writes nothing");
                Err(why)
            }
            Err(ReadError::Io(e)) => panic!("{e}"),
        }
    }

    #[test]
    fn a_whole_read_is_the_file_verbatim() {
        assert_eq!(read_str(b"a\nb\n", None, None, None).unwrap(), "a\nb\n");
        assert_eq!(
            read_str(b"a\nno newline", None, None, None).unwrap(),
            "a\nno newline"
        );
        assert_eq!(read_str(b"", None, None, None).unwrap(), "");
        assert_eq!(
            read_str(b"a\r\nb\r\n", None, None, None).unwrap(),
            "a\r\nb\r\n"
        );
    }

    #[test]
    fn a_line_range_says_where_it_sits() {
        let f = b"1\n2\n3\n4\n5\n";
        assert_eq!(
            read_str(f, Some(2), Some(2), None).unwrap(),
            "2\n3\n[lines 2-3 of 5; continue with offset=4]\n"
        );
        assert_eq!(
            read_str(f, Some(4), None, None).unwrap(),
            "4\n5\n[lines 4-5 of 5]\n"
        );
        assert_eq!(
            read_str(f, None, Some(1), None).unwrap(),
            "1\n[lines 1-1 of 5; continue with offset=2]\n"
        );
        assert_eq!(
            read_str(b"1\n2", Some(2), None, None).unwrap(),
            "2\n[lines 2-2 of 2]\n"
        );
    }

    #[test]
    fn the_byte_budget_cuts_on_a_line_boundary() {
        assert_eq!(
            read_str(b"aaa\nbbb\nccc\n", None, None, Some(9)).unwrap(),
            "aaa\nbbb\n[lines 1-2 of 3; continue with offset=3]\n"
        );
        assert_eq!(
            read_str(b"aaa\nbbb\n", None, None, Some(8)).unwrap(),
            "aaa\nbbb\n"
        );
    }

    #[test]
    fn an_overlong_first_line_shows_its_head() {
        assert_eq!(
            read_str(b"abcdefgh\nz\n", None, None, Some(4)).unwrap(),
            "abcd\n[line 1 of 2 cut: showing 4 of its 9 bytes; continue with offset=2]\n"
        );
        // Never split a UTF-8 character.
        assert_eq!(
            read_str("ééé".as_bytes(), None, None, Some(3)).unwrap(),
            "é\n[line 1 of 1 cut: showing 2 of its 6 bytes]\n"
        );
    }

    #[test]
    fn bad_ranges_and_binary_files_are_refused() {
        assert!(read_str(b"a\n", Some(0), None, None)
            .unwrap_err()
            .contains("1-based"));
        assert!(read_str(b"a\n", None, Some(0), None)
            .unwrap_err()
            .contains("at least 1"));
        assert!(read_str(b"a\nb\n", Some(3), None, None)
            .unwrap_err()
            .contains("past the end of the file (2 lines)"));
        assert!(read_str(b"ELF\0\0", None, None, None)
            .unwrap_err()
            .contains("binary"));
    }

    #[test]
    fn invalid_utf8_is_shown_lossily() {
        assert_eq!(
            read_str(b"ok \xff\n", None, None, None).unwrap(),
            "ok \u{fffd}\n"
        );
    }

    fn el(json: serde_json::Value) -> EnsureLineRequest {
        let mut v = json;
        v["path"] = "f".into();
        serde_json::from_value(v).unwrap()
    }

    /// Run `req` on `content`, expect `want` (None = unchanged), then check a repeat is unchanged.
    fn ensure(content: &str, req: serde_json::Value, want: Option<&str>) {
        let req = el(req);
        let first = ensure_line(content, &req).unwrap();
        assert_eq!(first.content.as_deref(), want, "{}", first.summary);
        let after = first.content.unwrap_or_else(|| content.to_string());
        let again = ensure_line(&after, &req).unwrap();
        assert_eq!(again.content, None, "repeat changed it: {}", again.summary);
    }

    #[test]
    fn ensure_line_present() {
        use serde_json::json as j;
        // Appended, with a newline added to an unterminated last line.
        ensure("a\nb\n", j!({"line": "c"}), Some("a\nb\nc\n"));
        ensure("a\nb", j!({"line": "c"}), Some("a\nb\nc\n"));
        ensure("", j!({"line": "c"}), Some("c\n"));
        // Already there.
        ensure("a\nc\n", j!({"line": "c"}), None);
        // The last regexp match is replaced, keeping its terminator.
        ensure(
            "port=1\nx\nport=2\r\n",
            j!({"line": "port=8080", "regexp": "^port="}),
            Some("port=1\nx\nport=8080\r\n"),
        );
        ensure(
            "#Port 22\n",
            j!({"line": "Port 2222", "search_string": "Port "}),
            Some("Port 2222\n"),
        );
        // No match: inserted after the last insert_after match, or before the last insert_before.
        ensure(
            "[a]\nk=1\n[b]\n",
            j!({"line": "z=9", "regexp": "^z=", "insert_after": "^k="}),
            Some("[a]\nk=1\nz=9\n[b]\n"),
        );
        ensure(
            "x\ny\n",
            j!({"line": "w", "insert_before": "^y"}),
            Some("x\nw\ny\n"),
        );
        ensure(
            "x\n",
            j!({"line": "w", "insert_before": "BOF"}),
            Some("w\nx\n"),
        );
        ensure(
            "x\n",
            j!({"line": "w", "insert_after": "^nomatch"}),
            Some("x\nw\n"),
        );
        // A CRLF file gets CRLF lines.
        ensure("a\r\n", j!({"line": "b"}), Some("a\r\nb\r\n"));
    }

    #[test]
    fn ensure_line_absent() {
        use serde_json::json as j;
        ensure(
            "a\nb\na\n",
            j!({"line": "a", "state": "absent"}),
            Some("b\n"),
        );
        ensure(
            "k=1\nk=2\nz\n",
            j!({"regexp": "^k=", "state": "absent"}),
            Some("z\n"),
        );
        ensure("z\n", j!({"search_string": "k=", "state": "absent"}), None);
    }

    #[test]
    fn ensure_line_refuses_contradictions() {
        use serde_json::json as j;
        for (req, why) in [
            (j!({}), "needs line"),
            (j!({"line": "a\nb"}), "single line"),
            (
                j!({"line": "a", "regexp": "x", "search_string": "y"}),
                "not both",
            ),
            (
                j!({"line": "a", "insert_after": "x", "insert_before": "y"}),
                "not both",
            ),
            (j!({"line": "a", "regexp": "("}), "not a valid regex"),
            (j!({"state": "absent"}), "needs regexp"),
            (
                j!({"state": "absent", "line": "a", "insert_after": "x"}),
                "only to state=present",
            ),
        ] {
            let err = ensure_line("", &el(req.clone())).unwrap_err();
            assert!(err.contains(why), "{req}: {err}");
        }
        let unknown = serde_json::from_value::<EnsureLineRequest>(j!({"path": "f", "lines": "a"}));
        assert!(unknown.is_err(), "a misspelled field must not be ignored");
    }

    #[test]
    fn a_unique_match_is_replaced() {
        assert_eq!(
            apply("let a = 1;\nlet b = 2;\n", &req("b = 2", "b = 3", false)),
            ok("let a = 1;\nlet b = 3;\n", 1)
        );
    }

    fn ok(content: &str, replaced: usize) -> Result<Applied, EditError> {
        Ok(Applied {
            content: content.into(),
            replaced,
        })
    }

    /// Applying the result of an edit again, with the same request, changes nothing.
    fn converges(content: &str, r: &EditRequest) {
        let once = apply(content, r).unwrap();
        assert!(once.replaced > 0, "first apply should change {content:?}");
        assert_eq!(
            apply(&once.content, r),
            ok(&once.content, 0),
            "repeat of {r:?}"
        );
    }

    #[test]
    fn a_repeated_edit_is_a_no_op() {
        converges("let b = 2;\n", &req("b = 2", "b = 3", false));
        // new_string contains old_string: the repeat must not wrap it twice.
        converges("call(foo);\n", &req("foo", "foo(bar)", false));
        converges("a a a", &req("a", "ab", true));
        // A deletion: once the text is gone there is nothing left to do.
        converges("keep\ndrop\n", &req("drop\n", "", false));
    }

    #[test]
    fn only_unconverged_sites_count() {
        // One `foo` is already `foo(bar)`; the other is the single pending site.
        assert_eq!(
            apply("foo(bar) foo", &req("foo", "foo(bar)", false)),
            ok("foo(bar) foo(bar)", 1)
        );
        assert_eq!(
            apply("foo foo foo(bar)", &req("foo", "foo(bar)", false)),
            Err(EditError::Ambiguous { count: 2 })
        );
    }

    #[test]
    fn no_match_is_refused() {
        assert_eq!(
            apply("abc", &req("xyz", "q", false)),
            Err(EditError::NotFound { crlf: false })
        );
    }

    #[test]
    fn overlapping_matches_are_ambiguous() {
        assert_eq!(
            apply("aaa", &req("aa", "X", false)),
            Err(EditError::Ambiguous { count: 2 })
        );
        assert_eq!(apply("aaa", &req("aa", "X", true)), ok("Xa", 1));
        assert_eq!(apply("é aé", &req("é", "e", true)), ok("e ae", 2));
    }

    #[test]
    fn an_lf_miss_in_a_crlf_file_says_so() {
        let e = apply("a\r\nb\r\n", &req("a\nb", "X", false)).unwrap_err();
        assert_eq!(e, EditError::NotFound { crlf: true });
        assert!(e.to_string().contains("CRLF"), "{e}");
        assert_eq!(
            apply("a\r\nb\r\n", &req("a\r\nb", "X", false)),
            ok("X\r\n", 1)
        );
    }

    #[test]
    fn several_matches_are_refused_without_replace_all() {
        assert_eq!(
            apply("x x x", &req("x", "y", false)),
            Err(EditError::Ambiguous { count: 3 })
        );
    }

    #[test]
    fn replace_all_replaces_every_match() {
        assert_eq!(apply("x x x", &req("x", "y", true)), ok("y y y", 3));
    }

    #[test]
    fn empty_and_identical_strings_are_refused() {
        assert_eq!(apply("abc", &req("", "q", false)), Err(EditError::EmptyOld));
        assert_eq!(
            apply("abc", &req("a", "a", false)),
            Err(EditError::NoChange)
        );
    }

    #[test]
    fn whitespace_is_significant() {
        assert_eq!(
            apply("    indented", &req("  indented\n", "x", false)),
            Err(EditError::NotFound { crlf: false })
        );
    }
}

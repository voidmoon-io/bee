//! Read and materialize committed source inside a scope-joined worker, without hooks or filters.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_OBJECT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RANGE_BYTES: usize = 64 * 1024;
mod materialize;
pub use materialize::Materialization;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePin {
    pub repository: String,
    pub commit: String,
    pub tree: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Materialize {
        pin: SourcePin,
        destination: std::path::PathBuf,
    },
    Pin {
        repository: String,
        commit: String,
    },
    Read {
        pin: SourcePin,
        path: String,
        start_line: usize,
        end_line: usize,
    },
}

#[derive(clap::Args, Debug)]
pub struct WorkerArgs {
    #[arg(long)]
    pub request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceRange {
    pub pin: SourcePin,
    pub path: String,
    pub blob: String,
    pub file_sha256: String,
    pub range_sha256: String,
    pub start_line: usize,
    pub end_line: usize,
    pub total_lines: usize,
    pub content: String,
}

fn object<'a>(repo: &'a gix::Repository, id: gix::ObjectId) -> Result<gix::Object<'a>, String> {
    if repo.find_header(id).map_err(err)?.size() > MAX_OBJECT_BYTES {
        return Err("source object exceeds 8 MiB limit".into());
    }
    let object = repo.find_object(id).map_err(err)?;
    if object.data.len() as u64 > MAX_OBJECT_BYTES {
        return Err("source object exceeds 8 MiB limit".into());
    }
    let actual =
        gix::objs::compute_hash(repo.object_hash(), object.kind, &object.data).map_err(err)?;
    if actual != id {
        return Err("Git object digest mismatch".into());
    }
    Ok(object)
}

fn commit_id(commit: &str) -> Result<gix::ObjectId, String> {
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("commit must be a full 40-character SHA-1 object id; refs and abbreviated ids are not accepted".into());
    }
    gix::ObjectId::from_hex(commit.as_bytes()).map_err(err)
}

pub fn query(request: Request) -> Result<serde_json::Value, String> {
    match request {
        Request::Materialize { pin, destination } => {
            serde_json::to_value(materialize::materialize(pin, &destination)?).map_err(err)
        }
        Request::Pin { repository, commit } => {
            let id = commit_id(&commit)?;
            let path = std::fs::canonicalize(repository).map_err(err)?;
            let repo = gix::open(&path).map_err(err)?;
            let commit = object(&repo, id)?.try_into_commit().map_err(err)?;
            let tree_id = commit.tree_id().map_err(err)?.detach();
            object(&repo, tree_id)?.try_into_tree().map_err(err)?;
            serde_json::to_value(SourcePin {
                repository: path.to_str().ok_or("repository path is not UTF-8")?.into(),
                commit: id.to_string(),
                tree: tree_id.to_string(),
            })
            .map_err(err)
        }
        Request::Read {
            pin,
            path,
            start_line,
            end_line,
        } => {
            if start_line == 0 || end_line < start_line || end_line - start_line >= 400 {
                return Err("request 1–400 lines using a 1-based inclusive range".into());
            }
            if path.is_empty()
                || path.len() > 4096
                || path.contains(['\\', '\0'])
                || path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err("path must be a normalized repository-relative file path".into());
            }
            let repo = gix::open(&pin.repository).map_err(err)?;
            let commit = object(&repo, commit_id(&pin.commit)?)?
                .try_into_commit()
                .map_err(err)?;
            let mut id = commit.tree_id().map_err(err)?.detach();
            if id.to_string() != pin.tree {
                return Err("pin tree does not match commit".into());
            }
            let components: Vec<_> = path.split('/').collect();
            for (index, component) in components.iter().enumerate() {
                let tree = object(&repo, id)?.try_into_tree().map_err(err)?;
                let entry = tree
                    .find_entry(component.as_bytes())
                    .ok_or("path not found in pinned tree")?;
                let mode = entry.mode().as_str();
                let last = index + 1 == components.len();
                if (!last && mode != "tree") || (last && mode != "blob" && mode != "exe") {
                    return Err("only regular source files are readable; symlinks, submodules and directories are refused".into());
                }
                id = entry.object_id();
            }
            let blob = object(&repo, id)?.try_into_blob().map_err(err)?;
            let text = std::str::from_utf8(&blob.data).map_err(|_| "source file is not UTF-8")?;
            if text.contains('\0') {
                return Err("binary source file is not supported".into());
            }
            let mut total_lines = 0;
            let mut content = String::new();
            for (index, line) in text.split_inclusive('\n').enumerate() {
                total_lines = index + 1;
                if (start_line..=end_line).contains(&total_lines) {
                    if content.len() + line.len() > MAX_RANGE_BYTES {
                        return Err("source range exceeds 64 KiB; request fewer lines".into());
                    }
                    content.push_str(line);
                }
            }
            if start_line > total_lines {
                return Err(format!(
                    "range starts past end of file ({} lines)",
                    total_lines
                ));
            }
            let end = end_line.min(total_lines);
            serde_json::to_value(SourceRange {
                pin,
                path,
                blob: id.to_string(),
                file_sha256: format!("{:x}", Sha256::digest(&blob.data)),
                range_sha256: format!("{:x}", Sha256::digest(content.as_bytes())),
                start_line,
                end_line: end,
                total_lines,
                content,
            })
            .map_err(err)
        }
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

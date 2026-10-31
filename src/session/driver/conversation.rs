//! The durable conversation. The journal carries only a bounded tail; older messages move to the
//! store's append-only conversation table in the same transaction as the commit that archives
//! them, so a commit never reserializes the whole history and a crash never splits it.
use super::DriverError;
use crate::provider::{Conversation, Message};
use crate::session::durable::{self as core, store::Append};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// Archive the tail once it holds this many messages or bytes.
const MAX_TAIL_MESSAGES: usize = 64;
const MAX_TAIL_BYTES: usize = 256 * 1024;
/// A session whose conversation reaches this size takes no new submissions.
pub(super) const MAX_CONVERSATION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub(super) struct StoredConversation {
    inner: Conversation,
    /// Messages `[..archived]` are in the store, not in the journal.
    archived: usize,
    archived_bytes: u64,
}

impl Deref for StoredConversation {
    type Target = Conversation;
    fn deref(&self) -> &Conversation {
        &self.inner
    }
}
impl DerefMut for StoredConversation {
    fn deref_mut(&mut self) -> &mut Conversation {
        &mut self.inner
    }
}

#[derive(Serialize)]
struct TailRef<'a> {
    system: &'a str,
    archived: usize,
    messages: &'a [Message],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tail {
    system: String,
    /// Absent in journals written before the conversation table: everything is in the tail.
    #[serde(default)]
    archived: usize,
    messages: Vec<Message>,
}

impl Serialize for StoredConversation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        TailRef {
            system: &self.inner.system,
            archived: self.archived,
            messages: &self.inner.messages[self.archived..],
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for StoredConversation {
    /// Yields only the tail; [`restore`](Self::restore) must prepend the archived messages.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tail = Tail::deserialize(deserializer)?;
        Ok(Self {
            inner: Conversation {
                system: tail.system,
                messages: tail.messages,
            },
            archived: tail.archived,
            archived_bytes: 0,
        })
    }
}

impl StoredConversation {
    pub fn new(system: String) -> Self {
        Self {
            inner: Conversation {
                system,
                messages: vec![],
            },
            archived: 0,
            archived_bytes: 0,
        }
    }

    pub fn conversation(&self) -> &Conversation {
        &self.inner
    }

    /// Prepend the store's archived messages to a freshly loaded tail. Exactly `archived` rows.
    pub fn restore(&mut self, rows: Vec<Vec<u8>>) -> Result<(), DriverError> {
        if rows.len() != self.archived {
            return Err(core::Error::InvalidSnapshot.into());
        }
        let mut messages = Vec::with_capacity(rows.len() + self.inner.messages.len());
        let mut bytes = 0_u64;
        for row in rows {
            bytes = bytes.saturating_add(row.len() as u64);
            messages.push(serde_json::from_slice(&row)?);
        }
        messages.append(&mut self.inner.messages);
        self.inner.messages = messages;
        self.archived_bytes = bytes;
        Ok(())
    }

    /// Bytes the whole conversation would take in the store.
    pub fn total_bytes(&self) -> Result<u64, DriverError> {
        let mut bytes = self.archived_bytes;
        for message in &self.inner.messages[self.archived..] {
            bytes = bytes.saturating_add(serde_json::to_vec(message)?.len() as u64);
        }
        Ok(bytes)
    }

    /// The rows to archive with the next commit when the tail is over its bound, marking them
    /// archived. The caller must [`unarchive`](Self::unarchive) if that commit fails.
    pub fn archive(&mut self) -> Result<Option<Archival>, DriverError> {
        let tail = &self.inner.messages[self.archived..];
        let mut rows = Vec::with_capacity(tail.len());
        let mut bytes = 0_usize;
        for message in tail {
            let row = serde_json::to_vec(message)?;
            bytes = bytes.saturating_add(row.len());
            rows.push(row);
        }
        if tail.len() < MAX_TAIL_MESSAGES && bytes < MAX_TAIL_BYTES {
            return Ok(None);
        }
        let undo = Archival {
            archived: self.archived,
            archived_bytes: self.archived_bytes,
            appends: rows
                .into_iter()
                .enumerate()
                .map(|(offset, message)| Append {
                    position: (self.archived + offset) as u64,
                    message,
                })
                .collect(),
        };
        self.archived = self.inner.messages.len();
        self.archived_bytes = self.archived_bytes.saturating_add(bytes as u64);
        Ok(Some(undo))
    }

    pub fn unarchive(&mut self, archival: &Archival) {
        self.archived = archival.archived;
        self.archived_bytes = archival.archived_bytes;
    }
}

/// Rows one commit appends, and the state to restore if it fails.
pub(super) struct Archival {
    archived: usize,
    archived_bytes: u64,
    pub appends: Vec<Append>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(n: usize) -> Message {
        Message::User {
            text: format!("message {n}"),
        }
    }

    #[test]
    fn the_journal_carries_only_the_tail_and_restores_the_rest() {
        let mut stored = StoredConversation::new("system".into());
        for n in 0..MAX_TAIL_MESSAGES {
            stored.push(user(n));
        }
        let archival = stored.archive().unwrap().expect("tail is full");
        assert_eq!(archival.appends.len(), MAX_TAIL_MESSAGES);
        stored.push(user(MAX_TAIL_MESSAGES));
        let value = serde_json::to_value(&stored).unwrap();
        assert_eq!(value["archived"], MAX_TAIL_MESSAGES);
        assert_eq!(value["messages"].as_array().unwrap().len(), 1);

        let mut loaded: StoredConversation = serde_json::from_value(value).unwrap();
        let rows: Vec<_> = archival.appends.into_iter().map(|a| a.message).collect();
        assert!(loaded.clone().restore(rows[1..].to_vec()).is_err());
        loaded.restore(rows).unwrap();
        assert_eq!(
            serde_json::to_value(loaded.conversation()).unwrap(),
            serde_json::to_value(stored.conversation()).unwrap()
        );
        assert_eq!(loaded.total_bytes().unwrap(), stored.total_bytes().unwrap());
    }

    #[test]
    fn an_old_journal_conversation_loads_whole_and_a_failed_archive_rolls_back() {
        // A journal from before the conversation table has no `archived`: all of it is the tail.
        let old = serde_json::json!({"system": "s", "messages": [user(0)]});
        let mut loaded: StoredConversation = serde_json::from_value(old).unwrap();
        loaded.restore(vec![]).unwrap();
        assert_eq!(loaded.messages.len(), 1);
        for n in 0..MAX_TAIL_MESSAGES {
            loaded.push(user(n));
        }
        let archival = loaded.archive().unwrap().unwrap();
        loaded.unarchive(&archival);
        assert_eq!(
            serde_json::to_value(&loaded).unwrap()["messages"]
                .as_array()
                .unwrap()
                .len(),
            MAX_TAIL_MESSAGES + 1
        );
    }
}

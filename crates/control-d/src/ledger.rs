use std::{path::Path, time::Duration};

use chrono::Utc;
use defsec_protocol::audit::{AuditEntry, AuditEventType, GENESIS_PREV_HASH, verify_audit_chain};
use defsec_protocol::rpc::AdminResponse;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::service::{ControlError, Result};

const MIGRATIONS: &[&str] = &[
    include_str!("schema.sql"),
    include_str!("schema_v2.sql"),
    include_str!("schema_v3.sql"),
    include_str!("schema_v4.sql"),
    include_str!("schema_v5.sql"),
];

/// Opens the local writer and applies pending migrations atomically.
pub fn open(path: impl AsRef<Path>) -> Result<Connection> {
    let mut db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: usize = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > MIGRATIONS.len() {
        return Err(ControlError::invalid(
            "ledger schema is newer than this daemon",
        ));
    }
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", index + 1)?;
    }
    tx.commit()?;
    Ok(db)
}

pub(crate) fn json_column<T: DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let raw: String = row.get(index)?;
    serde_json::from_str(&raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

pub(crate) fn optional_json<T: serde::de::DeserializeOwned>(
    r: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<T>> {
    r.get::<_, Option<String>>(index)?
        .as_ref()
        .map(|_| json_column(r, index))
        .transpose()
}

pub(crate) fn rows<T>(
    db: &Connection,
    sql: &str,
    args: impl rusqlite::Params,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    Ok(db
        .prepare(sql)?
        .query_map(args, map)?
        .collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn audit(
    db: &Connection,
    event: AuditEventType,
    actor: &str,
    request: &str,
    payload: Value,
) -> Result<()> {
    let last = db
        .query_row(
            "SELECT seq_no, entry_hash FROM audit_outbox ORDER BY seq_no DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let (seq, prev) = last.unwrap_or_else(|| (0, GENESIS_PREV_HASH.into()));
    let entry = AuditEntry::build(
        seq + 1,
        Utc::now(),
        prev,
        event,
        actor.into(),
        request.into(),
        payload,
    )?;
    db.execute(
        "INSERT INTO audit_outbox VALUES (?1, ?2, ?3)",
        params![
            entry.seq_no,
            entry.entry_hash,
            serde_json::to_string(&entry)?
        ],
    )?;
    Ok(())
}

pub(crate) fn verify(db: &Connection) -> Result<AdminResponse> {
    let records = rows(
        db,
        "SELECT seq_no, entry_hash, entry_json FROM audit_outbox ORDER BY seq_no",
        [],
        |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    let parsed = records
        .iter()
        .map(|(seq, hash, body)| {
            let entry: AuditEntry =
                serde_json::from_str(body).map_err(|e| format!("entry {seq}: {e}"))?;
            if entry.seq_no != *seq || entry.entry_hash != *hash {
                return Err(format!(
                    "entry {seq} differs from its indexed sequence or hash"
                ));
            }
            Ok(entry)
        })
        .collect::<std::result::Result<Vec<_>, String>>();
    let result = parsed.and_then(|entries| verify_audit_chain(&entries, 1, GENESIS_PREV_HASH));
    Ok(AdminResponse::AuditChainStatus {
        valid: result.is_ok(),
        entries_checked: records.len() as u64,
        latest_hash: result.as_ref().ok().cloned().flatten(),
        error: result.err(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_forward_only_and_set_writer_pragmas() {
        let path =
            std::env::temp_dir().join(format!("control-ledger-{}.sqlite", uuid::Uuid::new_v4()));
        let db = open(&path).unwrap();
        let journal: String = db
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        let sync: u32 = db
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        let foreign_keys: u32 = db
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!((journal.as_str(), sync, foreign_keys), ("wal", 2, 1));
        assert!(matches!(
            verify(&db).unwrap(),
            AdminResponse::AuditChainStatus {
                valid: true,
                entries_checked: 0,
                latest_hash: None,
                ..
            }
        ));
        db.pragma_update(None, "user_version", MIGRATIONS.len() + 1)
            .unwrap();
        drop(db);
        assert!(matches!(open(&path), Err(ControlError::Request { .. })));
        std::fs::remove_file(path).unwrap();
    }
}

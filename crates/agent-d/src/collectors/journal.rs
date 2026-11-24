//! `journal.unit_events`: cursor-backed bounded journald stream collection.
//!
//! The stream source is abstracted behind [`JournalSource`] so tests can
//! script batches, cursor gaps, and errors. The default [`JournalctlSource`]
//! invokes the fixed path `/usr/bin/journalctl` via `tokio::process::Command`
//! with a static argv allowlist — never a shell, never caller flags.
//!
//! Deterministic redaction and per-message byte caps are applied uniformly
//! in [`collect_journal`] regardless of the source, so scripted and real
//! events follow the exact same pipeline.

use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;

use defsec_policy::edge_floor::{validate_systemd_unit_name, EdgeSafetyConfig};
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::observation::{JournalEventRecord, ObservationPayload, ObservationStatus};
use defsec_protocol::watch::{DataClassification, JournalUnitEventsParams};
use tokio::io::AsyncReadExt;

use super::CollectorOutput;

pub const JOURNALCTL_PATH: &str = "/usr/bin/journalctl";
/// Hard cap on journalctl stdout before the child is killed.
pub const MAX_JOURNAL_STDOUT_BYTES: usize = 4 * 1024 * 1024;
/// Default syslog priority ceiling (0..=6, info and more severe).
pub const DEFAULT_MIN_PRIORITY: u8 = 6;
/// Cap on retained stderr for diagnostics.
const MAX_STDERR_SNIPPET_BYTES: usize = 8 * 1024;

/// One fetch result from a journal source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFetchOutcome {
    pub status: ObservationStatus,
    pub events: Vec<JournalEventRecord>,
    pub cursor_after: Option<String>,
    pub gap_detected: bool,
    pub partial_reasons: Vec<String>,
}

impl Default for JournalFetchOutcome {
    fn default() -> Self {
        Self {
            status: ObservationStatus::Ok,
            events: Vec::new(),
            cursor_after: None,
            gap_detected: false,
            partial_reasons: Vec::new(),
        }
    }
}

/// Async source of journal events, abstracted for testability.
///
/// Manually boxed (no `async-trait` dependency) so `&dyn JournalSource`
/// works inside collector functions.
pub trait JournalSource: Send + Sync {
    fn fetch<'a>(
        &'a self,
        unit: &'a str,
        min_priority: u8,
        after_cursor: Option<&'a str>,
        max_events: u32,
    ) -> Pin<Box<dyn Future<Output = JournalFetchOutcome> + Send + 'a>>;
}

/// Production source invoking fixed-path `journalctl` via `tokio::process`.
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalctlSource;

impl JournalctlSource {
    pub fn new() -> Self {
        Self
    }
}

impl JournalSource for JournalctlSource {
    fn fetch<'a>(
        &'a self,
        unit: &'a str,
        min_priority: u8,
        after_cursor: Option<&'a str>,
        max_events: u32,
    ) -> Pin<Box<dyn Future<Output = JournalFetchOutcome> + Send + 'a>> {
        Box::pin(run_journalctl(
            unit,
            min_priority,
            after_cursor,
            max_events,
        ))
    }
}

/// Build the static journalctl argv. No shell, no dynamic flags.
pub fn journalctl_argv(
    unit: &str,
    min_priority: u8,
    after_cursor: Option<&str>,
    max_events: u32,
) -> Vec<String> {
    let mut argv = vec![
        JOURNALCTL_PATH.to_string(),
        "--output=json".to_string(),
        format!("--unit={unit}"),
        format!("--priority=0..{min_priority}"),
        "-n".to_string(),
        max_events.to_string(),
        "--no-pager".to_string(),
    ];
    if let Some(cursor) = after_cursor {
        argv.push(format!("--after-cursor={cursor}"));
    }
    argv
}

async fn run_journalctl(
    unit: &str,
    min_priority: u8,
    after_cursor: Option<&str>,
    max_events: u32,
) -> JournalFetchOutcome {
    if validate_systemd_unit_name(unit).is_err() {
        return JournalFetchOutcome {
            status: ObservationStatus::Error,
            partial_reasons: vec![format!("refusing to query invalid unit name '{unit}'")],
            ..JournalFetchOutcome::default()
        };
    }

    let argv = journalctl_argv(unit, min_priority, after_cursor, max_events);
    let mut command = tokio::process::Command::new(JOURNALCTL_PATH);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            return JournalFetchOutcome {
                status: ObservationStatus::Error,
                partial_reasons: vec![format!("failed to spawn journalctl: {e}")],
                ..JournalFetchOutcome::default()
            };
        }
    };

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr_handle = child.stderr.take().expect("stderr piped");
    // Drain stderr concurrently so journalctl never blocks on a full pipe.
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stderr_handle.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() < MAX_STDERR_SNIPPET_BYTES {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    });

    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    let mut overflowed = false;
    loop {
        match stdout.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_JOURNAL_STDOUT_BYTES {
                    overflowed = true;
                    let _ = child.kill().await;
                    break;
                }
            }
            Err(e) => {
                let _ = child.kill().await;
                return JournalFetchOutcome {
                    status: ObservationStatus::Error,
                    partial_reasons: vec![format!("journalctl stdout read failed: {e}")],
                    ..JournalFetchOutcome::default()
                };
            }
        }
    }

    let wait_status = child.wait().await;
    let stderr = stderr_task.await.unwrap_or_default();

    if overflowed {
        return JournalFetchOutcome {
            status: ObservationStatus::TruncatedRejected,
            partial_reasons: vec![format!(
                "journalctl output exceeded hard stdout cap of {MAX_JOURNAL_STDOUT_BYTES} bytes; child killed"
            )],
            ..JournalFetchOutcome::default()
        };
    }

    let exit_ok = matches!(&wait_status, Ok(s) if s.success());
    if !exit_ok {
        let lower = stderr.to_ascii_lowercase();
        if lower.contains("cursor") {
            // Cursor invalidated (journal rotation / vacuum): restart from
            // head and report the gap explicitly. A snapshot cannot restore
            // missed historical stream events.
            return JournalFetchOutcome {
                status: ObservationStatus::Ok,
                gap_detected: true,
                cursor_after: None,
                events: Vec::new(),
                partial_reasons: vec![
                    "journal cursor invalidated (rotation or vacuum); restarting from head; missed historical events are not recoverable"
                        .to_string(),
                ],
            };
        }
        let snippet: String = stderr.chars().take(200).collect();
        return JournalFetchOutcome {
            status: ObservationStatus::Error,
            partial_reasons: vec![format!("journalctl exited with error: {snippet}")],
            ..JournalFetchOutcome::default()
        };
    }

    let events = parse_journalctl_json(&out, unit);
    let cursor_after = events
        .last()
        .map(|e| e.cursor.clone())
        .or_else(|| after_cursor.map(str::to_string));
    JournalFetchOutcome {
        status: ObservationStatus::Ok,
        events,
        cursor_after,
        gap_detected: false,
        partial_reasons: Vec::new(),
    }
}

/// Parse journalctl `--output=json` lines into raw (unredacted) records.
/// Malformed lines are skipped: streams must stay forward-progress.
pub fn parse_journalctl_json(bytes: &[u8], requested_unit: &str) -> Vec<JournalEventRecord> {
    let text = String::from_utf8_lossy(bytes);
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(cursor) = value.get("__CURSOR").and_then(|v| v.as_str()) else {
            continue;
        };
        let timestamp_us = value
            .get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64()))
            .unwrap_or(0);
        let priority = value
            .get("PRIORITY")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u8>().ok()).or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok())))
            .unwrap_or(DEFAULT_MIN_PRIORITY);
        let unit = value
            .get("_SYSTEMD_UNIT")
            .or_else(|| value.get("UNIT"))
            .and_then(|v| v.as_str())
            .unwrap_or(requested_unit)
            .to_string();
        let pid = value
            .get("_PID")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u32>().ok()).or_else(|| v.as_u64().and_then(|n| u32::try_from(n).ok())));
        let uid = value
            .get("_UID")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u32>().ok()).or_else(|| v.as_u64().and_then(|n| u32::try_from(n).ok())));
        let message = json_message_string(value.get("MESSAGE"));

        events.push(JournalEventRecord {
            cursor: cursor.to_string(),
            timestamp_us,
            unit,
            priority,
            pid,
            uid,
            message_redacted: message,
            truncated: false,
            redaction_applied: false,
            classification: DataClassification::BoundedRedactedText,
        });
    }
    events
}

/// journalctl may emit MESSAGE as a string or as an array of byte values
/// (invalid UTF-8 payloads).
fn json_message_string(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(items)) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|v| v.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

/// Marker keywords whose assigned values get masked. Case-insensitive.
const SECRET_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "bearer",
    "authorization",
    "secret",
    "api_key",
    "apikey",
    "credential",
    "client_secret",
];

const PRIVATE_KEY_MARKERS: &[&str] = &["private key", "-----begin"];

/// Deterministically redact secrets from a message.
///
/// - Any message containing private key material is replaced entirely.
/// - `marker=value` or `marker: value` assignments have their value masked
///   (`[REDACTED]`), including the following whitespace-delimited token when
///   the assignment operator ends the token (e.g. `Bearer <jwt>`).
pub fn redact_message(message: &str) -> (String, bool) {
    let lower = message.to_ascii_lowercase();
    if PRIVATE_KEY_MARKERS.iter().any(|m| lower.contains(m)) {
        return ("[REDACTED: private-key-material]".to_string(), true);
    }

    let tokens: Vec<&str> = message.split(' ').collect();
    let mut mask_next: Vec<bool> = vec![false; tokens.len()];
    let mut redacted = false;
    let mut output: Vec<String> = Vec::with_capacity(tokens.len());

    for (i, token) in tokens.iter().enumerate() {
        let token_lower = token.to_ascii_lowercase();
        let marker_hit = SECRET_MARKERS.iter().any(|m| token_lower.contains(m));
        let mut replacement = (*token).to_string();

        if marker_hit {
            if let Some((key_part, value_part)) = split_assignment(token) {
                redacted = true;
                if value_part.is_empty() {
                    // `marker=` / `marker:` with the value in the next token.
                    replacement = key_part;
                    if mask_next.get(i + 1).is_some() {
                        mask_next[i + 1] = true;
                    }
                } else {
                    replacement = format!("{key_part}[REDACTED]");
                }
            } else if is_bare_marker_word(&token_lower) && i + 1 < tokens.len() {
                // Bare marker word (e.g. `Bearer`) whose value follows.
                mask_next[i + 1] = true;
                redacted = true;
            }
        }

        if mask_next[i] {
            replacement = "[REDACTED]".to_string();
            redacted = true;
            // Keep marker semantics: `Bearer [REDACTED]` chains through the
            // next marker if this masked token was itself a marker word.
            if marker_hit && is_bare_marker_word(&token_lower) && i + 1 < tokens.len() {
                mask_next[i + 1] = true;
            }
        }

        output.push(replacement);
    }

    (output.join(" "), redacted)
}

/// Split `key=value` / `key: value` style tokens into (key-with-operator,
/// value). Returns `None` when the token has no assignment operator.
fn split_assignment(token: &str) -> Option<(String, String)> {
    if let Some(idx) = token.find('=') {
        let (key, value) = (token[..idx].to_string(), token[idx + 1..].to_string());
        if key.is_empty() {
            return None;
        }
        return Some((format!("{key}="), value));
    }
    if let Some(idx) = token.find(':') {
        let (key, value) = (token[..idx].to_string(), token[idx + 1..].to_string());
        if key.is_empty() {
            return None;
        }
        return Some((format!("{key}:"), value));
    }
    None
}

/// Marker words that mask the immediately following token even without an
/// inline assignment operator.
fn is_bare_marker_word(token_lower: &str) -> bool {
    token_lower == "bearer" || token_lower == "authorization:" || token_lower == "authorization"
}

/// Apply redaction and per-message byte truncation to a raw record.
/// Returns the finalized record.
pub fn finalize_event(record: JournalEventRecord, max_message_bytes: usize) -> JournalEventRecord {
    let (redacted, redaction_applied) = redact_message(&record.message_redacted);
    let (final_msg, truncated) = truncate_utf8(&redacted, max_message_bytes);
    JournalEventRecord {
        message_redacted: final_msg,
        truncated,
        redaction_applied,
        classification: DataClassification::BoundedRedactedText,
        ..record
    }
}

/// Byte-bounded truncation on a UTF-8 character boundary.
fn truncate_utf8(message: &str, max_bytes: usize) -> (String, bool) {
    if message.len() <= max_bytes {
        return (message.to_string(), false);
    }
    let mut cut = max_bytes;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    (message[..cut].to_string(), true)
}

/// Collect a `journal.unit_events` observation from the given source.
pub async fn collect_journal(
    params: &JournalUnitEventsParams,
    cfg: &EdgeSafetyConfig,
    cursor: Option<&str>,
    source: &dyn JournalSource,
) -> CollectorOutput {
    if let Err(reason) = validate_systemd_unit_name(&params.unit) {
        return super::error_output("invalid_unit_name", &reason);
    }
    let min_priority = params.min_priority.unwrap_or(DEFAULT_MIN_PRIORITY);
    let max_events = params.max_events_per_batch.unwrap_or(cfg.max_journal_batch_events);
    let max_message_bytes = params.max_message_bytes.unwrap_or(cfg.max_journal_message_bytes);

    let outcome = source
        .fetch(&params.unit, min_priority, cursor, max_events)
        .await;
    let events: Vec<JournalEventRecord> = outcome
        .events
        .into_iter()
        .map(|e| finalize_event(e, max_message_bytes))
        .collect();

    let payload = ObservationPayload::StreamBatch {
        events: events.clone(),
        cursor_before: cursor.map(str::to_string),
        cursor_after: outcome.cursor_after.clone(),
        gap_detected: outcome.gap_detected,
    };
    let state_hash = canonical_sha256_hex(&events).unwrap_or_default();
    let status = outcome.status;
    CollectorOutput {
        status,
        payload,
        state_hash,
        next_cursor: outcome.cursor_after,
        partial_reasons: outcome.partial_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(unit: &str) -> JournalUnitEventsParams {
        JournalUnitEventsParams {
            unit: unit.into(),
            min_priority: Some(6),
            max_events_per_batch: Some(50),
            max_message_bytes: None,
        }
    }

    fn raw_event(cursor: &str, message: &str) -> JournalEventRecord {
        JournalEventRecord {
            cursor: cursor.into(),
            timestamp_us: 1_000,
            unit: "sshd.service".into(),
            priority: 4,
            pid: Some(99),
            uid: Some(0),
            message_redacted: message.into(),
            truncated: false,
            redaction_applied: false,
            classification: DataClassification::BoundedRedactedText,
        }
    }

    struct MockJournalSource {
        batches: std::sync::Mutex<std::collections::VecDeque<JournalFetchOutcome>>,
        seen_cursors: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl MockJournalSource {
        fn new(batches: Vec<JournalFetchOutcome>) -> Self {
            Self {
                batches: std::sync::Mutex::new(batches.into()),
                seen_cursors: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl JournalSource for MockJournalSource {
        fn fetch(
            &self,
            _unit: &str,
            _min_priority: u8,
            after_cursor: Option<&str>,
            _max_events: u32,
        ) -> Pin<Box<dyn Future<Output = JournalFetchOutcome> + Send + '_>> {
            self.seen_cursors.lock().unwrap().push(after_cursor.map(str::to_string));
            let next = self.batches.lock().unwrap().pop_front();
            let outcome = next.unwrap_or_default();
            Box::pin(async move { outcome })
        }
    }

    #[test]
    fn redaction_masks_marker_values_but_not_plain_text() {
        let (msg, applied) = redact_message("login for alice password=hunter2 accepted");
        assert!(applied);
        assert!(msg.contains("password=[REDACTED]"));
        assert!(!msg.contains("hunter2"));

        let (msg, applied) = redact_message("Authorization: Bearer eyJhbGciOi.payload.sig");
        assert!(applied);
        assert_eq!(msg, "Authorization: [REDACTED] [REDACTED]");
        assert!(!msg.contains("eyJhbGciOi"));

        let (msg, applied) = redact_message("Accepted publickey for root from 10.0.0.5");
        assert!(!applied);
        assert_eq!(msg, "Accepted publickey for root from 10.0.0.5");

        let (msg, applied) = redact_message("-----BEGIN OPENSSH PRIVATE KEY-----");
        assert!(applied);
        assert_eq!(msg, "[REDACTED: private-key-material]");

        let (msg, applied) = redact_message("token: abcdef123456");
        assert!(applied);
        assert_eq!(msg, "token: [REDACTED]");
    }

    #[test]
    fn truncation_respects_byte_cap_and_char_boundaries() {
        let (msg, truncated) = truncate_utf8("abcdefghij", 4);
        assert!(truncated);
        assert_eq!(msg, "abcd");
        let (msg, truncated) = truncate_utf8("héllo wörld", 4);
        assert!(truncated);
        assert!(msg.chars().count() <= 4);
        assert!(msg.is_char_boundary(msg.len()));
        let (msg, truncated) = truncate_utf8("ok", 8);
        assert!(!truncated);
        assert_eq!(msg, "ok");
    }

    #[test]
    fn parses_journalctl_json_lines() {
        let stdout = concat!(
            "{\"__CURSOR\":\"c1\",\"__REALTIME_TIMESTAMP\":\"1700000000000000\",\"PRIORITY\":\"4\",\"_SYSTEMD_UNIT\":\"sshd.service\",\"_PID\":\"99\",\"_UID\":\"0\",\"MESSAGE\":\"sshd started\"}\n",
            "{\"__CURSOR\":\"c2\",\"__REALTIME_TIMESTAMP\":\"1700000001000000\",\"PRIORITY\":\"6\",\"MESSAGE\":[104,105]}\n",
            "not json at all\n",
            "{\"MESSAGE\":\"missing cursor\"}\n",
        );
        let events = parse_journalctl_json(stdout.as_bytes(), "sshd.service");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].cursor, "c1");
        assert_eq!(events[0].timestamp_us, 1_700_000_000_000_000);
        assert_eq!(events[0].unit, "sshd.service");
        assert_eq!(events[0].pid, Some(99));
        assert_eq!(events[0].message_redacted, "sshd started");
        assert_eq!(events[1].message_redacted, "hi");
    }

    #[tokio::test]
    async fn collector_advances_cursor_and_passes_previous_cursor_to_source() {
        let b1 = JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: vec![raw_event("c1", "hello")],
            cursor_after: Some("c1".into()),
            ..Default::default()
        };
        let b2 = JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: vec![raw_event("c2", "hello")],
            cursor_after: Some("c2".into()),
            ..Default::default()
        };
        let source = MockJournalSource::new(vec![b1, b2]);
        let cfg = EdgeSafetyConfig::default();

        let out1 = collect_journal(&params("sshd.service"), &cfg, None, &source).await;
        assert_eq!(out1.status, ObservationStatus::Ok);
        assert_eq!(out1.next_cursor.as_deref(), Some("c1"));
        match &out1.payload {
            ObservationPayload::StreamBatch {
                events,
                cursor_before,
                cursor_after,
                gap_detected,
            } => {
                assert_eq!(events.len(), 1);
                assert_eq!(cursor_before.as_deref(), None);
                assert_eq!(cursor_after.as_deref(), Some("c1"));
                assert!(!gap_detected);
            }
            other => panic!("unexpected payload {other:?}"),
        }

        let out2 = collect_journal(&params("sshd.service"), &cfg, out1.next_cursor.as_deref(), &source).await;
        assert_eq!(out2.next_cursor.as_deref(), Some("c2"));
        let seen = source.seen_cursors.lock().unwrap();
        assert_eq!(seen[0], None);
        assert_eq!(seen[1].as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn identical_repeated_events_are_preserved_not_deduplicated() {
        let same = || JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: vec![raw_event(&format!("c{}", 0), "same text again")],
            cursor_after: Some("c0".into()),
            ..Default::default()
        };
        let source = MockJournalSource::new(vec![same(), same()]);
        let cfg = EdgeSafetyConfig::default();
        let out1 = collect_journal(&params("sshd.service"), &cfg, None, &source).await;
        let out2 = collect_journal(&params("sshd.service"), &cfg, Some("c0"), &source).await;
        assert!(!out1.state_hash.is_empty());
        assert!(!out2.state_hash.is_empty());
        // Streams never suppress recurring identical text; both batches emit.
        match (&out1.payload, &out2.payload) {
            (ObservationPayload::StreamBatch { events: e1, .. }, ObservationPayload::StreamBatch { events: e2, .. }) => {
                assert!(!e1.is_empty());
                assert!(!e2.is_empty());
                assert_eq!(e1[0].message_redacted, e2[0].message_redacted);
            }
            other => panic!("unexpected payloads {other:?}"),
        }
    }

    #[tokio::test]
    async fn redaction_and_truncation_apply_through_the_pipeline() {
        let outcome = JournalFetchOutcome {
            status: ObservationStatus::Ok,
            events: vec![
                raw_event("c1", "auth ok apikey=supersecret123 done"),
                raw_event("c2", "a fairly long administrative message that certainly exceeds any tiny cap we configure here"),
            ],
            cursor_after: Some("c2".into()),
            ..Default::default()
        };
        let source = MockJournalSource::new(vec![outcome]);
        let mut p = params("sshd.service");
        p.max_message_bytes = Some(40);
        let cfg = EdgeSafetyConfig::default();

        let out = collect_journal(&p, &cfg, None, &source).await;
        let ObservationPayload::StreamBatch { events, .. } = &out.payload else {
            panic!("expected stream batch");
        };
        assert!(events[0].redaction_applied);
        assert!(!events[0].message_redacted.contains("supersecret123"));
        assert!(events[0].message_redacted.contains("apikey=[REDACTED]"));
        assert_eq!(events[0].classification, DataClassification::BoundedRedactedText);
        assert!(events[1].truncated);
        assert!(events[1].message_redacted.len() <= 40);
        assert!(!events[1].redaction_applied);
    }

    #[tokio::test]
    async fn cursor_gap_is_reported_explicitly() {
        let outcome = JournalFetchOutcome {
            status: ObservationStatus::Ok,
            gap_detected: true,
            cursor_after: None,
            partial_reasons: vec!["journal cursor invalidated (rotation or vacuum); restarting from head; missed historical events are not recoverable".into()],
            ..Default::default()
        };
        let source = MockJournalSource::new(vec![outcome]);
        let cfg = EdgeSafetyConfig::default();
        let out = collect_journal(&params("sshd.service"), &cfg, Some("stale"), &source).await;
        assert_eq!(out.status, ObservationStatus::Ok);
        assert_eq!(out.next_cursor, None);
        assert!(!out.partial_reasons.is_empty());
        match &out.payload {
            ObservationPayload::StreamBatch { gap_detected, events, .. } => {
                assert!(gap_detected);
                assert!(events.is_empty());
            }
            other => panic!("unexpected payload {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_unit_name_is_rejected_before_any_spawn() {
        let source = MockJournalSource::new(vec![]);
        let cfg = EdgeSafetyConfig::default();
        let mut p = params("sshd.service; rm -rf /");
        p.unit = "sshd.service; rm -rf /".into();
        let out = collect_journal(&p, &cfg, None, &source).await;
        assert_eq!(out.status, ObservationStatus::Error);
        assert!(
            out.partial_reasons[0].to_ascii_lowercase().contains("unit name"),
            "reason should name the rejected unit: {}",
            out.partial_reasons[0]
        );
    }

    #[test]
    fn journalctl_argv_is_static_and_cursor_aware() {
        let argv = journalctl_argv("sshd.service", 4, Some("cur-1"), 100);
        assert_eq!(argv[0], "/usr/bin/journalctl");
        assert!(argv.contains(&"--output=json".to_string()));
        assert!(argv.contains(&"--unit=sshd.service".to_string()));
        assert!(argv.contains(&"--priority=0..4".to_string()));
        assert!(argv.contains(&"--no-pager".to_string()));
        assert!(argv.contains(&"--after-cursor=cur-1".to_string()));
        assert!(argv.contains(&"100".to_string()));
        // No shell operators or arbitrary flags ever appear.
        assert!(argv.iter().all(|a| !a.contains(' ') || a.starts_with("--")));
    }
}

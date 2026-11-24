//! `sockets.listening`: pure-Rust parser for `/proc/net/{tcp,tcp,udp,udp6}`
//! with best-effort inode-to-process attribution.
//!
//! Safety properties:
//! - Never escalates privileges; unreadable `/proc/<pid>/fd` trees simply
//!   downgrade the observation to `Partial` with explicit reasons.
//! - Enforces a hard entry cap and refuses to emit a silently truncated
//!   snapshot (`TruncatedRejected`).
//! - Stable sort by `socket_key` plus canonical SHA-256 hashing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::observation::{
    ListeningSocketEntry, ObservationPayload, ObservationStatus, SocketsListeningSnapshot,
};
use defsec_protocol::watch::SocketsListeningParams;
use sha2::{Digest, Sha256};

use super::CollectorOutput;

/// Hard cap on emitted socket entries. Larger inventories are rejected
/// explicitly rather than silently truncated (design §5.2).
pub const MAX_SOCKET_ENTRIES: usize = 4096;

const PROC_NET_TCP: &str = "/proc/net/tcp";
const PROC_NET_TCP6: &str = "/proc/net/tcp6";
const PROC_NET_UDP: &str = "/proc/net/udp";
const PROC_NET_UDP6: &str = "/proc/net/udp6";

/// TCP `LISTEN` state as printed in `/proc/net/tcp*`.
const TCP_STATE_LISTEN: &str = "0A";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSocketRow {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub uid: u32,
    pub inode: u64,
    pub state_hex: String,
}

/// Process identity associated with a socket inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub pid_start_time_ticks: u64,
    pub comm: String,
    pub systemd_unit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessAttribution {
    pub by_inode: BTreeMap<u64, ProcessInfo>,
    pub permission_denied: bool,
    pub scanned_pids: usize,
}

/// Which `/proc/net` tables to consult for the given parameters.
pub fn table_paths(include_tcp: bool, include_udp: bool, include_ipv6: bool) -> Vec<(&'static str, &'static str)> {
    let mut tables = Vec::new();
    if include_tcp {
        tables.push(("tcp", PROC_NET_TCP));
    }
    if include_tcp && include_ipv6 {
        tables.push(("tcp6", PROC_NET_TCP6));
    }
    if include_udp {
        tables.push(("udp", PROC_NET_UDP));
    }
    if include_udp && include_ipv6 {
        tables.push(("udp6", PROC_NET_UDP6));
    }
    tables
}

/// Decode a little-endian hex IPv4 word (e.g. `0100007F`) into dotted quad.
pub fn decode_ipv4_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 8 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let word = u32::from_str_radix(hex_str, 16).ok()?;
    let net = word.swap_bytes();
    Some(format!(
        "{}.{}.{}.{}",
        (net >> 24) & 0xff,
        (net >> 16) & 0xff,
        (net >> 8) & 0xff,
        net & 0xff
    ))
}

/// Decode a `/proc/net/tcp6` style hex IPv6 address into canonical text.
///
/// The kernel prints each 32-bit word of the address in host (little-endian)
/// byte order, so each 4-byte group must be reversed.
pub fn decode_ipv6_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    for group in bytes.chunks_mut(4) {
        group.reverse();
    }
    Some(std::net::Ipv6Addr::from(bytes).to_string())
}

/// Decode a big-endian hex port (e.g. `0016` -> 22).
pub fn decode_port_hex(hex_str: &str) -> Option<u16> {
    if hex_str.is_empty() || hex_str.len() > 4 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(hex_str, 16).ok()
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` table into raw rows.
/// The header line is skipped; malformed lines are skipped.
pub fn parse_proc_net_table(text: &str, protocol: &str) -> Vec<RawSocketRow> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Some(local_port) = decode_port_hex(port_hex) else { continue };
        let expected_len = if protocol.ends_with('6') { 32 } else { 8 };
        let local_addr = if addr_hex.len() == expected_len {
            if expected_len == 8 {
                decode_ipv4_hex(addr_hex)
            } else {
                decode_ipv6_hex(addr_hex)
            }
        } else {
            None
        };
        let Some(local_addr) = local_addr else { continue };
        let (Ok(uid), Ok(inode)) = (fields[7].parse::<u32>(), fields[9].parse::<u64>()) else {
            continue;
        };
        rows.push(RawSocketRow {
            protocol: protocol.to_string(),
            local_addr,
            local_port,
            uid,
            inode,
            state_hex: fields[3].to_ascii_uppercase(),
        });
    }
    rows
}

/// Stable identity key, e.g. `tcp6:[::]:22:uid=0`.
pub fn socket_key(protocol: &str, local_addr: &str, local_port: u16, uid: u32) -> String {
    if local_addr.contains(':') {
        format!("{protocol}:[{local_addr}]:{local_port}:uid={uid}")
    } else {
        format!("{protocol}:{local_addr}:{local_port}:uid={uid}")
    }
}

/// Read the start time (field 22) from `/proc/<pid>/stat`, tolerating
/// parentheses and spaces inside the comm field.
pub fn parse_proc_stat_start_ticks(stat: &str) -> Option<u64> {
    let after_paren = stat.rfind(')')?;
    let rest = &stat[after_paren + 1..];
    // Fields after `)` start at overall field 3 (state), so field 22
    // (starttime) is whitespace index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Extract the comm field from a `/proc/<pid>/stat` read.
pub fn parse_proc_stat_comm(stat: &str) -> Option<String> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(stat[open + 1..close].to_string())
}

/// Best-effort scan of `/proc` to attribute socket inodes to processes.
/// No privilege escalation: unreadable entries set `permission_denied`.
pub fn scan_proc_processes() -> ProcessAttribution {
    let mut by_inode = BTreeMap::new();
    let mut permission_denied = false;
    let mut scanned_pids = 0usize;

    let proc = PathBuf::from("/proc");
    let dir_entries = match std::fs::read_dir(&proc) {
        Ok(entries) => entries,
        Err(_) => {
            return ProcessAttribution {
                by_inode,
                permission_denied: true,
                scanned_pids,
            }
        }
    };

    for entry in dir_entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        scanned_pids += 1;

        let stat_text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let comm = parse_proc_stat_comm(&stat_text).unwrap_or_default();
        let start_ticks = parse_proc_stat_start_ticks(&stat_text);
        let systemd_unit = read_systemd_unit_for_pid(pid);

        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(fds) => fds,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                permission_denied = true;
                continue;
            }
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            // Neither readlink(2) arguments nor its result come from untrusted
            // input beyond the fixed /proc path; best-effort only.
            let Ok(target) = fd.path().read_link() else {
                continue;
            };
            let Some(name) = target.to_str() else { continue };
            let Some(rest) = name.strip_prefix("socket:[") else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else { continue };
            if let Ok(inode) = inode_str.parse::<u64>() {
                by_inode.entry(inode).or_insert_with(|| ProcessInfo {
                    pid,
                    pid_start_time_ticks: start_ticks.unwrap_or(0),
                    comm: comm.clone(),
                    systemd_unit: systemd_unit.clone(),
                });
            }
        }
    }

    ProcessAttribution {
        by_inode,
        permission_denied,
        scanned_pids,
    }
}

/// Read the systemd unit owning a PID from `/proc/<pid>/cgroup`
/// (the `0::` unified cgroup v2 line, last path component).
fn read_systemd_unit_for_pid(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("0::") else {
            continue;
        };
        let last = rest.rsplit('/').next()?;
        if !last.is_empty() && last.contains('.') {
            return Some(last.to_string());
        }
    }
    None
}

/// Build the normalized snapshot from raw rows, applying protocol filtering
/// and optional process attribution. Returns `Err(reason)` when the hard
/// entry cap is exceeded.
pub fn build_socket_snapshot(
    rows: &[RawSocketRow],
    params: &SocketsListeningParams,
    attribution: Option<&ProcessAttribution>,
) -> Result<SocketsListeningSnapshot, String> {
    let filtered: Vec<&RawSocketRow> = rows
        .iter()
        .filter(|row| match row.protocol.as_str() {
            p if p.starts_with("tcp") => row.state_hex == TCP_STATE_LISTEN,
            _ => true, // UDP rows in /proc/net/udp* are all bound sockets
        })
        .collect();

    if filtered.len() > MAX_SOCKET_ENTRIES {
        return Err(format!(
            "socket inventory of {} entries exceeds hard cap {}; refusing to emit a silently truncated snapshot",
            filtered.len(),
            MAX_SOCKET_ENTRIES
        ));
    }

    let mut sockets = Vec::with_capacity(filtered.len());
    for row in filtered {
        let (pid, pid_start_time_ticks, comm, systemd_unit) = attribution
            .and_then(|a| a.by_inode.get(&row.inode))
            .map(|p| (Some(p.pid), Some(p.pid_start_time_ticks), Some(p.comm.clone()), p.systemd_unit.clone()))
            .unwrap_or((None, None, None, None));
        sockets.push(ListeningSocketEntry {
            socket_key: socket_key(&row.protocol, &row.local_addr, row.local_port, row.uid),
            protocol: row.protocol.clone(),
            local_addr: row.local_addr.clone(),
            local_port: row.local_port,
            uid: row.uid,
            inode: row.inode,
            pid,
            pid_start_time_ticks,
            comm,
            systemd_unit,
        });
    }
    sockets.sort_by(|a, b| a.socket_key.cmp(&b.socket_key));

    let partial_attribution = params.resolve_process
        && attribution
            .map(|a| a.permission_denied || sockets.iter().any(|s| s.pid.is_none()))
            .unwrap_or(true);

    Ok(SocketsListeningSnapshot {
        count: sockets.len(),
        partial_attribution,
        sockets,
    })
}

/// Collect a `sockets.listening` observation from the live host.
pub async fn collect_sockets(params: &SocketsListeningParams, _cfg: &EdgeSafetyConfig) -> CollectorOutput {
    let mut rows = Vec::new();
    let mut partial_reasons = Vec::new();
    let mut status = ObservationStatus::Ok;

    for (protocol, path) in table_paths(params.include_tcp, params.include_udp, params.include_ipv6) {
        match std::fs::read_to_string(path) {
            Ok(text) => rows.extend(parse_proc_net_table(&text, protocol)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // IPv6 tables may be absent on IPv6-disabled kernels.
                if !protocol.ends_with('6') {
                    status = ObservationStatus::Error;
                    partial_reasons.push(format!("missing kernel table {path}"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                status = ObservationStatus::PermissionDenied;
                partial_reasons.push(format!("permission denied reading {path}"));
            }
            Err(e) => {
                status = ObservationStatus::Error;
                partial_reasons.push(format!("failed reading {path}: {e}"));
            }
        }
    }

    let attribution = if params.resolve_process {
        Some(scan_proc_processes())
    } else {
        None
    };
    if let Some(a) = &attribution
        && a.permission_denied
    {
        partial_reasons.push(
            "process attribution incomplete: permission denied while scanning /proc/<pid>/fd; no privilege escalation attempted".to_string(),
        );
    }

    let snapshot = match build_socket_snapshot(&rows, params, attribution.as_ref()) {
        Ok(s) => s,
        Err(reason) => {
            let payload = ObservationPayload::ErrorDetail {
                code: "socket_inventory_too_large".to_string(),
                message: reason.clone(),
            };
            let hash = canonical_sha256_hex(&payload).unwrap_or_default();
            return CollectorOutput {
                status: ObservationStatus::TruncatedRejected,
                payload,
                state_hash: hash,
                next_cursor: None,
                partial_reasons: vec![reason],
            };
        }
    };

    if snapshot.partial_attribution && status == ObservationStatus::Ok {
        status = ObservationStatus::Partial;
        let unattributed = snapshot
            .sockets
            .iter()
            .filter(|s| s.pid.is_none())
            .count();
        partial_reasons.push(format!(
            "process attribution incomplete: {unattributed} of {} sockets unattributed",
            snapshot.count
        ));
    }

    let payload = ObservationPayload::Snapshot {
        data: serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null),
    };
    let state_hash = canonical_sha256_hex(&snapshot).unwrap_or_default();
    CollectorOutput {
        status,
        payload,
        state_hash,
        next_cursor: None,
        partial_reasons,
    }
}

/// Deterministic hash-stagger helper shared with the engine for tests.
pub fn stagger_phase(host_id: &str, salt: &str, interval_seconds: u64) -> u64 {
    if interval_seconds == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(host_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(salt.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(digest[0..8].try_into().unwrap()) % interval_seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11101 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22202 1 0000000000000000 100 0 0 10 0
   2: 7F000001:9C4A C0A80001:01BB 01 00000000:00000000 02:00000073 00000000  1000        0 33303 3 0000000000000000 21 3 28 10 -1
";

    const TCP6_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44404 1 0000000000000000 100 0 0 10 0
   1: B80D0120000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55505 1 0000000000000000 100 0 0 10 0
";

    const UDP_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 66606 1 0000000000000000 100 0 0 10 0
";

    fn params() -> SocketsListeningParams {
        SocketsListeningParams {
            include_tcp: true,
            include_udp: true,
            include_ipv6: true,
            resolve_process: false,
        }
    }

    #[test]
    fn decodes_hex_endianness_and_ports() {
        assert_eq!(decode_ipv4_hex("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(decode_ipv4_hex("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(decode_port_hex("0016"), Some(22));
        assert_eq!(decode_port_hex("1F90"), Some(8080));
        assert_eq!(decode_ipv6_hex("00000000000000000000000001000000").as_deref(), Some("::1"));
        assert_eq!(
            decode_ipv6_hex("B80D0120000000000000000000000000").as_deref(),
            Some("2001:db8::")
        );
        assert_eq!(decode_ipv6_hex("00000000000000000000000000000000").as_deref(), Some("::"));
        // Malformed inputs are rejected, not guessed.
        assert_eq!(decode_ipv4_hex("0100007"), None);
        assert_eq!(decode_ipv6_hex("0100"), None);
        assert_eq!(decode_port_hex("XYZW"), None);
    }

    #[test]
    fn parses_tcp_table_and_filters_to_listen() {
        let rows = parse_proc_net_table(TCP_FIXTURE, "tcp");
        assert_eq!(rows.len(), 3);
        let listen: Vec<&RawSocketRow> = rows.iter().filter(|r| r.state_hex == "0A").collect();
        assert_eq!(listen.len(), 2);
        assert_eq!(listen[0].local_addr, "127.0.0.1");
        assert_eq!(listen[0].local_port, 22);
        assert_eq!(listen[0].uid, 0);
        assert_eq!(listen[0].inode, 11101);
        assert_eq!(listen[1].local_addr, "0.0.0.0");
        assert_eq!(listen[1].local_port, 8080);
    }

    #[test]
    fn parses_tcp6_table() {
        let rows = parse_proc_net_table(TCP6_FIXTURE, "tcp6");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_addr, "::1");
        assert_eq!(rows[1].local_addr, "2001:db8::");
        assert_eq!(rows[1].local_port, 80);
    }

    #[test]
    fn udp_rows_are_all_bound_sockets() {
        let rows = parse_proc_net_table(UDP_FIXTURE, "udp");
        assert_eq!(rows.len(), 1);
        let snap = build_socket_snapshot(&rows, &params(), None).unwrap();
        assert_eq!(snap.count, 1);
        assert_eq!(snap.sockets[0].protocol, "udp");
        assert_eq!(snap.sockets[0].local_addr, "127.0.0.1");
        assert_eq!(snap.sockets[0].local_port, 53);
    }

    #[test]
    fn snapshot_is_stably_sorted_and_canonically_hashed() {
        let mut rows = parse_proc_net_table(TCP_FIXTURE, "tcp");
        rows.extend(parse_proc_net_table(TCP6_FIXTURE, "tcp6"));
        rows.extend(parse_proc_net_table(UDP_FIXTURE, "udp"));
        let mut snap = build_socket_snapshot(&rows, &params(), None).unwrap();
        let keys: Vec<&String> = snap.sockets.iter().map(|s| &s.socket_key).collect();
        for pair in keys.windows(2) {
            assert!(pair[0] <= pair[1], "socket keys must be stably sorted");
        }
        assert!(snap.sockets.iter().any(|s| s.socket_key.contains("[::1]")));
        let hash1 = canonical_sha256_hex(&snap).unwrap();
        // Reordering input rows must not change the canonical hash.
        rows.reverse();
        let snap2 = build_socket_snapshot(&rows, &params(), None).unwrap();
        let hash2 = canonical_sha256_hex(&snap2).unwrap();
        assert_eq!(hash1, hash2);
        snap.sockets.clear();
        let _ = snap;
    }

    #[test]
    fn table_selection_respects_params() {
        let both = table_paths(true, true, true);
        assert_eq!(both.len(), 4);
        let tcp_only_no_v6 = table_paths(true, false, false);
        assert_eq!(tcp_only_no_v6.len(), 1);
        assert_eq!(tcp_only_no_v6[0].0, "tcp");
        let udp_v6 = table_paths(false, true, true);
        assert_eq!(udp_v6.len(), 2);
        assert!(udp_v6.iter().all(|(p, _)| p.starts_with("udp")));
    }

    #[test]
    fn hard_entry_cap_rejects_instead_of_truncating() {
        let mut rows = Vec::new();
        for i in 0..=(MAX_SOCKET_ENTRIES as u64) {
            rows.push(RawSocketRow {
                protocol: "tcp".into(),
                local_addr: "10.0.0.1".into(),
                local_port: (1024 + (i % 1000)) as u16,
                uid: 0,
                inode: 100_000 + i,
                state_hex: "0A".into(),
            });
        }
        let err = build_socket_snapshot(&rows, &params(), None).unwrap_err();
        assert!(err.contains("hard cap"));
    }

    #[test]
    fn proc_stat_parse_extracts_comm_and_start_ticks() {
        // Realistic /proc/<pid>/stat line; field 22 (starttime) = 9876543.
        let stat = "12345 (my cool proc) R 1 12345 12345 0 -1 4194624 0 0 0 3 2 19 0 0 20 0 9 0 9876543 0 0 0 0";
        assert_eq!(parse_proc_stat_comm(&stat).as_deref(), Some("my cool proc"));
        assert_eq!(parse_proc_stat_start_ticks(&stat), Some(9876543));
        assert_eq!(parse_proc_stat_start_ticks("garbage"), None);
    }

    #[test]
    fn stagger_phase_is_deterministic_and_bounded() {
        let a = stagger_phase("edge-01", "w1", 15);
        let b = stagger_phase("edge-01", "w1", 15);
        assert_eq!(a, b);
        assert!(a < 15);
        // Different watches spread out (anti-thundering-herd property).
        let phases: Vec<u64> = (0..8).map(|i| stagger_phase("edge-01", &format!("w{i}"), 15)).collect();
        assert!(phases.iter().filter(|p| **p == a).count() < phases.len());
    }

    #[tokio::test]
    async fn real_local_probe_handles_partial_attribution_cleanly() {
        // Real host probe: must never fail, and partial attribution must be
        // an explicit `Partial` status with a clear reason, never silent.
        let cfg = EdgeSafetyConfig::default();
        let p = SocketsListeningParams {
            include_tcp: true,
            include_udp: true,
            include_ipv6: true,
            resolve_process: true,
        };
        let out = collect_sockets(&p, &cfg).await;
        assert!(
            out.status == ObservationStatus::Ok || out.status == ObservationStatus::Partial,
            "unexpected status {:?}",
            out.status
        );
        assert_eq!(out.state_hash.len(), 64);
        if out.status == ObservationStatus::Partial {
            assert!(!out.partial_reasons.is_empty(), "Partial needs explicit reasons");
        }
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: SocketsListeningSnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.count, snap.sockets.len());
        if snap.partial_attribution {
            assert!(out.status == ObservationStatus::Partial);
        }
    }
}

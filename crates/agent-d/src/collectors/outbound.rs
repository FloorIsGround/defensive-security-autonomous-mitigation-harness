//! `connections.outbound`: grouped outbound flow inventory parsed from
//! `/proc/net/{tcp,tcp6,udp,udp6}` with best-effort inode-to-process
//! attribution.
//!
//! Safety properties (mirroring `sockets.rs`):
//! - Never escalates privileges; unreadable `/proc/<pid>/fd` trees downgrade
//!   the observation to `Partial` with explicit reasons.
//! - No shelling out; pure `/proc` parsing shared with `sockets.listening`.
//! - Local ephemeral ports and PIDs are excluded from flow identity: they
//!   churn and would make snapshots unstable. Sockets are grouped by
//!   `<proto>:<remote_addr>:<remote_port>:<uid>:<comm or '?'>`.
//! - `LISTEN`, TCP `TIME_WAIT`/`CLOSE`, unconnected (zero-address) remotes,
//!   and — optionally — loopback remotes are excluded as noise.
//! - More flow groups than the cap produces an explicit `Partial` sample
//!   carrying `truncated: true` and the omitted count; never a silently
//!   truncated, apparently-complete snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::observation::{
    ConnectionsOutboundSnapshot, FlowAttribution, ObservationPayload, ObservationStatus,
    OutboundFlowEntry,
};
use defsec_protocol::watch::{ConnectionsOutboundParams, OUTBOUND_FLOWS_DEFAULT, OUTBOUND_FLOWS_HARD_MAX};

use super::sockets::{parse_proc_net_table, table_paths, ProcessAttribution, RawSocketRow};
use super::CollectorOutput;

/// TCP `LISTEN` state code in `/proc/net/tcp*`.
const TCP_STATE_LISTEN: &str = "0A";
/// TCP `TIME_WAIT` state code (transient kernel cleanup noise).
const TCP_STATE_TIME_WAIT: &str = "06";
/// TCP `CLOSE` state code.
const TCP_STATE_CLOSE: &str = "07";

/// Map a `/proc/net` state hex code to its canonical kernel name.
/// Unknown codes are reported as the raw hex string, never guessed.
pub fn proc_net_state_name(state_hex: &str) -> &str {
    match state_hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        other => other,
    }
}

fn is_excluded_tcp_state(state_hex: &str) -> bool {
    matches!(state_hex, TCP_STATE_LISTEN | TCP_STATE_TIME_WAIT | TCP_STATE_CLOSE)
}

/// True when the remote endpoint address is the unspecified (unconnected)
/// address `0.0.0.0` / `::`.
fn is_unspecified_remote(remote_addr: &str) -> bool {
    remote_addr
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified())
}

/// True when the remote endpoint address is loopback (`127.0.0.0/8`, `::1`,
/// including IPv4-mapped forms).
fn is_loopback_remote(remote_addr: &str) -> bool {
    remote_addr
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Effective retained-flow cap: the watch parameter (or default), clamped
/// by the protocol hard max and the local safety floor.
pub fn effective_flow_cap(params: &ConnectionsOutboundParams, cfg: &EdgeSafetyConfig) -> u32 {
    params
        .max_flows
        .unwrap_or(OUTBOUND_FLOWS_DEFAULT)
        .min(OUTBOUND_FLOWS_HARD_MAX)
        .min(cfg.max_outbound_flows)
        .max(1)
}

#[derive(Debug, Clone)]
struct FlowGroupAccumulator {
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    uid: u32,
    states: BTreeSet<String>,
    count: u32,
    comm: Option<String>,
    systemd_units: BTreeSet<String>,
    attributed: u32,
}

/// Stable flow identity: `<proto>:<remote_addr>:<remote_port>:<uid>:<comm or '?'>`.
/// Deterministically excludes protocol-varying local details (ephemeral
/// local port, PID, inode).
pub fn flow_key(protocol: &str, remote_addr: &str, remote_port: u16, uid: u32, comm: Option<&str>) -> String {
    format!(
        "{protocol}:{remote_addr}:{remote_port}:{uid}:{}",
        comm.unwrap_or("?")
    )
}

/// Build the normalized snapshot from raw rows. Pure and deterministic:
/// identical rows in any input order produce an identical canonical hash.
///
/// Per-flow `attribution` is `full`/`partial`/`none` according to how many
/// of the group's sockets resolved to a process; the top-level
/// `attribution_partial` mirrors `sockets.listening` (any unattributed
/// socket or a permission-denied `/proc` scan flags the whole sample).
pub fn build_outbound_snapshot(
    rows: &[RawSocketRow],
    params: &ConnectionsOutboundParams,
    attribution: Option<&ProcessAttribution>,
    max_flows: u32,
) -> ConnectionsOutboundSnapshot {
    let mut groups: BTreeMap<String, FlowGroupAccumulator> = BTreeMap::new();
    let mut any_unattributed = false;

    for row in rows {
        if row.protocol.starts_with("tcp") && is_excluded_tcp_state(&row.state_hex) {
            continue;
        }
        if is_unspecified_remote(&row.remote_addr) {
            continue;
        }
        if params.exclude_loopback && is_loopback_remote(&row.remote_addr) {
            continue;
        }

        let info = attribution.and_then(|a| a.by_inode.get(&row.inode));
        let comm = info.and_then(|p| (!p.comm.is_empty()).then(|| p.comm.clone()));
        if info.is_none() {
            any_unattributed = true;
        }

        let key = flow_key(
            &row.protocol,
            &row.remote_addr,
            row.remote_port,
            row.uid,
            comm.as_deref(),
        );
        let acc = groups.entry(key).or_insert_with(|| FlowGroupAccumulator {
            protocol: row.protocol.clone(),
            remote_addr: row.remote_addr.clone(),
            remote_port: row.remote_port,
            uid: row.uid,
            states: BTreeSet::new(),
            count: 0,
            comm: comm.clone(),
            systemd_units: BTreeSet::new(),
            attributed: 0,
        });
        acc.states.insert(proc_net_state_name(&row.state_hex).to_string());
        acc.count += 1;
        if let Some(p) = info {
            acc.attributed += 1;
            if let Some(unit) = &p.systemd_unit {
                acc.systemd_units.insert(unit.clone());
            }
        }
    }

    let total_flows = groups.len() as u32;
    let mut flows: Vec<OutboundFlowEntry> = Vec::with_capacity(groups.len().min(max_flows as usize));
    for (key, acc) in groups {
        if (flows.len() as u32) >= max_flows {
            break;
        }
        let attribution = if acc.attributed == acc.count && acc.attributed > 0 {
            FlowAttribution::Full
        } else if acc.attributed > 0 {
            FlowAttribution::Partial
        } else {
            FlowAttribution::None
        };
        flows.push(OutboundFlowEntry {
            flow_key: key,
            protocol: acc.protocol,
            remote_addr: acc.remote_addr,
            remote_port: acc.remote_port,
            uid: acc.uid,
            states: acc.states.into_iter().collect(),
            count: acc.count,
            comm: acc.comm,
            systemd_unit: if acc.systemd_units.len() == 1 {
                acc.systemd_units.into_iter().next()
            } else {
                None
            },
            attribution,
        });
    }

    // `flows` came from a BTreeMap iteration, so it is stably sorted by key.

    let omitted_flows = total_flows.saturating_sub(flows.len() as u32);
    let truncated = omitted_flows > 0;

    // Any unattributed socket (including in omitted groups) or a
    // permission-denied scan downgrades attribution exactly like
    // `sockets.listening`.
    let attribution_partial = params.resolve_process
        && attribution
            .map(|a| a.permission_denied || any_unattributed)
            .unwrap_or(true);

    ConnectionsOutboundSnapshot {
        flows,
        total_flows,
        attribution_partial,
        truncated: truncated.then_some(true),
        omitted_flows: truncated.then_some(omitted_flows),
    }
}

/// Collect a `connections.outbound` observation from the live host.
pub async fn collect_outbound(
    params: &ConnectionsOutboundParams,
    cfg: &EdgeSafetyConfig,
) -> CollectorOutput {
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
        Some(super::sockets::scan_proc_processes())
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

    let max_flows = effective_flow_cap(params, cfg);
    let snapshot = build_outbound_snapshot(&rows, params, attribution.as_ref(), max_flows);

    if let Some(omitted) = snapshot.omitted_flows
        && omitted > 0
        && status == ObservationStatus::Ok
    {
        status = ObservationStatus::Partial;
        partial_reasons.push(format!(
            "outbound flow inventory of {} groups exceeds cap {max_flows}: retained the first {max_flows} by flow key and omitted {omitted}",
            snapshot.total_flows
        ));
    }
    if snapshot.attribution_partial && status == ObservationStatus::Ok {
        status = ObservationStatus::Partial;
        let unattributed = rows.len().saturating_sub(
            rows.iter()
                .filter(|r| attribution.as_ref().is_some_and(|a| a.by_inode.contains_key(&r.inode)))
                .count(),
        );
        partial_reasons.push(format!(
            "process attribution incomplete: {unattributed} of {} sockets unattributed",
            rows.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::watch::CollectorType;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Fixture rows across protocols and states. Address encodings follow
    /// the kernel's little-endian per-32-bit-word printing (e.g. 192.168.0.1
    /// prints as 0100A8C0, and 2001:db8::1 as B80D0120...01000000).
    fn fixture_rows() -> Vec<RawSocketRow> {
        let raw_tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    0: 0100007F:9C4A 0100A8C0:01BB 01 00000000:00000000 02:00000073 00000000  1000        0 33303 3 0000000000000000 21 3 28 10 -1
    1: 0100007F:9C4B 0100A8C0:01BB 01 00000000:00000000 02:00000074 00000000  1000        0 33304 3 0000000000000000 21 3 28 10 -1
    2: 0100007F:9C4C 0100007F:0050 01 00000000:00000000 02:00000075 00000000  1000        0 33305 3 0000000000000000 21 3 28 10 -1
    3: 00000000:9C4D 0200A8C0:01BB 06 00000000:00000000 02:00000076 00000000  1000        0 33306 3 0000000000000000 21 3 28 10 -1
    4: 00000000:9C4E 0300A8C0:01BB 07 00000000:00000000 02:00000077 00000000  1000        0 33307 3 0000000000000000 21 3 28 10 -1
    5: 00000000:0016 00000000:0000 0A 00000000:00000000 02:00000078 00000000     0        0 33308 1 0000000000000000 100 0 0 10 0
";
        let raw_tcp6 = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    0: 00000000000000000000000001000000:9C4A B80D0120000000000000000001000000:0050 01 00000000:00000000 02:00000079 00000000  1000        0 33309 3 0000000000000000 21 3 28 10 -1
    1: 00000000000000000000000000000000:9C4B 00000000000000000000000000000000:0000 07 00000000:00000000 02:0000007A 00000000  1000        0 33310 3 0000000000000000 21 3 28 10 -1
";
        let raw_udp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    0: 0100007F:9C4A 0100A8C0:0035 01 00000000:00000000 02:0000007B 00000000  1000        0 33311 3 0000000000000000 21 3 28 10 -1
    1: 0100007F:0035 00000000:0000 07 00000000:00000000 02:0000007C 00000000     0        0 33312 1 0000000000000000 100 0 0 10 0
";
        let mut rows = parse_proc_net_table(raw_tcp, "tcp");
        rows.extend(parse_proc_net_table(raw_tcp6, "tcp6"));
        rows.extend(parse_proc_net_table(raw_udp, "udp"));
        rows
    }

    fn params() -> ConnectionsOutboundParams {
        ConnectionsOutboundParams {
            include_tcp: true,
            include_udp: true,
            include_ipv6: true,
            resolve_process: false,
            exclude_loopback: true,
            max_flows: None,
        }
    }

    fn row(protocol: &str, remote_addr: &str, remote_port: u16, uid: u32, inode: u64, state: &str) -> RawSocketRow {
        RawSocketRow {
            protocol: protocol.into(),
            local_addr: "10.0.0.1".into(),
            local_port: 40000,
            remote_addr: remote_addr.into(),
            remote_port,
            uid,
            inode,
            state_hex: state.into(),
        }
    }

    #[test]
    fn decodes_fixture_endpoints() {
        let rows = fixture_rows();
        // tcp row 0: remote C0A80001 -> 192.168.0.1:443
        assert_eq!(rows[0].remote_addr, "192.168.0.1");
        assert_eq!(rows[0].remote_port, 443);
        assert_eq!(
            rows[0].remote_addr.parse::<IpAddr>().unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))
        );
        // tcp6 row: remote B80D0120... -> 2001:db8::1:80
        let tcp6 = rows.iter().find(|r| r.protocol == "tcp6").unwrap();
        assert_eq!(tcp6.remote_addr, "2001:db8::1");
        assert_eq!(tcp6.remote_port, 80);
        assert_eq!(
            tcp6.remote_addr.parse::<IpAddr>().unwrap(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn excludes_listen_timewait_close_unconnected_and_loopback() {
        let rows = fixture_rows();
        let snap = build_outbound_snapshot(&rows, &params(), None, 256);
        // Remaining: 2x tcp -> 192.168.0.1:443 (grouped), 1x tcp6, 1x udp;
        // loopback tcp row (127.0.0.1:80) and all noise rows are excluded.
        assert_eq!(snap.total_flows, 3, "flows: {:#?}", snap.flows);
        assert!(!snap.flows.iter().any(|f| f.remote_addr == "127.0.0.1"));
        assert!(snap.flows.iter().any(|f| f.protocol == "tcp6" && f.remote_addr == "2001:db8::1"));
        assert!(snap.flows.iter().any(|f| f.protocol == "udp" && f.remote_port == 53));

        // Loopback exclusion is a toggle.
        let mut keep_loopback = params();
        keep_loopback.exclude_loopback = false;
        let snap = build_outbound_snapshot(&rows, &keep_loopback, None, 256);
        assert_eq!(snap.total_flows, 4);
        assert!(snap.flows.iter().any(|f| f.remote_addr == "127.0.0.1" && f.remote_port == 80));

        // Protocol selection happens through the table choice at collect
        // time (`table_paths`); the pure builder sees only the selected rows.
        let udp_rows: Vec<RawSocketRow> = rows
            .iter()
            .filter(|r| r.protocol.starts_with("udp"))
            .cloned()
            .collect();
        let snap = build_outbound_snapshot(&udp_rows, &params(), None, 256);
        assert_eq!(snap.total_flows, 1);
        assert_eq!(snap.flows[0].protocol, "udp");
    }

    #[test]
    fn groups_sockets_by_flow_key_with_sorted_states() {
        let rows = fixture_rows();
        let snap = build_outbound_snapshot(&rows, &params(), None, 256);
        let group = snap
            .flows
            .iter()
            .find(|f| f.flow_key == "tcp:192.168.0.1:443:1000:?")
            .expect("grouped flow key");
        assert_eq!(group.count, 2);
        assert_eq!(group.states, vec!["ESTABLISHED".to_string()]);
        assert_eq!(group.protocol, "tcp");
        assert_eq!(group.remote_port, 443);
        assert_eq!(group.uid, 1000);
        assert_eq!(group.comm, None);
        assert_eq!(group.attribution, FlowAttribution::None);

        // Multiple distinct states sort uniquely within one group.
        let mixed = vec![
            row("tcp", "192.0.2.9", 443, 7, 1, "08"),
            row("tcp", "192.0.2.9", 443, 7, 2, "01"),
            row("tcp", "192.0.2.9", 443, 7, 3, "0B"),
            row("tcp", "192.0.2.9", 443, 7, 4, "01"),
            row("tcp", "192.0.2.9", 443, 7, 5, "ZZ"),
        ];
        let snap = build_outbound_snapshot(&mixed, &params(), None, 256);
        assert_eq!(snap.flows[0].count, 5);
        assert_eq!(
            snap.flows[0].states,
            vec![
                "CLOSE_WAIT".to_string(),
                "CLOSING".to_string(),
                "ESTABLISHED".to_string(),
                "ZZ".to_string(),
            ]
        );
    }

    #[test]
    fn deterministic_truncation_keeps_first_max_flows_by_key() {
        let mut rows = Vec::new();
        for i in 0..10u32 {
            rows.push(row("tcp", &format!("192.0.2.{i}"), 443, 1000, 500 + i as u64, "01"));
        }
        let snap = build_outbound_snapshot(&rows, &params(), None, 4);
        assert_eq!(snap.total_flows, 10);
        assert_eq!(snap.flows.len(), 4);
        assert_eq!(snap.truncated, Some(true));
        assert_eq!(snap.omitted_flows, Some(6));
        // Deterministic retention: the first four flow keys in sorted order.
        let keys: Vec<&str> = snap.flows.iter().map(|f| f.flow_key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "tcp:192.0.2.0:443:1000:?",
                "tcp:192.0.2.1:443:1000:?",
                "tcp:192.0.2.2:443:1000:?",
                "tcp:192.0.2.3:443:1000:?",
            ]
        );
        // Reordering input does not change the canonical result.
        let mut shuffled = rows.clone();
        shuffled.reverse();
        let snap2 = build_outbound_snapshot(&shuffled, &params(), None, 4);
        assert_eq!(snap, snap2);
        assert_eq!(
            canonical_sha256_hex(&snap).unwrap(),
            canonical_sha256_hex(&snap2).unwrap()
        );

        // No truncation fields when everything fits.
        let full = build_outbound_snapshot(&rows, &params(), None, 10);
        assert_eq!(full.truncated, None);
        assert_eq!(full.omitted_flows, None);
        assert_eq!(full.total_flows, 10);
    }

    #[test]
    fn attribution_full_partial_none_and_top_level_flag() {
        let rows = vec![
            row("tcp", "192.0.2.1", 443, 100, 1, "01"),
            row("tcp", "192.0.2.9", 443, 100, 2, "01"),
            row("tcp", "192.0.2.9", 443, 100, 3, "01"),
            row("tcp", "192.0.2.3", 443, 100, 4, "01"),
            row("tcp", "192.0.2.3", 443, 100, 5, "01"),
            row("tcp", "192.0.2.4", 443, 100, 6, "01"),
        ];
        let mut attribution = ProcessAttribution {
            by_inode: BTreeMap::new(),
            permission_denied: true,
            scanned_pids: 6,
        };
        let info = |comm: &str, unit: Option<&str>| super::super::sockets::ProcessInfo {
            pid: 42,
            pid_start_time_ticks: 7,
            comm: comm.into(),
            systemd_unit: unit.map(str::to_string),
        };
        attribution.by_inode.insert(1, info("curl", Some("curl.service")));
        attribution.by_inode.insert(2, info("curl", Some("unit-a.service")));
        attribution.by_inode.insert(3, info("curl", Some("unit-b.service")));
        // An attributed socket whose comm could not be read groups under '?'
        // together with unattributed sockets: that group is Partial.
        attribution.by_inode.insert(4, info("", None));
        // inode 5 and 6 have no attribution entry.

        let mut p = params();
        p.resolve_process = true;
        let snap = build_outbound_snapshot(&rows, &p, Some(&attribution), 256);

        let full = snap.flows.iter().find(|f| f.remote_addr == "192.0.2.1").unwrap();
        assert_eq!(full.flow_key, "tcp:192.0.2.1:443:100:curl");
        assert_eq!(full.attribution, FlowAttribution::Full);
        assert_eq!(full.comm.as_deref(), Some("curl"));
        assert_eq!(full.systemd_unit.as_deref(), Some("curl.service"));

        // Two attributed sockets with the same comm but different units stay
        // in one group; the ambiguous unit is dropped, never guessed.
        let mixed_units = snap.flows.iter().find(|f| f.remote_addr == "192.0.2.9").unwrap();
        assert_eq!(mixed_units.count, 2);
        assert_eq!(mixed_units.attribution, FlowAttribution::Full);
        assert_eq!(mixed_units.systemd_unit, None);

        // The '?':keyed group mixes one attributed (unreadable comm) and one
        // unattributed socket: explicitly Partial.
        let partial = snap.flows.iter().find(|f| f.remote_addr == "192.0.2.3").unwrap();
        assert_eq!(partial.count, 2);
        assert_eq!(partial.attribution, FlowAttribution::Partial);
        assert_eq!(partial.comm, None);
        assert_eq!(partial.flow_key, "tcp:192.0.2.3:443:100:?");

        let none = snap.flows.iter().find(|f| f.remote_addr == "192.0.2.4").unwrap();
        assert_eq!(none.attribution, FlowAttribution::None);
        assert_eq!(none.comm, None);
        assert_eq!(none.flow_key, "tcp:192.0.2.4:443:100:?");

        // Top-level: unattributed sockets AND the permission-denied scan
        // both flag partial attribution when resolution was requested.
        assert!(snap.attribution_partial);

        // Without resolution requested, attribution is explicitly "none"
        // everywhere and never flags partial.
        let snap = build_outbound_snapshot(&rows, &params(), None, 256);
        assert!(!snap.attribution_partial);
        assert!(snap.flows.iter().all(|f| f.attribution == FlowAttribution::None));

        // A scan that attributed every socket (with readable comms) is fully
        // attributed, and unit presence alone does not flag partial.
        let mut full_map = attribution.by_inode.clone();
        full_map.insert(5, info("wget", None));
        full_map.insert(6, info("wget", None));
        let complete = ProcessAttribution {
            by_inode: full_map,
            permission_denied: false,
            scanned_pids: 6,
        };
        let snap = build_outbound_snapshot(&rows, &p, Some(&complete), 256);
        assert!(!snap.attribution_partial);
    }

    #[test]
    fn effective_flow_cap_is_bounded_by_floor() {
        let cfg = EdgeSafetyConfig::default();
        assert_eq!(effective_flow_cap(&params(), &cfg), OUTBOUND_FLOWS_DEFAULT);
        let mut p = params();
        p.max_flows = Some(1024);
        // The default local floor (512) clamps even a hard-max parameter.
        assert_eq!(effective_flow_cap(&p, &cfg), 512);
        let mut wide = cfg.clone();
        wide.max_outbound_flows = 4096;
        assert_eq!(effective_flow_cap(&p, &wide), 1024, "protocol hard max applies");
        let mut tight = cfg.clone();
        tight.max_outbound_flows = 64;
        p.max_flows = None;
        assert_eq!(effective_flow_cap(&p, &tight), 64);
        p.max_flows = Some(2000);
        assert_eq!(effective_flow_cap(&p, &tight), 64, "hard max wins over the parameter");
    }

    #[tokio::test]
    async fn live_local_probe_smoke() {
        // Real host probe: must never fail hard; /proc/net is readable on
        // this class of host. Partial attribution is explicit, never silent.
        let cfg = EdgeSafetyConfig::default();
        let p = params();
        let out = collect_outbound(&p, &cfg).await;
        assert!(
            out.status == ObservationStatus::Ok || out.status == ObservationStatus::Partial,
            "unexpected status {:?}",
            out.status
        );
        assert_eq!(out.state_hash.len(), 64);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: ConnectionsOutboundSnapshot = serde_json::from_value(data.clone()).unwrap();
        assert!(snap.total_flows >= snap.flows.len() as u32);
        if snap.attribution_partial {
            assert_eq!(out.status, ObservationStatus::Partial);
            assert!(!out.partial_reasons.is_empty(), "Partial needs explicit reasons");
        }
        // Snapshot collector: no cursor semantics.
        assert_eq!(out.next_cursor, None);
        // Flow keys never leak local ephemeral ports or PIDs, and no
        // listening sockets slipped through.
        for flow in &snap.flows {
            assert!(flow.flow_key.starts_with(&format!("{}:", flow.protocol)));
            assert!(!flow.states.iter().any(|s| s == "LISTEN"));
        }
        assert!(!CollectorType::ConnectionsOutbound.is_stream());
    }
}

//! `packages.inventory`: installed-package inventory parsed from the
//! Debian/Ubuntu dpkg status file (`/var/lib/dpkg/status`).
//!
//! Safety properties:
//! - Zero root required: the status file is world-readable by default.
//! - No shelling out to dpkg; pure stanza parsing with explicit states.
//! - Hard read cap of 32 MiB: an over-cap file is an explicit `Error`
//!   sample, never a partial parse that pretends to be complete.
//! - Malformed stanzas are skipped and counted, never silently dropped.
//! - Over-cap package counts produce an explicit `Partial` sample carrying
//!   `truncated: true` and the omitted count.

use std::io::Read;
use std::path::Path;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::canonical::{canonical_sha256_hex, sha256_hex};
use defsec_protocol::observation::{
    ObservationPayload, ObservationStatus, PackageInventoryEntry, PackagesInventorySnapshot,
};
use defsec_protocol::watch::{PackagesInventoryParams, PACKAGES_INVENTORY_DEFAULT, PACKAGES_INVENTORY_HARD_MAX};

use super::CollectorOutput;

/// Default dpkg status database path.
pub const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";
/// Hard read cap for the status file (32 MiB). Over-cap files are rejected
/// outright instead of partially parsed.
pub const MAX_STATUS_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Effective retained-package cap: the watch parameter (or default),
/// clamped by the protocol hard max and the local safety floor.
pub fn effective_package_cap(params: &PackagesInventoryParams, cfg: &EdgeSafetyConfig) -> u32 {
    params
        .max_packages
        .unwrap_or(PACKAGES_INVENTORY_DEFAULT)
        .min(PACKAGES_INVENTORY_HARD_MAX)
        .min(cfg.max_packages)
        .max(1)
}

/// Parse result of one dpkg status database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDpkgStatus {
    /// Installed packages, sorted by `package_key` then `version`.
    pub installed: Vec<PackageInventoryEntry>,
    /// Number of stanzas that failed to parse and were skipped.
    pub malformed_stanzas: u32,
    /// Number of stanzas read in total.
    pub total_stanzas: u32,
}

/// True when a dpkg `Status:` value selects an installed package
/// (`... installed`; `half-installed` and friends do not match).
pub fn is_installed_status(status_value: &str) -> bool {
    status_value.ends_with(" installed")
}

/// One parsed stanza: ordered fields plus a malformed marker set when any
/// line violated the debcontrol syntax.
struct Stanza {
    fields: Vec<(String, String)>,
    malformed: bool,
}

impl Stanza {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Parse a dpkg status database (debcontrol/RFC822-style stanzas separated
/// by blank lines; continuation lines start with a space or tab).
///
/// A stanza is malformed — counted and skipped — when any line violates the
/// field-line syntax, when it lacks a `Package` or `Status` field, or when
/// an installed stanza lacks a `Version`. A missing `Architecture` is
/// tolerated as `"unknown"` (pre-multi-arch databases).
pub fn parse_dpkg_status(text: &str) -> ParsedDpkgStatus {
    let mut stanzas: Vec<Stanza> = Vec::new();
    let mut current = Stanza {
        fields: Vec::new(),
        malformed: false,
    };
    let mut opened = false;

    for line in text.lines() {
        if line.trim().is_empty() {
            if opened {
                stanzas.push(Stanza {
                    fields: std::mem::take(&mut current.fields),
                    malformed: current.malformed,
                });
                current.malformed = false;
                opened = false;
            }
            continue;
        }
        opened = true;
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of the previous field — or malformed if it opens
            // a stanza.
            match current.fields.last_mut() {
                Some((_, value)) => {
                    let stripped = line.trim_start_matches([' ', '\t']);
                    value.push('\n');
                    value.push_str(stripped);
                }
                None => current.malformed = true,
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            current.malformed = true;
            continue;
        };
        if name.is_empty() || name.contains(' ') {
            current.malformed = true;
            continue;
        }
        current
            .fields
            .push((name.to_string(), value.trim().to_string()));
    }
    if opened {
        stanzas.push(current);
    }

    let mut installed: Vec<PackageInventoryEntry> = Vec::new();
    let mut malformed_stanzas = 0u32;
    for stanza in &stanzas {
        let installed_selected = stanza
            .get("Status")
            .is_some_and(is_installed_status);
        let valid = !stanza.malformed
            && stanza.get("Package").is_some()
            && stanza.get("Status").is_some()
            && (!installed_selected || stanza.get("Version").is_some());
        if !valid {
            malformed_stanzas += 1;
            continue;
        }
        if !installed_selected {
            continue;
        }
        let name = stanza.get("Package").unwrap_or_default();
        let arch = stanza.get("Architecture").unwrap_or("unknown");
        installed.push(PackageInventoryEntry {
            package_key: format!("{name}:{arch}"),
            name: name.to_string(),
            arch: arch.to_string(),
            version: stanza.get("Version").unwrap_or_default().to_string(),
        });
    }
    installed.sort();

    ParsedDpkgStatus {
        installed,
        malformed_stanzas,
        total_stanzas: stanzas.len() as u32,
    }
}

/// Build the normalized snapshot from parsed entries, applying the
/// deterministic retention rule (sorted by `package_key`, keep the first
/// `max_packages`).
pub fn build_packages_snapshot(
    parsed: &ParsedDpkgStatus,
    status_file_sha256: String,
    max_packages: u32,
) -> PackagesInventorySnapshot {
    let total_packages = parsed.installed.len() as u32;
    let kept = &parsed.installed[..(max_packages as usize).min(parsed.installed.len())];
    let omitted_packages = total_packages.saturating_sub(kept.len() as u32);
    let truncated = omitted_packages > 0;
    PackagesInventorySnapshot {
        packages: kept.to_vec(),
        total_packages,
        status_file_sha256,
        malformed_stanzas: parsed.malformed_stanzas,
        truncated: truncated.then_some(true),
        omitted_packages: truncated.then_some(omitted_packages),
    }
}

fn error_output(code: &str, message: String, status: ObservationStatus) -> CollectorOutput {
    let payload = ObservationPayload::ErrorDetail {
        code: code.to_string(),
        message: message.clone(),
    };
    let hash = canonical_sha256_hex(&payload).unwrap_or_default();
    CollectorOutput {
        status,
        payload,
        state_hash: hash,
        next_cursor: None,
        partial_reasons: vec![message],
    }
}

/// Collect a `packages.inventory` observation from `path` (the real dpkg
/// status file; injectable for tests).
pub async fn collect_packages_from(
    params: &PackagesInventoryParams,
    cfg: &EdgeSafetyConfig,
    path: &Path,
) -> CollectorOutput {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return error_output(
                "status_file_missing",
                format!("dpkg status file {} not found (non-Debian host?)", path.display()),
                ObservationStatus::NotFound,
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return error_output(
                "status_file_unreadable",
                format!("permission denied reading {}", path.display()),
                ObservationStatus::PermissionDenied,
            );
        }
        Err(e) => {
            return error_output(
                "status_file_open_failed",
                format!("failed opening {}: {e}", path.display()),
                ObservationStatus::Error,
            );
        }
    };

    // Enforce the hard read cap on the bytes actually read (no TOCTOU with
    // a pre-stat): read at most cap+1 bytes and reject over-cap results.
    let mut bytes = Vec::new();
    let mut limited = file.take((MAX_STATUS_FILE_BYTES + 1) as u64);
    if let Err(e) = limited.read_to_end(&mut bytes) {
        return error_output(
            "status_file_read_failed",
            format!("failed reading {}: {e}", path.display()),
            ObservationStatus::Error,
        );
    }
    if bytes.len() > MAX_STATUS_FILE_BYTES {
        return error_output(
            "status_file_too_large",
            format!(
                "dpkg status file {} exceeds the hard read cap of {} bytes; refusing a partial parse",
                path.display(),
                MAX_STATUS_FILE_BYTES
            ),
            ObservationStatus::Error,
        );
    }

    let status_file_sha256 = sha256_hex(&bytes);
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };
    let parsed = parse_dpkg_status(&text);

    let max_packages = effective_package_cap(params, cfg);
    let snapshot = build_packages_snapshot(&parsed, status_file_sha256, max_packages);

    let mut partial_reasons = Vec::new();
    let mut status = ObservationStatus::Ok;
    if let Some(omitted) = snapshot.omitted_packages
        && omitted > 0
    {
        status = ObservationStatus::Partial;
        partial_reasons.push(format!(
            "installed package inventory of {} entries exceeds cap {max_packages}: retained the first {max_packages} by package key and omitted {omitted}",
            snapshot.total_packages
        ));
    }
    if snapshot.malformed_stanzas > 0 {
        status = ObservationStatus::Partial;
        partial_reasons.push(format!(
            "{} of {} stanzas in {} were malformed and skipped",
            snapshot.malformed_stanzas,
            parsed.total_stanzas,
            path.display()
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

/// Collect a `packages.inventory` observation from the live host's dpkg
/// status database.
pub async fn collect_packages(
    params: &PackagesInventoryParams,
    cfg: &EdgeSafetyConfig,
) -> CollectorOutput {
    collect_packages_from(params, cfg, Path::new(DPKG_STATUS_PATH)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::watch::CollectorType;

    const STATUS_FIXTURE: &str = "\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2ubuntu3

Package: old-config
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: half-installed-pkg
Status: install ok half-installed
Architecture: amd64
Version: 2.0

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.39-0ubuntu8

Package: libc6
Status: install ok installed
Architecture: i386
Version: 2.39-0ubuntu8

Package: wget
Status: install ok installed
Architecture: all
Version: 1.21.4-1ubuntu4
Description: retrieves files from the web
 This is a continuation line that must not
 break the stanza parse.
";

    fn params() -> PackagesInventoryParams {
        PackagesInventoryParams { max_packages: None }
    }

    fn cfg() -> EdgeSafetyConfig {
        EdgeSafetyConfig::default()
    }

    #[test]
    fn parses_installed_packages_and_excludes_other_states() {
        let parsed = parse_dpkg_status(STATUS_FIXTURE);
        assert_eq!(parsed.total_stanzas, 6);
        assert_eq!(parsed.malformed_stanzas, 0);
        // deinstall/config-files and half-installed are excluded; the two
        // libc6 architectures are both installed (multi-arch).
        let names: Vec<&str> = parsed.installed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["bash", "libc6", "libc6", "wget"]);
        let keys: Vec<&str> = parsed
            .installed
            .iter()
            .map(|p| p.package_key.as_str())
            .collect();
        assert_eq!(keys, vec!["bash:amd64", "libc6:amd64", "libc6:i386", "wget:all"]);
        assert_eq!(parsed.installed[0].version, "5.2.15-2ubuntu3");
        assert!(parsed.installed.iter().all(|p| p.name != "old-config"));
        assert!(parsed.installed.iter().all(|p| p.name != "half-installed-pkg"));
        // The multi-line Description continuation was part of wget's stanza.
        assert_eq!(parsed.total_stanzas - parsed.installed.len() as u32, 2);
    }

    #[test]
    fn installed_status_suffix_is_strict() {
        assert!(is_installed_status("install ok installed"));
        assert!(is_installed_status("hold ok installed"));
        assert!(!is_installed_status("install ok half-installed"));
        assert!(!is_installed_status("deinstall ok config-files"));
        assert!(!is_installed_status("purge ok not-installed"));
        assert!(!is_installed_status("install ok unpacked"));
    }

    #[test]
    fn malformed_stanzas_are_counted_and_skipped() {
        let text = "\
Package: good
Status: install ok installed
Architecture: amd64
Version: 1.0

this line has no colon at all

Package:
Status: install ok installed

Package: missing-status
Architecture: amd64

Package: no-version
Status: install ok installed
Architecture: amd64

 leading continuation with no opener

Package: empty-arch
Status: install ok installed
Version: 9.9
";
        let parsed = parse_dpkg_status(text);
        assert_eq!(parsed.total_stanzas, 7);
        assert_eq!(parsed.malformed_stanzas, 5, "no-colon, empty Package field name, missing Status, installed without Version, orphan continuation");
        assert_eq!(parsed.installed.len(), 2, "good and empty-arch survive");
        // A missing Architecture is tolerated as 'unknown' (pre-multi-arch).
        let empty_arch = parsed.installed.iter().find(|p| p.name == "empty-arch").unwrap();
        assert_eq!(empty_arch.arch, "unknown");
        assert_eq!(empty_arch.package_key, "empty-arch:unknown");
    }

    #[test]
    fn build_snapshot_truncates_deterministically() {
        let parsed = parse_dpkg_status(STATUS_FIXTURE);
        let snap = build_packages_snapshot(&parsed, "ab".repeat(32), 3);
        assert_eq!(snap.total_packages, 4);
        assert_eq!(snap.packages.len(), 3);
        assert_eq!(snap.truncated, Some(true));
        assert_eq!(snap.omitted_packages, Some(1));
        assert_eq!(snap.packages[0].package_key, "bash:amd64");
        assert_eq!(snap.packages[2].package_key, "libc6:i386");
        assert_eq!(snap.malformed_stanzas, 0);

        let full = build_packages_snapshot(&parsed, "ab".repeat(32), 4096);
        assert_eq!(full.truncated, None);
        assert_eq!(full.omitted_packages, None);
        assert_eq!(full.total_packages, 4);
    }

    #[test]
    fn effective_package_cap_is_bounded_by_floor() {
        assert_eq!(effective_package_cap(&params(), &cfg()), PACKAGES_INVENTORY_DEFAULT);
        let mut p = params();
        p.max_packages = Some(16384);
        assert_eq!(effective_package_cap(&p, &cfg()), 16384);
        let mut tight = cfg();
        tight.max_packages = 100;
        p.max_packages = Some(5000);
        assert_eq!(effective_package_cap(&p, &tight), 100);
    }

    fn temp_status_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let dir = super::super::files::temp_root(&format!("packages-{tag}"));
        let path = dir.join("status");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[tokio::test]
    async fn collect_from_fixture_file_is_ok_and_hashed() {
        let path = temp_status_file("ok", STATUS_FIXTURE.as_bytes());
        let out = collect_packages_from(&params(), &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::Ok);
        assert!(out.partial_reasons.is_empty());
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: PackagesInventorySnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.total_packages, 4);
        assert_eq!(snap.packages.len(), 4);
        assert_eq!(snap.status_file_sha256, sha256_hex(STATUS_FIXTURE.as_bytes()));
        assert_eq!(out.state_hash, canonical_sha256_hex(&snap).unwrap());
    }

    #[tokio::test]
    async fn collect_truncation_and_malformed_report_partial() {
        // Cap below the fixture count -> explicit Partial + truncated fields.
        let path = temp_status_file("trunc", STATUS_FIXTURE.as_bytes());
        let mut p = params();
        p.max_packages = Some(2);
        let out = collect_packages_from(&p, &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::Partial);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: PackagesInventorySnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.truncated, Some(true));
        assert_eq!(snap.omitted_packages, Some(2));
        assert!(out.partial_reasons.iter().any(|r| r.contains("exceeds cap")));

        // Malformed stanzas downgrade to Partial with an explicit reason.
        let malformed =
            "Package: ok\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n\nnot a field line\n";
        let path = temp_status_file("malformed", malformed.as_bytes());
        let out = collect_packages_from(&params(), &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::Partial);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: PackagesInventorySnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.malformed_stanzas, 1);
        assert_eq!(snap.total_packages, 1);
        assert!(out.partial_reasons.iter().any(|r| r.contains("malformed")));
    }

    #[tokio::test]
    async fn over_cap_file_is_an_explicit_error_not_a_partial_parse() {
        // A status file one byte over the cap must be rejected outright.
        let dir = super::super::files::temp_root("packages-overcap");
        let path = dir.join("status");
        {
            use std::io::Write;
            let file = std::fs::File::create(&path).unwrap();
            let mut writer = std::io::BufWriter::new(&file);
            let chunk = "Package: p\nStatus: install ok installed\nVersion: 1\n\n".repeat(1024);
            let mut written = 0usize;
            while written <= MAX_STATUS_FILE_BYTES {
                writer.write_all(chunk.as_bytes()).unwrap();
                written += chunk.len();
            }
        }
        let out = collect_packages_from(&params(), &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::Error);
        match &out.payload {
            ObservationPayload::ErrorDetail { code, message } => {
                assert_eq!(code, "status_file_too_large");
                assert!(message.contains("hard read cap"));
            }
            other => panic!("expected error detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_file_is_notfound() {
        let path = std::path::PathBuf::from("/nonexistent/dpkg-status-for-tests");
        let out = collect_packages_from(&params(), &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::NotFound);
        match &out.payload {
            ObservationPayload::ErrorDetail { code, .. } => assert_eq!(code, "status_file_missing"),
            other => panic!("expected error detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn live_local_probe_smoke() {
        // Non-fatal live smoke: on a non-Debian host the file is simply
        // absent and the collector reports an explicit NotFound.
        let path = Path::new(DPKG_STATUS_PATH);
        if !path.exists() {
            eprintln!("skipping live dpkg probe: {DPKG_STATUS_PATH} not present");
            return;
        }
        let out = collect_packages_from(&params(), &cfg(), path).await;
        assert!(out.status.is_valid_sample(), "unexpected status {:?}", out.status);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot payload");
        };
        let snap: PackagesInventorySnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.status_file_sha256.len(), 64);
        assert_eq!(
            snap.total_packages,
            snap.packages.len() as u32 + snap.omitted_packages.unwrap_or(0)
        );
        assert!(!CollectorType::PackagesInventory.is_stream());
    }
}

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

use std::collections::{BTreeMap, btree_map::Entry};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_protocol::canonical::{canonical_sha256_hex, to_canonical_json_bytes};
use defsec_protocol::observation::{
    ObservationPayload, ObservationStatus, PackageInventoryEntry, PackagesInventorySnapshot,
};
use defsec_protocol::watch::{PackagesInventoryParams, PACKAGES_INVENTORY_DEFAULT, PACKAGES_INVENTORY_HARD_MAX};
use sha2::{Digest, Sha256};

use super::{CollectorOutput, SNAPSHOT_BYTES, bounded_snapshot_entries};

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

/// Retain only identity and version for each installed key.
#[derive(Debug, Default)]
struct ParsedDpkgStatus {
    installed: BTreeMap<String, String>,
    malformed_stanzas: u32,
    duplicate_stanzas: u32,
    total_stanzas: u32,
}

pub fn is_installed_status(status: &str) -> bool {
    status.ends_with(" installed")
}

fn is_lower_alphanumeric(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn valid_package_name(name: &str) -> bool {
    name.len() >= 2
        && is_lower_alphanumeric(name.as_bytes()[0])
        && name
            .bytes()
            .all(|b| is_lower_alphanumeric(b) || matches!(b, b'+' | b'-' | b'.'))
}

fn valid_architecture(arch: &str) -> bool {
    arch.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[derive(Default)]
struct Stanza {
    package: Option<String>,
    status: Option<String>,
    architecture: Option<String>,
    version: Option<String>,
    has_lines: bool,
    previous_field: bool,
    previous_scalar: bool,
    malformed: bool,
}

impl Stanza {
    fn read_line(&mut self, line: &str, parsed: &mut ParsedDpkgStatus) {
        if line.trim().is_empty() {
            std::mem::take(self).finish(parsed);
            return;
        }
        self.has_lines = true;
        if line.starts_with([' ', '\t']) {
            self.malformed |= !self.previous_field || self.previous_scalar;
            return;
        }
        let Some((name, value)) = line.split_once(':') else {
            self.malformed = true;
            return;
        };
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace()) {
            self.malformed = true;
            return;
        }
        self.previous_field = true;
        let field = match name {
            "Package" => Some(&mut self.package),
            "Status" => Some(&mut self.status),
            "Architecture" => Some(&mut self.architecture),
            "Version" => Some(&mut self.version),
            _ => None,
        };
        self.previous_scalar = field.is_some();
        if let Some(field) = field {
            if field.is_some() {
                self.malformed = true;
            } else {
                *field = Some(value.trim().to_string());
            }
        }
    }

    fn finish(self, parsed: &mut ParsedDpkgStatus) {
        if !self.has_lines {
            return;
        }
        parsed.total_stanzas += 1;
        let name = self.package.as_deref().unwrap_or_default();
        let arch = self.architecture.as_deref().unwrap_or("unknown");
        let installed = self.status.as_deref().is_some_and(is_installed_status);
        if self.malformed
            || !valid_package_name(name)
            || !valid_architecture(arch)
            || self.status.as_deref().is_none_or(str::is_empty)
            || (installed && self.version.as_deref().is_none_or(str::is_empty))
        {
            parsed.malformed_stanzas += 1;
            return;
        }
        if !installed {
            return;
        }

        let version = self.version.expect("installed stanza has a version");
        match parsed.installed.entry(format!("{name}:{arch}")) {
            Entry::Vacant(slot) => {
                slot.insert(version);
            }
            Entry::Occupied(mut slot) => {
                parsed.duplicate_stanzas += 1;
                if &version < slot.get() {
                    slot.insert(version);
                }
            }
        }
    }
}

/// Keep the sorted prefix that fits both the package count and byte budgets.
fn build_packages_snapshot(
    parsed: &ParsedDpkgStatus,
    status_file_sha256: String,
    max_packages: u32,
) -> PackagesInventorySnapshot {
    let total_packages = parsed.installed.len() as u32;
    let mut snapshot = PackagesInventorySnapshot {
        packages: Vec::new(),
        total_packages,
        status_file_sha256,
        malformed_stanzas: parsed.malformed_stanzas,
        duplicate_stanzas: parsed.duplicate_stanzas,
        truncated: Some(true),
        omitted_packages: Some(total_packages),
    };
    // Reserve space for the largest possible omission count before filling the array.
    let metadata_bytes = to_canonical_json_bytes(&snapshot)
        .expect("serializable snapshot")
        .len();
    let entries = parsed
        .installed
        .iter()
        // Raw strings provide a cheap lower bound before cloning very large entries.
        .take_while(|(key, version)| {
            2 * key.len() - 1 + version.len() <= SNAPSHOT_BYTES - metadata_bytes
        })
        .map(|(key, version)| {
            let (name, arch) = key.split_once(':').expect("validated package key");
            PackageInventoryEntry {
                package_key: key.clone(),
                name: name.into(),
                arch: arch.into(),
                version: version.clone(),
            }
        });
    snapshot.packages = bounded_snapshot_entries(entries, max_packages, metadata_bytes);
    let omitted = total_packages - snapshot.packages.len() as u32;
    snapshot.truncated = (omitted > 0).then_some(true);
    snapshot.omitted_packages = (omitted > 0).then_some(omitted);
    snapshot
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

    let mut reader = BufReader::new(file.take((MAX_STATUS_FILE_BYTES + 1) as u64));
    let mut parsed = ParsedDpkgStatus::default();
    let mut stanza = Stanza::default();
    let mut hash = Sha256::new();
    let mut line = Vec::new();
    let mut bytes_read = 0;
    let mut lines = 0usize;
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(n) => bytes_read += n,
            Err(e) => {
                return error_output(
                    "status_file_read_failed",
                    format!("failed reading {}: {e}", path.display()),
                    ObservationStatus::Error,
                );
            }
        }
        if bytes_read > MAX_STATUS_FILE_BYTES {
            return error_output(
                "status_file_too_large",
                format!(
                    "dpkg status file {} exceeds the hard read cap of {MAX_STATUS_FILE_BYTES} bytes",
                    path.display(),
                ),
                ObservationStatus::Error,
            );
        }
        hash.update(&line);
        let text = String::from_utf8_lossy(&line);
        stanza.read_line(text.trim_end_matches(['\r', '\n']), &mut parsed);
        lines += 1;
        if lines.is_multiple_of(256) {
            tokio::task::yield_now().await;
        }
    }
    stanza.finish(&mut parsed);
    let status_file_sha256 = hex::encode(hash.finalize());

    let max_packages = effective_package_cap(params, cfg);
    let snapshot = build_packages_snapshot(&parsed, status_file_sha256, max_packages);

    let mut partial_reasons = Vec::new();
    let mut status = ObservationStatus::Ok;
    if let Some(omitted) = snapshot.omitted_packages
        && omitted > 0
    {
        status = ObservationStatus::Partial;
        partial_reasons.push(format!(
            "installed package inventory of {} entries exceeds cap ({max_packages} entries or {SNAPSHOT_BYTES} snapshot bytes): retained {} by package key and omitted {omitted}",
            snapshot.total_packages,
            snapshot.packages.len()
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

    if snapshot.duplicate_stanzas > 0 {
        status = ObservationStatus::Partial;
        partial_reasons.push(format!(
            "{} duplicate installed stanzas in {} were skipped",
            snapshot.duplicate_stanzas,
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
    use defsec_protocol::canonical::sha256_hex;
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

    fn parse_dpkg_status(text: &str) -> ParsedDpkgStatus {
        let mut parsed = ParsedDpkgStatus::default();
        let mut stanza = Stanza::default();
        for line in text.lines() {
            stanza.read_line(line, &mut parsed);
        }
        stanza.finish(&mut parsed);
        parsed
    }

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
        let keys: Vec<_> = parsed.installed.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["bash:amd64", "libc6:amd64", "libc6:i386", "wget:all"]
        );
        assert_eq!(parsed.installed["bash:amd64"], "5.2.15-2ubuntu3");
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
        assert_eq!(parsed.installed["empty-arch:unknown"], "9.9");
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
    async fn snapshot_byte_budget_truncates_dense_status_file_in_key_order() {
        let version = "1".repeat(530);
        let text: String = (0..4096).rev().map(|i| format!(
            "Package: package-{i:04}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\n\n"
        )).collect();
        let unbounded = parse_dpkg_status(&text);
        let unbounded_entries: Vec<_> = unbounded.installed.iter().map(|(key, version)| {
            let (name, arch) = key.split_once(':').unwrap();
            serde_json::json!({"package_key": key, "name": name, "arch": arch, "version": version})
        }).collect();
        assert!(
            to_canonical_json_bytes(&unbounded_entries).unwrap().len()
                > defsec_protocol::wire::MAX_FRAME_BYTES
        );
        let path = temp_status_file("budget", text.as_bytes());
        let out = collect_packages_from(&params(), &cfg(), &path).await;
        assert_eq!(out.status, ObservationStatus::Partial);
        let ObservationPayload::Snapshot { data } = out.payload else {
            panic!("expected snapshot")
        };
        assert!(to_canonical_json_bytes(&data).unwrap().len() <= SNAPSHOT_BYTES);
        let snapshot: PackagesInventorySnapshot = serde_json::from_value(data).unwrap();
        assert_eq!(snapshot.total_packages, 4096);
        assert_eq!(snapshot.truncated, Some(true));
        assert_eq!(
            snapshot.omitted_packages,
            Some(4096 - snapshot.packages.len() as u32)
        );
        assert!(snapshot.omitted_packages.unwrap() > 0);
        for (i, entry) in snapshot.packages.iter().enumerate() {
            assert_eq!(entry.package_key, format!("package-{i:04}:amd64"));
        }
    }

    #[test]
    fn rejects_invalid_identities_and_deduplicates_independently_of_stanza_order() {
        let status = |name, arch, version| {
            format!(
                "Package: {name}\nStatus: install ok installed\nArchitecture: {arch}\nVersion: {version}\n\n"
            )
        };
        let stanzas = [
            status("a:b", "amd64", "1"),
            status("valid", "arch:extra", "3"),
            status("valid", "amd64", "2"),
            status("valid", "amd64", "1"),
        ];
        for input in [stanzas.concat(), stanzas.iter().rev().cloned().collect()] {
            let parsed = parse_dpkg_status(&input);
            assert_eq!(parsed.malformed_stanzas, 2);
            assert_eq!(parsed.duplicate_stanzas, 1);
            assert_eq!(parsed.installed.len(), 1);
            assert_eq!(parsed.installed["valid:amd64"], "1");
        }
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

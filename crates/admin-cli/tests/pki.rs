use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use defsec_mtls::RevocationList;
use serde_json::Value;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pki(dir: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_admin-cli"))
        .current_dir(dir)
        .args(["--admin-sock", "nonexistent.sock", "pki"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn local_pki_commands_issue_and_revoke_credentials() {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let dir = TempDir(std::env::temp_dir().join(format!("pki-{}", &id[..12])));
    fs::create_dir(&dir.0).unwrap();
    let ca = pki(
        &dir.0,
        &["init-ca", "--out-dir", "ca", "--valid-days", "30"],
    );
    assert_eq!(ca["cert_path"], "ca/ca.crt");
    let server = pki(
        &dir.0,
        &[
            "issue-server",
            "--ca-cert",
            "ca/ca.crt",
            "--ca-key",
            "ca/ca.key",
            "--out-dir",
            "server",
            "--dns",
            "localhost",
            "--dns",
            "control.example",
            "--ip",
            "127.0.0.1",
            "--valid-days",
            "5",
        ],
    );
    assert_eq!(
        server["dns"],
        serde_json::json!(["localhost", "control.example"])
    );
    assert_eq!(server["ip"], serde_json::json!(["127.0.0.1"]));
    assert!(
        server["serial_hex"]
            .as_str()
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    );
    let host = pki(
        &dir.0,
        &[
            "issue-host",
            "edge-01",
            "--ca-cert",
            "ca/ca.crt",
            "--ca-key",
            "ca/ca.key",
            "--out-dir",
            "host",
            "--valid-days",
            "5",
        ],
    );
    assert_eq!(host["host_id"], "edge-01");
    assert_eq!(host["spiffe_uri"], "spiffe://defsecautmit/host/edge-01");
    let serial = host["serial_hex"].as_str().unwrap();
    assert_ne!(server["serial_hex"], serial);
    let revoked = pki(
        &dir.0,
        &[
            "revoke",
            serial,
            "--revoked-file",
            "revoked_serials.json",
            "--reason",
            "test",
        ],
    );
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["serial_hex"], serial);
    assert!(
        RevocationList::load_or_empty(dir.0.join("revoked_serials.json"))
            .unwrap()
            .is_revoked(serial)
    );
    for stem in ["ca/ca", "server/server", "host/edge-01"] {
        let cert = fs::read_to_string(dir.0.join(format!("{stem}.crt"))).unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        let key = dir.0.join(format!("{stem}.key"));
        assert!(
            fs::read_to_string(&key)
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

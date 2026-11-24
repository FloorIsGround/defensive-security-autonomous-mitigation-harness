use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use defsec_mtls::{
    RevocationList,
    pki::{HOST_URI_PREFIX, init_ca, issue_host_cert, issue_server_cert},
};
use serde_json::{Value, json};

#[derive(Subcommand)]
pub(crate) enum PkiCommand {
    /// Create a new fleet root CA.
    InitCa {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "DefSecAutMit Fleet CA")]
        common_name: String,
        #[arg(long, default_value_t = 3650)]
        valid_days: u64,
    },
    /// Issue a TLS server certificate. If no SANs are specified, use the common name as its DNS SAN.
    IssueServer {
        #[command(flatten)]
        options: IssueOptions,
        #[arg(long, default_value = "localhost")]
        common_name: String,
        #[arg(long)]
        dns: Vec<String>,
        #[arg(long)]
        ip: Vec<IpAddr>,
    },
    /// Issue a TLS client certificate for an enrolled host ID.
    IssueHost {
        host_id: String,
        #[command(flatten)]
        options: IssueOptions,
    },
    /// Revoke a certificate serial for new agent connections.
    Revoke {
        serial_hex: String,
        #[arg(long)]
        revoked_file: PathBuf,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Args)]
pub(crate) struct IssueOptions {
    #[arg(long)]
    ca_cert: PathBuf,
    #[arg(long)]
    ca_key: PathBuf,
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long, default_value_t = 365)]
    valid_days: u64,
}

impl PkiCommand {
    pub(crate) fn run(self) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::InitCa {
                out_dir,
                common_name,
                valid_days,
            } => {
                let ca = init_ca(&common_name, valid_days)?;
                let (cert_path, key_path) = write_pair(&out_dir, "ca", &ca.cert_pem, &ca.key_pem)?;
                json!({"common_name": common_name, "cert_path": cert_path, "key_path": key_path})
            }
            Self::IssueServer {
                options,
                common_name,
                mut dns,
                ip,
            } => {
                if dns.is_empty() && ip.is_empty() {
                    dns.push(common_name.clone());
                }
                let cert = issue_server_cert(
                    &fs::read_to_string(options.ca_cert)?,
                    &fs::read_to_string(options.ca_key)?,
                    &common_name,
                    &dns,
                    &ip,
                    options.valid_days,
                )?;
                let (cert_path, key_path) =
                    write_pair(&options.out_dir, "server", &cert.cert_pem, &cert.key_pem)?;
                json!({
                    "serial_hex": cert.serial_hex, "dns": dns, "ip": ip,
                    "cert_path": cert_path, "key_path": key_path,
                })
            }
            Self::IssueHost { host_id, options } => {
                let cert = issue_host_cert(
                    &fs::read_to_string(options.ca_cert)?,
                    &fs::read_to_string(options.ca_key)?,
                    &host_id,
                    options.valid_days,
                )?;
                let (cert_path, key_path) =
                    write_pair(&options.out_dir, &host_id, &cert.cert_pem, &cert.key_pem)?;
                json!({
                    "host_id": host_id, "serial_hex": cert.serial_hex,
                    "spiffe_uri": format!("{HOST_URI_PREFIX}{host_id}"),
                    "cert_path": cert_path, "key_path": key_path,
                })
            }
            Self::Revoke {
                serial_hex,
                revoked_file,
                reason,
            } => {
                let serial_hex =
                    RevocationList::revoke(&revoked_file, &serial_hex, reason.as_deref())?;
                json!({"revoked": true, "serial_hex": serial_hex, "revoked_file": revoked_file})
            }
        })
    }
}

fn write_pair(dir: &Path, name: &str, cert: &str, key: &str) -> io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(dir)?;
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    write_new_file(&key_path, key)?;
    if let Err(error) = write_new_file(&cert_path, cert) {
        let _ = fs::remove_file(&key_path);
        return Err(error);
    }
    File::open(dir)?.sync_all()?;
    Ok((cert_path, key_path))
}

fn write_new_file(path: &Path, pem: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

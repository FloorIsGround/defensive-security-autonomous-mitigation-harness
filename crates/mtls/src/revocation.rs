use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{MtlsError, Result};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    revoked_serials: BTreeMap<String, Revocation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<DateTime<Utc>>,
}

impl RevocationList {
    pub fn load_or_empty(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let mut list = Self::default();
        let stored: Self = serde_json::from_slice(&bytes)?;
        for (serial, entry) in stored.revoked_serials {
            list.revoked_serials
                .insert(normalize_serial(&serial)?, entry);
        }
        Ok(list)
    }

    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        normalize_serial(serial_hex).is_ok_and(|serial| self.revoked_serials.contains_key(&serial))
    }

    /// Add a serial idempotently and return its normalized form.
    pub fn revoke(
        path: impl AsRef<Path>,
        serial_hex: &str,
        reason: Option<&str>,
    ) -> Result<String> {
        let serial = normalize_serial(serial_hex)?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        // Keep the lock inode stable across atomic replacements of the JSON file.
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)?;
        lock.lock()?;
        let mut list = Self::load_or_empty(path)?;
        if !list.revoked_serials.contains_key(&serial) {
            list.revoked_serials.insert(
                serial.clone(),
                Revocation {
                    reason: reason.map(str::to_owned),
                    revoked_at: Some(Utc::now()),
                },
            );
            let json = serde_json::to_vec_pretty(&list)?;
            atomic_write(path, parent, &json)?;
        }
        Ok(serial)
    }
}

fn atomic_write(path: &Path, parent: &Path, bytes: &[u8]) -> io::Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let (mut file, temp) = loop {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".revocations-{}-{id}.tmp", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => break (file, temp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub(crate) fn normalize_serial(serial: &str) -> Result<String> {
    if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MtlsError::Invalid(
            "expected a hexadecimal certificate serial",
        ));
    }
    let digits = serial.trim_start_matches('0');
    if digits.is_empty() || digits.len() > 40 {
        return Err(MtlsError::Invalid(
            "expected a positive certificate serial of at most 20 bytes",
        ));
    }
    let mut normalized = digits.to_ascii_lowercase();
    if normalized.len() % 2 == 1 {
        normalized.insert(0, '0');
    }
    Ok(normalized)
}

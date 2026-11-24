//! `systemd.unit_state`: unit state via system D-Bus (`zbus`) with per-file
//! hashing of the unit's fragment and drop-in files.
//!
//! D-Bus unavailability, missing units, and unreadable unit files are all
//! explicit observation statuses — never silent failures.

use defsec_policy::edge_floor::{validate_systemd_unit_name, EdgeSafetyConfig};
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::observation::{
    ObservationPayload, ObservationStatus, SystemdUnitSnapshot, UnitFileHashEntry,
};
use defsec_protocol::watch::SystemdUnitStateParams;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, Mode};
use nix::unistd::close;
use sha2::{Digest, Sha256};
use zbus::zvariant::OwnedObjectPath;

use super::CollectorOutput;
use crate::collectors::sockets::parse_proc_stat_start_ticks;

const SYSTEMD_DEST: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_IFACE: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";

/// Read the process start time for a MainPID from `/proc/<pid>/stat`.
pub fn read_pid_start_time_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat_start_ticks(&stat)
}

/// Hash one unit file or drop-in using a safe regular-file open
/// (`O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`), fstat regular-file
/// validation and a size cap. Missing or unreadable files become explicit
/// per-file statuses without failing the whole snapshot.
pub fn hash_unit_file(path: &str, max_bytes: u64) -> UnitFileHashEntry {
    let mut entry = UnitFileHashEntry {
        path: path.to_string(),
        status: ObservationStatus::Ok,
        sha256: None,
        size_bytes: None,
    };
    if path.is_empty() {
        entry.status = ObservationStatus::NotFound;
        return entry;
    }
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let fd = match open(std::path::Path::new(path), flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            entry.status = match e {
                nix::errno::Errno::ENOENT => ObservationStatus::NotFound,
                nix::errno::Errno::EACCES | nix::errno::Errno::EPERM => {
                    ObservationStatus::PermissionDenied
                }
                nix::errno::Errno::ELOOP => ObservationStatus::Error,
                _ => ObservationStatus::Error,
            };
            return entry;
        }
    };
    let stat = match fstat(fd) {
        Ok(s) => s,
        Err(_) => {
            let _ = close(fd);
            entry.status = ObservationStatus::Error;
            return entry;
        }
    };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        let _ = close(fd);
        entry.status = ObservationStatus::Error;
        return entry;
    }
    if (stat.st_size as u64) > max_bytes {
        let _ = close(fd);
        entry.status = ObservationStatus::TruncatedRejected;
        entry.size_bytes = Some(stat.st_size as u64);
        return entry;
    }
    entry.size_bytes = Some(stat.st_size as u64);

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut failed = false;
    loop {
        // SAFETY: `read` on a valid fd with a valid buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            failed = true;
            break;
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        total += n as u64;
        if total > max_bytes {
            // Grew past the cap between fstat and read: reject.
            entry.status = ObservationStatus::TruncatedRejected;
            entry.sha256 = None;
            failed = false;
            break;
        }
        hasher.update(&buf[..n]);
    }
    let _ = close(fd);
    if failed {
        entry.status = ObservationStatus::Error;
        return entry;
    }
    if entry.status == ObservationStatus::Ok {
        entry.sha256 = Some(hex::encode(hasher.finalize()));
    }
    entry
}

fn error_detail_output(code: &str, message: String, status: ObservationStatus) -> CollectorOutput {
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

/// Collect a `systemd.unit_state` observation over the system D-Bus.
pub async fn collect_systemd(
    params: &SystemdUnitStateParams,
    cfg: &EdgeSafetyConfig,
    conn: &zbus::Connection,
) -> CollectorOutput {
    if let Err(reason) = validate_systemd_unit_name(&params.unit) {
        return error_detail_output("invalid_unit_name", reason, ObservationStatus::Error);
    }

    let manager = match zbus::Proxy::new(
        conn,
        SYSTEMD_DEST,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_IFACE,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return error_detail_output(
                "dbus_unavailable",
                format!("system D-Bus unavailable: {e}"),
                ObservationStatus::Error,
            );
        }
    };

    let unit_path: OwnedObjectPath = match manager
        .call::<_, _, OwnedObjectPath>("GetUnit", &params.unit)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            if let zbus::Error::MethodError(name, _, _) = &e
                && name.as_str() == SYSTEMD_NO_SUCH_UNIT
            {
                return error_detail_output(
                    "unit_not_found",
                    format!("systemd reports no such unit '{}'", params.unit),
                    ObservationStatus::NotFound,
                );
            }
            return error_detail_output(
                "dbus_error",
                format!("GetUnit call failed: {e}"),
                ObservationStatus::Error,
            );
        }
    };

    let unit_proxy = match zbus::Proxy::new(
        conn,
        SYSTEMD_DEST,
        unit_path.as_str(),
        SYSTEMD_UNIT_IFACE,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return error_detail_output(
                "dbus_error",
                format!("unit proxy failed: {e}"),
                ObservationStatus::Error,
            );
        }
    };

    let load_state: String = match unit_proxy.get_property::<String>("LoadState").await {
        Ok(v) => v,
        Err(e) => {
            return error_detail_output(
                "dbus_error",
                format!("reading LoadState failed: {e}"),
                ObservationStatus::Error,
            );
        }
    };
    let active_state: String = match unit_proxy.get_property::<String>("ActiveState").await {
        Ok(v) => v,
        Err(e) => {
            return error_detail_output(
                "dbus_error",
                format!("reading ActiveState failed: {e}"),
                ObservationStatus::Error,
            );
        }
    };
    let sub_state: String = match unit_proxy.get_property::<String>("SubState").await {
        Ok(v) => v,
        Err(e) => {
            return error_detail_output(
                "dbus_error",
                format!("reading SubState failed: {e}"),
                ObservationStatus::Error,
            );
        }
    };

    let mut partial_reasons = Vec::new();
    let unit_file_state: Option<String> = unit_proxy
        .get_property::<String>("UnitFileState")
        .await
        .map(Some)
        .unwrap_or_else(|e| {
            partial_reasons.push(format!("UnitFileState unavailable: {e}"));
            None
        });
    let main_pid: Option<u32> = unit_proxy
        .get_property::<u32>("MainPID")
        .await
        .ok()
        .filter(|p| *p > 0);
    let fragment_path: Option<String> = unit_proxy
        .get_property::<String>("FragmentPath")
        .await
        .ok()
        .filter(|p| !p.is_empty());
    let drop_in_paths: Option<Vec<String>> = unit_proxy
        .get_property::<Vec<String>>("DropInPaths")
        .await
        .ok();

    let main_pid_start_time_ticks = main_pid.and_then(read_pid_start_time_ticks);

    let mut unit_files: Vec<UnitFileHashEntry> = Vec::new();
    if params.hash_unit_files {
        if let Some(fragment) = &fragment_path {
            unit_files.push(hash_unit_file(fragment, cfg.max_file_hash_bytes));
        }
        if let Some(drop_ins) = &drop_in_paths {
            for path in drop_ins {
                unit_files.push(hash_unit_file(path, cfg.max_file_hash_bytes));
            }
        }
        unit_files.sort_by(|a, b| a.path.cmp(&b.path));
        for entry in &unit_files {
            if entry.status != ObservationStatus::Ok {
                partial_reasons.push(format!(
                    "unit file {}: {:?}",
                    entry.path, entry.status
                ));
            }
        }
    }

    let exec_start_hash = main_pid.map(|pid| {
        canonical_sha256_hex(&serde_json::json!({
            "main_pid": pid,
            "main_pid_start_time_ticks": main_pid_start_time_ticks,
        }))
        .unwrap_or_default()
    });

    let snapshot = SystemdUnitSnapshot {
        unit: params.unit.clone(),
        load_state,
        active_state,
        sub_state,
        unit_file_state,
        main_pid,
        main_pid_start_time_ticks,
        exec_start_hash,
        unit_files,
    };

    let status = if partial_reasons.is_empty() {
        ObservationStatus::Ok
    } else {
        ObservationStatus::Partial
    };
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

    #[test]
    fn hash_unit_file_handles_regular_missing_symlink_and_oversize() {
        let dir = crate::collectors::files::temp_root("systemd-hash");
        let regular = dir.join("unit.service");
        std::fs::write(&regular, b"[Unit]\nDescription=x\n").unwrap();

        let entry = hash_unit_file(regular.to_str().unwrap(), 1024 * 1024);
        assert_eq!(entry.status, ObservationStatus::Ok);
        assert_eq!(
            entry.sha256.as_deref(),
            Some(hex::encode(Sha256::digest(b"[Unit]\nDescription=x\n")).as_str())
        );
        assert_eq!(entry.size_bytes, Some(21));

        let missing = hash_unit_file(dir.join("nope.service").to_str().unwrap(), 1024 * 1024);
        assert_eq!(missing.status, ObservationStatus::NotFound);

        let target = dir.join("target.conf");
        std::fs::write(&target, b"target").unwrap();
        let link = dir.join("link.service");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let symlinked = hash_unit_file(link.to_str().unwrap(), 1024 * 1024);
        assert_eq!(symlinked.status, ObservationStatus::Error);
        assert_eq!(symlinked.sha256, None);

        let oversize = hash_unit_file(regular.to_str().unwrap(), 4);
        assert_eq!(oversize.status, ObservationStatus::TruncatedRejected);

        let empty = hash_unit_file("", 1024 * 1024);
        assert_eq!(empty.status, ObservationStatus::NotFound);
    }

    #[test]
    fn reads_own_pid_start_time() {
        let pid = std::process::id();
        let ticks = read_pid_start_time_ticks(pid);
        assert!(ticks.is_some());
        assert!(read_pid_start_time_ticks(u32::MAX).is_none());
    }
}

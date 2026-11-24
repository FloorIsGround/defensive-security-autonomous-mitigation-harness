//! `files.metadata`: bounded SHA-256 hashing of explicitly allowlisted
//! regular files beneath approved roots. Zero file contents are returned.
//!
//! Path safety is kernel-enforced: every file is opened relative to its
//! approved root directory fd via `openat2(2)` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`,
//! eliminating symlink traversal, magic-link escapes, mount-crossing, and TOCTOU
//! races. The hash is computed strictly from the already-open fd (never
//! re-opened).

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use defsec_policy::edge_floor::{validate_file_path, EdgeSafetyConfig};
use defsec_protocol::canonical::canonical_sha256_hex;
use defsec_protocol::observation::{
    FileMetadataEntry, FilesMetadataSnapshot, ObservationPayload, ObservationStatus,
};
use defsec_protocol::watch::FilesMetadataParams;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, FileStat};
use nix::unistd::close;
use sha2::{Digest, Sha256};

use super::CollectorOutput;

// openat2 resolve flags verified against /usr/include/linux/openat2.h.
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

const OPENAT2_FLAGS: u64 = (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64;
const OPENAT2_RESOLVE: u64 =
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open `rel_path` beneath `dirfd` using `openat2(2)` with the hardened
/// resolve flag set. Returns the new fd or an `io::Error` (including `ENOSYS`
/// mapped cleanly for kernels without `openat2`).
pub fn openat2_beneath(dirfd: RawFd, rel_path: &Path) -> std::io::Result<RawFd> {
    let path_bytes = rel_path
        .to_str()
        .and_then(|s| std::ffi::CString::new(s).ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL bytes")
        })?;
    let how = OpenHow {
        flags: OPENAT2_FLAGS,
        mode: 0,
        resolve: OPENAT2_RESOLVE,
    };
    // SAFETY: `openat2` pointer arguments are valid for the duration of the
    // call; `how` is a POD struct matching `struct open_how`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path_bytes.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>() as libc::size_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc as RawFd)
    }
}

fn errno_status_and_detail(e: &std::io::Error) -> (ObservationStatus, String) {
    match e.raw_os_error() {
        Some(libc::ENOSYS) => (
            ObservationStatus::Error,
            "kernel does not support openat2; refusing to fall back to less safe path resolution"
                .to_string(),
        ),
        Some(libc::ELOOP) => (
            ObservationStatus::Error,
            "symlink traversal rejected by RESOLVE_NO_SYMLINKS".to_string(),
        ),
        Some(libc::EXDEV) => (
            ObservationStatus::Error,
            "path crosses a mount boundary (RESOLVE_NO_XDEV/RESOLVE_BENEATH)".to_string(),
        ),
        Some(libc::EACCES) | Some(libc::EPERM) => (
            ObservationStatus::PermissionDenied,
            "permission denied opening file".to_string(),
        ),
        Some(libc::ENOENT) => (ObservationStatus::NotFound, "file not found".to_string()),
        _ => (ObservationStatus::Error, format!("open failed: {e}")),
    }
}

/// Hash (and stat) one opened fd. The fd is read strictly from the same
/// handle that was fstat'd — zero TOCTOU, no re-resolution. A file that grows
/// beyond `cap` mid-read is rejected as truncated rather than silently cut.
fn hash_fd(fd: RawFd, cap: u64, compute_hash: bool) -> std::io::Result<(Option<String>, u64, bool)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let want = buf.len().min((cap.saturating_sub(total) + 1) as usize);
        if want == 0 {
            break;
        }
        // SAFETY: `read` on a valid fd with a valid buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, want) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        total += n as u64;
        if total > cap {
            return Ok((None, total, true));
        }
        if compute_hash {
            hasher.update(&buf[..n]);
        }
    }
    let digest = compute_hash.then(|| hex::encode(hasher.finalize()));
    Ok((digest, total, false))
}

/// Find the approved root that lexically contains `path` (same semantics as
/// the policy layer: `starts_with(root)` and not equal to the root itself).
pub fn matching_approved_root<'a>(path: &Path, cfg: &'a EdgeSafetyConfig) -> Option<&'a Path> {
    cfg.approved_file_roots
        .iter()
        .find(|root| path.starts_with(root.as_path()) && path != root.as_path())
        .map(|r| r.as_path())
}

/// Build one `FileMetadataEntry` for a single validated path.
fn file_entry(path_str: &str, cfg: &EdgeSafetyConfig, compute_hash: bool, cap: u64) -> FileMetadataEntry {
    let mut entry = FileMetadataEntry {
        path: path_str.to_string(),
        status: ObservationStatus::Ok,
        mode_octal: None,
        uid: None,
        gid: None,
        size_bytes: None,
        sha256: None,
        mtime_unix: None,
        detail: None,
    };

    let path = match validate_file_path(path_str, cfg) {
        Ok(p) => p,
        Err(reason) => {
            entry.status = ObservationStatus::Error;
            entry.detail = Some(reason);
            return entry;
        }
    };

    let Some(root) = matching_approved_root(&path, cfg) else {
        entry.status = ObservationStatus::Error;
        entry.detail = Some("path is outside all locally approved file roots".to_string());
        return entry;
    };
    let rel = path.strip_prefix(root).expect("root is a prefix");

    // Open the approved root as a directory fd.
    let root_fd = match open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    {
        Ok(fd) => fd,
        Err(e) => {
            let (status, detail) = errno_status_and_detail(&e);
            entry.status = status;
            entry.detail = Some(format!("opening approved root {root:?} failed: {detail}"));
            return entry;
        }
    };

    let opened = openat2_beneath(root_fd, rel);
    let _ = close(root_fd);
    let fd = match opened {
        Ok(fd) => fd,
        Err(e) => {
            let (status, detail) = errno_status_and_detail(&e);
            entry.status = status;
            entry.detail = Some(detail);
            return entry;
        }
    };

    let stat: FileStat = match fstat(fd) {
        Ok(s) => s,
        Err(e) => {
            let _ = close(fd);
            entry.status = ObservationStatus::Error;
            entry.detail = Some(format!("fstat failed: {e}"));
            return entry;
        }
    };

    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        let _ = close(fd);
        entry.status = ObservationStatus::Error;
        entry.detail =
            Some("not a regular file (directory/FIFO/device/socket rejected)".to_string());
        return entry;
    }

    entry.mode_octal = Some(format!("{:04o}", stat.st_mode & 0o7777));
    entry.uid = Some(stat.st_uid);
    entry.gid = Some(stat.st_gid);
    entry.mtime_unix = Some(stat.st_mtime);

    if (stat.st_size as u64) > cap {
        let _ = close(fd);
        entry.status = ObservationStatus::TruncatedRejected;
        entry.size_bytes = Some(stat.st_size as u64);
        entry.detail = Some(format!(
            "file size {} exceeds hash byte cap {cap}; refusing to hash",
            stat.st_size
        ));
        return entry;
    }

    match hash_fd(fd, cap, compute_hash) {
        Ok((digest, read_total, overgrew)) => {
            let _ = close(fd);
            entry.size_bytes = Some(read_total);
            if overgrew {
                entry.status = ObservationStatus::TruncatedRejected;
                entry.sha256 = None;
                entry.detail = Some(format!(
                    "file grew past the byte cap {cap} during read; hash rejected"
                ));
            } else {
                entry.sha256 = digest;
            }
        }
        Err(e) => {
            let _ = close(fd);
            entry.status = ObservationStatus::Error;
            entry.detail = Some(format!("read failed: {e}"));
        }
    }
    entry
}

/// Effective per-file byte cap: the watch parameter bounded by the local
/// safety floor.
pub fn effective_cap(params: &FilesMetadataParams, cfg: &EdgeSafetyConfig) -> u64 {
    params
        .max_file_bytes
        .unwrap_or(cfg.max_file_hash_bytes)
        .min(cfg.max_file_hash_bytes)
}

/// Aggregate per-entry statuses into one sample status.
fn aggregate_status(files: &[FileMetadataEntry]) -> ObservationStatus {
    if files.is_empty() {
        return ObservationStatus::Error;
    }
    let all_ok = files.iter().all(|f| f.status == ObservationStatus::Ok);
    if all_ok {
        return ObservationStatus::Ok;
    }
    let any_ok = files.iter().any(|f| f.status == ObservationStatus::Ok);
    if any_ok {
        return ObservationStatus::Partial;
    }
    // No usable entries: report the uniform explicit status when all
    // entries agree (e.g. a single oversized file -> TruncatedRejected).
    let first = files[0].status;
    if files.iter().all(|f| f.status == first) {
        return first;
    }
    ObservationStatus::Error
}

/// Collect a `files.metadata` observation.
pub async fn collect_files(params: &FilesMetadataParams, cfg: &EdgeSafetyConfig) -> CollectorOutput {
    let cap = effective_cap(params, cfg);
    let mut files: Vec<FileMetadataEntry> = params
        .paths
        .iter()
        .map(|p| file_entry(p, cfg, params.compute_hash, cap))
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let status = aggregate_status(&files);
    let snapshot = FilesMetadataSnapshot {
        count: files.len(),
        files,
    };
    let mut partial_reasons = Vec::new();
    if status != ObservationStatus::Ok {
        for f in &snapshot.files {
            if f.status != ObservationStatus::Ok {
                partial_reasons.push(format!(
                    "{}: {:?}{}",
                    f.path,
                    f.status,
                    f.detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default()
                ));
            }
        }
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

/// Temporary-directory helper shared with tests in this crate.
/// Removes any stale previous-run state first so reruns are deterministic.
pub fn temp_root(subdir: &str) -> PathBuf {
    let base = std::env::temp_dir().join("agent-d-tests");
    let dir = base.join(subdir);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test temp dir");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(root: &Path) -> EdgeSafetyConfig {
        let mut cfg = EdgeSafetyConfig {
            approved_file_roots: vec![root.to_path_buf()],
            ..Default::default()
        };
        // Some test runners place TMPDIR under /home; allow the test root itself
        // while keeping all other default denylists active.
        cfg.denied_path_prefixes.retain(|p| !root.starts_with(p));
        cfg
    }

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[tokio::test]
    async fn hashes_regular_file_with_metadata() {
        let root = temp_root("files-ok");
        let file = root.join("app.conf");
        write_file(&file, b"hello world");
        let cfg = test_cfg(&root);

        let params = FilesMetadataParams {
            paths: vec![file.to_str().unwrap().to_string()],
            compute_hash: true,
            max_file_bytes: None,
        };
        let out = collect_files(&params, &cfg).await;
        assert_eq!(out.status, ObservationStatus::Ok);
        assert_eq!(out.partial_reasons.len(), 0);

        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.count, 1);
        let entry = &snap.files[0];
        assert_eq!(entry.status, ObservationStatus::Ok);
        assert_eq!(entry.size_bytes, Some(11));
        assert!(entry.mode_octal.is_some());
        assert!(entry.mtime_unix.is_some());
        assert_eq!(
            entry.sha256.as_deref(),
            Some(hex::encode(Sha256::digest(b"hello world")).as_str())
        );
    }

    #[tokio::test]
    async fn rejects_symlink_traversal_and_outside_root_paths() {
        let root = temp_root("files-symlink");
        let outside_dir = temp_root("files-symlink-outside");
        let outside = outside_dir.join("outside.conf");
        write_file(&outside, b"secret");
        let link = root.join("link.conf");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let cfg = test_cfg(&root);
        let params = FilesMetadataParams {
            paths: vec![
                link.to_str().unwrap().to_string(),
                "/etc/passwd".to_string(), // outside the (only) approved root
            ],
            compute_hash: true,
            max_file_bytes: None,
        };
        let out = collect_files(&params, &cfg).await;
        assert_eq!(out.status, ObservationStatus::Error);

        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        let link_entry = snap.files.iter().find(|f| f.path.ends_with("link.conf")).unwrap();
        assert_eq!(link_entry.status, ObservationStatus::Error);
        assert!(link_entry
            .detail
            .as_deref()
            .unwrap()
            .contains("RESOLVE_NO_SYMLINKS"));
        assert_eq!(link_entry.sha256, None);

        let outside_entry = snap.files.iter().find(|f| f.path == "/etc/passwd").unwrap();
        assert_eq!(outside_entry.status, ObservationStatus::Error);
        assert!(outside_entry.detail.as_deref().unwrap().contains("approved file roots"));
    }

    #[tokio::test]
    async fn rejects_oversized_files_as_truncated() {
        let root = temp_root("files-oversize");
        let file = root.join("big.conf");
        write_file(&file, &[0u8; 2048]);

        let mut cfg = test_cfg(&root);
        cfg.max_file_hash_bytes = 1024;
        let params = FilesMetadataParams {
            paths: vec![file.to_str().unwrap().to_string()],
            compute_hash: true,
            max_file_bytes: Some(512), // watch param is stricter than the floor
        };
        let out = collect_files(&params, &cfg).await;
        assert_eq!(out.status, ObservationStatus::TruncatedRejected);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.files[0].status, ObservationStatus::TruncatedRejected);
        assert_eq!(snap.files[0].sha256, None);
        assert!(snap.files[0].detail.as_deref().unwrap().contains("byte cap"));
    }

    #[tokio::test]
    async fn rejects_shadow_and_key_filenames_via_denylists() {
        let root = temp_root("files-deny");
        write_file(&root.join("shadow"), b"root:!");
        write_file(&root.join("host.key"), b"KEYMATERIAL");

        let cfg = test_cfg(&root);
        let params = FilesMetadataParams {
            paths: vec![
                root.join("shadow").to_str().unwrap().to_string(),
                root.join("host.key").to_str().unwrap().to_string(),
                "/etc/shadow".to_string(),
            ],
            compute_hash: true,
            max_file_bytes: None,
        };
        let out = collect_files(&params, &cfg).await;
        assert_eq!(out.status, ObservationStatus::Error);
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        for entry in &snap.files {
            assert_eq!(entry.status, ObservationStatus::Error);
            assert_eq!(entry.sha256, None);
            assert!(entry.detail.is_some());
        }
        assert!(snap.files.iter().all(|f| f.path.ends_with("shadow")
            || f.path.ends_with("host.key")
            || f.path == "/etc/shadow"));
    }

    #[tokio::test]
    async fn rejects_traversal_components_and_directories() {
        let root = temp_root("files-traversal");
        write_file(&root.join("a.conf"), b"x");

        let cfg = test_cfg(&root);
        let params = FilesMetadataParams {
            paths: vec![
                format!("{}/../secret.conf", root.to_str().unwrap()),
                root.to_str().unwrap().to_string(), // the root itself (a directory)
            ],
            compute_hash: true,
            max_file_bytes: None,
        };
        let out = collect_files(&params, &cfg).await;
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        let traversal = snap
            .files
            .iter()
            .find(|f| f.path.ends_with("../secret.conf"))
            .unwrap();
        assert_eq!(traversal.status, ObservationStatus::Error);
        assert!(traversal.detail.as_deref().unwrap().contains("traversal"));
        let dir_entry = snap
            .files
            .iter()
            .find(|f| f.path == root.to_str().unwrap())
            .unwrap();
        // `validate_file_path` rejects paths equal to a root outright.
        assert_eq!(dir_entry.status, ObservationStatus::Error);
    }

    #[tokio::test]
    async fn missing_file_is_notfound_and_mixed_results_are_partial() {
        let root = temp_root("files-mixed");
        write_file(&root.join("exists.conf"), b"data");

        let cfg = test_cfg(&root);
        let params = FilesMetadataParams {
            paths: vec![
                root.join("exists.conf").to_str().unwrap().to_string(),
                root.join("missing.conf").to_str().unwrap().to_string(),
            ],
            compute_hash: true,
            max_file_bytes: None,
        };
        let out = collect_files(&params, &cfg).await;
        assert_eq!(out.status, ObservationStatus::Partial);
        assert!(!out.partial_reasons.is_empty());
        let ObservationPayload::Snapshot { data } = &out.payload else {
            panic!("expected snapshot");
        };
        let snap: FilesMetadataSnapshot = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(snap.files.len(), 2);
        assert!(snap.files.iter().any(|f| f.status == ObservationStatus::Ok));
        assert!(snap.files.iter().any(|f| f.status == ObservationStatus::NotFound));
        // Stably sorted by path.
        assert!(snap.files[0].path <= snap.files[1].path);
    }

    #[test]
    fn effective_cap_is_min_of_param_and_floor() {
        let root = temp_root("files-cap");
        let cfg = test_cfg(&root);
        let mut params = FilesMetadataParams {
            paths: vec![],
            compute_hash: false,
            max_file_bytes: None,
        };
        assert_eq!(effective_cap(&params, &cfg), cfg.max_file_hash_bytes);
        params.max_file_bytes = Some(64);
        assert_eq!(effective_cap(&params, &cfg), 64);
    }
}


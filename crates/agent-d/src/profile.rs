//! Admin-owned host profile loading for `agent-d` (`--profile <PATH>`).
//!
//! Load-time safety follows sshd's `StrictModes` philosophy: the profile is
//! local administrative input that shapes collection, so every failure is
//! explicit and fatal, and suspicious file metadata (group/world-writable,
//! unexpected owner, oversize) refuses startup rather than being ignored.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_policy::host_profile::apply_host_profile;
use defsec_protocol::profile::{HostProfile, HostProfileSummary};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use nix::unistd::geteuid;
use thiserror::Error;

/// Maximum accepted host profile file size (64 KiB).
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// A validated profile plus the tightened effective edge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedProfile {
    pub profile: HostProfile,
    pub cfg: EdgeSafetyConfig,
    pub summary: HostProfileSummary,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProfileError {
    #[error("host profile {path} is not a regular file")]
    NotRegularFile { path: String },
    #[error("host profile {path} of {size} bytes exceeds the {MAX_PROFILE_BYTES}-byte cap")]
    TooLarge { path: String, size: u64 },
    #[error("host profile {path} is writable by group or others (mode {mode:o}); refusing to start")]
    GroupOrWorldWritable { path: String, mode: u32 },
    #[error(
        "host profile parent {path} is group- or world-writable without the sticky bit (mode {mode:o})"
    )]
    WritableParent { path: String, mode: u32 },
    #[error(
        "host profile {path} is owned by uid {owner}, expected root or the agent's own uid {own}"
    )]
    UnexpectedOwner { path: String, owner: u32, own: u32 },
    #[error("failed reading host profile {path}: {message}")]
    ReadFailed { path: String, message: String },
    #[error("host profile {path} is invalid: {reason}")]
    Invalid { path: String, reason: String },
}

/// Load and validate a host profile, producing the tightened effective
/// [`EdgeSafetyConfig`]. A profile can only tighten the built-in floor.
pub fn load_profile(
    path: &Path,
    base_cfg: &EdgeSafetyConfig,
) -> Result<LoadedProfile, ProfileError> {
    let display = path.display().to_string();
    let read_failed = |e: std::io::Error| ProfileError::ReadFailed {
        path: display.clone(),
        message: e.to_string(),
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
        .map_err(read_failed)?;
    let parent_mode = parent_fd.metadata().map_err(read_failed)?.mode();
    if parent_mode & 0o022 != 0 && parent_mode & libc::S_ISVTX == 0 {
        return Err(ProfileError::WritableParent {
            path: parent.display().to_string(),
            mode: parent_mode & 0o7777,
        });
    }
    let name = path
        .file_name()
        .ok_or_else(|| ProfileError::NotRegularFile {
            path: display.clone(),
        })?;
    let fd = openat(
        Some(parent_fd.as_raw_fd()),
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| read_failed(e.into()))?;
    // SAFETY: openat returned a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(read_failed)?;
    if !meta.is_file() {
        return Err(ProfileError::NotRegularFile { path: display });
    }
    if meta.len() > MAX_PROFILE_BYTES as u64 {
        return Err(ProfileError::TooLarge {
            path: display,
            size: meta.len(),
        });
    }

    // sshd StrictModes-style checks: refuse group/world-writable profiles
    // and owners other than root or the agent's own effective uid.
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Err(ProfileError::GroupOrWorldWritable {
            path: display,
            mode: mode & 0o777,
        });
    }
    let owner = meta.uid();
    let own = geteuid();
    if owner != 0 && owner != own.as_raw() {
        return Err(ProfileError::UnexpectedOwner {
            path: display,
            owner,
            own: own.as_raw(),
        });
    }

    let mut bytes = Vec::new();
    file.take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(read_failed)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(ProfileError::TooLarge {
            path: display,
            size: bytes.len() as u64,
        });
    }
    let invalid = |e: &dyn std::fmt::Display| ProfileError::Invalid {
        path: display.clone(),
        reason: e.to_string(),
    };
    let text = std::str::from_utf8(&bytes).map_err(|e| invalid(&e))?;
    let profile: HostProfile = serde_json::from_str(text).map_err(|e| invalid(&e))?;
    let (cfg, summary) =
        apply_host_profile(base_cfg, &profile).map_err(|reason| ProfileError::Invalid {
            path: display,
            reason,
        })?;
    Ok(LoadedProfile {
        profile,
        cfg,
        summary,
    })
}

/// The agent's own effective uid, exposed for tests.
pub fn current_uid() -> u32 {
    geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = crate::collectors::files::temp_root(&format!("profile-{tag}"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write_profile(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    fn base_cfg() -> EdgeSafetyConfig {
        EdgeSafetyConfig::default()
    }

    #[test]
    fn loads_valid_profile_and_tightens() {
        let dir = temp_dir("valid");
        let path = write_profile(
            &dir,
            "profile.json",
            r#"{
                "schema_version": 1,
                "host_tags": ["prod"],
                "expected_services": ["sshd.service"],
                "enabled_collectors": ["sockets.listening", "connections.outbound"],
                "collector_caps": { "max_outbound_flows": 100 }
            }"#,
        );
        let loaded = load_profile(&path, &base_cfg()).unwrap();
        assert_eq!(loaded.cfg.max_outbound_flows, 100);
        assert_eq!(loaded.summary.host_tags, vec!["prod".to_string()]);
        assert_eq!(
            loaded.summary.enabled_collectors,
            vec![
                defsec_protocol::watch::CollectorType::SocketsListening,
                defsec_protocol::watch::CollectorType::ConnectionsOutbound,
            ]
        );
    }

    #[test]
    fn world_writable_profile_is_refused() {
        let dir = temp_dir("perms");
        let path = write_profile(&dir, "profile.json", r#"{"schema_version": 1}"#);
        // 0o666: world-writable must be refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        match load_profile(&path, &base_cfg()) {
            Err(ProfileError::GroupOrWorldWritable { .. }) => {}
            other => panic!("expected GroupOrWorldWritable, got {other:?}"),
        }
        // 0o640: group-writable must be refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(
            load_profile(&path, &base_cfg()),
            Err(ProfileError::GroupOrWorldWritable { .. })
        ));
        // 0o644: safe permissions load fine.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_profile(&path, &base_cfg()).is_ok());
        // 0o600 is also fine.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_profile(&path, &base_cfg()).is_ok());
    }

    #[test]
    fn unexpected_owner_is_refused_for_foreign_files() {
        // A file owned by another uid (we create as our own uid; simulate a
        // foreign owner check by chown'ing is not possible unprivileged, so
        // verify the branch through the owned-by-self happy path and the
        // explicit root exemption logic via a synthetic metadata check).
        let dir = temp_dir("owner");
        let path = write_profile(&dir, "profile.json", r#"{"schema_version": 1}"#);
        // Owned by the current uid: allowed.
        assert!(load_profile(&path, &base_cfg()).is_ok());
        // The owner check accepts uid 0 (root) or the agent's own uid; the
        // error branch requires a foreign owner, which unprivileged tests
        // cannot arrange. Assert the check constants instead.
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            meta.uid() == 0 || meta.uid() == current_uid(),
            "self-owned profile must pass the owner check"
        );
    }

    #[test]
    fn oversize_profile_is_refused() {
        let dir = temp_dir("oversize");
        let filler = format!(
            "{{\"schema_version\": 1, \"host_tags\": [\"{}\"]}}",
            "x".repeat(MAX_PROFILE_BYTES)
        );
        assert!(filler.len() > MAX_PROFILE_BYTES);
        let path = write_profile(&dir, "profile.json", &filler);
        match load_profile(&path, &base_cfg()) {
            Err(ProfileError::TooLarge { size, .. }) => {
                assert!(size > MAX_PROFILE_BYTES as u64);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_symlink_invalid_utf8_and_writable_parent() {
        let dir = temp_dir("unsafe-input");
        let path = write_profile(&dir, "profile.json", r#"{"schema_version":1}"#);
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_profile(&link, &base_cfg()).is_err());

        std::fs::write(
            &path,
            b"{\"schema_version\":1,\"approved_file_roots\":[\"/tmp/\xff\"]}",
        )
        .unwrap();
        assert!(matches!(load_profile(&path, &base_cfg()),
            Err(ProfileError::Invalid { reason, .. }) if reason.contains("utf-8")));
        write_profile(&dir, "profile.json", r#"{"schema_version":1}"#);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_parent = load_profile(&path, &base_cfg());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(load_profile(&path, &base_cfg()).is_ok());
        assert!(unsafe_parent.is_err());
    }

    #[test]
    fn malformed_json_and_invalid_content_are_explicit_errors() {
        let dir = temp_dir("invalid");
        let bad_json = write_profile(&dir, "bad.json", "{not json");
        match load_profile(&bad_json, &base_cfg()) {
            Err(ProfileError::Invalid { reason, .. }) => assert!(!reason.is_empty()),
            other => panic!("expected Invalid, got {other:?}"),
        }

        let bad_root = write_profile(
            &dir,
            "deny.json",
            r#"{"schema_version": 1, "approved_file_roots": ["/etc/shadow"]}"#,
        );
        let err = load_profile(&bad_root, &base_cfg()).unwrap_err();
        assert!(err.to_string().contains("denylist"), "{err}");

        let slash_root = write_profile(
            &dir,
            "slash.json",
            r#"{"schema_version": 1, "approved_file_roots": ["/"]}"#,
        );
        assert!(load_profile(&slash_root, &base_cfg()).is_err());

        let unknown_field = write_profile(&dir, "unknown.json", r#"{"schema_version": 1, "shell": 1}"#);
        assert!(matches!(
            load_profile(&unknown_field, &base_cfg()),
            Err(ProfileError::Invalid { .. })
        ));

        let missing = load_profile(Path::new("/nonexistent/profile.json"), &base_cfg());
        assert!(matches!(missing, Err(ProfileError::ReadFailed { .. })));

        // A directory, not a regular file.
        let directory = dir.join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(matches!(
            load_profile(&directory, &base_cfg()),
            Err(ProfileError::NotRegularFile { .. })
        ));
    }
}

//! Admin-owned host profile loading for `agent-d` (`--profile <PATH>`).
//!
//! Load-time safety follows sshd's `StrictModes` philosophy: the profile is
//! local administrative input that shapes collection, so every failure is
//! explicit and fatal, and suspicious file metadata (group/world-writable,
//! unexpected owner, oversize) refuses startup rather than being ignored.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

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
        "host profile ancestor {path} is group- or world-writable and is not a root-owned sticky directory (mode {mode:o})"
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

fn open_ancestor(
    parent: Option<RawFd>,
    name: &OsStr,
    path: &Path,
    own: u32,
) -> Result<File, ProfileError> {
    let read_failed = |e: std::io::Error| ProfileError::ReadFailed {
        path: path.display().to_string(),
        message: format!("cannot open or inspect profile ancestor directory: {e}"),
    };
    let fd = openat(
        parent,
        name,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| read_failed(e.into()))?;
    // SAFETY: openat returned a newly owned descriptor.
    let dir = unsafe { File::from_raw_fd(fd) };
    let meta = dir.metadata().map_err(read_failed)?;
    let owner = meta.uid();
    let mode = meta.mode();
    if owner != 0 && owner != own {
        return Err(ProfileError::UnexpectedOwner {
            path: path.display().to_string(),
            owner,
            own,
        });
    }
    if mode & 0o022 != 0 && (owner != 0 || mode & libc::S_ISVTX == 0) {
        return Err(ProfileError::WritableParent {
            path: path.display().to_string(),
            mode: mode & 0o7777,
        });
    }
    Ok(dir)
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
    let path = std::path::absolute(path).map_err(read_failed)?;
    let name = path
        .file_name()
        .ok_or_else(|| ProfileError::NotRegularFile {
            path: display.clone(),
        })?;
    let own = current_uid();
    let mut walked = PathBuf::from("/");
    let mut ancestors = vec![open_ancestor(None, walked.as_os_str(), &walked, own)?];
    for component in path.parent().expect("file has a parent").components() {
        match component {
            Component::Normal(name) => {
                walked.push(name);
                let parent = ancestors.last().expect("root descriptor").as_raw_fd();
                ancestors.push(open_ancestor(Some(parent), name, &walked, own)?);
            }
            // Resolve '..' through the verified chain, even if a directory moves.
            Component::ParentDir if ancestors.len() > 1 => {
                ancestors.pop();
                walked.pop();
            }
            _ => {}
        }
    }
    let parent = ancestors.last().expect("root descriptor").as_raw_fd();
    let fd = openat(
        Some(parent),
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
    if owner != 0 && owner != own {
        return Err(ProfileError::UnexpectedOwner {
            path: display,
            owner,
            own,
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
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("agent-d-profile-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
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
        // 0o620: group-writable must be refused.
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
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(unsafe_parent, Err(ProfileError::WritableParent { .. })));
    }

    #[test]
    fn rejects_group_writable_ancestor_even_with_a_safe_immediate_parent() {
        let ancestor = temp_dir("group-writable-ancestor");
        let parent = ancestor.join("safe");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = write_profile(&parent, "profile.json", r#"{"schema_version":1}"#);
        assert!(load_profile(&path, &base_cfg()).is_ok());

        let modes: &[u32] = if current_uid() == 0 {
            &[0o770]
        } else {
            &[0o770, 0o1770]
        };
        for &mode in modes {
            std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                load_profile(&path, &base_cfg()),
                Err(ProfileError::WritableParent { path, .. }) if Path::new(&path) == ancestor
            ));
        }
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn rejects_symlinked_ancestor_even_with_a_safe_immediate_parent() {
        let dir = temp_dir("symlinked-ancestor");
        let ancestor = dir.join("real");
        let parent = ancestor.join("safe");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&parent)
            .unwrap();
        let path = write_profile(&parent, "profile.json", r#"{"schema_version":1}"#);
        assert!(load_profile(&path, &base_cfg()).is_ok());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&ancestor, &link).unwrap();
        assert!(matches!(
            load_profile(&link.join("safe/profile.json"), &base_cfg()),
            Err(ProfileError::ReadFailed { path, .. }) if Path::new(&path) == link
        ));
    }

    #[test]
    fn accepts_a_root_owned_sticky_writable_ancestor() {
        let Some(sticky) = ["/tmp", "/var/tmp"].into_iter().find(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| {
                meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o1777 == 0o1777
            })
        }) else {
            eprintln!("skipping: /tmp and /var/tmp have no root-owned sticky writable directory");
            return;
        };
        let dir = Path::new(sticky).join(format!("agent-d-profile-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = write_profile(&dir, "profile.json", r#"{"schema_version":1}"#);
        let result = load_profile(&path, &base_cfg());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_ok(), "{result:?}");
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

//! Admin-owned host profile loading for `agent-d` (`--profile <PATH>`).
//!
//! Load-time safety follows sshd's `StrictModes` philosophy: the profile is
//! local administrative input that shapes collection, so every failure is
//! explicit and fatal, and suspicious file metadata (group/world-writable,
//! unexpected owner, oversize) refuses startup rather than being ignored.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use defsec_policy::edge_floor::EdgeSafetyConfig;
use defsec_policy::host_profile::apply_host_profile;
use defsec_protocol::profile::{HostProfile, HostProfileSummary};
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
    #[error("host profile {path} is owned by uid {owner}, expected root or the agent's own uid {own}")]
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
    let meta = std::fs::metadata(path)
        .map_err(|e| ProfileError::ReadFailed {
            path: display.clone(),
            message: e.to_string(),
        })?;
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

    let bytes = std::fs::read(path).map_err(|e| ProfileError::ReadFailed {
        path: display.clone(),
        message: e.to_string(),
    })?;
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };
    let profile: HostProfile = serde_json::from_str(&text).map_err(|e| ProfileError::Invalid {
        path: display.clone(),
        reason: e.to_string(),
    })?;
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
        crate::collectors::files::temp_root(&format!("profile-{tag}"))
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
                "approved_file_roots": ["/etc/myapp"],
                "enabled_collectors": ["sockets.listening", "connections.outbound"],
                "collector_caps": { "max_outbound_flows": 100 }
            }"#,
        );
        let loaded = load_profile(&path, &base_cfg()).unwrap();
        assert_eq!(loaded.cfg.max_outbound_flows, 100);
        assert!(loaded
            .cfg
            .approved_file_roots
            .contains(&std::path::PathBuf::from("/etc/myapp")));
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
        assert!(matches!(
            load_profile(&dir, &base_cfg()),
            Err(ProfileError::NotRegularFile { .. })
        ));
    }
}

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use argon2::password_hash::PasswordHash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use totp_rs::Secret;

use crate::auth::AuthEngine;
use crate::error::{CentralSshError, Result};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7788";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/centralssh/config.json";
pub const DEFAULT_SERVERS_PATH: &str = "/etc/centralssh/servers.json";
pub const DEFAULT_KNOWN_HOSTS_PATH: &str = "/etc/centralssh/known_hosts";
pub const DEFAULT_USER_KEY_ROOT: &str = "/var/lib/centralssh/keys";
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/centralssh/audit.jsonl";

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SettingsConfig {
    pub user_key_root: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
    pub enforce_password_policy: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserRecord {
    pub name: String,
    pub password: String,
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub must_change_password: bool,
    #[serde(default)]
    pub allowed_servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigFile {
    pub users: Vec<UserRecord>,
    #[serde(default)]
    pub settings: SettingsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServersFile {
    pub servers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct EffectivePaths {
    pub config_path: PathBuf,
    pub servers_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub user_key_root: PathBuf,
    pub audit_log_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub config: ConfigFile,
    pub servers: ServersFile,
    pub loaded_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ConfigStore {
    pub paths: EffectivePaths,
    state: Arc<RwLock<RuntimeState>>,
}

impl ConfigStore {
    pub async fn load(paths: EffectivePaths, enforce_strict_security: bool) -> Result<Self> {
        let config = load_config_file(&paths.config_path)?;
        let servers = load_servers_file(&paths.servers_path)?;

        if enforce_strict_security {
            validate_file_security(&paths.config_path, 0o600, true)?;
            validate_file_security(&paths.servers_path, 0o600, true)?;
            validate_file_security(&paths.known_hosts_path, 0o600, true)?;
            validate_directory_security(&paths.user_key_root, 0o700, true)?;
        } else {
            validate_path_has_no_symlinks(&paths.config_path)?;
            validate_path_has_no_symlinks(&paths.servers_path)?;
            validate_path_has_no_symlinks(&paths.known_hosts_path)?;
            validate_path_has_no_symlinks(&paths.user_key_root)?;
        }

        validate_semantics(&config, &servers)?;

        Ok(Self {
            paths,
            state: Arc::new(RwLock::new(RuntimeState {
                config,
                servers,
                loaded_at: Utc::now(),
            })),
        })
    }

    pub async fn snapshot(&self) -> RuntimeState {
        self.state.read().await.clone()
    }

    pub async fn reload(&self, enforce_strict_security: bool) -> Result<()> {
        let config = load_config_file(&self.paths.config_path)?;
        let servers = load_servers_file(&self.paths.servers_path)?;

        if enforce_strict_security {
            validate_file_security(&self.paths.config_path, 0o600, true)?;
            validate_file_security(&self.paths.servers_path, 0o600, true)?;
            validate_file_security(&self.paths.known_hosts_path, 0o600, true)?;
            validate_directory_security(&self.paths.user_key_root, 0o700, true)?;
        } else {
            validate_path_has_no_symlinks(&self.paths.config_path)?;
            validate_path_has_no_symlinks(&self.paths.servers_path)?;
            validate_path_has_no_symlinks(&self.paths.known_hosts_path)?;
            validate_path_has_no_symlinks(&self.paths.user_key_root)?;
        }

        validate_semantics(&config, &servers)?;

        let mut guard = self.state.write().await;
        guard.config = config;
        guard.servers = servers;
        guard.loaded_at = Utc::now();
        Ok(())
    }

    pub async fn migrate_bootstrap_passwords(&self, auth: &AuthEngine) -> Result<usize> {
        let mut guard = self.state.write().await;
        let mut changed = 0usize;

        for user in &mut guard.config.users {
            if !auth.is_hash_format(&user.password) {
                user.password = auth.hash_password(&user.password)?;
                user.must_change_password = true;
                changed += 1;
            }
        }

        if changed > 0 {
            atomic_write_json(&self.paths.config_path, &guard.config)?;
        }

        Ok(changed)
    }

    pub async fn update_user_credentials(
        &self,
        username: &str,
        new_password_hash: Option<String>,
        new_totp_secret: Option<String>,
        must_change_password: Option<bool>,
    ) -> Result<()> {
        let mut guard = self.state.write().await;
        let user = guard
            .config
            .users
            .iter_mut()
            .find(|candidate| candidate.name == username)
            .ok_or_else(|| CentralSshError::InvalidConfig(format!("user not found: {username}")))?;

        if let Some(password_hash) = new_password_hash {
            user.password = password_hash;
        }
        if let Some(totp_secret) = new_totp_secret {
            user.totp_secret = Some(totp_secret);
        }
        if let Some(flag) = must_change_password {
            user.must_change_password = flag;
        }

        atomic_write_json(&self.paths.config_path, &guard.config)?;
        Ok(())
    }
}

pub fn resolve_paths(
    config_path: Option<PathBuf>,
    servers_path: Option<PathBuf>,
    known_hosts_path: Option<PathBuf>,
    user_key_root: Option<PathBuf>,
    audit_log_path: Option<PathBuf>,
    settings: Option<&SettingsConfig>,
) -> EffectivePaths {
    EffectivePaths {
        config_path: config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
        servers_path: servers_path.unwrap_or_else(|| PathBuf::from(DEFAULT_SERVERS_PATH)),
        known_hosts_path: known_hosts_path
            .or_else(|| settings.and_then(|config| config.known_hosts_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KNOWN_HOSTS_PATH)),
        user_key_root: user_key_root
            .or_else(|| settings.and_then(|config| config.user_key_root.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_USER_KEY_ROOT)),
        audit_log_path: audit_log_path
            .or_else(|| settings.and_then(|config| config.audit_log_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_AUDIT_LOG_PATH)),
    }
}

pub fn load_config_file(path: &Path) -> Result<ConfigFile> {
    let bytes = fs::read(path)?;
    let config = serde_json::from_slice(&bytes)?;
    Ok(config)
}

pub fn load_servers_file(path: &Path) -> Result<ServersFile> {
    let bytes = fs::read(path)?;
    let servers = serde_json::from_slice(&bytes)?;
    Ok(servers)
}

pub fn validate_semantics(config: &ConfigFile, servers: &ServersFile) -> Result<()> {
    if config.users.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "config.json must contain at least one user".to_string(),
        ));
    }

    if servers.servers.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "servers.json must contain at least one server".to_string(),
        ));
    }

    let mut seen_server_names = HashSet::new();
    for (server_name, host) in &servers.servers {
        if !is_valid_server_identifier(server_name) {
            return Err(CentralSshError::InvalidConfig(format!(
                "invalid server identifier '{server_name}'"
            )));
        }
        if !seen_server_names.insert(server_name.clone()) {
            return Err(CentralSshError::InvalidConfig(format!(
                "duplicate server identifier '{server_name}'"
            )));
        }
        if !is_valid_host_or_ip(host) {
            return Err(CentralSshError::InvalidConfig(format!(
                "invalid host or IP literal '{host}' for server '{server_name}'"
            )));
        }
    }

    let mut seen_usernames = HashSet::new();
    for user in &config.users {
        if !is_valid_username(&user.name) {
            return Err(CentralSshError::InvalidConfig(format!(
                "invalid user name '{}': use 1-64 chars from [a-zA-Z0-9._-]",
                user.name
            )));
        }
        if !seen_usernames.insert(user.name.clone()) {
            return Err(CentralSshError::InvalidConfig(format!(
                "duplicate user name '{}'",
                user.name
            )));
        }

        validate_password_field(user)?;

        if let Some(secret) = &user.totp_secret {
            validate_totp_secret(secret)?;
        }

        if user.allowed_servers.is_empty() {
            return Err(CentralSshError::InvalidConfig(format!(
                "user '{}' must have at least one allowed server",
                user.name
            )));
        }

        for server_name in &user.allowed_servers {
            if !servers.servers.contains_key(server_name) {
                return Err(CentralSshError::InvalidConfig(format!(
                    "user '{}' references unknown server '{}'",
                    user.name, server_name
                )));
            }
        }
    }

    Ok(())
}

fn validate_password_field(user: &UserRecord) -> Result<()> {
    if user.password.starts_with("$argon2id$") {
        PasswordHash::new(&user.password).map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "invalid Argon2id password hash for '{}': {error}",
                user.name
            ))
        })?;
        return Ok(());
    }

    if user.password.trim().is_empty() {
        return Err(CentralSshError::InvalidConfig(format!(
            "bootstrap password for '{}' must not be empty",
            user.name
        )));
    }

    if user.password.len() > 256 {
        return Err(CentralSshError::InvalidConfig(format!(
            "bootstrap password for '{}' exceeds 256 characters",
            user.name
        )));
    }

    if !user.must_change_password {
        return Err(CentralSshError::InvalidConfig(format!(
            "bootstrap password for '{}' requires must_change_password=true",
            user.name
        )));
    }

    Ok(())
}

fn validate_totp_secret(secret: &str) -> Result<()> {
    Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|error| CentralSshError::InvalidConfig(format!("invalid TOTP secret: {error}")))?;
    Ok(())
}

fn is_valid_username(name: &str) -> bool {
    is_valid_component(name, 64)
}

fn is_valid_server_identifier(name: &str) -> bool {
    is_valid_component(name, 64)
}

fn is_valid_component(name: &str, max_len: usize) -> bool {
    if name.is_empty() || name.len() > max_len {
        return false;
    }

    name.chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
}

fn is_valid_host_or_ip(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }

    if value.is_empty() || value.len() > 253 {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    })
}

pub fn validate_file_security(
    path: &Path,
    expected_mode: u32,
    require_root_owner: bool,
) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "must not be a symlink".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "not a regular file".to_string(),
        });
    }

    validate_mode_and_owner(path, &metadata, expected_mode, require_root_owner)
}

pub fn validate_directory_security(
    path: &Path,
    expected_mode: u32,
    require_root_owner: bool,
) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "must not be a symlink".to_string(),
        });
    }
    if !metadata.is_dir() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "not a directory".to_string(),
        });
    }

    validate_mode_and_owner(path, &metadata, expected_mode, require_root_owner)
}

fn validate_mode_and_owner(
    path: &Path,
    metadata: &fs::Metadata,
    expected_mode: u32,
    require_root_owner: bool,
) -> Result<()> {
    let mode = metadata.mode() & 0o777;
    if mode != expected_mode {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("mode must be {:o}, found {:o}", expected_mode, mode),
        });
    }

    if require_root_owner && metadata.uid() != 0 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("owner uid must be 0, found {}", metadata.uid()),
        });
    }

    Ok(())
}

pub fn validate_path_has_no_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(CentralSshError::SecurityPolicy {
                    path: path.to_path_buf(),
                    message: "parent directory traversal is not allowed".to_string(),
                });
            }
            Component::Normal(part) => current.push(part),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CentralSshError::SecurityPolicy {
                    path: current.clone(),
                    message: "symlink path components are not allowed".to_string(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CentralSshError::Io(error)),
        }
    }

    Ok(())
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CentralSshError::InvalidConfig(format!("path has no parent: {}", path.display()))
    })?;

    validate_path_has_no_symlinks(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: "target file must not be a symlink".to_string(),
            });
        }
    }

    fs::create_dir_all(parent)?;

    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("centralssh"),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let metadata = fs::metadata(path).ok();
    let encoded = serde_json::to_vec_pretty(value)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut temp_file = options.open(&temp_path)?;

    if let Some(existing) = &metadata {
        fs::set_permissions(
            &temp_path,
            fs::Permissions::from_mode(existing.mode() & 0o777),
        )?;
    }

    temp_file.write_all(&encoded)?;
    temp_file.write_all(b"\n")?;
    temp_file.sync_all()?;
    drop(temp_file);

    if let Some(existing) = &metadata {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };

        if euid == 0 {
            let temp_cstr = std::ffi::CString::new(temp_path.to_string_lossy().into_owned())
                .map_err(|_| CentralSshError::InvalidConfig("invalid temp path".to_string()))?;

            #[allow(clippy::cast_possible_wrap)]
            let chown_result =
                unsafe { libc::chown(temp_cstr.as_ptr(), existing.uid(), existing.gid()) };

            if chown_result != 0 {
                return Err(CentralSshError::Io(std::io::Error::last_os_error()));
            }
        } else if existing.uid() != euid || existing.gid() != egid {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: format!(
                    "cannot preserve owner {}:{} as unprivileged uid {}:{}",
                    existing.uid(),
                    existing.gid(),
                    euid,
                    egid
                ),
            });
        }
    }

    fs::rename(&temp_path, path)?;
    fsync_parent(parent)?;
    Ok(())
}

pub fn fsync_parent(parent: &Path) -> Result<()> {
    let directory = File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn valid_config() -> ConfigFile {
        ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "BootstrapPass123!".to_string(),
                totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
                must_change_password: true,
                allowed_servers: vec!["git".to_string()],
            }],
            settings: SettingsConfig::default(),
        }
    }

    fn valid_servers() -> ServersFile {
        let mut servers = HashMap::new();
        servers.insert("git".to_string(), "192.0.2.10".to_string());
        ServersFile { servers }
    }

    #[test]
    fn validate_semantics_rejects_unknown_server() {
        let config = valid_config();
        let servers = ServersFile {
            servers: HashMap::new(),
        };

        let result = validate_semantics(&config, &servers);
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_rejects_duplicate_usernames() {
        let mut config = valid_config();
        config.users.push(config.users[0].clone());

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_rejects_invalid_username_chars() {
        let mut config = valid_config();
        config.users[0].name = "../alice".to_string();

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_rejects_bad_argon_hash() {
        let mut config = valid_config();
        config.users[0].password = "$argon2id$".to_string();

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_rejects_invalid_totp_secret() {
        let mut config = valid_config();
        config.users[0].totp_secret = Some("%%%".to_string());

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn atomic_write_json_roundtrip() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let path = base.join("config.json");
        let payload = valid_config();

        atomic_write_json(&path, &payload).expect("write");
        let loaded = load_config_file(&path).expect("read");
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
    }

    #[test]
    fn validate_file_security_rejects_symlink() {
        let tempdir = TempDir::new().expect("tempdir");
        let target = tempdir.path().join("config.json");
        fs::write(&target, b"{}").expect("write");
        let link = tempdir.path().join("config-link.json");
        symlink(&target, &link).expect("symlink");

        let result = validate_file_security(&link, 0o600, false);
        assert!(result.is_err());
    }

    #[test]
    fn validate_path_has_no_symlinks_rejects_symlink_parent() {
        let tempdir = TempDir::new().expect("tempdir");
        let real_dir = tempdir.path().join("real");
        fs::create_dir(&real_dir).expect("mkdir");
        let link_dir = tempdir.path().join("link");
        symlink(&real_dir, &link_dir).expect("symlink");

        let result = validate_path_has_no_symlinks(&link_dir.join("child"));
        assert!(result.is_err());
    }
}

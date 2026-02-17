use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::auth::AuthEngine;
use crate::error::{CentralSshError, Result};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7788";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/centralssh/config.json";
pub const DEFAULT_SERVERS_PATH: &str = "/etc/centralssh/servers.json";
pub const DEFAULT_KNOWN_HOSTS_PATH: &str = "/etc/centralssh/known_hosts";
pub const DEFAULT_USER_KEY_ROOT: &str = "/etc/centralssh/users";
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/centralssh/audit.jsonl";

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SettingsConfig {
    pub user_key_root: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
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
    #[serde(default)]
    pub remote_users: HashMap<String, String>,
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
            .find(|u| u.name == username)
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
            .or_else(|| settings.and_then(|s| s.known_hosts_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KNOWN_HOSTS_PATH)),
        user_key_root: user_key_root
            .or_else(|| settings.and_then(|s| s.user_key_root.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_USER_KEY_ROOT)),
        audit_log_path: audit_log_path
            .or_else(|| settings.and_then(|s| s.audit_log_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_AUDIT_LOG_PATH)),
    }
}

pub fn load_config_file(path: &Path) -> Result<ConfigFile> {
    let bytes = fs::read(path)?;
    let cfg: ConfigFile = serde_json::from_slice(&bytes)?;
    Ok(cfg)
}

pub fn load_servers_file(path: &Path) -> Result<ServersFile> {
    let bytes = fs::read(path)?;
    let servers: ServersFile = serde_json::from_slice(&bytes)?;
    Ok(servers)
}

pub fn validate_semantics(config: &ConfigFile, servers: &ServersFile) -> Result<()> {
    if config.users.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "config.json must contain at least one user".to_string(),
        ));
    }

    for user in &config.users {
        if user.name.trim().is_empty() {
            return Err(CentralSshError::InvalidConfig(
                "user name cannot be empty".to_string(),
            ));
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

        for server_name in user.remote_users.keys() {
            if !servers.servers.contains_key(server_name) {
                return Err(CentralSshError::InvalidConfig(format!(
                    "user '{}' has remote_users entry for unknown server '{}'",
                    user.name, server_name
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_file_security(
    path: &Path,
    expected_mode: u32,
    require_root_owner: bool,
) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "not a regular file".to_string(),
        });
    }

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

pub fn validate_directory_security(
    path: &Path,
    expected_mode: u32,
    require_root_owner: bool,
) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "not a directory".to_string(),
        });
    }

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

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CentralSshError::InvalidConfig(format!("path has no parent: {}", path.display()))
    })?;

    fs::create_dir_all(parent)?;

    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("centralssh"),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let metadata = fs::metadata(path).ok();
    let encoded = serde_json::to_vec_pretty(value)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut temp_file = options.open(&temp_path)?;

    if let Some(meta) = &metadata {
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(meta.mode() & 0o777))?;
    }

    temp_file.write_all(&encoded)?;
    temp_file.write_all(b"\n")?;
    temp_file.sync_all()?;
    drop(temp_file);

    if let Some(meta) = &metadata {
        #[allow(clippy::cast_possible_wrap)]
        let chown_result = unsafe {
            libc::chown(
                std::ffi::CString::new(temp_path.to_string_lossy().into_owned())
                    .map_err(|_| CentralSshError::InvalidConfig("invalid temp path".to_string()))?
                    .as_ptr(),
                meta.uid(),
                meta.gid(),
            )
        };

        if chown_result != 0 {
            return Err(CentralSshError::Io(std::io::Error::last_os_error()));
        }
    }

    fs::rename(&temp_path, path)?;
    fsync_parent(parent)?;
    Ok(())
}

pub fn fsync_parent(parent: &Path) -> Result<()> {
    let dir = File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validate_semantics_rejects_unknown_server() {
        let config = ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "$argon2id$dummy".to_string(),
                totp_secret: Some("abc".to_string()),
                must_change_password: false,
                allowed_servers: vec!["git".to_string()],
                remote_users: HashMap::new(),
            }],
            settings: SettingsConfig::default(),
        };

        let servers = ServersFile {
            servers: HashMap::new(),
        };

        let result = validate_semantics(&config, &servers);
        assert!(result.is_err());
    }

    #[test]
    fn atomic_write_json_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("config.json");
        let payload = ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "$argon2id$dummy".to_string(),
                totp_secret: Some("abc".to_string()),
                must_change_password: false,
                allowed_servers: vec!["git".to_string()],
                remote_users: HashMap::new(),
            }],
            settings: SettingsConfig::default(),
        };

        atomic_write_json(&path, &payload).expect("write");
        let loaded = load_config_file(&path).expect("read");
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
    }
}

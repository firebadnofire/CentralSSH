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
use toml_edit::{DocumentMut, Item, value};

use crate::abuse::Fail2banConfig;
use crate::auth::{AuthEngine, build_totp_from_secret};
use crate::error::{CentralSshError, Result};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7788";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/centralssh/config.toml";
pub const DEFAULT_SERVERS_PATH: &str = "/etc/centralssh/servers.toml";
pub const DEFAULT_KNOWN_HOSTS_PATH: &str = "/etc/centralssh/known_hosts";
pub const DEFAULT_USER_KEY_ROOT: &str = "/var/lib/centralssh/keys";
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/centralssh/audit.jsonl";
pub const DEFAULT_MIN_PASSWORD_POLICY: usize = 12;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SettingsConfig {
    pub user_key_root: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
    pub whitelist_path: Option<PathBuf>,
    pub per_user_per_server: Option<bool>,
    pub drop_to_menu: Option<bool>,
    pub hide_proxy_ip: Option<bool>,
    pub enforce_password_policy: Option<bool>,
    pub min_password_policy: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KexPolicyConfig {
    #[serde(default = "default_frontend_preferred_kex")]
    pub frontend_preferred: Vec<String>,
    #[serde(default)]
    #[serde(alias = "require_post_quantum")]
    pub frontend_require_post_quantum: bool,
    #[serde(default = "default_backend_preferred_kex")]
    pub backend_preferred: Vec<String>,
    #[serde(default)]
    pub backend_require_post_quantum: bool,
}

impl Default for KexPolicyConfig {
    fn default() -> Self {
        Self {
            frontend_preferred: default_frontend_preferred_kex(),
            frontend_require_post_quantum: false,
            backend_preferred: default_backend_preferred_kex(),
            backend_require_post_quantum: false,
        }
    }
}

fn default_frontend_preferred_kex() -> Vec<String> {
    vec![
        "mlkem768x25519-sha256".to_string(),
        "curve25519-sha256".to_string(),
        "curve25519-sha256@libssh.org".to_string(),
    ]
}

fn default_backend_preferred_kex() -> Vec<String> {
    default_frontend_preferred_kex()
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
    #[serde(default)]
    pub kex_policy: KexPolicyConfig,
    #[serde(default)]
    pub fail2ban: Option<Fail2banConfig>,
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
    pub whitelist_path: Option<PathBuf>,
    pub per_user_per_server: bool,
    pub drop_to_menu: bool,
    pub hide_proxy_ip: bool,
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
        let mut config = load_config_file(&paths.config_path)?;
        let servers = load_servers_file(&paths.servers_path)?;
        apply_runtime_overrides(&mut config, &paths);

        if enforce_strict_security {
            validate_file_security(&paths.config_path, 0o600, true)?;
            validate_file_security(&paths.servers_path, 0o600, true)?;
            validate_file_security(&paths.known_hosts_path, 0o600, true)?;
            validate_directory_security(&paths.user_key_root, 0o700, true)?;
            validate_optional_file_security(paths.whitelist_path.as_deref(), 0o600)?;
        } else {
            validate_path_has_no_symlinks(&paths.config_path)?;
            validate_path_has_no_symlinks(&paths.servers_path)?;
            validate_path_has_no_symlinks(&paths.known_hosts_path)?;
            validate_path_has_no_symlinks(&paths.user_key_root)?;
            validate_optional_path_has_no_symlinks(paths.whitelist_path.as_deref())?;
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
        let mut config = load_config_file(&self.paths.config_path)?;
        let servers = load_servers_file(&self.paths.servers_path)?;
        apply_runtime_overrides(&mut config, &self.paths);

        if enforce_strict_security {
            validate_file_security(&self.paths.config_path, 0o600, true)?;
            validate_file_security(&self.paths.servers_path, 0o600, true)?;
            validate_file_security(&self.paths.known_hosts_path, 0o600, true)?;
            validate_directory_security(&self.paths.user_key_root, 0o700, true)?;
            validate_optional_file_security(self.paths.whitelist_path.as_deref(), 0o600)?;
        } else {
            validate_path_has_no_symlinks(&self.paths.config_path)?;
            validate_path_has_no_symlinks(&self.paths.servers_path)?;
            validate_path_has_no_symlinks(&self.paths.known_hosts_path)?;
            validate_path_has_no_symlinks(&self.paths.user_key_root)?;
            validate_optional_path_has_no_symlinks(self.paths.whitelist_path.as_deref())?;
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
        let mut document = load_config_document(&self.paths.config_path)?;
        let mut changed = 0usize;

        for user in &mut guard.config.users {
            if !auth.is_hash_format(&user.password) {
                let new_password_hash = auth.hash_password(&user.password)?;
                update_user_record_in_document(
                    &mut document,
                    &user.name,
                    Some(new_password_hash.clone()),
                    None,
                    Some(true),
                )?;
                user.password = new_password_hash;
                user.must_change_password = true;
                changed += 1;
            }
        }

        if changed > 0 {
            atomic_write_document(&self.paths.config_path, &document)?;
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
        let password_hash_for_doc = new_password_hash.clone();
        let totp_secret_for_doc = new_totp_secret.clone();
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

        let mut document = load_config_document(&self.paths.config_path)?;
        update_user_record_in_document(
            &mut document,
            username,
            password_hash_for_doc,
            totp_secret_for_doc,
            must_change_password,
        )?;
        atomic_write_document(&self.paths.config_path, &document)?;
        Ok(())
    }
}

pub fn resolve_paths(
    config_path: Option<PathBuf>,
    servers_path: Option<PathBuf>,
    known_hosts_path: Option<PathBuf>,
    user_key_root: Option<PathBuf>,
    audit_log_path: Option<PathBuf>,
    whitelist_path: Option<PathBuf>,
    per_user_per_server: Option<bool>,
    drop_to_menu: Option<bool>,
    hide_proxy_ip: Option<bool>,
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
        whitelist_path: whitelist_path
            .or_else(|| settings.and_then(|config| config.whitelist_path.clone())),
        per_user_per_server: per_user_per_server
            .or_else(|| settings.and_then(|config| config.per_user_per_server))
            .unwrap_or(true),
        drop_to_menu: drop_to_menu
            .or_else(|| settings.and_then(|config| config.drop_to_menu))
            .unwrap_or(false),
        hide_proxy_ip: hide_proxy_ip
            .or_else(|| settings.and_then(|config| config.hide_proxy_ip))
            .unwrap_or(false),
    }
}

fn apply_runtime_overrides(config: &mut ConfigFile, paths: &EffectivePaths) {
    config.settings.whitelist_path = paths.whitelist_path.clone();
    config.settings.per_user_per_server = Some(paths.per_user_per_server);
    config.settings.drop_to_menu = Some(paths.drop_to_menu);
    config.settings.hide_proxy_ip = Some(paths.hide_proxy_ip);
}

pub fn load_config_file(path: &Path) -> Result<ConfigFile> {
    let bytes = fs::read(path)?;
    let config = toml::from_slice(&bytes)?;
    Ok(config)
}

pub fn load_servers_file(path: &Path) -> Result<ServersFile> {
    let bytes = fs::read(path)?;
    let servers = toml::from_slice(&bytes)?;
    Ok(servers)
}

fn validate_optional_file_security(path: Option<&Path>, mode: u32) -> Result<()> {
    if let Some(path) = path {
        validate_file_security(path, mode, true)?;
    }
    Ok(())
}

fn validate_optional_path_has_no_symlinks(path: Option<&Path>) -> Result<()> {
    if let Some(path) = path {
        validate_path_has_no_symlinks(path)?;
    }
    Ok(())
}

fn load_config_document(path: &Path) -> Result<DocumentMut> {
    let content = fs::read_to_string(path)?;
    content.parse::<DocumentMut>().map_err(|error| {
        CentralSshError::InvalidConfig(format!(
            "failed to parse config.toml for in-place update: {error}"
        ))
    })
}

fn update_user_record_in_document(
    document: &mut DocumentMut,
    username: &str,
    new_password_hash: Option<String>,
    new_totp_secret: Option<String>,
    must_change_password: Option<bool>,
) -> Result<()> {
    let users = document["users"].as_array_of_tables_mut().ok_or_else(|| {
        CentralSshError::InvalidConfig(
            "config.toml is missing [[users]] for credential update".to_string(),
        )
    })?;

    let Some(user_table) = users.iter_mut().find(|table| {
        table
            .get("name")
            .and_then(Item::as_str)
            .is_some_and(|name| name == username)
    }) else {
        return Err(CentralSshError::InvalidConfig(format!(
            "user not found in config.toml: {username}"
        )));
    };

    if let Some(password_hash) = new_password_hash {
        user_table["password"] = value(password_hash);
    }
    if let Some(totp_secret) = new_totp_secret {
        user_table["totp_secret"] = value(totp_secret);
    }
    if let Some(flag) = must_change_password {
        user_table["must_change_password"] = value(flag);
    }

    Ok(())
}

pub fn validate_semantics(config: &ConfigFile, servers: &ServersFile) -> Result<()> {
    if let Some(fail2ban) = &config.fail2ban {
        fail2ban.effective(config.settings.whitelist_path.as_deref())?;
    }
    crate::crypto_policy::validate_kex_policy(&config.kex_policy)?;

    if let Some(min_password_policy) = config.settings.min_password_policy {
        if min_password_policy > 256 {
            return Err(CentralSshError::InvalidConfig(format!(
                "settings.min_password_policy must be <= 256, found {min_password_policy}"
            )));
        }
    }

    if config.users.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "config.toml must contain at least one user".to_string(),
        ));
    }

    if servers.servers.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "servers.toml must contain at least one server".to_string(),
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

    if is_rejected_bootstrap_placeholder(&user.password) {
        return Err(CentralSshError::InvalidConfig(format!(
            "bootstrap password for '{}' is a documented placeholder and must be replaced",
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

fn is_rejected_bootstrap_placeholder(password: &str) -> bool {
    matches!(
        password,
        "TemporaryPassword123!"
            | "AnotherTempPass123!"
            | "REPLACE_WITH_UNIQUE_TEMPORARY_PASSWORD"
            | "CHANGE_ME_BEFORE_STARTING"
    )
}

fn validate_totp_secret(secret: &str) -> Result<()> {
    build_totp_from_secret(secret)?;
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

#[cfg(test)]
pub fn atomic_write_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut encoded = toml::to_string_pretty(value)?.into_bytes();
    if !encoded.ends_with(b"\n") {
        encoded.push(b'\n');
    }
    atomic_write_bytes(path, &encoded)
}

fn atomic_write_document(path: &Path, document: &DocumentMut) -> Result<()> {
    let mut encoded = document.to_string().into_bytes();
    if !encoded.ends_with(b"\n") {
        encoded.push(b'\n');
    }
    atomic_write_bytes(path, &encoded)
}

fn atomic_write_bytes(path: &Path, encoded: &[u8]) -> Result<()> {
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

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut temp_file = options.open(&temp_path)?;

    if let Some(existing) = &metadata {
        fs::set_permissions(
            &temp_path,
            fs::Permissions::from_mode(existing.mode() & 0o777),
        )?;
    }

    temp_file.write_all(encoded)?;
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
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn valid_config() -> ConfigFile {
        ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "BootstrapPass123!".to_string(),
                totp_secret: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
                must_change_password: true,
                allowed_servers: vec!["git".to_string()],
            }],
            settings: SettingsConfig::default(),
            kex_policy: KexPolicyConfig::default(),
            fail2ban: None,
        }
    }

    fn valid_servers() -> ServersFile {
        let mut servers = HashMap::new();
        servers.insert("git".to_string(), "192.0.2.10".to_string());
        ServersFile { servers }
    }

    fn canonical_tempdir_path(tempdir: &TempDir) -> PathBuf {
        fs::canonicalize(tempdir.path()).expect("canonicalize tempdir")
    }

    fn write_temp_file(tempdir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = canonical_tempdir_path(tempdir).join(name);
        fs::write(&path, contents).expect("write temp file");
        normalize_test_file_owner(&path);
        path
    }

    fn normalize_test_file_owner(path: &Path) {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let c_path = CString::new(path.as_os_str().as_bytes()).expect("test path cstring");
        let result = unsafe { libc::chown(c_path.as_ptr(), euid, egid) };

        if result != 0 {
            let metadata = fs::metadata(path).expect("metadata after failed chown");
            if metadata.uid() != euid || metadata.gid() != egid {
                panic!(
                    "failed to normalize test file owner to {euid}:{egid}: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
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
    fn validate_semantics_rejects_documented_bootstrap_placeholders() {
        let mut config = valid_config();
        config.users[0].password = "REPLACE_WITH_UNIQUE_TEMPORARY_PASSWORD".to_string();

        let result = validate_semantics(&config, &valid_servers());

        assert!(
            matches!(result, Err(CentralSshError::InvalidConfig(message)) if message.contains("documented placeholder"))
        );
    }

    #[test]
    fn validate_semantics_rejects_invalid_totp_secret() {
        let mut config = valid_config();
        config.users[0].totp_secret = Some("%%%".to_string());

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_rejects_short_decodable_totp_secret() {
        let mut config = valid_config();
        config.users[0].totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn validate_semantics_accepts_runtime_valid_totp_secret() {
        let config = valid_config();

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_ok());
    }

    #[test]
    fn atomic_write_toml_roundtrip() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let path = base.join("config.toml");
        let payload = valid_config();

        atomic_write_toml(&path, &payload).expect("write");
        let loaded = load_config_file(&path).expect("read");
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
    }

    #[test]
    fn load_config_file_accepts_minimal_toml_without_optional_fields() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"
[[users]]
name = "alice"
password = "BootstrapPass123!"
must_change_password = true
allowed_servers = ["git"]
"#,
        );

        let loaded = load_config_file(&path).expect("load config");

        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
        assert_eq!(loaded.users[0].totp_secret, None);
        assert!(loaded.settings.user_key_root.is_none());
        assert!(loaded.settings.known_hosts_path.is_none());
        assert!(loaded.settings.audit_log_path.is_none());
        assert!(loaded.settings.whitelist_path.is_none());
        assert_eq!(loaded.settings.per_user_per_server, None);
        assert_eq!(loaded.settings.drop_to_menu, None);
        assert_eq!(loaded.settings.hide_proxy_ip, None);
        assert_eq!(loaded.settings.enforce_password_policy, None);
        assert_eq!(loaded.settings.min_password_policy, None);
        assert_eq!(
            loaded.kex_policy.frontend_preferred,
            default_frontend_preferred_kex()
        );
        assert!(!loaded.kex_policy.frontend_require_post_quantum);
        assert_eq!(
            loaded.kex_policy.backend_preferred,
            default_backend_preferred_kex()
        );
        assert!(!loaded.kex_policy.backend_require_post_quantum);
    }

    #[test]
    fn load_config_file_accepts_multiple_users_and_settings_paths() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"
[[users]]
name = "alice"
password = "$argon2id$v=19$m=65536,t=3,p=1$YWFhYWFhYWFhYWFhYWFhYQ$5SJ0fY5fKQh0nqS5BTPw8P7GIw6Y73Q2xU1j5V6k8To"
allowed_servers = ["git", "httpd"]

[[users]]
name = "bob"
password = "TestOnlyBootstrapPass456!"
must_change_password = true
allowed_servers = ["git"]

[settings]
user_key_root = "/var/lib/centralssh/keys"
known_hosts_path = "/etc/centralssh/known_hosts"
audit_log_path = "/var/log/centralssh/audit.jsonl"
whitelist_path = "/etc/centralssh/whitelist.txt"
per_user_per_server = false
drop_to_menu = true
hide_proxy_ip = true
enforce_password_policy = false
min_password_policy = 20
"#,
        );

        let loaded = load_config_file(&path).expect("load config");

        assert_eq!(loaded.users.len(), 2);
        assert_eq!(loaded.users[0].allowed_servers, vec!["git", "httpd"]);
        assert_eq!(loaded.users[1].name, "bob");
        assert_eq!(
            loaded.settings.user_key_root,
            Some(PathBuf::from("/var/lib/centralssh/keys"))
        );
        assert_eq!(
            loaded.settings.known_hosts_path,
            Some(PathBuf::from("/etc/centralssh/known_hosts"))
        );
        assert_eq!(
            loaded.settings.audit_log_path,
            Some(PathBuf::from("/var/log/centralssh/audit.jsonl"))
        );
        assert_eq!(
            loaded.settings.whitelist_path,
            Some(PathBuf::from("/etc/centralssh/whitelist.txt"))
        );
        assert_eq!(loaded.settings.per_user_per_server, Some(false));
        assert_eq!(loaded.settings.drop_to_menu, Some(true));
        assert_eq!(loaded.settings.hide_proxy_ip, Some(true));
        assert_eq!(loaded.settings.enforce_password_policy, Some(false));
        assert_eq!(loaded.settings.min_password_policy, Some(20));
    }

    #[test]
    fn load_config_file_accepts_legacy_frontend_require_post_quantum_field() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"
[[users]]
name = "alice"
password = "BootstrapPass123!"
must_change_password = true
allowed_servers = ["git"]

[kex_policy]
require_post_quantum = true
"#,
        );

        let loaded = load_config_file(&path).expect("load config");

        assert!(loaded.kex_policy.frontend_require_post_quantum);
        assert!(!loaded.kex_policy.backend_require_post_quantum);
    }

    #[test]
    fn validate_semantics_rejects_min_password_policy_above_maximum() {
        let mut config = valid_config();
        config.settings.min_password_policy = Some(257);

        let result = validate_semantics(&config, &valid_servers());
        assert!(result.is_err());
    }

    #[test]
    fn load_config_file_rejects_wrong_allowed_servers_type() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"
[[users]]
name = "alice"
password = "BootstrapPass123!"
must_change_password = true
allowed_servers = "git"
"#,
        );

        let result = load_config_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_file_accepts_array_of_inline_tables() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"
users = [
  { name = "alice", password = "BootstrapPass123!", must_change_password = true, allowed_servers = ["git"] }
]
"#,
        );

        let loaded = load_config_file(&path).expect("load config");
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
        assert_eq!(loaded.users[0].allowed_servers, vec!["git"]);
    }

    #[test]
    fn load_servers_file_accepts_comments_hostname_and_ipv6() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "servers.toml",
            r#"
# comment
[servers]
git = "git.internal.example"
dns = "2001:db8::53"
"#,
        );

        let loaded = load_servers_file(&path).expect("load servers");

        assert_eq!(
            loaded.servers.get("git"),
            Some(&"git.internal.example".to_string())
        );
        assert_eq!(loaded.servers.get("dns"), Some(&"2001:db8::53".to_string()));
    }

    #[test]
    fn load_servers_file_rejects_wrong_table_type() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "servers.toml",
            r#"
servers = ["git"]
"#,
        );

        let result = load_servers_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn atomic_write_toml_omits_none_optional_fields() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let path = base.join("config.toml");
        let payload = ConfigFile {
            users: vec![UserRecord {
                name: "alice".to_string(),
                password: "BootstrapPass123!".to_string(),
                totp_secret: None,
                must_change_password: true,
                allowed_servers: vec!["git".to_string()],
            }],
            settings: SettingsConfig::default(),
            kex_policy: KexPolicyConfig::default(),
            fail2ban: None,
        };

        atomic_write_toml(&path, &payload).expect("write");
        let encoded = fs::read_to_string(&path).expect("read string");

        assert!(!encoded.contains("totp_secret"));
        assert!(!encoded.contains("user_key_root"));
        assert!(!encoded.contains("per_user_per_server"));
        assert!(!encoded.contains("hide_proxy_ip"));
    }

    #[test]
    fn config_document_update_preserves_comments() {
        let tempdir = TempDir::new().expect("tempdir");
        let path = write_temp_file(
            &tempdir,
            "config.toml",
            r#"# top comment
[[users]]
# user comment
name = "alice"
password = "BootstrapPass123!"
must_change_password = true
allowed_servers = ["git"]
"#,
        );

        let mut document = load_config_document(&path).expect("load document");
        update_user_record_in_document(
            &mut document,
            "alice",
            Some(
                "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuv"
                    .to_string(),
            ),
            Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            Some(false),
        )
        .expect("update document");
        atomic_write_document(&path, &document).expect("write document");

        let encoded = fs::read_to_string(&path).expect("read string");
        assert!(encoded.contains("# top comment"));
        assert!(encoded.contains("# user comment"));
        assert!(encoded.contains("totp_secret"));
    }

    #[test]
    fn validate_file_security_rejects_symlink() {
        let tempdir = TempDir::new().expect("tempdir");
        let target = tempdir.path().join("config.toml");
        fs::write(&target, b"{}").expect("write");
        let link = tempdir.path().join("config-link.toml");
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, warn};

use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::config::{ConfigFile, fsync_parent, validate_path_has_no_symlinks};
use crate::error::{CentralSshError, Result};

const DEFAULT_FAIL2BAN_ENABLED: bool = true;
const DEFAULT_MAX_FAILURES: u32 = 5;
const DEFAULT_FIND_TIME: Duration = Duration::from_secs(60);
const DEFAULT_BAN_TIME: Duration = Duration::from_secs(10 * 60);
const DEFAULT_MAX_BAN_TIME: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;
const DEFAULT_DELAY_BEFORE_BAN: bool = true;
const DEFAULT_DELAY_TIME: Duration = Duration::from_secs(2);
const DEFAULT_PERSIST_STATE: bool = true;
const DEFAULT_STATE_PATH: &str = "/var/lib/centralssh/fail2ban_state.json";

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Fail2banWhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Fail2banConfig {
    pub enabled: Option<bool>,
    pub max_failures: Option<u32>,
    pub find_time: Option<String>,
    pub ban_time: Option<String>,
    pub max_ban_time: Option<String>,
    pub backoff_multiplier: Option<f64>,
    pub delay_before_ban: Option<bool>,
    pub delay_time: Option<String>,
    pub persist_state: Option<bool>,
    pub state_path: Option<PathBuf>,
    #[serde(default)]
    pub whitelist: Fail2banWhitelistConfig,
}

#[derive(Debug, Clone)]
pub struct Fail2banSettings {
    pub enabled: bool,
    pub max_failures: u32,
    pub find_time: Duration,
    pub ban_time: Duration,
    pub max_ban_time: Duration,
    pub backoff_multiplier: f64,
    pub delay_before_ban: bool,
    pub delay_time: Duration,
    pub persist_state: bool,
    pub state_path: PathBuf,
    pub whitelist: Vec<IpNet>,
}

impl Default for Fail2banSettings {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_FAIL2BAN_ENABLED,
            max_failures: DEFAULT_MAX_FAILURES,
            find_time: DEFAULT_FIND_TIME,
            ban_time: DEFAULT_BAN_TIME,
            max_ban_time: DEFAULT_MAX_BAN_TIME,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            delay_before_ban: DEFAULT_DELAY_BEFORE_BAN,
            delay_time: DEFAULT_DELAY_TIME,
            persist_state: DEFAULT_PERSIST_STATE,
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            whitelist: vec![
                "127.0.0.1/32".parse().expect("default ipv4 localhost cidr"),
                "::1/128".parse().expect("default ipv6 localhost cidr"),
            ],
        }
    }
}

impl Fail2banSettings {
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|cidr| cidr.contains(&ip))
    }
}

impl Fail2banConfig {
    pub fn effective(&self, whitelist_path: Option<&Path>) -> Result<Fail2banSettings> {
        let defaults = Fail2banSettings::default();
        let settings = Fail2banSettings {
            enabled: self.enabled.unwrap_or(defaults.enabled),
            max_failures: self.max_failures.unwrap_or(defaults.max_failures),
            find_time: parse_duration_option(
                self.find_time.as_deref(),
                defaults.find_time,
                "find_time",
            )?,
            ban_time: parse_duration_option(
                self.ban_time.as_deref(),
                defaults.ban_time,
                "ban_time",
            )?,
            max_ban_time: parse_duration_option(
                self.max_ban_time.as_deref(),
                defaults.max_ban_time,
                "max_ban_time",
            )?,
            backoff_multiplier: self
                .backoff_multiplier
                .unwrap_or(defaults.backoff_multiplier),
            delay_before_ban: self.delay_before_ban.unwrap_or(defaults.delay_before_ban),
            delay_time: parse_duration_option(
                self.delay_time.as_deref(),
                defaults.delay_time,
                "delay_time",
            )?,
            persist_state: self.persist_state.unwrap_or(defaults.persist_state),
            state_path: self
                .state_path
                .clone()
                .unwrap_or_else(|| defaults.state_path.clone()),
            whitelist: parse_whitelist(&self.whitelist.ips, whitelist_path)?,
        };

        validate_fail2ban_settings(&settings)?;
        Ok(settings)
    }
}

fn parse_duration_option(value: Option<&str>, default: Duration, field: &str) -> Result<Duration> {
    value
        .map(|raw| {
            humantime::parse_duration(raw).map_err(|error| {
                CentralSshError::InvalidConfig(format!(
                    "invalid fail2ban.{field} duration '{raw}': {error}"
                ))
            })
        })
        .transpose()
        .map(|duration| duration.unwrap_or(default))
}

fn parse_whitelist(values: &[String], whitelist_path: Option<&Path>) -> Result<Vec<IpNet>> {
    let mut whitelist = Fail2banSettings::default().whitelist;
    let mut seen = whitelist.iter().cloned().collect::<HashSet<_>>();

    for entry in values {
        let cidr = entry.parse::<IpNet>().map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "invalid fail2ban whitelist entry '{entry}': {error}"
            ))
        })?;
        if seen.insert(cidr) {
            whitelist.push(cidr);
        }
    }

    if let Some(path) = whitelist_path {
        for entry in read_whitelist_file(path)? {
            if seen.insert(entry) {
                whitelist.push(entry);
            }
        }
    }

    Ok(whitelist)
}

fn read_whitelist_file(path: &Path) -> Result<Vec<IpNet>> {
    let content = fs::read_to_string(path)?;
    let mut whitelist = Vec::new();

    for (line_number, raw_line) in content.lines().enumerate() {
        let line = raw_line
            .split_once('#')
            .map(|(head, _)| head)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }

        let ip = line.parse::<IpAddr>().map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "invalid fail2ban whitelist IP '{}' at {}:{}: {}",
                line,
                path.display(),
                line_number + 1,
                error
            ))
        })?;
        whitelist.push(single_host_net(ip));
    }

    Ok(whitelist)
}

fn single_host_net(ip: IpAddr) -> IpNet {
    IpNet::from(ip)
}

pub fn validate_fail2ban_settings(settings: &Fail2banSettings) -> Result<()> {
    if settings.max_failures == 0 {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.max_failures must be >= 1".to_string(),
        ));
    }
    if settings.find_time.is_zero() {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.find_time must be > 0".to_string(),
        ));
    }
    if settings.ban_time.is_zero() {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.ban_time must be > 0".to_string(),
        ));
    }
    if settings.max_ban_time < settings.ban_time {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.max_ban_time must be >= fail2ban.ban_time".to_string(),
        ));
    }
    if settings.backoff_multiplier < 1.0 {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.backoff_multiplier must be >= 1.0".to_string(),
        ));
    }
    if settings.delay_before_ban && settings.delay_time.is_zero() {
        return Err(CentralSshError::InvalidConfig(
            "fail2ban.delay_time must be > 0 when delay_before_ban is enabled".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AbuseEntry {
    #[serde(default)]
    pub recent_failures: VecDeque<DateTime<Utc>>,
    #[serde(default)]
    pub total_failures: u64,
    #[serde(default)]
    pub ban_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ban_count: u32,
    #[serde(default)]
    pub last_failure: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_success: Option<DateTime<Utc>>,
    #[serde(default)]
    pub recent_usernames: VecDeque<String>,
    #[serde(default)]
    pub recent_target_servers: VecDeque<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    #[serde(default)]
    entries: HashMap<String, AbuseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanEventKind {
    Created,
    Extended,
}

#[derive(Debug, Clone)]
pub struct BanEvent {
    pub kind: BanEventKind,
    pub ban_until: DateTime<Utc>,
    pub ban_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct PreAuthCheck {
    pub whitelisted: bool,
    pub had_state: bool,
    pub expired_ban: bool,
    pub banned: bool,
    pub ban_until: Option<DateTime<Utc>>,
    pub ban_duration: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct FailureOutcome {
    pub whitelisted: bool,
    pub delay: Option<Duration>,
    pub ban_event: Option<BanEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct SuccessOutcome;

#[derive(Debug, Default)]
struct AbuseTrackerCore {
    entries: HashMap<IpAddr, AbuseEntry>,
}

impl AbuseTrackerCore {
    fn apply_loaded_state(&mut self, entries: HashMap<IpAddr, AbuseEntry>) {
        self.entries = entries;
    }

    fn check_ip(
        &mut self,
        ip: IpAddr,
        now: DateTime<Utc>,
        settings: &Fail2banSettings,
    ) -> PreAuthCheck {
        if !settings.enabled {
            return PreAuthCheck {
                whitelisted: false,
                had_state: false,
                expired_ban: false,
                banned: false,
                ban_until: None,
                ban_duration: None,
            };
        }

        if settings.is_whitelisted(ip) {
            let had_state = self.entries.contains_key(&ip);
            return PreAuthCheck {
                whitelisted: true,
                had_state,
                expired_ban: false,
                banned: false,
                ban_until: None,
                ban_duration: None,
            };
        }

        let Some(entry) = self.entries.get_mut(&ip) else {
            return PreAuthCheck {
                whitelisted: false,
                had_state: false,
                expired_ban: false,
                banned: false,
                ban_until: None,
                ban_duration: None,
            };
        };

        prune_failures(entry, now, settings.find_time);
        let had_state = true;
        let expired_ban = entry
            .ban_until
            .filter(|ban_until| *ban_until <= now)
            .map(|_| {
                entry.ban_until = None;
                true
            })
            .unwrap_or(false);

        if let Some(ban_until) = entry.ban_until.filter(|ban_until| *ban_until > now) {
            let remaining = (ban_until - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(0));
            return PreAuthCheck {
                whitelisted: false,
                had_state,
                expired_ban,
                banned: true,
                ban_until: Some(ban_until),
                ban_duration: Some(remaining),
            };
        }

        PreAuthCheck {
            whitelisted: false,
            had_state,
            expired_ban,
            banned: false,
            ban_until: None,
            ban_duration: None,
        }
    }

    fn record_failure(
        &mut self,
        ip: IpAddr,
        username: Option<&str>,
        target_server: Option<&str>,
        now: DateTime<Utc>,
        settings: &Fail2banSettings,
    ) -> FailureOutcome {
        if !settings.enabled {
            return FailureOutcome {
                whitelisted: false,
                delay: None,
                ban_event: None,
            };
        }

        if settings.is_whitelisted(ip) {
            return FailureOutcome {
                whitelisted: true,
                delay: None,
                ban_event: None,
            };
        }

        let entry = self.entries.entry(ip).or_default();
        prune_failures(entry, now, settings.find_time);
        entry.last_failure = Some(now);
        entry.total_failures = entry.total_failures.saturating_add(1);
        entry.recent_failures.push_back(now);
        push_recent_value(&mut entry.recent_usernames, username);
        push_recent_value(&mut entry.recent_target_servers, target_server);

        let failure_count = entry.recent_failures.len() as u32;
        if failure_count >= settings.max_failures {
            let previous_bans = entry.ban_count;
            let ban_duration = compute_ban_duration(settings, previous_bans);
            let ban_until = now + chrono::TimeDelta::from_std(ban_duration).unwrap_or_default();
            entry.ban_until = Some(ban_until);
            entry.ban_count = entry.ban_count.saturating_add(1);
            return FailureOutcome {
                whitelisted: false,
                delay: None,
                ban_event: Some(BanEvent {
                    kind: if previous_bans == 0 {
                        BanEventKind::Created
                    } else {
                        BanEventKind::Extended
                    },
                    ban_until,
                    ban_duration,
                }),
            };
        }

        let delay = if settings.delay_before_ban
            && settings.max_failures > 1
            && failure_count >= settings.max_failures.saturating_sub(1)
        {
            Some(settings.delay_time)
        } else {
            None
        };

        FailureOutcome {
            whitelisted: false,
            delay,
            ban_event: None,
        }
    }

    fn record_success(
        &mut self,
        ip: IpAddr,
        now: DateTime<Utc>,
        settings: &Fail2banSettings,
    ) -> SuccessOutcome {
        if !settings.enabled {
            return SuccessOutcome;
        }
        if settings.is_whitelisted(ip) {
            return SuccessOutcome;
        }

        if let Some(entry) = self.entries.get_mut(&ip) {
            if entry.ban_until.is_some_and(|ban_until| ban_until > now) {
                entry.last_success = Some(now);
                return SuccessOutcome;
            }

            entry.last_success = Some(now);
            entry.recent_failures.clear();
            entry.recent_usernames.clear();
            entry.recent_target_servers.clear();
        }

        SuccessOutcome
    }

    fn snapshot_for_persistence(
        &mut self,
        now: DateTime<Utc>,
        settings: &Fail2banSettings,
    ) -> PersistedState {
        let mut persisted = HashMap::new();
        self.entries.retain(|_, entry| {
            prune_failures(entry, now, settings.find_time);
            let active = !entry.recent_failures.is_empty()
                || entry.ban_until.is_some_and(|ban_until| ban_until > now)
                || entry.ban_count > 0
                || entry.last_failure.is_some()
                || entry.last_success.is_some();
            active
        });

        for (ip, entry) in &self.entries {
            persisted.insert(ip.to_string(), entry.clone());
        }

        PersistedState { entries: persisted }
    }
}

fn push_recent_value(values: &mut VecDeque<String>, value: Option<&str>) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return;
    };

    if values.iter().any(|existing| existing == value) {
        return;
    }

    if values.len() >= 5 {
        values.pop_front();
    }
    values.push_back(value.to_string());
}

fn prune_failures(entry: &mut AbuseEntry, now: DateTime<Utc>, window: Duration) {
    let Ok(window) = chrono::TimeDelta::from_std(window) else {
        return;
    };
    while entry
        .recent_failures
        .front()
        .is_some_and(|timestamp| *timestamp + window < now)
    {
        entry.recent_failures.pop_front();
    }
}

fn compute_ban_duration(settings: &Fail2banSettings, previous_ban_count: u32) -> Duration {
    let scale = settings.backoff_multiplier.powi(previous_ban_count as i32);
    let scaled = settings.ban_time.mul_f64(scale);
    scaled.min(settings.max_ban_time)
}

#[derive(Clone)]
pub struct AbuseTracker {
    settings: Arc<RwLock<Fail2banSettings>>,
    core: Arc<Mutex<AbuseTrackerCore>>,
    audit: AuditLogger,
}

impl AbuseTracker {
    pub async fn from_config(config: &ConfigFile, audit: AuditLogger) -> Result<Self> {
        let effective = config
            .fail2ban
            .clone()
            .unwrap_or_default()
            .effective(config.settings.whitelist_path.as_deref())?;
        let tracker = Self {
            settings: Arc::new(RwLock::new(effective.clone())),
            core: Arc::new(Mutex::new(AbuseTrackerCore::default())),
            audit,
        };
        tracker.load_persisted_state(&effective).await;
        Ok(tracker)
    }

    pub async fn reload_from_config(&self, config: &ConfigFile) -> Result<()> {
        let effective = config
            .fail2ban
            .clone()
            .unwrap_or_default()
            .effective(config.settings.whitelist_path.as_deref())?;
        {
            let mut guard = self.settings.write().await;
            *guard = effective.clone();
        }
        self.load_persisted_state(&effective).await;
        Ok(())
    }

    pub async fn check_ip(&self, ip: IpAddr) -> PreAuthCheck {
        let settings = self.settings.read().await.clone();
        let mut guard = self.core.lock().await;
        let result = guard.check_ip(ip, Utc::now(), &settings);
        if result.expired_ban || result.banned {
            self.persist_if_enabled(&settings, &mut guard).await;
        }
        result
    }

    pub async fn record_failure(
        &self,
        ip: IpAddr,
        username: Option<&str>,
        target_server: Option<&str>,
    ) -> FailureOutcome {
        let settings = self.settings.read().await.clone();
        let mut guard = self.core.lock().await;
        let outcome = guard.record_failure(ip, username, target_server, Utc::now(), &settings);
        self.persist_if_enabled(&settings, &mut guard).await;
        outcome
    }

    pub async fn record_success(&self, ip: IpAddr) -> SuccessOutcome {
        let settings = self.settings.read().await.clone();
        let mut guard = self.core.lock().await;
        let outcome = guard.record_success(ip, Utc::now(), &settings);
        self.persist_if_enabled(&settings, &mut guard).await;
        outcome
    }

    async fn load_persisted_state(&self, settings: &Fail2banSettings) {
        if !settings.persist_state {
            return;
        }

        match read_state_file(&settings.state_path, settings) {
            Ok(entries) => {
                let mut guard = self.core.lock().await;
                guard.apply_loaded_state(entries);
            }
            Err(error) => {
                warn!(error = %error, path = %settings.state_path.display(), "failed to load fail2ban state");
                let _ = self
                    .audit
                    .log(AuditEvent::system(
                        "fail2ban_state_load",
                        AuditResult::Error,
                        Some(error.to_string()),
                    ))
                    .await;
            }
        }
    }

    async fn persist_if_enabled(&self, settings: &Fail2banSettings, guard: &mut AbuseTrackerCore) {
        if !settings.persist_state {
            return;
        }

        let snapshot = guard.snapshot_for_persistence(Utc::now(), settings);
        if let Err(error) = write_state_file(&settings.state_path, &snapshot) {
            error!(error = %error, path = %settings.state_path.display(), "failed to persist fail2ban state");
            let _ = self
                .audit
                .log(AuditEvent::system(
                    "fail2ban_state_save",
                    AuditResult::Error,
                    Some(error.to_string()),
                ))
                .await;
        }
    }
}

fn read_state_file(
    path: &Path,
    settings: &Fail2banSettings,
) -> Result<HashMap<IpAddr, AbuseEntry>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(CentralSshError::Io(error)),
    };

    let persisted: PersistedState = serde_json::from_slice(&bytes)?;
    let mut entries = HashMap::new();
    let now = Utc::now();
    for (raw_ip, mut entry) in persisted.entries {
        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            continue;
        };
        prune_failures(&mut entry, now, settings.find_time);
        if entry.ban_until.is_some_and(|ban_until| ban_until <= now) {
            entry.ban_until = None;
        }
        if !entry.recent_failures.is_empty()
            || entry.ban_until.is_some()
            || entry.ban_count > 0
            || entry.last_failure.is_some()
            || entry.last_success.is_some()
        {
            entries.insert(ip, entry);
        }
    }

    Ok(entries)
}

fn write_state_file(path: &Path, value: &PersistedState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CentralSshError::InvalidConfig(format!(
            "fail2ban state path has no parent: {}",
            path.display()
        ))
    })?;
    validate_path_has_no_symlinks(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: "fail2ban state path must not be a symlink".to_string(),
            });
        }
    }

    fs::create_dir_all(parent)?;
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fail2ban_state"),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let metadata = fs::metadata(path).ok();
    let mut encoded = serde_json::to_vec_pretty(value)?;
    if !encoded.ends_with(b"\n") {
        encoded.push(b'\n');
    }

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp_path)?;
    if let Some(existing) = &metadata {
        fs::set_permissions(
            &temp_path,
            fs::Permissions::from_mode(existing.mode() & 0o777),
        )?;
    }
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_tempdir_path(tempdir: &TempDir) -> PathBuf {
        fs::canonicalize(tempdir.path()).expect("canonicalize tempdir")
    }
    use crate::config::{ConfigFile, SettingsConfig};
    use std::str::FromStr;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::task::JoinSet;

    fn settings() -> Fail2banSettings {
        Fail2banSettings {
            whitelist: Vec::new(),
            persist_state: false,
            state_path: PathBuf::from("/tmp/unused"),
            ..Fail2banSettings::default()
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-02T20:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc)
    }

    #[test]
    fn basic_ban_after_n_failures_within_window() {
        let ip = IpAddr::from_str("192.0.2.10").expect("ip");
        let settings = settings();
        let mut core = AbuseTrackerCore::default();
        let start = now();

        for offset in 0..4 {
            let outcome = core.record_failure(
                ip,
                Some("alice"),
                None,
                start + chrono::TimeDelta::seconds(offset),
                &settings,
            );
            assert!(outcome.ban_event.is_none());
        }

        let banned = core.record_failure(
            ip,
            Some("alice"),
            None,
            start + chrono::TimeDelta::seconds(4),
            &settings,
        );
        assert!(matches!(
            banned.ban_event.as_ref().map(|event| &event.kind),
            Some(BanEventKind::Created)
        ));
    }

    #[test]
    fn no_ban_when_failures_fall_outside_sliding_window() {
        let ip = IpAddr::from_str("192.0.2.11").expect("ip");
        let mut settings = settings();
        settings.find_time = Duration::from_secs(10);
        let mut core = AbuseTrackerCore::default();
        let start = now();

        for offset in [0, 11, 22, 33, 44] {
            let outcome = core.record_failure(
                ip,
                Some("alice"),
                None,
                start + chrono::TimeDelta::seconds(offset),
                &settings,
            );
            assert!(outcome.ban_event.is_none());
        }
    }

    #[test]
    fn repeated_bans_backoff_exponentially() {
        let ip = IpAddr::from_str("192.0.2.12").expect("ip");
        let settings = settings();
        let mut core = AbuseTrackerCore::default();
        let start = now();

        let first = core.record_failure(ip, None, None, start, &settings);
        let second = core.record_failure(
            ip,
            None,
            None,
            start + chrono::TimeDelta::seconds(1),
            &settings,
        );
        let third = core.record_failure(
            ip,
            None,
            None,
            start + chrono::TimeDelta::seconds(2),
            &settings,
        );
        let fourth = core.record_failure(
            ip,
            None,
            None,
            start + chrono::TimeDelta::seconds(3),
            &settings,
        );
        assert!(first.ban_event.is_none());
        assert!(second.ban_event.is_none());
        assert!(third.ban_event.is_none());
        assert!(fourth.ban_event.is_none());
        let created = core.record_failure(
            ip,
            None,
            None,
            start + chrono::TimeDelta::seconds(4),
            &settings,
        );
        let first_ban = created.ban_event.expect("first ban");

        let after_expiry = first_ban.ban_until + chrono::TimeDelta::seconds(1);
        let _ = core.check_ip(ip, after_expiry, &settings);
        for offset in 0..5 {
            let outcome = core.record_failure(
                ip,
                None,
                None,
                after_expiry + chrono::TimeDelta::seconds(offset.into()),
                &settings,
            );
            if offset < 4 {
                assert!(outcome.ban_event.is_none());
            } else {
                let second_ban = outcome.ban_event.expect("second ban");
                assert_eq!(second_ban.kind, BanEventKind::Extended);
                assert_eq!(second_ban.ban_duration, settings.ban_time.mul_f64(2.0));
            }
        }
    }

    #[test]
    fn ban_time_is_capped() {
        let mut settings = settings();
        settings.ban_time = Duration::from_secs(10);
        settings.max_ban_time = Duration::from_secs(15);
        let duration = compute_ban_duration(&settings, 10);
        assert_eq!(duration, settings.max_ban_time);
    }

    #[test]
    fn expired_bans_are_ignored() {
        let ip = IpAddr::from_str("192.0.2.13").expect("ip");
        let settings = settings();
        let mut core = AbuseTrackerCore::default();
        let start = now();
        for offset in 0..5 {
            let _ = core.record_failure(
                ip,
                None,
                None,
                start + chrono::TimeDelta::seconds(offset.into()),
                &settings,
            );
        }

        let ban_until = core
            .entries
            .get(&ip)
            .and_then(|entry| entry.ban_until)
            .expect("ban");
        let check = core.check_ip(ip, ban_until + chrono::TimeDelta::seconds(1), &settings);
        assert!(!check.banned);
        assert!(check.expired_ban);
    }

    #[test]
    fn success_clears_recent_failures_for_non_banned_ips() {
        let ip = IpAddr::from_str("192.0.2.14").expect("ip");
        let settings = settings();
        let mut core = AbuseTrackerCore::default();
        let start = now();
        for offset in 0..2 {
            let _ = core.record_failure(
                ip,
                Some("alice"),
                None,
                start + chrono::TimeDelta::seconds(offset.into()),
                &settings,
            );
        }

        let _ = core.record_success(ip, start + chrono::TimeDelta::seconds(10), &settings);
        assert!(
            core.entries
                .get(&ip)
                .expect("entry")
                .recent_failures
                .is_empty()
        );
    }

    #[test]
    fn whitelist_bypass_supports_ipv4_cidr() {
        let mut settings = settings();
        settings.whitelist = vec!["192.168.0.0/16".parse().expect("cidr")];
        let ip = IpAddr::from_str("192.168.10.10").expect("ip");
        let mut core = AbuseTrackerCore::default();
        let outcome = core.record_failure(ip, None, None, now(), &settings);
        assert!(outcome.whitelisted);
        assert!(core.entries.is_empty());
    }

    #[test]
    fn whitelist_bypass_supports_ipv6_cidr() {
        let mut settings = settings();
        settings.whitelist = vec!["2001:db8::/32".parse().expect("cidr")];
        let ip = IpAddr::from_str("2001:db8::1234").expect("ip");
        let mut core = AbuseTrackerCore::default();
        let outcome = core.record_failure(ip, None, None, now(), &settings);
        assert!(outcome.whitelisted);
    }

    #[test]
    fn whitelist_file_supports_ipv4_and_ipv6_per_row() {
        let tempdir = TempDir::new().expect("tempdir");
        let whitelist_path = tempdir.path().join("whitelist.txt");
        fs::write(
            &whitelist_path,
            "203.0.113.10\n\n# comment\n2001:db8::10  # inline comment\n",
        )
        .expect("write whitelist");

        let loaded = read_whitelist_file(&whitelist_path).expect("load whitelist");

        assert!(loaded.contains(&single_host_net(
            IpAddr::from_str("203.0.113.10").expect("ipv4")
        )));
        assert!(loaded.contains(&single_host_net(
            IpAddr::from_str("2001:db8::10").expect("ipv6")
        )));
    }

    #[test]
    fn fail2ban_effective_merges_inline_and_file_whitelist_entries() {
        let tempdir = TempDir::new().expect("tempdir");
        let whitelist_path = tempdir.path().join("whitelist.txt");
        fs::write(&whitelist_path, "203.0.113.10\n2001:db8::10\n").expect("write whitelist");

        let config = Fail2banConfig {
            whitelist: Fail2banWhitelistConfig {
                ips: vec!["198.51.100.0/24".to_string()],
            },
            ..Fail2banConfig::default()
        };

        let effective = config
            .effective(Some(&whitelist_path))
            .expect("effective settings");

        assert!(effective.is_whitelisted(IpAddr::from_str("127.0.0.1").expect("localhost")));
        assert!(effective.is_whitelisted(IpAddr::from_str("198.51.100.42").expect("inline")));
        assert!(effective.is_whitelisted(IpAddr::from_str("203.0.113.10").expect("file ipv4")));
        assert!(effective.is_whitelisted(IpAddr::from_str("2001:db8::10").expect("file ipv6")));
    }

    #[test]
    fn fail2ban_effective_rejects_invalid_whitelist_file_ip() {
        let tempdir = TempDir::new().expect("tempdir");
        let whitelist_path = tempdir.path().join("whitelist.txt");
        fs::write(&whitelist_path, "not-an-ip\n").expect("write whitelist");

        let error = Fail2banConfig::default()
            .effective(Some(&whitelist_path))
            .expect_err("invalid whitelist file must fail");

        assert!(error.to_string().contains("invalid fail2ban whitelist IP"));
    }

    #[tokio::test]
    async fn corrupted_or_missing_state_file_does_not_crash() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = canonical_tempdir_path(&tempdir);
        let path = base.join("state.json");
        fs::write(&path, b"{not valid json").expect("write");
        let logger = AuditLogger::new(base.join("audit.jsonl"), false).expect("logger");
        let tracker = AbuseTracker {
            settings: Arc::new(RwLock::new(Fail2banSettings {
                persist_state: true,
                state_path: path.clone(),
                whitelist: Vec::new(),
                ..Fail2banSettings::default()
            })),
            core: Arc::new(Mutex::new(AbuseTrackerCore::default())),
            audit: logger,
        };

        tracker
            .load_persisted_state(&tracker.settings.read().await.clone())
            .await;
        assert!(tracker.core.lock().await.entries.is_empty());
    }

    #[test]
    fn persisted_json_never_contains_password_fields() {
        let state = PersistedState::default();
        let encoded = serde_json::to_string(&state).expect("json");
        assert!(!encoded.contains("\"password\""));
        assert!(!encoded.contains("\"token\""));
    }

    #[tokio::test]
    async fn concurrent_failure_recording_is_safe() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = canonical_tempdir_path(&tempdir);
        let logger = AuditLogger::new(base.join("audit.jsonl"), false).expect("logger");
        let tracker = Arc::new(AbuseTracker {
            settings: Arc::new(RwLock::new(Fail2banSettings {
                persist_state: false,
                state_path: base.join("state.json"),
                whitelist: Vec::new(),
                ..Fail2banSettings::default()
            })),
            core: Arc::new(Mutex::new(AbuseTrackerCore::default())),
            audit: logger,
        });
        let ip = IpAddr::from_str("192.0.2.55").expect("ip");
        let mut join_set = JoinSet::new();

        for _ in 0..16 {
            let tracker = tracker.clone();
            join_set.spawn(async move { tracker.record_failure(ip, Some("alice"), None).await });
        }

        while let Some(result) = join_set.join_next().await {
            result.expect("task");
        }

        let check = tracker.check_ip(ip).await;
        assert!(check.banned);
    }

    #[tokio::test]
    async fn abuse_tracker_honors_whitelist_path_from_config_settings() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = canonical_tempdir_path(&tempdir);
        let whitelist_path = base.join("whitelist.txt");
        fs::write(&whitelist_path, "203.0.113.10\n").expect("write whitelist");
        let logger = AuditLogger::new(base.join("audit.jsonl"), false).expect("logger");
        let config = ConfigFile {
            users: Vec::new(),
            settings: SettingsConfig {
                whitelist_path: Some(whitelist_path),
                ..SettingsConfig::default()
            },
            kex_policy: crate::config::KexPolicyConfig::default(),
            fail2ban: Some(Fail2banConfig::default()),
            server_user_policies: HashMap::new(),
        };

        let tracker = AbuseTracker::from_config(&config, logger)
            .await
            .expect("tracker");
        let outcome = tracker
            .record_failure(IpAddr::from_str("203.0.113.10").expect("ip"), None, None)
            .await;

        assert!(outcome.whitelisted);
    }
}

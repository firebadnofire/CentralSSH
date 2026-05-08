use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::config::validate_path_has_no_symlinks;
use crate::error::{CentralSshError, Result};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
    Banned,
    Delayed,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub request_id: String,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub username: Option<String>,
    pub target_server: Option<String>,
    pub auth_method: Option<String>,
    pub result: AuditResult,
    pub reason: Option<String>,
    pub ban_duration_seconds: Option<u64>,
    pub ban_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_side: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kex_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kex_algorithms_offered: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classical_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_required: Option<bool>,
}

impl AuditEvent {
    pub fn system(event_type: &str, result: AuditResult, reason: Option<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            request_id: "system".to_string(),
            remote_ip: None,
            remote_port: None,
            username: None,
            target_server: None,
            auth_method: None,
            result,
            reason,
            ban_duration_seconds: None,
            ban_until: None,
            transport_side: None,
            kex_algorithm: None,
            kex_algorithms_offered: None,
            post_quantum: None,
            hybrid: None,
            classical_fallback: None,
            pq_required: None,
        }
    }
}

#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
    file: Arc<Mutex<std::fs::File>>,
}

impl AuditLogger {
    pub fn new(path: PathBuf, enforce_strict_security: bool) -> Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            CentralSshError::InvalidConfig(format!(
                "audit log path has no parent: {}",
                path.display()
            ))
        })?;
        validate_path_has_no_symlinks(parent)?;

        fs::create_dir_all(parent)?;

        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(CentralSshError::SecurityPolicy {
                    path: path.clone(),
                    message: "audit log path must not be a symlink".to_string(),
                });
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        if enforce_strict_security {
            validate_audit_file_security(&path)?;
        } else {
            validate_path_has_no_symlinks(&path)?;
        }

        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub async fn log(&self, event: AuditEvent) -> Result<()> {
        let mut guard = self.file.lock().await;
        serde_json::to_writer(&mut *guard, &event)?;
        guard.write_all(b"\n")?;
        guard.sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_audit_file_security(path: &Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "audit log path must not be a symlink".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "audit log path is not a regular file".to_string(),
        });
    }

    let mode = metadata.mode() & 0o777;
    if mode != 0o600 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("audit log mode must be 600, found {:o}", mode),
        });
    }

    if metadata.uid() != 0 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("audit log owner uid must be 0, found {}", metadata.uid()),
        });
    }

    Ok(())
}

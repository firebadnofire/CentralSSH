use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::error::{CentralSshError, Result};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub session_id: String,
    pub source_ip: Option<String>,
    pub username: Option<String>,
    pub target_server: Option<String>,
    pub result: AuditResult,
    pub reason_code: Option<String>,
}

#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
    file: Arc<Mutex<std::fs::File>>,
}

impl AuditLogger {
    pub fn new(path: PathBuf, enforce_strict_security: bool) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        if enforce_strict_security {
            validate_audit_file_security(&path)?;
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
    let metadata = fs::metadata(path)?;
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

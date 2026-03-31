use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use tokio::sync::Notify;
use tracing::error;

use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::auth::AuthEngine;
use crate::config::ConfigStore;
use crate::error::Result;

#[derive(Clone)]
pub struct AppState {
    pub config_store: ConfigStore,
    pub auth: AuthEngine,
    pub audit: AuditLogger,
    pub strict_security: bool,
    pub reload_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapReport {
    pub migrated_passwords: usize,
}

impl AppState {
    pub async fn bootstrap(&self) -> Result<BootstrapReport> {
        let migrated_passwords = self
            .config_store
            .migrate_bootstrap_passwords(&self.auth)
            .await?;

        Ok(BootstrapReport { migrated_passwords })
    }

    pub async fn reload_on_signal_loop(&self) {
        loop {
            self.reload_notify.notified().await;
            let result = self.config_store.reload(self.strict_security).await;
            if let Err(error) = &result {
                error!(error = %error, "config reload failed");
            }

            let _ = self
                .audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "config_reload".to_string(),
                    session_id: "system".to_string(),
                    source_ip: None,
                    username: None,
                    target_server: None,
                    result: if result.is_ok() {
                        AuditResult::Success
                    } else {
                        AuditResult::Failure
                    },
                    reason_code: result.err().map(|error| error.to_string()),
                })
                .await;
        }
    }
}

pub fn host_key_path_from_config_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("/etc/centralssh"))
        .join("host_ed25519")
}

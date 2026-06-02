use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Notify;
use tracing::error;

use crate::abuse::AbuseTracker;
use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::auth::AuthEngine;
use crate::config::ConfigStore;
use crate::error::Result;
use crate::keys::ensure_private_keys_for_config_users;

#[derive(Clone)]
pub struct AppState {
    pub config_store: ConfigStore,
    pub auth: AuthEngine,
    pub audit: AuditLogger,
    pub abuse: AbuseTracker,
    pub strict_security: bool,
    pub reload_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapReport {
    pub migrated_passwords: usize,
    pub created_user_dirs: usize,
    pub created_server_dirs: usize,
    pub created_private_keys: usize,
    pub created_public_keys: usize,
}

impl AppState {
    pub async fn bootstrap(&self) -> Result<BootstrapReport> {
        let migrated_passwords = self
            .config_store
            .migrate_bootstrap_passwords(&self.auth)
            .await?;
        let snapshot = self.config_store.snapshot().await;
        let key_report = ensure_private_keys_for_config_users(
            &self.config_store.paths.user_key_root,
            &snapshot.config,
            self.config_store.paths.per_user_per_server,
        )?;

        Ok(BootstrapReport {
            migrated_passwords,
            created_user_dirs: key_report.created_user_dirs,
            created_server_dirs: key_report.created_server_dirs,
            created_private_keys: key_report.created_private_keys,
            created_public_keys: key_report.created_public_keys,
        })
    }

    pub async fn reload_on_signal_loop(&self) {
        loop {
            self.reload_notify.notified().await;
            let result = self.config_store.reload(self.strict_security).await;
            if result.is_ok() {
                let snapshot = self.config_store.snapshot().await;
                if let Err(error) = self.abuse.reload_from_config(&snapshot.config).await {
                    error!(error = %error, "fail2ban reload failed");
                }
            }
            if let Err(error) = &result {
                error!(error = %error, "config reload failed");
            }

            let _ = self
                .audit
                .log(AuditEvent::system(
                    "config_reload",
                    if result.is_ok() {
                        AuditResult::Success
                    } else {
                        AuditResult::Failure
                    },
                    result.err().map(|error| error.to_string()),
                ))
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

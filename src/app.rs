use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::auth::AuthEngine;
use crate::config::{ConfigStore, UserRecord};
use crate::error::{CentralSshError, Result};
use crate::keys::{KeyProvisionResult, reconcile_user_keys};
use crate::ssh;
use crate::ui;

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
    pub key_reconciliation: Vec<KeyProvisionResult>,
}

#[derive(Debug, Clone)]
pub struct TransportAuthContext {
    pub username: String,
    pub totp_verified: bool,
}

impl AppState {
    pub async fn bootstrap(&self) -> Result<BootstrapReport> {
        let migrated_passwords = self
            .config_store
            .migrate_bootstrap_passwords(&self.auth)
            .await?;

        let snapshot = self.config_store.snapshot().await;
        let usernames = snapshot
            .config
            .users
            .iter()
            .map(|u| u.name.clone())
            .collect::<Vec<_>>();

        let key_reconciliation =
            reconcile_user_keys(&self.config_store.paths.user_key_root, &usernames)?;

        Ok(BootstrapReport {
            migrated_passwords,
            key_reconciliation,
        })
    }

    pub async fn reload_on_signal_loop(&self) {
        loop {
            self.reload_notify.notified().await;
            let result = self.config_store.reload(self.strict_security).await;
            if let Err(err) = &result {
                error!(error = %err, "config reload failed");
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
                    reason_code: result.err().map(|e| e.to_string()),
                })
                .await;
        }
    }
}

pub async fn handle_stream_session<S>(
    mut stream: S,
    state: Arc<AppState>,
    source_ip: IpAddr,
    transport_auth: Option<TransportAuthContext>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session_id = Uuid::new_v4().to_string();
    ui::write_text(&mut stream, &ui::render_gateway_banner()).await?;

    let mut authenticated_user = None;
    let mut attempt_count = 0usize;
    let mut used_transport_auth = false;
    let mut totp_verified = false;

    if let Some(transport_auth) = transport_auth {
        let snapshot = state.config_store.snapshot().await;
        if let Some(user) = snapshot
            .config
            .users
            .iter()
            .find(|candidate| candidate.name == transport_auth.username)
        {
            authenticated_user = Some(user.clone());
            totp_verified = transport_auth.totp_verified;
            used_transport_auth = true;
        } else {
            return Err(CentralSshError::AuthenticationFailed);
        }
    }

    while attempt_count < 5 && authenticated_user.is_none() {
        let username = ui::prompt_line(
            &mut stream,
            "Username: ",
            state.auth.pre_auth_timeout(),
            64,
            ui::EchoMode::Visible,
        )
        .await?
        .trim()
        .to_string();

        let password = ui::prompt_line(
            &mut stream,
            "Password: ",
            state.auth.pre_auth_timeout(),
            256,
            ui::EchoMode::Hidden,
        )
        .await?
        .trim()
        .to_string();

        let password = AuthEngine::zeroize_password(password);

        if let Err(err) = state
            .auth
            .consume_rate_limit_token(source_ip, &username)
            .await
        {
            state
                .audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "auth_attempt".to_string(),
                    session_id: session_id.clone(),
                    source_ip: Some(source_ip.to_string()),
                    username: Some(username.clone()),
                    target_server: None,
                    result: AuditResult::Blocked,
                    reason_code: Some(err.to_string()),
                })
                .await?;

            ui::write_text(&mut stream, "\r\nRate limit exceeded. Try again later.\r\n").await?;
            return Err(CentralSshError::RateLimitExceeded);
        }

        let snapshot = state.config_store.snapshot().await;
        match state.auth.verify_password_constant_time(
            &snapshot.config.users,
            &username,
            password.as_str(),
        ) {
            Ok(mut user) => {
                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "auth_password".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(user.name.clone()),
                        target_server: None,
                        result: AuditResult::Success,
                        reason_code: None,
                    })
                    .await?;

                if let Err(err) = run_first_login_flows_if_needed(
                    &mut stream,
                    state.clone(),
                    &session_id,
                    source_ip,
                    &mut user,
                )
                .await
                {
                    let message = match &err {
                        CentralSshError::InputCanceled => String::new(),
                        CentralSshError::InvalidConfig(reason) => {
                            format!("\r\nCredential update failed: {reason}\r\n")
                        }
                        CentralSshError::SecurityPolicy { message, .. } => {
                            format!(
                                "\r\nCredential update blocked by security policy: {message}\r\n"
                            )
                        }
                        _ => "\r\nCredential update failed. Contact an administrator.\r\n"
                            .to_string(),
                    };

                    if !message.is_empty() {
                        let _ = ui::write_text(&mut stream, &message).await;
                    }

                    return Err(err);
                }

                // TOTP challenge is always required before menu access.
                let code = ui::prompt_line(
                    &mut stream,
                    "TOTP Code: ",
                    state.auth.pre_auth_timeout(),
                    16,
                    ui::EchoMode::Hidden,
                )
                .await?;

                let secret = user.totp_secret.clone().ok_or_else(|| {
                    CentralSshError::InvalidConfig("missing TOTP secret".to_string())
                })?;

                if let Err(err) = state.auth.verify_totp_code(&secret, code.trim()) {
                    attempt_count += 1;
                    state
                        .audit
                        .log(AuditEvent {
                            timestamp: Utc::now(),
                            event_type: "auth_totp".to_string(),
                            session_id: session_id.clone(),
                            source_ip: Some(source_ip.to_string()),
                            username: Some(user.name.clone()),
                            target_server: None,
                            result: AuditResult::Failure,
                            reason_code: Some(err.to_string()),
                        })
                        .await?;

                    ui::write_text(&mut stream, "\r\nInvalid authentication credentials.\r\n")
                        .await?;
                    continue;
                }

                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "auth_totp".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(user.name.clone()),
                        target_server: None,
                        result: AuditResult::Success,
                        reason_code: None,
                    })
                    .await?;

                totp_verified = true;
                authenticated_user = Some(user);
            }
            Err(err) => {
                attempt_count += 1;
                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "auth_attempt".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(username.clone()),
                        target_server: None,
                        result: AuditResult::Failure,
                        reason_code: Some(err.to_string()),
                    })
                    .await?;

                ui::write_text(&mut stream, "\r\nInvalid authentication credentials.\r\n").await?;
            }
        }
    }

    let Some(mut user) = authenticated_user else {
        state
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: "auth_lockout".to_string(),
                session_id: session_id.clone(),
                source_ip: Some(source_ip.to_string()),
                username: None,
                target_server: None,
                result: AuditResult::Blocked,
                reason_code: Some("too_many_attempts".to_string()),
            })
            .await?;

        ui::write_text(
            &mut stream,
            "\r\nMaximum authentication attempts exceeded.\r\n",
        )
        .await?;
        return Err(CentralSshError::AuthenticationFailed);
    };

    if used_transport_auth {
        let had_totp_before = user.totp_secret.is_some();
        if let Err(err) = run_first_login_flows_if_needed(
            &mut stream,
            state.clone(),
            &session_id,
            source_ip,
            &mut user,
        )
        .await
        {
            let message = match &err {
                CentralSshError::InputCanceled => String::new(),
                CentralSshError::InvalidConfig(reason) => {
                    format!("\r\nCredential update failed: {reason}\r\n")
                }
                CentralSshError::SecurityPolicy { message, .. } => {
                    format!("\r\nCredential update blocked by security policy: {message}\r\n")
                }
                _ => "\r\nCredential update failed. Contact an administrator.\r\n".to_string(),
            };

            if !message.is_empty() {
                let _ = ui::write_text(&mut stream, &message).await;
            }

            return Err(err);
        }

        let snapshot = state.config_store.snapshot().await;
        if let Some(fresh_user) = snapshot
            .config
            .users
            .iter()
            .find(|candidate| candidate.name == user.name)
        {
            user = fresh_user.clone();
        } else {
            return Err(CentralSshError::AuthorizationDenied);
        }

        if !had_totp_before && user.totp_secret.is_some() {
            // TOTP enrollment flow includes successful code verification.
            totp_verified = true;
        }

        if !totp_verified {
            let code = ui::prompt_line(
                &mut stream,
                "TOTP Code: ",
                state.auth.pre_auth_timeout(),
                16,
                ui::EchoMode::Hidden,
            )
            .await?;

            let secret = user
                .totp_secret
                .clone()
                .ok_or_else(|| CentralSshError::InvalidConfig("missing TOTP secret".to_string()))?;

            if let Err(err) = state.auth.verify_totp_code(&secret, code.trim()) {
                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "auth_totp".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(user.name.clone()),
                        target_server: None,
                        result: AuditResult::Failure,
                        reason_code: Some(err.to_string()),
                    })
                    .await?;

                ui::write_text(&mut stream, "\r\nInvalid authentication credentials.\r\n").await?;
                return Err(CentralSshError::AuthenticationFailed);
            }

            state
                .audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "auth_totp".to_string(),
                    session_id: session_id.clone(),
                    source_ip: Some(source_ip.to_string()),
                    username: Some(user.name.clone()),
                    target_server: None,
                    result: AuditResult::Success,
                    reason_code: None,
                })
                .await?;
        }
    }

    loop {
        let snapshot = state.config_store.snapshot().await;
        if let Some(fresh_user) = snapshot
            .config
            .users
            .iter()
            .find(|candidate| candidate.name == user.name)
        {
            user = fresh_user.clone();
        } else {
            return Err(CentralSshError::AuthorizationDenied);
        }

        let entries = user
            .allowed_servers
            .iter()
            .filter_map(|server_name| {
                snapshot
                    .servers
                    .servers
                    .get(server_name)
                    .map(|ip| (server_name.clone(), ip.clone()))
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            ui::write_text(
                &mut stream,
                "\r\nNo allowed servers are currently available.\r\n",
            )
            .await?;
            return Err(CentralSshError::AuthorizationDenied);
        }

        ui::write_text(&mut stream, &ui::render_server_menu(&user.name, &entries)).await?;
        let selection_raw = ui::read_line(
            &mut stream,
            state.auth.menu_timeout(),
            16,
            ui::EchoMode::Visible,
        )
        .await?;
        let selection = selection_raw.trim();

        if matches!(selection, "q" | "Q" | "quit" | "exit") {
            ui::write_text(&mut stream, "\r\nGoodbye.\r\n").await?;
            return Ok(());
        }

        let index = match selection.parse::<usize>() {
            Ok(parsed) if parsed > 0 && parsed <= entries.len() => parsed - 1,
            _ => {
                ui::write_text(&mut stream, "\r\nInvalid selection.\r\n").await?;
                continue;
            }
        };

        let (target_name, target_ip) = entries[index].clone();
        let remote_user = user.name.clone();

        let private_key_path = state
            .config_store
            .paths
            .user_key_root
            .join(&user.name)
            .join("id_ed25519");

        if !private_key_path.exists() {
            let message = format!(
                "\r\nMissing key {}. Ask an administrator to reconcile keys.\r\n",
                private_key_path.display()
            );
            ui::write_text(&mut stream, &message).await?;

            state
                .audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "proxy_start".to_string(),
                    session_id: session_id.clone(),
                    source_ip: Some(source_ip.to_string()),
                    username: Some(user.name.clone()),
                    target_server: Some(target_name.clone()),
                    result: AuditResult::Failure,
                    reason_code: Some("missing_user_private_key".to_string()),
                })
                .await?;
            continue;
        }

        state
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: "server_selected".to_string(),
                session_id: session_id.clone(),
                source_ip: Some(source_ip.to_string()),
                username: Some(user.name.clone()),
                target_server: Some(target_name.clone()),
                result: AuditResult::Success,
                reason_code: None,
            })
            .await?;

        ui::write_text(&mut stream, "\r\nOpening proxied SSH session...\r\n").await?;
        let proxy_result = ssh::proxy::proxy_session(
            &mut stream,
            &state.config_store.paths.known_hosts_path,
            &target_ip,
            &remote_user,
            &private_key_path,
            state.auth.proxy_idle_timeout(),
        )
        .await;

        match proxy_result {
            Ok(()) => {
                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "proxy_end".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(user.name.clone()),
                        target_server: Some(target_name.clone()),
                        result: AuditResult::Success,
                        reason_code: None,
                    })
                    .await?;
            }
            Err(err) => {
                let lower = err.to_string().to_ascii_lowercase();
                let error_message = if lower.contains("known host")
                    || lower.contains("host key")
                    || lower.contains("check_known_hosts")
                {
                    format!(
                        "\r\nProxy error for {} ({}): host key verification failed. \
Administrator must update {} and reload CentralSSH with SIGHUP.\r\n",
                        target_name,
                        target_ip,
                        state.config_store.paths.known_hosts_path.display()
                    )
                } else {
                    format!(
                        "\r\nProxy error for {} ({}): {}\r\n",
                        target_name, target_ip, err
                    )
                };

                ui::write_text(&mut stream, &error_message).await?;
                state
                    .audit
                    .log(AuditEvent {
                        timestamp: Utc::now(),
                        event_type: "proxy_end".to_string(),
                        session_id: session_id.clone(),
                        source_ip: Some(source_ip.to_string()),
                        username: Some(user.name.clone()),
                        target_server: Some(target_name.clone()),
                        result: AuditResult::Failure,
                        reason_code: Some(err.to_string()),
                    })
                    .await?;
                continue;
            }
        }
    }
}

async fn run_first_login_flows_if_needed<S>(
    stream: &mut S,
    state: Arc<AppState>,
    session_id: &str,
    source_ip: IpAddr,
    user: &mut UserRecord,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if user.must_change_password {
        ui::write_text(stream, "\r\nPassword change required.\r\n").await?;
        let enforce_password_policy = state
            .config_store
            .snapshot()
            .await
            .config
            .settings
            .enforce_password_policy
            .unwrap_or(true);

        loop {
            let new_password = ui::prompt_line(
                stream,
                "New password: ",
                state.auth.pre_auth_timeout(),
                256,
                ui::EchoMode::Hidden,
            )
            .await?;
            let confirm_password = ui::prompt_line(
                stream,
                "Confirm password: ",
                state.auth.pre_auth_timeout(),
                256,
                ui::EchoMode::Hidden,
            )
            .await?;

            if new_password != confirm_password {
                ui::write_text(stream, "\r\nPasswords do not match.\r\n").await?;
                continue;
            }

            let new_password_trimmed = new_password.trim();
            if enforce_password_policy {
                match state
                    .auth
                    .enforce_password_policy(new_password_trimmed, &user.password)
                {
                    Ok(()) => {}
                    Err(CentralSshError::InvalidConfig(message)) => {
                        let feedback = format!("\r\n{message}\r\n");
                        ui::write_text(stream, &feedback).await?;
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            } else if new_password_trimmed.is_empty() {
                ui::write_text(
                    stream,
                    "\r\npassword cannot be empty when policy is disabled\r\n",
                )
                .await?;
                continue;
            }

            let new_hash = state.auth.hash_password(new_password_trimmed)?;
            if let Err(err) = state
                .config_store
                .update_user_credentials(&user.name, Some(new_hash.clone()), None, Some(false))
                .await
            {
                ui::write_text(
                    stream,
                    "\r\nFailed to persist password change. Contact an administrator.\r\n",
                )
                .await?;
                return Err(err);
            }

            user.password = new_hash;
            user.must_change_password = false;

            state
                .audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "password_change".to_string(),
                    session_id: session_id.to_string(),
                    source_ip: Some(source_ip.to_string()),
                    username: Some(user.name.clone()),
                    target_server: None,
                    result: AuditResult::Success,
                    reason_code: None,
                })
                .await?;
            break;
        }
    }

    if user.totp_secret.is_none() {
        ui::write_text(stream, "\r\nTOTP enrollment required.\r\n").await?;

        let secret = state.auth.generate_totp_secret();
        let url = state.auth.otpauth_url("CentralSSH", &user.name, &secret)?;
        let qr = ui::render_enrollment_qr(&url)?;

        let enrollment_text = format!(
            "\r\nAdd this account to your authenticator app:\r\n\r\n{}\r\n\r\nSecret: {}\r\nURI: {}\r\n\r\n",
            qr, secret, url
        );
        ui::write_text(stream, &enrollment_text).await?;

        loop {
            let code = ui::prompt_line(
                stream,
                "Enter verification code: ",
                state.auth.pre_auth_timeout(),
                16,
                ui::EchoMode::Hidden,
            )
            .await?;

            match state.auth.verify_totp_code(&secret, code.trim()) {
                Ok(()) => {
                    state
                        .config_store
                        .update_user_credentials(
                            &user.name,
                            None,
                            Some(secret.clone()),
                            Some(false),
                        )
                        .await?;
                    user.totp_secret = Some(secret.clone());

                    state
                        .audit
                        .log(AuditEvent {
                            timestamp: Utc::now(),
                            event_type: "totp_enrollment".to_string(),
                            session_id: session_id.to_string(),
                            source_ip: Some(source_ip.to_string()),
                            username: Some(user.name.clone()),
                            target_server: None,
                            result: AuditResult::Success,
                            reason_code: None,
                        })
                        .await?;

                    ui::write_text(stream, "\r\nTOTP enrollment complete.\r\n").await?;
                    break;
                }
                Err(_) => {
                    ui::write_text(stream, "\r\nInvalid TOTP code. Try again.\r\n").await?;
                }
            }
        }
    }

    info!(username = %user.name, "first login checks complete");
    warn!(username = %user.name, "sensitive operations completed; verify audit trail");

    Ok(())
}

pub fn host_key_path_from_config_dir(config_path: &std::path::Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/etc/centralssh"))
        .join("host_ed25519")
}

use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use qrcode::QrCode;
use qrcode::types::Color;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Sig, client};
use ssh_key::{LineEnding, PrivateKey};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::abuse::{BanEvent, BanEventKind, FailureOutcome, PreAuthCheck};
use crate::app::AppState;
use crate::audit::{AuditEvent, AuditResult};
use crate::config::validate_path_has_no_symlinks;
use crate::config::{
    DEFAULT_MIN_PASSWORD_POLICY, EffectiveAuthorizationPolicy, UserRecord,
    resolve_effective_authorization_policy,
};
use crate::crypto_policy::{
    apply_client_transport_crypto_policy, apply_server_transport_crypto_policy,
};
use crate::error::{CentralSshError, Result};

pub mod proxy;

const SSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
const SSH_KEEPALIVE_MAX: usize = 3;
const ENROLLMENT_QR_QUIET_ZONE: usize = 4;
const ENROLLMENT_QR_DARK_MODULE: &str = "█";
const ENROLLMENT_QR_LIGHT_MODULE: &str = " ";
const ENROLLMENT_QR_TOP_HALF_DARK_BOTTOM_LIGHT: &str = "▀";
const ENROLLMENT_QR_TOP_HALF_LIGHT_BOTTOM_DARK: &str = "▄";

#[derive(Clone)]
struct GatewayServer {
    state: Arc<AppState>,
}

struct GatewayHandler {
    state: Arc<AppState>,
    peer_ip: IpAddr,
    peer_port: Option<u16>,
    session_id: String,
    keyboard_auth_state: Option<KeyboardAuthState>,
    authenticated_username: Option<String>,
    pending_target: Option<proxy::SelectedTarget>,
    active_policy: Option<EffectiveAuthorizationPolicy>,
    proxy_session: Option<proxy::ProxySession>,
    session_channel_state: Arc<Mutex<HashMap<ChannelId, proxy::SessionChannelState>>>,
    connection_logged: bool,
}

struct PendingAuthContext {
    user: UserRecord,
    new_password_hash: Option<String>,
    login_password: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy)]
struct PasswordPolicyConfig {
    enforce: bool,
    min_length: usize,
}

enum KeyboardAuthState {
    AwaitPassword {
        username: String,
    },
    AwaitExistingTotp {
        username: String,
        password: Zeroizing<String>,
    },
    AwaitNewPassword {
        context: PendingAuthContext,
        password_policy: PasswordPolicyConfig,
    },
    AwaitConfirmPassword {
        context: PendingAuthContext,
        password_policy: PasswordPolicyConfig,
        candidate_password: Zeroizing<String>,
    },
    AwaitEnrollmentTotp {
        context: PendingAuthContext,
        secret: String,
    },
    AwaitSelection {
        context: PendingAuthContext,
    },
}

impl GatewayServer {
    fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl server::Server for GatewayServer {
    type Handler = GatewayHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        GatewayHandler {
            state: self.state.clone(),
            peer_ip: peer_addr
                .map(|address| address.ip())
                .unwrap_or(IpAddr::from([0, 0, 0, 0])),
            peer_port: peer_addr.map(|address| address.port()),
            session_id: uuid::Uuid::new_v4().to_string(),
            keyboard_auth_state: None,
            authenticated_username: None,
            pending_target: None,
            active_policy: None,
            proxy_session: None,
            session_channel_state: Arc::new(Mutex::new(HashMap::new())),
            connection_logged: false,
        }
    }
}

impl GatewayHandler {
    fn keyboard_interactive_methods() -> MethodSet {
        MethodSet::from(&[MethodKind::KeyboardInteractive][..])
    }

    fn reject_to_keyboard_interactive() -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(Self::keyboard_interactive_methods()),
            partial_success: false,
        }
    }

    fn keyboard_prompt(instructions: String, prompt: &'static str, echo: bool) -> Auth {
        Auth::Partial {
            name: Cow::Borrowed("CentralSSH Gateway"),
            instructions: Cow::Owned(instructions),
            prompts: Cow::Owned(vec![(Cow::Borrowed(prompt), echo)]),
        }
    }

    fn password_prompt(_username: &str) -> Auth {
        Self::keyboard_prompt(String::new(), "Password: ", false)
    }

    fn new_password_prompt(_username: &str, message: Option<&str>) -> Auth {
        let mut instructions = String::new();
        if let Some(message) = message {
            instructions.push_str(message);
            instructions.push('\n');
            instructions.push('\n');
        }
        instructions.push_str("\nPassword change required before target access.\n");
        Self::keyboard_prompt(instructions, "New password: ", false)
    }

    fn confirm_password_prompt(_username: &str) -> Auth {
        Self::keyboard_prompt(
            "Confirm your new password.\n".to_string(),
            "Confirm password: ",
            false,
        )
    }

    fn totp_prompt(_username: &str, message: Option<&str>) -> Auth {
        let mut instructions = String::new();
        if let Some(message) = message {
            instructions.push_str(message);
            instructions.push('\n');
            instructions.push('\n');
        }
        instructions.push_str("\nEnter the current TOTP code.\n");
        Self::keyboard_prompt(instructions, "TOTP Code: ", false)
    }

    fn enrollment_prompt(_username: &str, secret: &str, url: &str, message: Option<&str>) -> Auth {
        let mut instructions = String::new();
        if let Some(message) = message {
            instructions.push_str(message);
            instructions.push('\n');
            instructions.push('\n');
        }
        instructions.push_str(
            "\nTOTP enrollment is required before target access.\n\
Add this account to your authenticator app and enter the resulting code.\n\n",
        );
        instructions.push_str("Secret: ");
        instructions.push_str(secret);
        instructions.push('\n');
        instructions.push_str("URI: ");
        instructions.push_str(url);
        instructions.push_str("\n\n");
        match render_enrollment_qr_if_terminal_fits(url) {
            Ok(Some(qr)) => {
                instructions.push_str("Scan this QR code with your authenticator app.\n\n");
                instructions.push_str(&qr);
                instructions.push('\n');
            }
            Ok(None) => {
                instructions.push_str(
                    "Terminal is too small for the inline QR code.\n\
Use the plaintext secret or URI above.\n\n",
                );
            }
            Err(error) => {
                instructions.push_str(&format!(
                    "Unable to render the inline QR code: {error}\n\
Use the plaintext secret or URI above.\n\n"
                ));
            }
        }
        Self::keyboard_prompt(instructions, "Verification code: ", false)
    }

    fn should_prompt_existing_totp(user: Option<&UserRecord>) -> bool {
        user.is_none_or(|candidate| {
            !candidate.must_change_password && candidate.totp_secret.is_some()
        })
    }

    fn enrollment_qr_dimensions(url: &str) -> Result<(usize, usize)> {
        let qr = QrCode::new(url.as_bytes())
            .map_err(|e| CentralSshError::InvalidConfig(format!("failed to generate QR: {e}")))?;
        let side_modules = qr.width() + (ENROLLMENT_QR_QUIET_ZONE * 2);
        Ok((side_modules, side_modules.div_ceil(2)))
    }

    fn build_pending_context(
        user: UserRecord,
        login_password: Option<Zeroizing<String>>,
    ) -> PendingAuthContext {
        PendingAuthContext {
            user,
            new_password_hash: None,
            login_password,
        }
    }

    async fn selection_prompt(&self, username: &str, error_message: Option<&str>) -> Result<Auth> {
        let entries = match self.allowed_server_entries(username).await {
            Ok(entries) => entries,
            Err(error) => {
                self.log_event(
                    "authorization_denied",
                    Some(username),
                    None,
                    None,
                    AuditResult::Denied,
                    Some(error.to_string()),
                    None,
                    None,
                )
                .await;
                return Err(error);
            }
        };
        let hide_proxy_ip = self.state.config_store.paths.hide_proxy_ip;
        let mut instructions = String::new();
        if let Some(message) = error_message {
            instructions.push_str(message);
            instructions.push('\n');
            instructions.push('\n');
        }
        instructions.push_str("\nSelect a server:\n\n");
        for (index, (name, host)) in entries.iter().enumerate() {
            if hide_proxy_ip {
                instructions.push_str(&format!("{}) {}\n", index + 1, name));
            } else {
                instructions.push_str(&format!("{}) {} ({})\n", index + 1, name, host));
            }
        }

        Ok(Self::keyboard_prompt(
            instructions,
            "Enter selection (or 'Q' to quit): ",
            true,
        ))
    }

    async fn allowed_server_entries(&self, username: &str) -> Result<Vec<(String, String)>> {
        let snapshot = self.state.config_store.snapshot().await;
        let user = snapshot
            .config
            .users
            .iter()
            .find(|candidate| candidate.name == username)
            .ok_or(CentralSshError::AuthorizationDenied)?;

        let entries = user
            .allowed_servers
            .iter()
            .filter_map(|server_name| {
                snapshot
                    .servers
                    .servers
                    .get(server_name)
                    .map(|host| (server_name.clone(), host.clone()))
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            return Err(CentralSshError::AuthorizationDenied);
        }

        Ok(entries)
    }

    async fn log_event(
        &self,
        event_type: &str,
        username: Option<&str>,
        target_server: Option<&str>,
        auth_method: Option<&str>,
        result: AuditResult,
        reason: Option<String>,
        ban_duration: Option<Duration>,
        ban_until: Option<chrono::DateTime<Utc>>,
    ) {
        let _ = self
            .state
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: event_type.to_string(),
                request_id: self.session_id.clone(),
                remote_ip: Some(self.peer_ip.to_string()),
                remote_port: self.peer_port,
                username: username.map(ToOwned::to_owned),
                target_server: target_server.map(ToOwned::to_owned),
                auth_method: auth_method.map(ToOwned::to_owned),
                result,
                reason,
                ban_duration_seconds: ban_duration.map(|duration| duration.as_secs()),
                ban_until,
                request_type: None,
                request_detail: None,
                transport_side: None,
                kex_algorithm: None,
                kex_algorithms_offered: None,
                post_quantum: None,
                hybrid: None,
                classical_fallback: None,
                pq_required: None,
            })
            .await;
    }

    async fn log_connection_opened_once(&mut self) {
        if self.connection_logged {
            return;
        }
        self.connection_logged = true;
        self.log_event(
            "connection_opened",
            None,
            None,
            None,
            AuditResult::Success,
            None,
            None,
            None,
        )
        .await;
    }

    fn current_target_name(&self) -> Option<&str> {
        self.pending_target.as_ref().map(|target| target.name.as_str())
    }

    fn current_policy(&self) -> Option<EffectiveAuthorizationPolicy> {
        self.active_policy
    }

    async fn log_policy_denial(
        &self,
        event_type: &str,
        request_type: &str,
        request_detail: Option<String>,
        reason: &str,
    ) {
        let _ = self
            .state
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: event_type.to_string(),
                request_id: self.session_id.clone(),
                remote_ip: Some(self.peer_ip.to_string()),
                remote_port: self.peer_port,
                username: self.authenticated_username.clone(),
                target_server: self.current_target_name().map(ToOwned::to_owned),
                auth_method: None,
                result: AuditResult::Denied,
                reason: Some(reason.to_string()),
                ban_duration_seconds: None,
                ban_until: None,
                request_type: Some(request_type.to_string()),
                request_detail,
                transport_side: None,
                kex_algorithm: None,
                kex_algorithms_offered: None,
                post_quantum: None,
                hybrid: None,
                classical_fallback: None,
                pq_required: None,
            })
            .await;
    }

    fn denied_protocol_message(protocol: &str) -> String {
        format!("{}: access denied", protocol.to_ascii_lowercase())
    }

    fn deny_protocol_and_close(
        &self,
        session: &mut Session,
        channel: ChannelId,
        protocol: &str,
    ) -> std::result::Result<(), russh::Error> {
        session.channel_success(channel)?;
        session.extended_data(
            channel,
            1,
            bytes::Bytes::from(format!("{}\n", Self::denied_protocol_message(protocol))),
        )?;
        session.exit_status_request(channel, 1)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn resolve_target_policy(
        &self,
        username: &str,
        target_name: &str,
    ) -> Result<EffectiveAuthorizationPolicy> {
        let snapshot = self.state.config_store.snapshot().await;
        resolve_effective_authorization_policy(
            &snapshot.config,
            username,
            target_name,
            self.state.config_store.paths.per_user_per_server,
        )
    }

    async fn log_ban_event(&self, ban_event: &BanEvent) {
        self.log_event(
            match ban_event.kind {
                BanEventKind::Created => "ban_created",
                BanEventKind::Extended => "ban_extended",
            },
            None,
            None,
            None,
            AuditResult::Banned,
            Some("fail2ban threshold reached".to_string()),
            Some(ban_event.ban_duration),
            Some(ban_event.ban_until),
        )
        .await;
    }

    async fn apply_failure_outcome(
        &self,
        outcome: &FailureOutcome,
        username: Option<&str>,
        target_server: Option<&str>,
        auth_method: Option<&str>,
    ) {
        if outcome.whitelisted {
            self.log_event(
                "whitelist_bypass",
                username,
                target_server,
                auth_method,
                AuditResult::Success,
                Some("fail2ban bypassed for whitelisted IP".to_string()),
                None,
                None,
            )
            .await;
            return;
        }

        if let Some(delay) = outcome.delay {
            self.log_event(
                "rate_limit_delay_applied",
                username,
                target_server,
                auth_method,
                AuditResult::Delayed,
                Some("pre-ban tarpit delay applied".to_string()),
                Some(delay),
                None,
            )
            .await;
            sleep(delay).await;
        }

        if let Some(ban_event) = &outcome.ban_event {
            self.log_ban_event(ban_event).await;
        }
    }

    async fn enforce_pre_auth_policy(
        &mut self,
        auth_method: &str,
    ) -> std::result::Result<Option<Auth>, russh::Error> {
        self.log_connection_opened_once().await;
        let check = self.state.abuse.check_ip(self.peer_ip).await;
        self.handle_pre_auth_check(auth_method, check).await
    }

    async fn handle_pre_auth_check(
        &self,
        auth_method: &str,
        check: PreAuthCheck,
    ) -> std::result::Result<Option<Auth>, russh::Error> {
        if check.expired_ban {
            self.log_event(
                "ban_expired",
                None,
                None,
                Some(auth_method),
                AuditResult::Success,
                Some("active ban expired".to_string()),
                check.ban_duration,
                check.ban_until,
            )
            .await;
        }

        if check.whitelisted && check.had_state {
            self.log_event(
                "whitelist_bypass",
                None,
                None,
                Some(auth_method),
                AuditResult::Success,
                Some("fail2ban bypassed for whitelisted IP".to_string()),
                None,
                None,
            )
            .await;
        }

        if check.banned {
            self.log_event(
                "connection_rejected_banned",
                None,
                None,
                Some(auth_method),
                AuditResult::Banned,
                Some("active fail2ban ban".to_string()),
                check.ban_duration,
                check.ban_until,
            )
            .await;
            return Ok(Some(Self::reject_to_keyboard_interactive()));
        }

        Ok(None)
    }

    async fn handle_password_response(
        &mut self,
        username: String,
        password: String,
    ) -> std::result::Result<Auth, russh::Error> {
        let snapshot = self.state.config_store.snapshot().await;
        let matched_user = snapshot
            .config
            .users
            .iter()
            .find(|candidate| candidate.name == username);

        if Self::should_prompt_existing_totp(matched_user) {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitExistingTotp {
                username: username.clone(),
                password: Zeroizing::new(password),
            });
            return Ok(Self::totp_prompt(&username, None));
        }

        let Some(_) = matched_user.cloned() else {
            return Ok(Self::totp_prompt(&username, None));
        };

        self.log_event(
            "auth_attempt",
            Some(&username),
            None,
            Some("keyboard_interactive"),
            AuditResult::Success,
            Some("received password response".to_string()),
            None,
            None,
        )
        .await;

        if let Err(error) = self
            .state
            .auth
            .consume_rate_limit_token(self.peer_ip, &username)
            .await
        {
            self.log_event(
                "auth_failure",
                Some(&username),
                None,
                Some("keyboard_interactive"),
                AuditResult::Denied,
                Some(error.to_string()),
                None,
                None,
            )
            .await;
            let outcome = self
                .state
                .abuse
                .record_failure(self.peer_ip, Some(&username), None)
                .await;
            self.apply_failure_outcome(
                &outcome,
                Some(&username),
                None,
                Some("keyboard_interactive"),
            )
            .await;
            return Ok(Self::reject_to_keyboard_interactive());
        }

        let user = match self.state.auth.verify_password_constant_time(
            &snapshot.config.users,
            &username,
            &password,
        ) {
            Ok(user) => user,
            Err(error) => {
                self.log_event(
                    "auth_failure",
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                    AuditResult::Failure,
                    Some(error.to_string()),
                    None,
                    None,
                )
                .await;
                let outcome = self
                    .state
                    .abuse
                    .record_failure(self.peer_ip, Some(&username), None)
                    .await;
                self.apply_failure_outcome(
                    &outcome,
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                )
                .await;
                return Ok(Self::reject_to_keyboard_interactive());
            }
        };

        self.log_event(
            "auth_password",
            Some(&username),
            None,
            Some("keyboard_interactive"),
            AuditResult::Success,
            None,
            None,
            None,
        )
        .await;

        self.advance_after_initial_auth(
            Self::build_pending_context(user, None),
            PasswordPolicyConfig {
                enforce: snapshot
                    .config
                    .settings
                    .enforce_password_policy
                    .unwrap_or(true),
                min_length: snapshot
                    .config
                    .settings
                    .min_password_policy
                    .unwrap_or(DEFAULT_MIN_PASSWORD_POLICY),
            },
        )
        .await
    }

    async fn advance_after_initial_auth(
        &mut self,
        context: PendingAuthContext,
        password_policy: PasswordPolicyConfig,
    ) -> std::result::Result<Auth, russh::Error> {
        let username = context.user.name.clone();

        if context.user.must_change_password {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitNewPassword {
                context,
                password_policy,
            });
            return Ok(Self::new_password_prompt(&username, None));
        }

        if context.user.totp_secret.is_some() {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitSelection { context });
            return self
                .selection_prompt(&username, None)
                .await
                .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())));
        }

        let secret = self.state.auth.generate_totp_secret();
        let url = self
            .state
            .auth
            .otpauth_url("CentralSSH", &username, &secret)
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;
        self.keyboard_auth_state = Some(KeyboardAuthState::AwaitEnrollmentTotp {
            context,
            secret: secret.clone(),
        });
        Ok(Self::enrollment_prompt(&username, &secret, &url, None))
    }

    async fn handle_existing_totp_response(
        &mut self,
        username: String,
        password: Zeroizing<String>,
        code: String,
    ) -> std::result::Result<Auth, russh::Error> {
        self.log_event(
            "auth_attempt",
            Some(&username),
            None,
            Some("keyboard_interactive"),
            AuditResult::Success,
            Some("received password and totp response".to_string()),
            None,
            None,
        )
        .await;
        if let Err(error) = self
            .state
            .auth
            .consume_rate_limit_token(self.peer_ip, &username)
            .await
        {
            self.log_event(
                "auth_failure",
                Some(&username),
                None,
                Some("keyboard_interactive"),
                AuditResult::Denied,
                Some(error.to_string()),
                None,
                None,
            )
            .await;
            let outcome = self
                .state
                .abuse
                .record_failure(self.peer_ip, Some(&username), None)
                .await;
            self.apply_failure_outcome(
                &outcome,
                Some(&username),
                None,
                Some("keyboard_interactive"),
            )
            .await;
            return Ok(Self::reject_to_keyboard_interactive());
        }

        let snapshot = self.state.config_store.snapshot().await;
        let user_exists = snapshot
            .config
            .users
            .iter()
            .any(|candidate| candidate.name == username);
        match self
            .state
            .auth
            .verify_password_and_optional_totp_constant_time(
                &snapshot.config.users,
                &username,
                password.as_str(),
                code.trim(),
            ) {
            Ok(user) => {
                self.log_event(
                    "auth_success",
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                    AuditResult::Success,
                    None,
                    None,
                    None,
                )
                .await;
                let _ = self.state.abuse.record_success(self.peer_ip).await;

                let context = PendingAuthContext {
                    user,
                    new_password_hash: None,
                    login_password: None,
                };

                if context.user.totp_secret.is_some() {
                    self.log_event(
                        "auth_totp",
                        Some(&username),
                        None,
                        Some("keyboard_interactive"),
                        AuditResult::Success,
                        None,
                        None,
                        None,
                    )
                    .await;
                }

                self.advance_after_initial_auth(
                    context,
                    PasswordPolicyConfig {
                        enforce: snapshot
                            .config
                            .settings
                            .enforce_password_policy
                            .unwrap_or(true),
                        min_length: snapshot
                            .config
                            .settings
                            .min_password_policy
                            .unwrap_or(DEFAULT_MIN_PASSWORD_POLICY),
                    },
                )
                .await
            }
            Err(error) => {
                if matches!(error, CentralSshError::TotpInvalid) {
                    self.log_event(
                        "auth_failure",
                        Some(&username),
                        None,
                        Some("keyboard_interactive"),
                        AuditResult::Failure,
                        Some(error.to_string()),
                        None,
                        None,
                    )
                    .await;
                } else {
                    self.log_event(
                        "auth_failure",
                        Some(&username),
                        None,
                        Some("keyboard_interactive"),
                        AuditResult::Failure,
                        Some(error.to_string()),
                        None,
                        None,
                    )
                    .await;
                    if !user_exists {
                        self.log_event(
                            "unknown_username_attempt",
                            Some(&username),
                            None,
                            Some("keyboard_interactive"),
                            AuditResult::Failure,
                            Some("unknown username".to_string()),
                            None,
                            None,
                        )
                        .await;
                    }
                }

                let outcome = self
                    .state
                    .abuse
                    .record_failure(self.peer_ip, Some(&username), None)
                    .await;
                self.apply_failure_outcome(
                    &outcome,
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                )
                .await;

                if !matches!(error, CentralSshError::TotpInvalid) {
                    return Ok(Self::reject_to_keyboard_interactive());
                }
                Ok(Self::reject_to_keyboard_interactive())
            }
        }
    }

    async fn handle_new_password_response(
        &mut self,
        context: PendingAuthContext,
        password_policy: PasswordPolicyConfig,
        new_password: String,
    ) -> std::result::Result<Auth, russh::Error> {
        let username = context.user.name.clone();
        self.keyboard_auth_state = Some(KeyboardAuthState::AwaitConfirmPassword {
            candidate_password: Zeroizing::new(new_password),
            context,
            password_policy,
        });
        Ok(Self::confirm_password_prompt(&username))
    }

    async fn handle_confirm_password_response(
        &mut self,
        mut context: PendingAuthContext,
        password_policy: PasswordPolicyConfig,
        candidate_password: Zeroizing<String>,
        confirmation: String,
    ) -> std::result::Result<Auth, russh::Error> {
        let username = context.user.name.clone();

        if candidate_password.as_str() != confirmation {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitNewPassword {
                context,
                password_policy,
            });
            return Ok(Self::new_password_prompt(
                &username,
                Some("Passwords do not match."),
            ));
        }

        let new_password = candidate_password.as_str();
        if password_policy.enforce {
            if let Err(error) = self.state.auth.enforce_password_policy(
                new_password,
                &context.user.password,
                password_policy.min_length,
            ) {
                let message = match error {
                    CentralSshError::InvalidConfig(message) => message,
                    other => other.to_string(),
                };
                self.keyboard_auth_state = Some(KeyboardAuthState::AwaitNewPassword {
                    context,
                    password_policy,
                });
                return Ok(Self::new_password_prompt(&username, Some(&message)));
            }
        } else if new_password.is_empty() {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitNewPassword {
                context,
                password_policy,
            });
            return Ok(Self::new_password_prompt(
                &username,
                Some("Password must not be empty."),
            ));
        }

        context.new_password_hash = Some(
            self.state
                .auth
                .hash_password(new_password)
                .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?,
        );

        let secret = self.state.auth.generate_totp_secret();
        let url = self
            .state
            .auth
            .otpauth_url("CentralSSH", &username, &secret)
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;
        self.keyboard_auth_state = Some(KeyboardAuthState::AwaitEnrollmentTotp {
            context,
            secret: secret.clone(),
        });
        Ok(Self::enrollment_prompt(&username, &secret, &url, None))
    }

    async fn commit_pending_updates(
        &mut self,
        context: &mut PendingAuthContext,
        new_totp_secret: Option<String>,
    ) -> std::result::Result<(), russh::Error> {
        let new_password_hash = context.new_password_hash.clone();
        self.state
            .config_store
            .update_user_credentials(
                &context.user.name,
                new_password_hash.clone(),
                new_totp_secret.clone(),
                Some(false),
            )
            .await
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;

        if let Some(password_hash) = new_password_hash {
            context.user.password = password_hash;
            context.user.must_change_password = false;
            self.log_event(
                "password_change",
                Some(&context.user.name),
                None,
                Some("keyboard_interactive"),
                AuditResult::Success,
                None,
                None,
                None,
            )
            .await;
        }

        if let Some(secret) = new_totp_secret {
            context.user.totp_secret = Some(secret);
            self.log_event(
                "totp_enrollment",
                Some(&context.user.name),
                None,
                Some("keyboard_interactive"),
                AuditResult::Success,
                None,
                None,
                None,
            )
            .await;
        }

        Ok(())
    }

    async fn handle_enrollment_response(
        &mut self,
        mut context: PendingAuthContext,
        secret: String,
        code: String,
    ) -> std::result::Result<Auth, russh::Error> {
        let username = context.user.name.clone();
        let staged_login_password = context.login_password.take();
        if let Err(error) = self.state.auth.verify_totp_code(&secret, code.trim()) {
            context.login_password = staged_login_password;
            self.log_event(
                "auth_failure",
                Some(&username),
                None,
                Some("keyboard_interactive"),
                AuditResult::Failure,
                Some(error.to_string()),
                None,
                None,
            )
            .await;
            let outcome = self
                .state
                .abuse
                .record_failure(self.peer_ip, Some(&username), None)
                .await;
            self.apply_failure_outcome(
                &outcome,
                Some(&username),
                None,
                Some("keyboard_interactive"),
            )
            .await;

            let url = self
                .state
                .auth
                .otpauth_url("CentralSSH", &username, &secret)
                .map_err(|inner| russh::Error::IO(std::io::Error::other(inner.to_string())))?;
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitEnrollmentTotp {
                context,
                secret: secret.clone(),
            });
            return Ok(Self::enrollment_prompt(
                &username,
                &secret,
                &url,
                Some("Invalid TOTP code."),
            ));
        }

        if let Some(login_password) = staged_login_password {
            if let Err(error) = self
                .state
                .auth
                .consume_rate_limit_token(self.peer_ip, &username)
                .await
            {
                self.log_event(
                    "auth_failure",
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                    AuditResult::Denied,
                    Some(error.to_string()),
                    None,
                    None,
                )
                .await;
                let outcome = self
                    .state
                    .abuse
                    .record_failure(self.peer_ip, Some(&username), None)
                    .await;
                self.apply_failure_outcome(
                    &outcome,
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                )
                .await;
                return Ok(Self::reject_to_keyboard_interactive());
            }

            if let Err(error) = self.state.auth.verify_password_constant_time(
                &self.state.config_store.snapshot().await.config.users,
                &username,
                login_password.as_str(),
            ) {
                self.log_event(
                    "auth_failure",
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                    AuditResult::Failure,
                    Some(error.to_string()),
                    None,
                    None,
                )
                .await;
                let outcome = self
                    .state
                    .abuse
                    .record_failure(self.peer_ip, Some(&username), None)
                    .await;
                self.apply_failure_outcome(
                    &outcome,
                    Some(&username),
                    None,
                    Some("keyboard_interactive"),
                )
                .await;
                return Ok(Self::reject_to_keyboard_interactive());
            }

            self.log_event(
                "auth_success",
                Some(&username),
                None,
                Some("keyboard_interactive"),
                AuditResult::Success,
                None,
                None,
                None,
            )
            .await;
        }

        self.log_event(
            "auth_totp",
            Some(&username),
            None,
            Some("keyboard_interactive"),
            AuditResult::Success,
            None,
            None,
            None,
        )
        .await;
        let _ = self.state.abuse.record_success(self.peer_ip).await;
        self.commit_pending_updates(&mut context, Some(secret))
            .await?;

        self.keyboard_auth_state = Some(KeyboardAuthState::AwaitSelection { context });
        self.selection_prompt(&username, None)
            .await
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))
    }

    async fn handle_selection_response(
        &mut self,
        context: PendingAuthContext,
        selection: String,
    ) -> std::result::Result<Auth, russh::Error> {
        let username = context.user.name.clone();
        if selection.trim().eq_ignore_ascii_case("q") {
            self.keyboard_auth_state = None;
            self.authenticated_username = None;
            self.pending_target = None;
            self.active_policy = None;
            return Err(russh::Error::Disconnect);
        }
        let entries = self
            .allowed_server_entries(&username)
            .await
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;

        let index = match selection.trim().parse::<usize>() {
            Ok(value) if value > 0 && value <= entries.len() => value - 1,
            _ => {
                self.keyboard_auth_state = Some(KeyboardAuthState::AwaitSelection { context });
                return self
                    .selection_prompt(&username, Some("Invalid selection."))
                    .await
                    .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())));
            }
        };

        let (target_name, target_host) = entries[index].clone();
        self.pending_target = Some(proxy::SelectedTarget {
            name: target_name,
            host: target_host,
        });
        self.authenticated_username = Some(username);
        self.keyboard_auth_state = None;
        Ok(Auth::Accept)
    }

    async fn connect_selected_target(
        &mut self,
        session: &mut Session,
        username: &str,
        target: proxy::SelectedTarget,
    ) -> std::result::Result<(), russh::Error> {
        self.log_event(
            "server_selected",
            Some(username),
            Some(&target.name),
            None,
            AuditResult::Success,
            None,
            None,
            None,
        )
        .await;

        let policy = self
            .resolve_target_policy(username, &target.name)
            .await
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;

        match proxy::ProxySession::connect(
            self.state.clone(),
            self.session_id.clone(),
            self.peer_ip,
            username.to_string(),
            target.clone(),
            session.handle(),
            self.session_channel_state.clone(),
        )
        .await
        {
            Ok(proxy_session) => {
                self.log_event(
                    "proxy_start",
                    Some(username),
                    Some(&target.name),
                    None,
                    AuditResult::Success,
                    None,
                    None,
                    None,
                )
                .await;
                self.active_policy = Some(policy);
                self.proxy_session = Some(proxy_session);
                Ok(())
            }
            Err(error) => {
                self.active_policy = None;
                self.log_event(
                    "proxy_start",
                    Some(username),
                    Some(&target.name),
                    None,
                    AuditResult::Failure,
                    Some(error.to_string()),
                    None,
                    None,
                )
                .await;

                let message = format!("Failed to connect to target {}: {}", target.name, error);
                session.disconnect(russh::Disconnect::ByApplication, &message, "en")?;
                Ok(())
            }
        }
    }

    async fn handle_menu_channel_input(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<bool, russh::Error> {
        let Some(username) = self.authenticated_username.clone() else {
            return Ok(false);
        };

        let mut maybe_line = None;
        {
            let mut guard = self.session_channel_state.lock().await;
            let Some(channel_state) = guard.get_mut(&channel) else {
                return Ok(false);
            };
            if !channel_state.menu_active {
                return Ok(false);
            }

            for byte in data {
                match *byte {
                    b'\r' | b'\n' => {
                        let _ = session.data(channel, bytes::Bytes::from_static(b"\r\n"));
                        let line = String::from_utf8_lossy(&channel_state.input_buffer).to_string();
                        channel_state.input_buffer.clear();
                        maybe_line = Some(line);
                        break;
                    }
                    0x08 | 0x7f => {
                        if channel_state.input_buffer.pop().is_some() {
                            let _ = session.data(channel, bytes::Bytes::from_static(b"\x08 \x08"));
                        }
                    }
                    _ => {
                        channel_state.input_buffer.push(*byte);
                        let _ = session.data(channel, bytes::Bytes::copy_from_slice(&[*byte]));
                    }
                }
            }
        }

        let Some(selection) = maybe_line else {
            return Ok(true);
        };

        if selection.trim().eq_ignore_ascii_case("q") {
            session.disconnect(russh::Disconnect::ByApplication, "user exited menu", "en")?;
            return Ok(true);
        }

        let entries = self
            .allowed_server_entries(&username)
            .await
            .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;
        let index = match selection.trim().parse::<usize>() {
            Ok(value) if value > 0 && value <= entries.len() => value - 1,
            _ => {
                let retry = self
                    .selection_prompt(&username, Some("Invalid selection."))
                    .await
                    .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;
                if let Auth::Partial {
                    instructions,
                    prompts,
                    ..
                } = retry
                {
                    let mut text = instructions.into_owned();
                    if let Some((prompt, _)) = prompts.into_owned().into_iter().next() {
                        text.push_str(prompt.as_ref());
                    }
                    let _ = session.data(channel, bytes::Bytes::from(text));
                }
                return Ok(true);
            }
        };

        let (target_name, target_host) = entries[index].clone();
        let target = proxy::SelectedTarget {
            name: target_name,
            host: target_host,
        };

        {
            let mut guard = self.session_channel_state.lock().await;
            if let Some(channel_state) = guard.get_mut(&channel) {
                channel_state.menu_active = false;
            }
        }

        self.connect_selected_target(session, &username, target)
            .await?;
        if let Some(proxy_session) = &self.proxy_session {
            proxy_session
                .open_session_channel_by_id(channel)
                .await
                .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))?;

            let replay = {
                self.session_channel_state
                    .lock()
                    .await
                    .get(&channel)
                    .cloned()
            };

            if let Some(replay) = replay {
                if let Some(pty) = replay.pty {
                    proxy_session
                        .request_pty(
                            channel,
                            true,
                            &pty.term,
                            pty.col_width,
                            pty.row_height,
                            pty.pix_width,
                            pty.pix_height,
                            &pty.terminal_modes,
                        )
                        .await
                        .map_err(|error| {
                            russh::Error::IO(std::io::Error::other(error.to_string()))
                        })?;
                }
                match replay.request {
                    proxy::SessionRequest::Shell => {
                        proxy_session
                            .request_shell(channel, true)
                            .await
                            .map_err(|error| {
                                russh::Error::IO(std::io::Error::other(error.to_string()))
                            })?;
                    }
                    proxy::SessionRequest::Exec(command) => {
                        proxy_session
                            .exec(channel, true, command)
                            .await
                            .map_err(|error| {
                                russh::Error::IO(std::io::Error::other(error.to_string()))
                            })?;
                    }
                    proxy::SessionRequest::Subsystem(name) => {
                        proxy_session
                            .request_subsystem(channel, true, name)
                            .await
                            .map_err(|error| {
                                russh::Error::IO(std::io::Error::other(error.to_string()))
                            })?;
                    }
                    proxy::SessionRequest::None => {}
                }
            }
        }

        Ok(true)
    }
}

fn terminal_dimensions_from_env() -> Option<(usize, usize)> {
    let columns = env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let rows = env::var("LINES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);

    match (columns, rows) {
        (Some(columns), Some(rows)) => Some((columns, rows)),
        _ => None,
    }
}

fn terminal_likely_supports_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|key| {
        env::var(key)
            .ok()
            .map(|value| {
                let upper = value.to_ascii_uppercase();
                upper.contains("UTF-8") || upper.contains("UTF8")
            })
            .unwrap_or(false)
    })
}

fn render_enrollment_qr_if_terminal_fits(url: &str) -> Result<Option<String>> {
    if !terminal_likely_supports_utf8() {
        return Ok(None);
    }

    if let Some((columns, rows)) = terminal_dimensions_from_env() {
        let (required_columns, required_rows) = GatewayHandler::enrollment_qr_dimensions(url)?;
        if columns < required_columns || rows < required_rows {
            return Ok(None);
        }
    }

    Ok(Some(render_enrollment_qr(url)?))
}

fn render_enrollment_qr(url: &str) -> Result<String> {
    let qr = QrCode::new(url.as_bytes())
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to generate QR: {e}")))?;
    let colors = qr.to_colors();
    let width = qr.width();
    let total = width + (ENROLLMENT_QR_QUIET_ZONE * 2);
    let mut out = String::new();

    for y in (0..total).step_by(2) {
        for x in 0..total {
            let module = match (
                qr_module_is_dark(&colors, width, x, y),
                qr_module_is_dark(&colors, width, x, y + 1),
            ) {
                (true, true) => ENROLLMENT_QR_DARK_MODULE,
                (false, false) => ENROLLMENT_QR_LIGHT_MODULE,
                (true, false) => ENROLLMENT_QR_TOP_HALF_DARK_BOTTOM_LIGHT,
                (false, true) => ENROLLMENT_QR_TOP_HALF_LIGHT_BOTTOM_DARK,
            };
            out.push_str(module);
        }
        out.push('\n');
    }

    Ok(out.replace('\n', "\r\n"))
}

fn qr_module_is_dark(colors: &[Color], width: usize, x: usize, y: usize) -> bool {
    let src_x = x as isize - ENROLLMENT_QR_QUIET_ZONE as isize;
    let src_y = y as isize - ENROLLMENT_QR_QUIET_ZONE as isize;

    if src_x < 0 || src_y < 0 || (src_x as usize) >= width || (src_y as usize) >= width {
        return false;
    }

    let idx = (src_y as usize) * width + (src_x as usize);
    colors[idx] == Color::Dark
}

fn apply_server_transport_config(
    config: &mut server::Config,
    policy: &crate::config::KexPolicyConfig,
) -> Result<crate::crypto_policy::KexPolicySummary> {
    let summary = apply_server_transport_crypto_policy(config, policy)?;
    // Russh defaults to a 10-minute inactivity timeout, which breaks quiet
    // long-lived exec sessions. Keep them alive with infrequent SSH keepalives
    // instead of a hard idle reap.
    config.inactivity_timeout = None;
    config.keepalive_interval = Some(SSH_KEEPALIVE_INTERVAL);
    config.keepalive_max = SSH_KEEPALIVE_MAX;
    Ok(summary)
}

fn apply_client_transport_config(
    config: &mut client::Config,
    policy: &crate::config::KexPolicyConfig,
) -> Result<crate::crypto_policy::KexPolicySummary> {
    let summary = apply_client_transport_crypto_policy(config, policy)?;
    config.inactivity_timeout = None;
    config.keepalive_interval = Some(SSH_KEEPALIVE_INTERVAL);
    config.keepalive_max = SSH_KEEPALIVE_MAX;
    Ok(summary)
}

impl server::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        if let Some(decision) = self.enforce_pre_auth_policy("none").await? {
            return Ok(decision);
        }
        // OpenSSH commonly probes `none` first to discover allowed methods.
        // Treat that as protocol negotiation, not as a credential failure.
        self.log_event(
            "protocol_error",
            None,
            None,
            Some("none"),
            AuditResult::Denied,
            Some("unsupported auth method".to_string()),
            None,
            None,
        )
        .await;
        Ok(Self::reject_to_keyboard_interactive())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        if let Some(decision) = self.enforce_pre_auth_policy("publickey").await? {
            return Ok(decision);
        }
        // Clients may opportunistically try publickey before falling back to
        // keyboard-interactive. Do not count method discovery as abuse.
        self.log_event(
            "protocol_error",
            None,
            None,
            Some("publickey"),
            AuditResult::Denied,
            Some("unsupported auth method".to_string()),
            None,
            None,
        )
        .await;
        Ok(Self::reject_to_keyboard_interactive())
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        if let Some(decision) = self.enforce_pre_auth_policy("password").await? {
            return Ok(decision);
        }
        // Password auth is intentionally disabled in favor of
        // keyboard-interactive. A client trying it first is not a bad password.
        self.log_event(
            "protocol_error",
            None,
            None,
            Some("password"),
            AuditResult::Denied,
            Some("unsupported auth method".to_string()),
            None,
            None,
        )
        .await;
        Ok(Self::reject_to_keyboard_interactive())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> std::result::Result<Auth, Self::Error> {
        if let Some(decision) = self.enforce_pre_auth_policy("keyboard_interactive").await? {
            return Ok(decision);
        }
        if self.authenticated_username.is_some() && self.proxy_session.is_some() {
            return Ok(Auth::Accept);
        }

        let username = user.trim().to_string();
        if username.is_empty() {
            self.log_event(
                "protocol_error",
                None,
                None,
                Some("keyboard_interactive"),
                AuditResult::Denied,
                Some("empty username".to_string()),
                None,
                None,
            )
            .await;
            let outcome = self
                .state
                .abuse
                .record_failure(self.peer_ip, None, None)
                .await;
            self.apply_failure_outcome(&outcome, None, None, Some("keyboard_interactive"))
                .await;
            return Ok(Self::reject_to_keyboard_interactive());
        }

        let had_existing_state = self.keyboard_auth_state.is_some();
        let Some(mut response) = response else {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitPassword {
                username: username.clone(),
            });
            return Ok(Self::password_prompt(&username));
        };

        let first_response = response
            .next()
            .map(|value| String::from_utf8_lossy(value.as_ref()).to_string());

        if !had_existing_state
            && first_response
                .as_deref()
                .is_none_or(|value| value.is_empty())
        {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitPassword {
                username: username.clone(),
            });
            return Ok(Self::password_prompt(&username));
        }

        let response_text = first_response.unwrap_or_default();

        match self
            .keyboard_auth_state
            .take()
            .unwrap_or(KeyboardAuthState::AwaitPassword {
                username: username.clone(),
            }) {
            KeyboardAuthState::AwaitPassword { username } => {
                self.handle_password_response(username, response_text).await
            }
            KeyboardAuthState::AwaitExistingTotp { username, password } => {
                self.handle_existing_totp_response(username, password, response_text)
                    .await
            }
            KeyboardAuthState::AwaitNewPassword {
                context,
                password_policy,
            } => {
                self.handle_new_password_response(context, password_policy, response_text)
                    .await
            }
            KeyboardAuthState::AwaitConfirmPassword {
                context,
                password_policy,
                candidate_password,
            } => {
                self.handle_confirm_password_response(
                    context,
                    password_policy,
                    candidate_password,
                    response_text,
                )
                .await
            }
            KeyboardAuthState::AwaitEnrollmentTotp { context, secret } => {
                self.handle_enrollment_response(context, secret, response_text)
                    .await
            }
            KeyboardAuthState::AwaitSelection { context } => {
                self.handle_selection_response(context, response_text).await
            }
        }
    }

    async fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(username) = self.authenticated_username.clone() else {
            session.disconnect(
                russh::Disconnect::ByApplication,
                "authentication completed without a selected identity",
                "en",
            )?;
            return Ok(());
        };
        let Some(target) = self.pending_target.clone() else {
            session.disconnect(
                russh::Disconnect::ByApplication,
                "authentication completed without a selected target",
                "en",
            )?;
            return Ok(());
        };
        self.connect_selected_target(session, &username, target)
            .await
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        self.session_channel_state
            .lock()
            .await
            .entry(channel.id())
            .or_default();
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(false);
        };

        match proxy_session.open_session_channel(channel).await {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "failed to open target session channel");
                Ok(false)
            }
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(false);
        };
        let Some(policy) = self.current_policy() else {
            return Ok(false);
        };
        if !local_forwarding_permitted(policy) {
            self.log_policy_denial(
                "denied_local_forward",
                "direct-tcpip",
                Some(format!(
                    "{host_to_connect}:{port_to_connect} from {originator_address}:{originator_port}"
                )),
                "local forwarding disabled by authorization policy",
            )
            .await;
            return Ok(false);
        }

        match proxy_session
            .open_direct_tcpip_channel(
                channel,
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "failed to open direct-tcpip target channel");
                Ok(false)
            }
        }
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        self.session_channel_state
            .lock()
            .await
            .entry(channel)
            .or_default()
            .pty = Some(proxy::ChannelPtyState {
            term: term.to_string(),
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes: modes.to_vec(),
        });

        match proxy_session
            .request_pty(
                channel, true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
        {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, "failed to relay pty request");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.proxy_session.is_some() {
            warn!(
                ?channel,
                single_connection,
                x11_auth_protocol,
                x11_screen_number,
                "rejecting x11 forwarding request"
            );
        }
        let _ = session.channel_failure(channel);

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.session_channel_state
            .lock()
            .await
            .entry(channel)
            .or_default()
            .request = proxy::SessionRequest::Shell;

        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        match proxy_session.request_shell(channel, true).await {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, "failed to relay shell request");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        self.session_channel_state
            .lock()
            .await
            .entry(channel)
            .or_default()
            .request = proxy::SessionRequest::Exec(data.to_vec());

        let Some(policy) = self.current_policy() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        if let Err(scp_mode) = validate_exec_request(policy, data) {
            self.log_policy_denial(
                "denied_scp",
                "exec",
                Some(String::from_utf8_lossy(data).into_owned()),
                &format!("scp disabled by authorization policy ({scp_mode})"),
            )
            .await;
            return self.deny_protocol_and_close(session, channel, "scp");
        }

        match proxy_session.exec(channel, true, data.to_vec()).await {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, command = %String::from_utf8_lossy(data), "failed to relay exec request");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        self.session_channel_state
            .lock()
            .await
            .entry(channel)
            .or_default()
            .request = proxy::SessionRequest::Subsystem(name.to_string());

        let Some(policy) = self.current_policy() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        if !subsystem_request_permitted(policy, name) {
            self.log_policy_denial(
                "denied_sftp",
                "subsystem",
                Some(name.to_string()),
                "sftp disabled by authorization policy",
            )
            .await;
            return self.deny_protocol_and_close(session, channel, "sftp");
        }

        match proxy_session
            .request_subsystem(channel, true, name.to_string())
            .await
        {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, subsystem = name, "failed to relay subsystem request");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        match proxy_session
            .set_env(
                channel,
                true,
                variable_name.to_string(),
                variable_value.to_string(),
            )
            .await
        {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, variable_name, "failed to relay env request");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(());
        };

        if let Err(error) = proxy_session
            .window_change(channel, col_width, row_height, pix_width, pix_height)
            .await
        {
            warn!(error = %error, ?channel, "non-fatal window-change relay failure");
        }

        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        match proxy_session.signal(channel, signal).await {
            Ok(()) => {
                let _ = session.channel_success(channel);
            }
            Err(error) => {
                warn!(error = %error, ?channel, "failed to relay signal");
                let _ = session.channel_failure(channel);
                proxy_session.abort(error.to_string()).await;
            }
        }

        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(false)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self
            .handle_menu_channel_input(channel, data, session)
            .await?
        {
            return Ok(());
        }

        let Some(proxy_session) = &self.proxy_session else {
            return Ok(());
        };

        if let Err(error) = proxy_session.data(channel, data).await {
            warn!(error = %error, ?channel, "failed to relay channel data");
            proxy_session.abort(error.to_string()).await;
        }

        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(());
        };

        if let Err(error) = proxy_session.extended_data(channel, code, data).await {
            warn!(error = %error, ?channel, code, "failed to relay channel extended data");
            proxy_session.abort(error.to_string()).await;
        }

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(());
        };

        if let Err(error) = proxy_session.channel_eof(channel).await {
            warn!(error = %error, ?channel, "failed to relay channel EOF");
            proxy_session.abort(error.to_string()).await;
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let menu_active = self
            .session_channel_state
            .lock()
            .await
            .get(&channel)
            .map(|state| state.menu_active)
            .unwrap_or(false);
        if !menu_active {
            self.session_channel_state.lock().await.remove(&channel);
        }

        let Some(proxy_session) = &self.proxy_session else {
            return Ok(());
        };

        if let Err(error) = proxy_session.channel_close(channel).await {
            warn!(error = %error, ?channel, "failed to relay channel close");
            proxy_session.abort(error.to_string()).await;
        }

        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(false);
        };
        let Some(policy) = self.current_policy() else {
            return Ok(false);
        };
        if !remote_forwarding_permitted(policy) {
            self.log_policy_denial(
                "denied_remote_forward",
                "tcpip-forward",
                Some(format!("{address}:{port}")),
                "remote forwarding disabled by authorization policy",
            )
            .await;
            return Ok(false);
        }

        match proxy_session.tcpip_forward(address, *port).await {
            Ok(allocated_port) => {
                *port = allocated_port;
                Ok(true)
            }
            Err(error) => {
                warn!(error = %error, "failed to establish remote forwarding on target");
                Ok(false)
            }
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(proxy_session) = &self.proxy_session else {
            return Ok(false);
        };
        let Some(policy) = self.current_policy() else {
            return Ok(false);
        };
        if !remote_forwarding_permitted(policy) {
            self.log_policy_denial(
                "denied_remote_forward",
                "cancel-tcpip-forward",
                Some(format!("{address}:{port}")),
                "remote forwarding disabled by authorization policy",
            )
            .await;
            return Ok(false);
        }

        match proxy_session.cancel_tcpip_forward(address, port).await {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "failed to cancel remote forwarding on target");
                Ok(false)
            }
        }
    }
}

fn local_forwarding_permitted(policy: EffectiveAuthorizationPolicy) -> bool {
    policy.allow_local_forwarding
}

fn remote_forwarding_permitted(policy: EffectiveAuthorizationPolicy) -> bool {
    policy.allow_remote_forwarding
}

fn subsystem_request_permitted(policy: EffectiveAuthorizationPolicy, name: &str) -> bool {
    name != "sftp" || policy.allow_sftp
}

fn validate_exec_request(
    policy: EffectiveAuthorizationPolicy,
    data: &[u8],
) -> std::result::Result<(), &'static str> {
    if !policy.allow_scp {
        if let Some(mode) = classify_scp_exec_request(data) {
            return Err(mode);
        }
    }
    Ok(())
}

fn classify_scp_exec_request(data: &[u8]) -> Option<&'static str> {
    let command = std::str::from_utf8(data).ok()?.trim();
    if command.is_empty() {
        return None;
    }

    let tokens = shell_like_split(command)?;
    let executable = tokens.first()?;
    let basename = executable.rsplit('/').next().unwrap_or(executable.as_str());
    if basename != "scp" {
        return None;
    }

    let mut after_double_dash = false;
    for token in tokens.iter().skip(1) {
        if after_double_dash {
            break;
        }
        if token == "--" {
            after_double_dash = true;
            continue;
        }
        if !token.starts_with('-') || token == "-" {
            continue;
        }
        if token.len() == 2 {
            match token.as_bytes()[1] {
                b't' => return Some("sink"),
                b'f' => return Some("source"),
                _ => continue,
            }
        }

        for flag in token[1..].chars() {
            match flag {
                't' => return Some("sink"),
                'f' => return Some("source"),
                _ => {}
            }
        }
    }

    None
}

fn shell_like_split(command: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '\\' if !in_single => {
                let escaped = chars.next()?;
                current.push(escaped);
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }

    if in_single || in_double {
        return None;
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Some(tokens)
}

pub async fn run_gateway_server(
    listen_addr: &str,
    host_key_path: &std::path::Path,
    state: Arc<AppState>,
    strict_security: bool,
) -> Result<()> {
    let frontend_kex_policy = state.config_store.snapshot().await.config.kex_policy;
    ensure_server_host_key(host_key_path)?;
    if strict_security {
        validate_host_key_security(host_key_path)?;
    }

    let mut config = server::Config::default();
    config.methods = MethodSet::from(&[MethodKind::KeyboardInteractive][..]);
    config.auth_rejection_time = Duration::from_secs(3);
    let frontend_kex_summary = apply_server_transport_config(&mut config, &frontend_kex_policy)?;

    let host_key = russh::keys::load_secret_key(host_key_path, None)
        .map_err(|error| CentralSshError::Ssh(format!("failed to load host key: {error}")))?;
    config.keys.push(host_key);

    info!(
        offered_kex = %frontend_kex_summary.offered_algorithms.join(","),
        require_post_quantum = frontend_kex_summary.require_post_quantum,
        classical_fallback = frontend_kex_summary.classical_fallback,
        "frontend SSH KEX policy applied"
    );
    let _ = state
        .audit
        .log(AuditEvent {
            timestamp: Utc::now(),
            event_type: "frontend_kex_policy_loaded".to_string(),
            request_id: "system".to_string(),
            remote_ip: None,
            remote_port: None,
            username: None,
            target_server: None,
            auth_method: None,
            result: AuditResult::Success,
            reason: Some(
                "frontend negotiated KEX audit is not exposed by the current russh server handler API"
                    .to_string(),
            ),
            ban_duration_seconds: None,
            ban_until: None,
            request_type: None,
            request_detail: None,
            transport_side: Some("frontend".to_string()),
            kex_algorithm: None,
            kex_algorithms_offered: Some(frontend_kex_summary.offered_algorithms.clone()),
            post_quantum: Some(!frontend_kex_summary.classical_fallback),
            hybrid: None,
            classical_fallback: Some(frontend_kex_summary.classical_fallback),
            pq_required: Some(frontend_kex_summary.require_post_quantum),
        })
        .await;

    let config = Arc::new(config);
    let mut server = GatewayServer::new(state);
    let listen_socket: SocketAddr = listen_addr.parse().map_err(|error| {
        CentralSshError::InvalidConfig(format!("invalid listen address '{listen_addr}': {error}"))
    })?;

    server
        .run_on_address(config, listen_socket)
        .await
        .map_err(|error| {
            error!(error = %error, "gateway server stopped with error");
            CentralSshError::Ssh(error.to_string())
        })
}

fn ensure_server_host_key(path: &std::path::Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;

    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: "host key path must not be a symlink".to_string(),
            });
        }
        if !metadata.is_file() {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: "host key path is not a regular file".to_string(),
            });
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        validate_path_has_no_symlinks(parent)?;
        fs::create_dir_all(parent)?;
    }

    let host_key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .map_err(|error| {
            CentralSshError::InvalidConfig(format!("failed to create host key: {error}"))
        })?;

    let encoded = host_key.to_openssh(LineEnding::LF).map_err(|error| {
        CentralSshError::InvalidConfig(format!("failed to encode host key: {error}"))
    })?;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn validate_host_key_security(path: &std::path::Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "host key path must not be a symlink".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "host key path is not a regular file".to_string(),
        });
    }

    let mode = metadata.mode() & 0o777;
    if mode != 0o600 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("host key mode must be 600, found {:o}", mode),
        });
    }

    if metadata.uid() != 0 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("host key owner uid must be 0, found {}", metadata.uid()),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn terminal_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn server_transport_config_disables_idle_reap_and_enables_sparse_keepalives() {
        let mut config = server::Config::default();
        apply_server_transport_config(&mut config, &crate::config::KexPolicyConfig::default())
            .expect("server transport config");

        assert_eq!(config.inactivity_timeout, None);
        assert_eq!(config.keepalive_interval, Some(SSH_KEEPALIVE_INTERVAL));
        assert_eq!(config.keepalive_max, SSH_KEEPALIVE_MAX);
        assert_eq!(
            config.limits.rekey_write_limit,
            crate::crypto_policy::SSH_REKEY_BYTES
        );
        assert_eq!(
            config.limits.rekey_read_limit,
            crate::crypto_policy::SSH_REKEY_BYTES
        );
        assert_eq!(
            config.limits.rekey_time_limit,
            crate::crypto_policy::SSH_REKEY_TIME
        );
    }

    #[test]
    fn client_transport_config_disables_idle_reap_and_enables_sparse_keepalives() {
        let mut config = client::Config::default();
        let summary =
            apply_client_transport_config(&mut config, &crate::config::KexPolicyConfig::default())
                .expect("client transport config");

        assert_eq!(config.inactivity_timeout, None);
        assert_eq!(config.keepalive_interval, Some(SSH_KEEPALIVE_INTERVAL));
        assert_eq!(config.keepalive_max, SSH_KEEPALIVE_MAX);
        assert!(summary.classical_fallback);
        assert_eq!(
            config.limits.rekey_write_limit,
            crate::crypto_policy::SSH_REKEY_BYTES
        );
        assert_eq!(
            config.limits.rekey_read_limit,
            crate::crypto_policy::SSH_REKEY_BYTES
        );
        assert_eq!(
            config.limits.rekey_time_limit,
            crate::crypto_policy::SSH_REKEY_TIME
        );
    }

    #[test]
    fn ensure_server_host_key_rejects_symlink_without_touching_target() {
        let tempdir = TempDir::new().expect("tempdir");
        let real_key = tempdir.path().join("real_host_key");
        fs::write(&real_key, b"not-a-real-key").expect("write target");
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o644)).expect("chmod target");

        let symlink_path = tempdir.path().join("host_ed25519");
        symlink(&real_key, &symlink_path).expect("symlink");

        let error = ensure_server_host_key(&symlink_path).expect_err("symlink must fail");
        assert!(matches!(error, CentralSshError::SecurityPolicy { .. }));

        let mode = fs::metadata(&real_key)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn existing_totp_prompt_is_skipped_for_unenrolled_users() {
        let user = UserRecord {
            name: "alice".to_string(),
            password: "ignored".to_string(),
            totp_secret: None,
            must_change_password: true,
            allowed_servers: vec!["git".to_string()],
            authorization: crate::config::AuthorizationPolicyConfig::default(),
        };

        assert!(!GatewayHandler::should_prompt_existing_totp(Some(&user)));
    }

    #[test]
    fn existing_totp_prompt_is_skipped_while_password_change_is_required() {
        let user = UserRecord {
            name: "alice".to_string(),
            password: "ignored".to_string(),
            totp_secret: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            must_change_password: true,
            allowed_servers: vec!["git".to_string()],
            authorization: crate::config::AuthorizationPolicyConfig::default(),
        };

        assert!(!GatewayHandler::should_prompt_existing_totp(Some(&user)));
    }

    #[test]
    fn existing_totp_prompt_is_kept_for_enrolled_or_unknown_users() {
        let user = UserRecord {
            name: "alice".to_string(),
            password: "ignored".to_string(),
            totp_secret: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            must_change_password: false,
            allowed_servers: vec!["git".to_string()],
            authorization: crate::config::AuthorizationPolicyConfig::default(),
        };

        assert!(GatewayHandler::should_prompt_existing_totp(Some(&user)));
        assert!(GatewayHandler::should_prompt_existing_totp(None));
    }

    #[test]
    fn classify_scp_exec_request_matches_source_and_sink_modes() {
        assert_eq!(classify_scp_exec_request(b"scp -t /tmp/file"), Some("sink"));
        assert_eq!(classify_scp_exec_request(b"scp -f /tmp/file"), Some("source"));
        assert_eq!(
            classify_scp_exec_request(b"/usr/bin/scp -prvf /tmp/file"),
            Some("source")
        );
        assert_eq!(
            classify_scp_exec_request(b"scp -d -t -- /tmp/file"),
            Some("sink")
        );
    }

    #[test]
    fn classify_scp_exec_request_ignores_non_scp_execs() {
        assert_eq!(classify_scp_exec_request(b"uname -a"), None);
        assert_eq!(classify_scp_exec_request(b"scp /tmp/file"), None);
        assert_eq!(classify_scp_exec_request(b"sh -c 'scp -t /tmp/file'"), None);
        assert_eq!(classify_scp_exec_request(b""), None);
    }

    #[test]
    fn denied_protocol_message_is_user_facing() {
        assert_eq!(
            GatewayHandler::denied_protocol_message("SFTP"),
            "sftp: access denied"
        );
        assert_eq!(
            GatewayHandler::denied_protocol_message("SCP"),
            "scp: access denied"
        );
    }

    #[test]
    fn password_prompt_omits_redundant_user_label() {
        let Auth::Partial { instructions, .. } = GatewayHandler::password_prompt("alice") else {
            panic!("expected partial auth prompt");
        };
        assert!(instructions.is_empty());
    }

    #[test]
    fn local_forwarding_policy_allows_and_denies_as_configured() {
        let denied = EffectiveAuthorizationPolicy {
            allow_local_forwarding: false,
            allow_remote_forwarding: false,
            allow_sftp: true,
            allow_scp: true,
        };
        let allowed = EffectiveAuthorizationPolicy {
            allow_local_forwarding: true,
            ..denied
        };

        assert!(!local_forwarding_permitted(denied));
        assert!(local_forwarding_permitted(allowed));
    }

    #[test]
    fn remote_forwarding_policy_allows_and_denies_as_configured() {
        let denied = EffectiveAuthorizationPolicy {
            allow_local_forwarding: false,
            allow_remote_forwarding: false,
            allow_sftp: true,
            allow_scp: true,
        };
        let allowed = EffectiveAuthorizationPolicy {
            allow_remote_forwarding: true,
            ..denied
        };

        assert!(!remote_forwarding_permitted(denied));
        assert!(remote_forwarding_permitted(allowed));
    }

    #[test]
    fn sftp_policy_allows_and_denies_as_configured() {
        let denied = EffectiveAuthorizationPolicy {
            allow_local_forwarding: false,
            allow_remote_forwarding: false,
            allow_sftp: false,
            allow_scp: true,
        };
        let allowed = EffectiveAuthorizationPolicy {
            allow_sftp: true,
            ..denied
        };

        assert!(!subsystem_request_permitted(denied, "sftp"));
        assert!(subsystem_request_permitted(allowed, "sftp"));
        assert!(subsystem_request_permitted(denied, "netconf"));
    }

    #[test]
    fn scp_policy_allows_and_denies_as_configured() {
        let denied = EffectiveAuthorizationPolicy {
            allow_local_forwarding: false,
            allow_remote_forwarding: false,
            allow_sftp: true,
            allow_scp: false,
        };
        let allowed = EffectiveAuthorizationPolicy {
            allow_scp: true,
            ..denied
        };

        assert!(validate_exec_request(denied, b"scp -t /tmp/file").is_err());
        assert!(validate_exec_request(allowed, b"scp -t /tmp/file").is_ok());
        assert!(validate_exec_request(denied, b"uname -a").is_ok());
    }

    #[test]
    fn shell_like_split_rejects_unbalanced_quotes() {
        assert!(shell_like_split("scp -t 'unterminated").is_none());
    }

    #[test]
    fn enrollment_qr_dimensions_are_positive() {
        let (columns, rows) = GatewayHandler::enrollment_qr_dimensions(
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CentralSSH",
        )
        .expect("dimensions");

        assert!(columns > 0);
        assert!(rows > 0);
    }

    #[test]
    fn render_enrollment_qr_emits_compact_unicode_rows() {
        let rendered = render_enrollment_qr(
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CentralSSH",
        )
        .expect("rendered qr");

        assert!(rendered.contains(ENROLLMENT_QR_DARK_MODULE));
        assert!(rendered.contains("\r\n"));
        assert!(rendered.contains('█') || rendered.contains('▀') || rendered.contains('▄'));
        assert!(!rendered.contains("\x1b["));
    }

    #[test]
    fn enrollment_prompt_shows_secret_and_uri_before_qr() {
        let _guard = terminal_env_lock().lock().expect("terminal env lock");
        unsafe {
            env::remove_var("COLUMNS");
            env::remove_var("LINES");
        }

        let auth = GatewayHandler::enrollment_prompt(
            "alice",
            "JBSWY3DPEHPK3PXP",
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXP&issuer=CentralSSH",
            None,
        );

        let Auth::Partial { instructions, .. } = auth else {
            panic!("expected partial auth prompt");
        };
        let instructions = instructions.as_ref();

        let secret_index = instructions.find("Secret:").expect("secret");
        let uri_index = instructions.find("URI:").expect("uri");
        let qr_index = instructions
            .find("Scan this QR code with your authenticator app.")
            .expect("qr notice");

        assert!(secret_index < qr_index);
        assert!(uri_index < qr_index);
    }

    #[test]
    fn terminal_dimensions_are_absent_when_env_missing() {
        let _guard = terminal_env_lock().lock().expect("terminal env lock");
        unsafe {
            env::remove_var("COLUMNS");
            env::remove_var("LINES");
        }

        assert_eq!(terminal_dimensions_from_env(), None);
    }

    #[test]
    fn enrollment_qr_renders_when_terminal_size_is_unavailable() {
        let _guard = terminal_env_lock().lock().expect("terminal env lock");
        unsafe {
            env::remove_var("COLUMNS");
            env::remove_var("LINES");
            env::set_var("LANG", "en_US.UTF-8");
        }

        let rendered = render_enrollment_qr_if_terminal_fits(
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CentralSSH",
        )
        .expect("qr render result");

        assert!(rendered.is_some());
    }

    #[test]
    fn enrollment_qr_is_suppressed_when_terminal_is_explicitly_too_small() {
        let _guard = terminal_env_lock().lock().expect("terminal env lock");
        unsafe {
            env::set_var("COLUMNS", "20");
            env::set_var("LINES", "10");
            env::set_var("LANG", "en_US.UTF-8");
        }

        let rendered = render_enrollment_qr_if_terminal_fits(
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CentralSSH",
        )
        .expect("qr render result");

        assert!(rendered.is_none());
    }

    #[test]
    fn enrollment_qr_is_suppressed_without_utf8_locale() {
        let _guard = terminal_env_lock().lock().expect("terminal env lock");
        unsafe {
            env::remove_var("LC_ALL");
            env::remove_var("LC_CTYPE");
            env::set_var("LANG", "C");
            env::remove_var("COLUMNS");
            env::remove_var("LINES");
        }

        let rendered = render_enrollment_qr_if_terminal_fits(
            "otpauth://totp/CentralSSH:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CentralSSH",
        )
        .expect("qr render result");

        assert!(rendered.is_none());
    }
}

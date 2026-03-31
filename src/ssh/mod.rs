use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use ssh_key::{LineEnding, PrivateKey};
use tracing::{error, warn};

use crate::app::{AppState, TransportAuthContext};
use crate::error::{CentralSshError, Result};

pub mod proxy;

#[derive(Clone)]
struct GatewayServer {
    state: Arc<AppState>,
}

#[derive(Clone)]
struct GatewayHandler {
    state: Arc<AppState>,
    peer_ip: IpAddr,
    pending_session_channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    keyboard_auth_state: Option<KeyboardAuthState>,
    transport_authenticated_username: Option<String>,
    transport_totp_verified: bool,
}

#[derive(Debug, Clone)]
enum KeyboardAuthState {
    AwaitUsername,
    AwaitPassword {
        username: String,
    },
    AwaitTotp {
        username: String,
        totp_secret: String,
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
            pending_session_channels: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            keyboard_auth_state: None,
            transport_authenticated_username: None,
            transport_totp_verified: false,
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

    fn keyboard_prompt(prompt: &'static str, echo: bool) -> Auth {
        Auth::Partial {
            name: Cow::Borrowed("CentralSSH Gateway"),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(vec![(Cow::Borrowed(prompt), echo)]),
        }
    }
}

impl server::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        Ok(Self::reject_to_keyboard_interactive())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> std::result::Result<Auth, Self::Error> {
        Ok(Self::reject_to_keyboard_interactive())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> std::result::Result<Auth, Self::Error> {
        if self.transport_authenticated_username.is_some() {
            return Ok(Auth::Accept);
        }

        let Some(mut response) = response else {
            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitUsername);
            return Ok(Self::keyboard_prompt("Username: ", true));
        };

        let response_text = response
            .next()
            .map(|value| String::from_utf8_lossy(value.as_ref()).trim().to_string())
            .unwrap_or_default();

        match self
            .keyboard_auth_state
            .clone()
            .unwrap_or(KeyboardAuthState::AwaitUsername)
        {
            KeyboardAuthState::AwaitUsername => {
                if response_text.is_empty() {
                    self.keyboard_auth_state = Some(KeyboardAuthState::AwaitUsername);
                    return Ok(Self::keyboard_prompt("Username: ", true));
                }
                self.keyboard_auth_state = Some(KeyboardAuthState::AwaitPassword {
                    username: response_text,
                });
                Ok(Self::keyboard_prompt("Password: ", false))
            }
            KeyboardAuthState::AwaitPassword { username } => {
                if self
                    .state
                    .auth
                    .consume_rate_limit_token(self.peer_ip, &username)
                    .await
                    .is_err()
                {
                    self.keyboard_auth_state = None;
                    return Ok(Self::reject_to_keyboard_interactive());
                }

                let snapshot = self.state.config_store.snapshot().await;
                match self.state.auth.verify_password_constant_time(
                    &snapshot.config.users,
                    &username,
                    response_text.as_str(),
                ) {
                    Ok(user) => {
                        if let Some(totp_secret) = user.totp_secret.clone() {
                            self.keyboard_auth_state = Some(KeyboardAuthState::AwaitTotp {
                                username: user.name.clone(),
                                totp_secret,
                            });
                            Ok(Self::keyboard_prompt("TOTP Code: ", false))
                        } else {
                            self.transport_authenticated_username = Some(user.name);
                            self.transport_totp_verified = false;
                            self.keyboard_auth_state = None;
                            Ok(Auth::Accept)
                        }
                    }
                    Err(_) => {
                        self.keyboard_auth_state = None;
                        Ok(Self::reject_to_keyboard_interactive())
                    }
                }
            }
            KeyboardAuthState::AwaitTotp {
                username,
                totp_secret,
            } => {
                if self
                    .state
                    .auth
                    .verify_totp_code(&totp_secret, response_text.as_str())
                    .is_ok()
                {
                    self.transport_authenticated_username = Some(username);
                    self.transport_totp_verified = true;
                    self.keyboard_auth_state = None;
                    Ok(Auth::Accept)
                } else {
                    self.keyboard_auth_state = None;
                    Ok(Self::reject_to_keyboard_interactive())
                }
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let id = channel.id();
        self.pending_session_channels
            .lock()
            .await
            .insert(id, channel);
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = session.channel_success(channel);

        let maybe_channel = self.pending_session_channels.lock().await.remove(&channel);
        let Some(channel_handle) = maybe_channel else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        let stream = channel_handle.into_stream();
        let state = self.state.clone();
        let source_ip = self.peer_ip;
        let transport_auth = self
            .transport_authenticated_username
            .as_ref()
            .map(|username| TransportAuthContext {
                username: username.clone(),
                totp_verified: self.transport_totp_verified,
            });

        tokio::spawn(async move {
            if let Err(err) =
                crate::app::handle_stream_session(stream, state, source_ip, transport_auth).await
            {
                if matches!(err, crate::error::CentralSshError::InputCanceled) {
                    return;
                }
                warn!(error = %err, source_ip = %source_ip, "session terminated with error");
            }
        });

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(false)
    }
}

pub async fn run_gateway_server(
    listen_addr: &str,
    host_key_path: &Path,
    state: Arc<AppState>,
    strict_security: bool,
) -> Result<()> {
    ensure_server_host_key(host_key_path)?;
    if strict_security {
        validate_host_key_security(host_key_path)?;
    }

    let mut config = server::Config::default();
    config.methods = MethodSet::from(&[MethodKind::KeyboardInteractive][..]);
    config.auth_rejection_time = Duration::from_secs(3);

    let host_key = russh::keys::load_secret_key(host_key_path, None)
        .map_err(|e| CentralSshError::Ssh(format!("failed to load host key: {e}")))?;
    config.keys.push(host_key);

    let config = Arc::new(config);
    let mut server = GatewayServer::new(state);
    let listen_socket: SocketAddr = listen_addr.parse().map_err(|e| {
        CentralSshError::InvalidConfig(format!("invalid listen address '{listen_addr}': {e}"))
    })?;

    server
        .run_on_address(config, listen_socket)
        .await
        .map_err(|e| {
            error!(error = %e, "gateway server stopped with error");
            CentralSshError::Ssh(e.to_string())
        })
}

fn ensure_server_host_key(path: &Path) -> Result<()> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let host_key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to create host key: {e}")))?;

    let encoded = host_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to encode host key: {e}")))?;

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

fn validate_host_key_security(path: &Path) -> Result<()> {
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

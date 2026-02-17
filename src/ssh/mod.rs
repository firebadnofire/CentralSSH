use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use ssh_key::{LineEnding, PrivateKey};
use tracing::{error, warn};

use crate::app::AppState;
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
        }
    }
}

impl server::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        // Transport authentication is intentionally minimal. CentralSSH performs
        // all credential checks through the internal login flow before access.
        Ok(Auth::Accept)
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
        Ok(Auth::Accept)
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
        session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_success(channel);

        let maybe_channel = self.pending_session_channels.lock().await.remove(&channel);
        let Some(channel_handle) = maybe_channel else {
            session.channel_failure(channel);
            return Ok(());
        };

        let stream = channel_handle.into_stream();
        let state = self.state.clone();
        let source_ip = self.peer_ip;

        tokio::spawn(async move {
            if let Err(err) = crate::app::handle_stream_session(stream, state, source_ip).await {
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
        session.channel_failure(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_failure(channel);
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_failure(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        session.channel_failure(channel);
        Ok(false)
    }
}

pub async fn run_gateway_server(
    listen_addr: &str,
    host_key_path: &Path,
    state: Arc<AppState>,
) -> Result<()> {
    ensure_server_host_key(host_key_path)?;

    let mut config = server::Config::default();
    config.auth_rejection_time = Duration::from_secs(3);

    let host_key = russh::keys::load_secret_key(host_key_path, None)
        .map_err(|e| CentralSshError::Ssh(format!("failed to load host key: {e}")))?;
    config.keys.push(host_key);

    let config = Arc::new(config);
    let server = GatewayServer::new(state);
    let listen_socket: SocketAddr = listen_addr.parse().map_err(|e| {
        CentralSshError::InvalidConfig(format!("invalid listen address '{listen_addr}': {e}"))
    })?;

    server
        .run_on_address(config, listen_socket)
        .await
        .map_err(|e: russh::Error| {
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

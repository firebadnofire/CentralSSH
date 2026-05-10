use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use russh::client::{self, Handle as ClientHandle};
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts_path, load_secret_key};
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, Sig};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::crypto_policy::{is_hybrid_kex_name, is_post_quantum_kex_name};
use crate::error::{CentralSshError, Result};
use crate::keys::resolve_user_server_private_key_path;
use crate::ssh::apply_client_transport_config;
use crate::ui::render_server_menu;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct SelectedTarget {
    pub name: String,
    pub host: String,
}

#[derive(Clone)]
struct StrictKnownHostsVerifier {
    expected_host: String,
    known_hosts_path: PathBuf,
}

#[derive(Clone)]
struct ProxyAuditContext {
    audit: AuditLogger,
    session_id: String,
    source_ip: String,
    username: String,
    target_server: String,
}

impl ProxyAuditContext {
    async fn log(&self, event_type: &str, result: AuditResult, reason_code: Option<String>) {
        let _ = self
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: event_type.to_string(),
                request_id: self.session_id.clone(),
                remote_ip: Some(self.source_ip.clone()),
                remote_port: None,
                username: Some(self.username.clone()),
                target_server: Some(self.target_server.clone()),
                auth_method: None,
                result,
                reason: reason_code,
                ban_duration_seconds: None,
                ban_until: None,
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

    async fn log_kex_negotiated(
        &self,
        event_type: &str,
        transport_side: &str,
        kex_algorithm: &str,
    ) {
        let _ = self
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: event_type.to_string(),
                request_id: self.session_id.clone(),
                remote_ip: Some(self.source_ip.clone()),
                remote_port: None,
                username: Some(self.username.clone()),
                target_server: Some(self.target_server.clone()),
                auth_method: None,
                result: AuditResult::Success,
                reason: None,
                ban_duration_seconds: None,
                ban_until: None,
                transport_side: Some(transport_side.to_string()),
                kex_algorithm: Some(kex_algorithm.to_string()),
                kex_algorithms_offered: None,
                post_quantum: Some(is_post_quantum_kex_name(kex_algorithm)),
                hybrid: Some(is_hybrid_kex_name(kex_algorithm)),
                classical_fallback: Some(!is_post_quantum_kex_name(kex_algorithm)),
                pq_required: None,
            })
            .await;
    }

    async fn log_kex_policy_applied(
        &self,
        transport_side: &str,
        offered_algorithms: Vec<String>,
        require_post_quantum: bool,
        classical_fallback: bool,
    ) {
        let _ = self
            .audit
            .log(AuditEvent {
                timestamp: Utc::now(),
                event_type: "backend_kex_policy_applied".to_string(),
                request_id: self.session_id.clone(),
                remote_ip: Some(self.source_ip.clone()),
                remote_port: None,
                username: Some(self.username.clone()),
                target_server: Some(self.target_server.clone()),
                auth_method: None,
                result: AuditResult::Success,
                reason: None,
                ban_duration_seconds: None,
                ban_until: None,
                transport_side: Some(transport_side.to_string()),
                kex_algorithm: None,
                kex_algorithms_offered: Some(offered_algorithms),
                post_quantum: Some(!classical_fallback),
                hybrid: None,
                classical_fallback: Some(classical_fallback),
                pq_required: Some(require_post_quantum),
            })
            .await;
    }
}

#[derive(Clone)]
struct TargetClientHandler {
    verifier: StrictKnownHostsVerifier,
    server_handle: server::Handle,
    last_error: Arc<Mutex<Option<String>>>,
    audit_context: ProxyAuditContext,
}

pub struct ProxySession {
    app_state: Arc<AppState>,
    server_handle: server::Handle,
    frontend_channel_state: Arc<Mutex<HashMap<ChannelId, SessionChannelState>>>,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Arc<Mutex<ChannelWriteHalf<client::Msg>>>>>>,
    last_error: Arc<Mutex<Option<String>>>,
    audit_context: ProxyAuditContext,
    username: String,
    drop_to_menu: bool,
}

#[derive(Debug, Clone)]
pub struct ChannelPtyState {
    pub term: String,
    pub col_width: u32,
    pub row_height: u32,
    pub pix_width: u32,
    pub pix_height: u32,
    pub terminal_modes: Vec<(russh::Pty, u32)>,
}

#[derive(Debug, Clone, Default)]
pub struct SessionChannelState {
    pub pty: Option<ChannelPtyState>,
    pub shell_requested: bool,
    pub menu_active: bool,
    pub input_buffer: Vec<u8>,
}

#[derive(Debug)]
enum BackendSessionAction {
    ForwardData {
        extended_code: Option<u32>,
        data: Bytes,
    },
    Eof,
    Close,
    Success,
    Failure,
    XonXoff {
        client_can_do: bool,
    },
    ExitStatus {
        exit_status: u32,
    },
    ExitSignal {
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    WindowAdjusted,
}

impl client::Handler for TargetClientHandler {
    type Error = russh::Error;

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.audit_context
            .log_kex_negotiated("backend_kex_negotiated", "backend", names.kex.as_ref())
            .await;
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        check_known_hosts_path(
            &self.verifier.expected_host,
            22,
            server_public_key,
            &self.verifier.known_hosts_path,
        )
        .map_err(|error| russh::Error::IO(std::io::Error::other(error.to_string())))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        target_channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let server_handle = self.server_handle.clone();
        let connected_address = connected_address.to_string();
        let originator_address = originator_address.to_string();
        let last_error = self.last_error.clone();

        tokio::spawn(async move {
            let result = async {
                let frontend_channel = server_handle
                    .channel_open_forwarded_tcpip(
                        connected_address.clone(),
                        connected_port,
                        originator_address.clone(),
                        originator_port,
                    )
                    .await
                    .map_err(|error| CentralSshError::Ssh(error.to_string()))?;

                spawn_raw_channel_bridge(frontend_channel, target_channel, last_error.clone());
                Ok::<(), CentralSshError>(())
            }
            .await;

            if let Err(error) = result {
                record_error(&last_error, error.to_string()).await;
            }
        });

        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        target_channel: Channel<client::Msg>,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let server_handle = self.server_handle.clone();
        let originator_address = originator_address.to_string();
        let last_error = self.last_error.clone();

        tokio::spawn(async move {
            let result = async {
                let frontend_channel = server_handle
                    .channel_open_x11(originator_address.clone(), originator_port)
                    .await
                    .map_err(|error| CentralSshError::Ssh(error.to_string()))?;

                spawn_raw_channel_bridge(frontend_channel, target_channel, last_error.clone());
                Ok::<(), CentralSshError>(())
            }
            .await;

            if let Err(error) = result {
                record_error(&last_error, error.to_string()).await;
            }
        });

        Ok(())
    }
}

impl ProxySession {
    pub async fn connect(
        app_state: Arc<AppState>,
        session_id: String,
        source_ip: IpAddr,
        username: String,
        target: SelectedTarget,
        server_handle: server::Handle,
        frontend_channel_state: Arc<Mutex<HashMap<ChannelId, SessionChannelState>>>,
    ) -> Result<Self> {
        let private_key_path = resolve_user_server_private_key_path(
            &app_state.config_store.paths.user_key_root,
            &username,
            &target.name,
            app_state.config_store.paths.per_user_per_server,
            app_state.strict_security,
        )?;

        let last_error = Arc::new(Mutex::new(None));
        let config_snapshot = app_state.config_store.snapshot().await;
        let audit_context = ProxyAuditContext {
            audit: app_state.audit.clone(),
            session_id,
            source_ip: source_ip.to_string(),
            username: username.clone(),
            target_server: target.name,
        };
        let handler = TargetClientHandler {
            verifier: StrictKnownHostsVerifier {
                expected_host: target.host.clone(),
                known_hosts_path: app_state.config_store.paths.known_hosts_path.clone(),
            },
            server_handle: server_handle.clone(),
            last_error: last_error.clone(),
            audit_context: audit_context.clone(),
        };

        let target_addr = format!("{}:22", target.host);
        let mut config = client::Config::default();
        let backend_kex_summary =
            apply_client_transport_config(&mut config, &config_snapshot.config.kex_policy)?;
        audit_context
            .log_kex_policy_applied(
                "backend",
                backend_kex_summary.offered_algorithms.clone(),
                backend_kex_summary.require_post_quantum,
                backend_kex_summary.classical_fallback,
            )
            .await;
        let config = Arc::new(config);
        let mut target_handle = client::connect(config, target_addr, handler)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))?;

        let private_key = load_secret_key(&private_key_path, None).map_err(|error| {
            CentralSshError::Ssh(format!("failed to load private key: {error}"))
        })?;

        let best_rsa_hash = target_handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();

        let auth_result = target_handle
            .authenticate_publickey(
                username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(private_key), best_rsa_hash),
            )
            .await
            .map_err(|error| CentralSshError::Ssh(format!("public key auth failed: {error}")))?;

        if !auth_result.success() {
            return Err(CentralSshError::Ssh(
                "target rejected public key authentication".to_string(),
            ));
        }

        info!(
            session_id = %audit_context.session_id,
            username = %username,
            target_host = %target.host,
            "backend SSH authentication succeeded"
        );

        Ok(Self {
            app_state,
            server_handle,
            frontend_channel_state,
            target_handle: Arc::new(Mutex::new(target_handle)),
            session_channels: Arc::new(Mutex::new(HashMap::new())),
            last_error,
            audit_context,
            username,
            drop_to_menu: config_snapshot.config.settings.drop_to_menu.unwrap_or(false),
        })
    }

    pub async fn open_session_channel(&self, frontend_channel: Channel<server::Msg>) -> Result<()> {
        self.open_session_channel_by_id(frontend_channel.id()).await
    }

    pub async fn open_session_channel_by_id(&self, frontend_id: ChannelId) -> Result<()> {
        debug!(
            session_id = %self.audit_context.session_id,
            frontend_channel = ?frontend_id,
            "opening proxied session channel"
        );
        let target_channel = {
            let handle = self.target_handle.lock().await;
            handle
                .channel_open_session()
                .await
                .map_err(|error| CentralSshError::Ssh(error.to_string()))?
        };
        let (target_read, target_write) = target_channel.split();
        let backend = Arc::new(Mutex::new(target_write));
        self.session_channels
            .lock()
            .await
            .insert(frontend_id, backend.clone());

        spawn_session_bridge(
            frontend_id,
            target_read,
            self.server_handle.clone(),
            self.target_handle.clone(),
            self.session_channels.clone(),
            self.last_error.clone(),
            self.app_state.clone(),
            self.username.clone(),
            self.drop_to_menu,
            self.frontend_channel_state.clone(),
        );

        Ok(())
    }

    pub async fn request_pty(
        &self,
        channel: ChannelId,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(russh::Pty, u32)],
    ) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        backend
            .lock()
            .await
            .request_pty(
                want_reply,
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
            )
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!(
                    "failed to relay pty request term={term} cols={col_width} rows={row_height} pix_width={pix_width} pix_height={pix_height}: {error}"
                ))
            })
    }

    pub async fn request_shell(&self, channel: ChannelId, want_reply: bool) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        backend
            .lock()
            .await
            .request_shell(want_reply)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!("failed to relay shell request: {error}"))
            })
    }

    pub async fn exec(&self, channel: ChannelId, want_reply: bool, command: Vec<u8>) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        let command_display = String::from_utf8_lossy(command.as_slice()).to_string();
        backend
            .lock()
            .await
            .exec(want_reply, command)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!(
                    "failed to relay exec request command={command_display}: {error}"
                ))
            })
    }

    pub async fn request_subsystem(
        &self,
        channel: ChannelId,
        want_reply: bool,
        name: String,
    ) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        let subsystem_name = name.clone();
        backend
            .lock()
            .await
            .request_subsystem(want_reply, name)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!(
                    "failed to relay subsystem request {subsystem_name}: {error}"
                ))
            })
    }

    pub async fn set_env(
        &self,
        channel: ChannelId,
        want_reply: bool,
        variable_name: String,
        variable_value: String,
    ) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        let variable_name_display = variable_name.clone();
        let variable_value_display = variable_value.clone();
        backend
            .lock()
            .await
            .set_env(want_reply, variable_name, variable_value)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!(
                    "failed to relay env request {}={}: {error}",
                    variable_name_display, variable_value_display
                ))
            })
    }

    pub async fn window_change(
        &self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<()> {
        debug!(
            session_id = %self.audit_context.session_id,
            username = %self.audit_context.username,
            target_server = %self.audit_context.target_server,
            frontend_channel = ?channel,
            cols = col_width,
            rows = row_height,
            pix_width,
            pix_height,
            "forwarding window-change"
        );
        let backend = self.backend_channel(channel).await?;
        backend
            .lock()
            .await
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!(
                    "failed to relay window-change cols={col_width} rows={row_height} pix_width={pix_width} pix_height={pix_height}: {error}"
                ))
            })
    }

    pub async fn signal(&self, channel: ChannelId, signal: Sig) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        let signal_display = format!("{signal:?}");
        backend
            .lock()
            .await
            .signal(signal)
            .await
            .map_err(|error| {
                CentralSshError::Ssh(format!("failed to relay signal {signal_display}: {error}"))
            })
    }

    pub async fn data(&self, channel: ChannelId, data: &[u8]) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        write_channel_data(backend, None, data)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn extended_data(&self, channel: ChannelId, code: u32, data: &[u8]) -> Result<()> {
        let backend = self.backend_channel(channel).await?;
        write_channel_data(backend, Some(code), data)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn channel_eof(&self, channel: ChannelId) -> Result<()> {
        let Some(backend) = self.session_channels.lock().await.get(&channel).cloned() else {
            return Ok(());
        };
        backend
            .lock()
            .await
            .eof()
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn channel_close(&self, channel: ChannelId) -> Result<()> {
        let Some(backend) = self.session_channels.lock().await.remove(&channel) else {
            return Ok(());
        };
        backend
            .lock()
            .await
            .close()
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn abort(&self, reason: String) {
        abort_proxy_session(
            &self.server_handle,
            &self.target_handle,
            &self.last_error,
            reason,
        )
        .await;
    }

    async fn backend_channel(
        &self,
        channel: ChannelId,
    ) -> Result<Arc<Mutex<ChannelWriteHalf<client::Msg>>>> {
        self.session_channels
            .lock()
            .await
            .get(&channel)
            .cloned()
            .ok_or_else(|| {
                CentralSshError::Ssh(format!(
                    "missing proxied backend session channel for frontend channel {channel:?}"
                ))
            })
    }

    pub async fn open_direct_tcpip_channel(
        &self,
        frontend_channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<()> {
        let target_channel = {
            let handle = self.target_handle.lock().await;
            handle
                .channel_open_direct_tcpip(
                    host_to_connect.to_string(),
                    port_to_connect,
                    originator_address.to_string(),
                    originator_port,
                )
                .await
                .map_err(|error| CentralSshError::Ssh(error.to_string()))?
        };

        spawn_raw_channel_bridge(frontend_channel, target_channel, self.last_error.clone());
        Ok(())
    }

    pub async fn tcpip_forward(&self, address: &str, port: u32) -> Result<u32> {
        let handle = self.target_handle.lock().await;
        handle
            .tcpip_forward(address.to_string(), port)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn cancel_tcpip_forward(&self, address: &str, port: u32) -> Result<()> {
        let handle = self.target_handle.lock().await;
        handle
            .cancel_tcpip_forward(address.to_string(), port)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }
}

impl Drop for ProxySession {
    fn drop(&mut self) {
        let target_handle = self.target_handle.clone();
        let last_error = self.last_error.clone();
        let audit_context = self.audit_context.clone();

        tokio::spawn(async move {
            {
                let handle = target_handle.lock().await;
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "gateway session closed", "en")
                    .await;
            }

            let failure_reason = last_error.lock().await.clone();
            audit_context
                .log(
                    "proxy_end",
                    if failure_reason.is_some() {
                        AuditResult::Failure
                    } else {
                        AuditResult::Success
                    },
                    failure_reason,
                )
                .await;
        });
    }
}

fn spawn_session_bridge(
    frontend_id: ChannelId,
    target_read: ChannelReadHalf,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Arc<Mutex<ChannelWriteHalf<client::Msg>>>>>>,
    last_error: Arc<Mutex<Option<String>>>,
    app_state: Arc<AppState>,
    username: String,
    drop_to_menu: bool,
    frontend_channel_state: Arc<Mutex<HashMap<ChannelId, SessionChannelState>>>,
) {
    tokio::spawn(async move {
        let close_frontend = relay_backend_session(
            frontend_id,
            target_read,
            server_handle.clone(),
            target_handle.clone(),
            session_channels,
            last_error.clone(),
            app_state,
            username,
            drop_to_menu,
            frontend_channel_state,
        );

        if close_frontend.await {
            let _ = server_handle.close(frontend_id).await;
        }
    });
}

fn spawn_raw_channel_bridge(
    frontend_channel: Channel<server::Msg>,
    target_channel: Channel<client::Msg>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    tokio::spawn(async move {
        let (frontend_read, frontend_write) = frontend_channel.split();
        let (target_read, target_write) = target_channel.split();

        let front_to_back = relay_raw_channel(frontend_read, target_write, last_error.clone());
        let back_to_front = relay_raw_channel(target_read, frontend_write, last_error.clone());

        let _ = tokio::join!(front_to_back, back_to_front);
    });
}

async fn relay_backend_session(
    frontend_id: ChannelId,
    mut target_read: ChannelReadHalf,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Arc<Mutex<ChannelWriteHalf<client::Msg>>>>>>,
    last_error: Arc<Mutex<Option<String>>>,
    app_state: Arc<AppState>,
    username: String,
    drop_to_menu: bool,
    frontend_channel_state: Arc<Mutex<HashMap<ChannelId, SessionChannelState>>>,
) -> bool {
    loop {
        match target_read.wait().await {
            Some(message) => {
                let action = match classify_backend_session_msg(message) {
                    Ok(action) => action,
                    Err(reason) => {
                        abort_proxy_session(&server_handle, &target_handle, &last_error, reason)
                            .await;
                        return true;
                    }
                };

                let should_break = matches!(action, BackendSessionAction::Close);
                if let Err(error) =
                    apply_backend_session_action(action, frontend_id, &server_handle).await
                {
                    abort_proxy_session(&server_handle, &target_handle, &last_error, error).await;
                    return true;
                }

                if should_break {
                    session_channels.lock().await.remove(&frontend_id);
                    return !activate_menu_after_disconnect(
                        &app_state,
                        &server_handle,
                        &username,
                        frontend_id,
                        drop_to_menu,
                        &frontend_channel_state,
                    )
                    .await;
                }
            }
            None => {
                session_channels.lock().await.remove(&frontend_id);
                return !activate_menu_after_disconnect(
                    &app_state,
                    &server_handle,
                    &username,
                    frontend_id,
                    drop_to_menu,
                    &frontend_channel_state,
                )
                .await;
            }
        }
    }
}

async fn activate_menu_after_disconnect(
    app_state: &Arc<AppState>,
    server_handle: &server::Handle,
    username: &str,
    frontend_id: ChannelId,
    drop_to_menu: bool,
    frontend_channel_state: &Arc<Mutex<HashMap<ChannelId, SessionChannelState>>>,
) -> bool {
    if !drop_to_menu {
        return false;
    }

    {
        let mut guard = frontend_channel_state.lock().await;
        let Some(channel_state) = guard.get_mut(&frontend_id) else {
            return false;
        };
        if !channel_state.shell_requested {
            return false;
        }
        channel_state.menu_active = true;
        channel_state.input_buffer.clear();
    }

    let snapshot = app_state.config_store.snapshot().await;
    let Some(user) = snapshot
        .config
        .users
        .iter()
        .find(|candidate| candidate.name == username)
    else {
        return false;
    };

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
        return false;
    }

    let menu = render_server_menu(username, &entries);
    server_handle
        .data(frontend_id, Bytes::from(menu))
        .await
        .is_ok()
}

async fn relay_raw_channel<S>(
    mut reader: ChannelReadHalf,
    writer: ChannelWriteHalf<S>,
    last_error: Arc<Mutex<Option<String>>>,
) where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    loop {
        match reader.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if let Err(error) = write_raw_channel_data(&writer, None, &data).await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::WindowAdjusted { .. }) => {
                // SSH flow-control updates are handled by the library transport.
            }
            Some(ChannelMsg::ExtendedData { ext, data }) => {
                if let Err(error) = write_raw_channel_data(&writer, Some(ext), &data).await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::Eof) => {
                if let Err(error) = writer.eof().await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::Close) => {
                let _ = writer.close().await;
                break;
            }
            Some(other) => {
                record_error(
                    &last_error,
                    format!("unexpected raw channel message: {other:?}"),
                )
                .await;
                let _ = writer.close().await;
                break;
            }
            None => {
                let _ = writer.close().await;
                break;
            }
        }
    }
}

fn classify_backend_session_msg(
    message: ChannelMsg,
) -> std::result::Result<BackendSessionAction, String> {
    match message {
        ChannelMsg::Data { data } => Ok(BackendSessionAction::ForwardData {
            extended_code: None,
            data,
        }),
        ChannelMsg::ExtendedData { ext, data } => Ok(BackendSessionAction::ForwardData {
            extended_code: Some(ext),
            data,
        }),
        ChannelMsg::Eof => Ok(BackendSessionAction::Eof),
        ChannelMsg::Close => Ok(BackendSessionAction::Close),
        ChannelMsg::Success => Ok(BackendSessionAction::Success),
        ChannelMsg::Failure => Ok(BackendSessionAction::Failure),
        ChannelMsg::XonXoff { client_can_do } => {
            Ok(BackendSessionAction::XonXoff { client_can_do })
        }
        ChannelMsg::ExitStatus { exit_status } => {
            Ok(BackendSessionAction::ExitStatus { exit_status })
        }
        ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            lang_tag,
        } => Ok(BackendSessionAction::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            lang_tag,
        }),
        ChannelMsg::WindowAdjusted { .. } => Ok(BackendSessionAction::WindowAdjusted),
        unexpected @ (ChannelMsg::Open { .. }
        | ChannelMsg::OpenFailure(_)
        | ChannelMsg::RequestPty { .. }
        | ChannelMsg::RequestShell { .. }
        | ChannelMsg::Exec { .. }
        | ChannelMsg::Signal { .. }
        | ChannelMsg::RequestSubsystem { .. }
        | ChannelMsg::RequestX11 { .. }
        | ChannelMsg::SetEnv { .. }
        | ChannelMsg::WindowChange { .. }
        | ChannelMsg::AgentForward { .. }) => Err(format!(
            "unexpected target session channel message: {unexpected:?}"
        )),
        other => Err(format!(
            "unhandled target session channel message: {other:?}"
        )),
    }
}

async fn apply_backend_session_action(
    action: BackendSessionAction,
    frontend_id: ChannelId,
    server_handle: &server::Handle,
) -> std::result::Result<(), String> {
    match action {
        BackendSessionAction::ForwardData {
            extended_code,
            data,
        } => {
            if let Some(ext) = extended_code {
                server_handle
                    .extended_data(frontend_id, ext, data)
                    .await
                    .map_err(|failed_data: Bytes| {
                        String::from_utf8_lossy(failed_data.as_ref()).to_string()
                    })
            } else {
                server_handle
                    .data(frontend_id, data)
                    .await
                    .map_err(|failed_data: Bytes| {
                        String::from_utf8_lossy(failed_data.as_ref()).to_string()
                    })
            }
        }
        BackendSessionAction::Eof => server_handle
            .eof(frontend_id)
            .await
            .map_err(|_| format!("failed to send EOF to frontend channel {frontend_id:?}")),
        BackendSessionAction::Close => server_handle
            .close(frontend_id)
            .await
            .map_err(|_| format!("failed to close frontend channel {frontend_id:?}")),
        BackendSessionAction::Success => server_handle
            .channel_success(frontend_id)
            .await
            .map_err(|_| format!("failed to send success to frontend channel {frontend_id:?}")),
        BackendSessionAction::Failure => server_handle
            .channel_failure(frontend_id)
            .await
            .map_err(|_| format!("failed to send failure to frontend channel {frontend_id:?}")),
        BackendSessionAction::XonXoff { client_can_do } => server_handle
            .xon_xoff_request(frontend_id, client_can_do)
            .await
            .map_err(|_| format!("failed to relay xon-xoff for frontend channel {frontend_id:?}")),
        BackendSessionAction::ExitStatus { exit_status } => server_handle
            .exit_status_request(frontend_id, exit_status)
            .await
            .map_err(|_| format!("failed to send exit-status to frontend channel {frontend_id:?}")),
        BackendSessionAction::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            lang_tag,
        } => server_handle
            .exit_signal_request(
                frontend_id,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            )
            .await
            .map_err(|_| format!("failed to send exit-signal to frontend channel {frontend_id:?}")),
        BackendSessionAction::WindowAdjusted => Ok(()),
    }
}

async fn write_channel_data(
    backend: Arc<Mutex<ChannelWriteHalf<client::Msg>>>,
    extended_code: Option<u32>,
    data: &[u8],
) -> std::result::Result<(), russh::Error> {
    let guard = backend.lock().await;
    write_raw_channel_data(&*guard, extended_code, data).await
}

async fn write_raw_channel_data<S>(
    writer: &ChannelWriteHalf<S>,
    extended_code: Option<u32>,
    data: &[u8],
) -> std::result::Result<(), russh::Error>
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let mut tx = writer.make_writer_ext(extended_code);
    tx.write_all(data).await?;
    tx.flush().await?;
    Ok(())
}

async fn abort_proxy_session(
    server_handle: &server::Handle,
    target_handle: &Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    last_error: &Arc<Mutex<Option<String>>>,
    reason: String,
) {
    record_error(last_error, reason.clone()).await;
    warn!(error = %reason, "aborting proxied SSH session");
    let _ = server_handle
        .disconnect(Disconnect::ByApplication, reason.clone(), "en".to_string())
        .await;
    {
        let handle = target_handle.lock().await;
        let _ = handle
            .disconnect(Disconnect::ByApplication, &reason, "en")
            .await;
    }
}

async fn record_error(last_error: &Arc<Mutex<Option<String>>>, message: String) {
    let mut guard = last_error.lock().await;
    if guard.is_none() {
        *guard = Some(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(bytes: &[u8]) -> Bytes {
        Bytes::copy_from_slice(bytes)
    }

    #[test]
    fn classify_backend_impossible_message_is_hard_error() {
        let error = classify_backend_session_msg(ChannelMsg::RequestShell { want_reply: true })
            .expect_err("hard error");
        assert!(error.contains("unexpected target session channel message"));
    }

    #[test]
    fn classify_backend_data_is_forwarded() {
        let action = classify_backend_session_msg(ChannelMsg::Data {
            data: data(b"stdout"),
        })
        .expect("backend data action");

        match action {
            BackendSessionAction::ForwardData {
                extended_code,
                data,
            } => {
                assert!(extended_code.is_none());
                assert_eq!(data.as_ref(), b"stdout");
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

}

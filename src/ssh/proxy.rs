use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use russh::client::{self, Handle as ClientHandle};
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts_path, load_secret_key};
use russh::server;
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, CryptoVec, Disconnect, Sig,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::audit::{AuditEvent, AuditLogger, AuditResult};
use crate::error::{CentralSshError, Result};
use crate::keys::resolve_user_server_private_key_path;
use crate::ssh::apply_client_transport_config;

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
                session_id: self.session_id.clone(),
                source_ip: Some(self.source_ip.clone()),
                username: Some(self.username.clone()),
                target_server: Some(self.target_server.clone()),
                result,
                reason_code,
            })
            .await;
    }
}

#[derive(Clone)]
struct TargetClientHandler {
    verifier: StrictKnownHostsVerifier,
    server_handle: server::Handle,
    last_error: Arc<Mutex<Option<String>>>,
}

pub struct ProxySession {
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    last_error: Arc<Mutex<Option<String>>>,
    audit_context: ProxyAuditContext,
}

#[derive(Debug)]
enum FrontendSessionAction {
    ForwardData {
        extended_code: Option<u32>,
        data: CryptoVec,
    },
    RequestPty {
        want_reply: bool,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: Vec<(russh::Pty, u32)>,
    },
    RequestShell {
        want_reply: bool,
    },
    Exec {
        want_reply: bool,
        command: Vec<u8>,
    },
    Signal {
        signal: Sig,
    },
    RequestSubsystem {
        want_reply: bool,
        name: String,
    },
    RequestX11 {
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: String,
        x11_authentication_cookie: String,
        x11_screen_number: u32,
    },
    SetEnv {
        want_reply: bool,
        variable_name: String,
        variable_value: String,
    },
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    RejectAgentForward {
        want_reply: bool,
    },
    Eof,
    Close,
}

#[derive(Debug)]
enum BackendSessionAction {
    ForwardData {
        extended_code: Option<u32>,
        data: CryptoVec,
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
    ) -> Result<Self> {
        let private_key_path = resolve_user_server_private_key_path(
            &app_state.config_store.paths.user_key_root,
            &username,
            &target.name,
            app_state.strict_security,
        )?;

        let last_error = Arc::new(Mutex::new(None));
        let handler = TargetClientHandler {
            verifier: StrictKnownHostsVerifier {
                expected_host: target.host.clone(),
                known_hosts_path: app_state.config_store.paths.known_hosts_path.clone(),
            },
            server_handle: server_handle.clone(),
            last_error: last_error.clone(),
        };

        let target_addr = format!("{}:22", target.host);
        let mut config = client::Config::default();
        apply_client_transport_config(&mut config);
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

        Ok(Self {
            server_handle,
            target_handle: Arc::new(Mutex::new(target_handle)),
            last_error,
            audit_context: ProxyAuditContext {
                audit: app_state.audit.clone(),
                session_id,
                source_ip: source_ip.to_string(),
                username,
                target_server: target.name,
            },
        })
    }

    pub async fn open_session_channel(&self, frontend_channel: Channel<server::Msg>) -> Result<()> {
        let frontend_id = frontend_channel.id();
        let (frontend_read, _) = frontend_channel.split();
        let target_channel = {
            let handle = self.target_handle.lock().await;
            handle
                .channel_open_session()
                .await
                .map_err(|error| CentralSshError::Ssh(error.to_string()))?
        };
        let (target_read, target_write) = target_channel.split();
        let backend = Arc::new(Mutex::new(target_write));

        spawn_session_bridge(
            frontend_id,
            frontend_read,
            target_read,
            backend,
            self.server_handle.clone(),
            self.target_handle.clone(),
            self.last_error.clone(),
            self.audit_context.clone(),
        );

        Ok(())
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
        let mut handle = self.target_handle.lock().await;
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
    frontend_read: ChannelReadHalf,
    target_read: ChannelReadHalf,
    backend: Arc<Mutex<ChannelWriteHalf<client::Msg>>>,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    last_error: Arc<Mutex<Option<String>>>,
    audit_context: ProxyAuditContext,
) {
    tokio::spawn(async move {
        let front_to_back = relay_frontend_session(
            frontend_read,
            backend.clone(),
            server_handle.clone(),
            target_handle.clone(),
            last_error.clone(),
            audit_context.clone(),
        );
        let back_to_front = relay_backend_session(
            frontend_id,
            target_read,
            server_handle.clone(),
            target_handle.clone(),
            last_error.clone(),
        );

        let _ = tokio::join!(front_to_back, back_to_front);

        let _ = server_handle.close(frontend_id).await;
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

async fn relay_frontend_session(
    mut frontend_read: ChannelReadHalf,
    backend: Arc<Mutex<ChannelWriteHalf<client::Msg>>>,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    last_error: Arc<Mutex<Option<String>>>,
    audit_context: ProxyAuditContext,
) {
    loop {
        match frontend_read.wait().await {
            Some(message) => {
                let action = match classify_frontend_session_msg(message) {
                    Ok(action) => action,
                    Err(reason) => {
                        abort_proxy_session(&server_handle, &target_handle, &last_error, reason)
                            .await;
                        break;
                    }
                };

                let should_break = matches!(action, FrontendSessionAction::Close);
                if let Err(error) =
                    apply_frontend_session_action(action, backend.clone(), &audit_context).await
                {
                    abort_proxy_session(&server_handle, &target_handle, &last_error, error).await;
                    break;
                }

                if should_break {
                    break;
                }
            }
            None => {
                let _ = backend.lock().await.close().await;
                break;
            }
        }
    }
}

async fn relay_backend_session(
    frontend_id: ChannelId,
    mut target_read: ChannelReadHalf,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    loop {
        match target_read.wait().await {
            Some(message) => {
                let action = match classify_backend_session_msg(message) {
                    Ok(action) => action,
                    Err(reason) => {
                        abort_proxy_session(&server_handle, &target_handle, &last_error, reason)
                            .await;
                        break;
                    }
                };

                let should_break = matches!(action, BackendSessionAction::Close);
                if let Err(error) =
                    apply_backend_session_action(action, frontend_id, &server_handle).await
                {
                    abort_proxy_session(&server_handle, &target_handle, &last_error, error).await;
                    break;
                }

                if should_break {
                    break;
                }
            }
            None => {
                let _ = server_handle.close(frontend_id).await;
                break;
            }
        }
    }
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

fn classify_frontend_session_msg(
    message: ChannelMsg,
) -> std::result::Result<FrontendSessionAction, String> {
    match message {
        ChannelMsg::Data { data } => Ok(FrontendSessionAction::ForwardData {
            extended_code: None,
            data,
        }),
        ChannelMsg::ExtendedData { ext, data } => Ok(FrontendSessionAction::ForwardData {
            extended_code: Some(ext),
            data,
        }),
        ChannelMsg::Eof => Ok(FrontendSessionAction::Eof),
        ChannelMsg::Close => Ok(FrontendSessionAction::Close),
        ChannelMsg::RequestPty {
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
        } => Ok(FrontendSessionAction::RequestPty {
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
        }),
        ChannelMsg::RequestShell { want_reply } => {
            Ok(FrontendSessionAction::RequestShell { want_reply })
        }
        ChannelMsg::Exec {
            want_reply,
            command,
        } => Ok(FrontendSessionAction::Exec {
            want_reply,
            command,
        }),
        ChannelMsg::Signal { signal } => Ok(FrontendSessionAction::Signal { signal }),
        ChannelMsg::RequestSubsystem { want_reply, name } => {
            Ok(FrontendSessionAction::RequestSubsystem { want_reply, name })
        }
        ChannelMsg::RequestX11 {
            want_reply,
            single_connection,
            x11_authentication_protocol,
            x11_authentication_cookie,
            x11_screen_number,
        } => Ok(FrontendSessionAction::RequestX11 {
            want_reply,
            single_connection,
            x11_authentication_protocol,
            x11_authentication_cookie,
            x11_screen_number,
        }),
        ChannelMsg::SetEnv {
            want_reply,
            variable_name,
            variable_value,
        } => Ok(FrontendSessionAction::SetEnv {
            want_reply,
            variable_name,
            variable_value,
        }),
        ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => Ok(FrontendSessionAction::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        }),
        ChannelMsg::AgentForward { want_reply } => {
            Ok(FrontendSessionAction::RejectAgentForward { want_reply })
        }
        unexpected @ (ChannelMsg::Open { .. }
        | ChannelMsg::OpenFailure(_)
        | ChannelMsg::XonXoff { .. }
        | ChannelMsg::ExitStatus { .. }
        | ChannelMsg::ExitSignal { .. }
        | ChannelMsg::WindowAdjusted { .. }
        | ChannelMsg::Success
        | ChannelMsg::Failure) => Err(format!(
            "unexpected frontend session channel message: {unexpected:?}"
        )),
        other => Err(format!(
            "unhandled frontend session channel message: {other:?}"
        )),
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

async fn apply_frontend_session_action(
    action: FrontendSessionAction,
    backend: Arc<Mutex<ChannelWriteHalf<client::Msg>>>,
    audit_context: &ProxyAuditContext,
) -> std::result::Result<(), String> {
    match action {
        FrontendSessionAction::ForwardData {
            extended_code,
            data,
        } => write_channel_data(backend, extended_code, &data)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::RequestPty {
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
        } => backend
            .lock()
            .await
            .request_pty(
                want_reply,
                &term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                &terminal_modes,
            )
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::RequestShell { want_reply } => backend
            .lock()
            .await
            .request_shell(want_reply)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::Exec {
            want_reply,
            command,
        } => backend
            .lock()
            .await
            .exec(want_reply, command)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::Signal { signal } => backend
            .lock()
            .await
            .signal(signal)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::RequestSubsystem { want_reply, name } => backend
            .lock()
            .await
            .request_subsystem(want_reply, name)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::RequestX11 {
            want_reply,
            single_connection,
            x11_authentication_protocol,
            x11_authentication_cookie,
            x11_screen_number,
        } => backend
            .lock()
            .await
            .request_x11(
                want_reply,
                single_connection,
                x11_authentication_protocol,
                x11_authentication_cookie,
                x11_screen_number,
            )
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::SetEnv {
            want_reply,
            variable_name,
            variable_value,
        } => backend
            .lock()
            .await
            .set_env(want_reply, variable_name, variable_value)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => backend
            .lock()
            .await
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::RejectAgentForward { want_reply } => {
            let reason = if want_reply {
                "agent forwarding disabled by policy".to_string()
            } else {
                "agent forwarding disabled by policy (no-reply request)".to_string()
            };
            audit_context
                .log("agent_forward_request", AuditResult::Failure, Some(reason))
                .await;
            Ok(())
        }
        FrontendSessionAction::Eof => backend
            .lock()
            .await
            .eof()
            .await
            .map_err(|error| error.to_string()),
        FrontendSessionAction::Close => backend
            .lock()
            .await
            .close()
            .await
            .map_err(|error| error.to_string()),
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
                    .map_err(|failed_data| String::from_utf8_lossy(&failed_data).to_string())
            } else {
                server_handle
                    .data(frontend_id, data)
                    .await
                    .map_err(|failed_data| String::from_utf8_lossy(&failed_data).to_string())
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
    data: &CryptoVec,
) -> std::result::Result<(), russh::Error> {
    let guard = backend.lock().await;
    write_raw_channel_data(&*guard, extended_code, data).await
}

async fn write_raw_channel_data<S>(
    writer: &ChannelWriteHalf<S>,
    extended_code: Option<u32>,
    data: &CryptoVec,
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

    fn data(bytes: &[u8]) -> CryptoVec {
        CryptoVec::from_slice(bytes)
    }

    #[test]
    fn classify_frontend_exec_is_forwarded() {
        let action = classify_frontend_session_msg(ChannelMsg::Exec {
            want_reply: true,
            command: b"printf ok".to_vec(),
        })
        .expect("exec action");

        match action {
            FrontendSessionAction::Exec {
                want_reply,
                command,
            } => {
                assert!(want_reply);
                assert_eq!(command, b"printf ok");
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn classify_frontend_subsystem_is_forwarded() {
        let action = classify_frontend_session_msg(ChannelMsg::RequestSubsystem {
            want_reply: true,
            name: "sftp".to_string(),
        })
        .expect("subsystem action");

        match action {
            FrontendSessionAction::RequestSubsystem { want_reply, name } => {
                assert!(want_reply);
                assert_eq!(name, "sftp");
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn classify_frontend_env_is_forwarded() {
        let action = classify_frontend_session_msg(ChannelMsg::SetEnv {
            want_reply: true,
            variable_name: "LANG".to_string(),
            variable_value: "C.UTF-8".to_string(),
        })
        .expect("env action");

        match action {
            FrontendSessionAction::SetEnv {
                want_reply,
                variable_name,
                variable_value,
            } => {
                assert!(want_reply);
                assert_eq!(variable_name, "LANG");
                assert_eq!(variable_value, "C.UTF-8");
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn classify_frontend_signal_is_forwarded() {
        let action = classify_frontend_session_msg(ChannelMsg::Signal { signal: Sig::TERM })
            .expect("signal action");

        match action {
            FrontendSessionAction::Signal { signal } => {
                assert!(matches!(signal, Sig::TERM));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn classify_frontend_agent_forward_is_policy_rejection() {
        let action = classify_frontend_session_msg(ChannelMsg::AgentForward { want_reply: true })
            .expect("agent-forward action");

        match action {
            FrontendSessionAction::RejectAgentForward { want_reply } => {
                assert!(want_reply);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn classify_frontend_impossible_message_is_hard_error() {
        let error = classify_frontend_session_msg(ChannelMsg::Success).expect_err("hard error");
        assert!(error.contains("unexpected frontend session channel message"));
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

    #[test]
    fn channel_open_failure_is_frontend_hard_error() {
        let error = classify_frontend_session_msg(ChannelMsg::OpenFailure(
            russh::ChannelOpenFailure::UnknownChannelType,
        ))
        .expect_err("hard error");
        assert!(error.contains("unexpected frontend session channel message"));
    }
}

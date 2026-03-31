use std::collections::HashMap;
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
use tracing::warn;

use crate::app::AppState;
use crate::audit::{AuditEvent, AuditResult};
use crate::error::{CentralSshError, Result};
use crate::keys::resolve_user_server_private_key_path;

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
struct TargetClientHandler {
    verifier: StrictKnownHostsVerifier,
    server_handle: server::Handle,
    last_error: Arc<Mutex<Option<String>>>,
}

pub struct ProxySession {
    app_state: Arc<AppState>,
    session_id: String,
    source_ip: IpAddr,
    username: String,
    target: SelectedTarget,
    server_handle: server::Handle,
    target_handle: Arc<Mutex<ClientHandle<TargetClientHandler>>>,
    session_routes: Arc<Mutex<HashMap<ChannelId, SessionRoute>>>,
    last_error: Arc<Mutex<Option<String>>>,
}

struct SessionRoute {
    backend: Arc<Mutex<ChannelWriteHalf<client::Msg>>>,
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
        let config = Arc::new(client::Config::default());
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
            app_state,
            session_id,
            source_ip,
            username,
            target,
            server_handle,
            target_handle: Arc::new(Mutex::new(target_handle)),
            session_routes: Arc::new(Mutex::new(HashMap::new())),
            last_error,
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

        self.session_routes.lock().await.insert(
            frontend_id,
            SessionRoute {
                backend: backend.clone(),
            },
        );

        spawn_session_bridge(
            frontend_id,
            frontend_read,
            target_read,
            backend,
            self.server_handle.clone(),
            self.session_routes.clone(),
            self.last_error.clone(),
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

    pub async fn request_pty(
        &self,
        frontend_channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
    ) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_shell(&self, frontend_channel: ChannelId) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .request_shell(true)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_exec(&self, frontend_channel: ChannelId, command: &[u8]) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .exec(true, command.to_vec())
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_subsystem(&self, frontend_channel: ChannelId, name: &str) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .request_subsystem(true, name.to_string())
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_env(
        &self,
        frontend_channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
    ) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .set_env(true, variable_name.to_string(), variable_value.to_string())
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_window_change(
        &self,
        frontend_channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
    }

    pub async fn request_signal(&self, frontend_channel: ChannelId, signal: Sig) -> Result<()> {
        let backend = self.session_backend(frontend_channel).await?;
        backend
            .lock()
            .await
            .signal(signal)
            .await
            .map_err(|error| CentralSshError::Ssh(error.to_string()))
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

    async fn session_backend(
        &self,
        frontend_channel: ChannelId,
    ) -> Result<Arc<Mutex<ChannelWriteHalf<client::Msg>>>> {
        let routes = self.session_routes.lock().await;
        routes
            .get(&frontend_channel)
            .map(|route| route.backend.clone())
            .ok_or(CentralSshError::AuthorizationDenied)
    }
}

impl Drop for ProxySession {
    fn drop(&mut self) {
        let audit = self.app_state.audit.clone();
        let target_handle = self.target_handle.clone();
        let session_id = self.session_id.clone();
        let source_ip = self.source_ip.to_string();
        let username = self.username.clone();
        let target_server = self.target.name.clone();
        let last_error = self.last_error.clone();

        tokio::spawn(async move {
            {
                let handle = target_handle.lock().await;
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "gateway session closed", "en")
                    .await;
            }

            let failure_reason = last_error.lock().await.clone();
            let _ = audit
                .log(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: "proxy_end".to_string(),
                    session_id,
                    source_ip: Some(source_ip),
                    username: Some(username),
                    target_server: Some(target_server),
                    result: if failure_reason.is_some() {
                        AuditResult::Failure
                    } else {
                        AuditResult::Success
                    },
                    reason_code: failure_reason,
                })
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
    session_routes: Arc<Mutex<HashMap<ChannelId, SessionRoute>>>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    tokio::spawn(async move {
        let front_to_back =
            relay_frontend_session(frontend_read, backend.clone(), last_error.clone());
        let back_to_front = relay_backend_session(
            frontend_id,
            target_read,
            server_handle.clone(),
            last_error.clone(),
        );

        let _ = tokio::join!(front_to_back, back_to_front);

        session_routes.lock().await.remove(&frontend_id);
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
    last_error: Arc<Mutex<Option<String>>>,
) {
    loop {
        match frontend_read.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if let Err(error) = write_channel_data(backend.clone(), None, &data).await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::ExtendedData { ext, data }) => {
                if let Err(error) = write_channel_data(backend.clone(), Some(ext), &data).await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::Eof) => {
                if let Err(error) = backend.lock().await.eof().await {
                    record_error(&last_error, error.to_string()).await;
                    break;
                }
            }
            Some(other) => {
                warn!(?other, "ignoring unexpected client session channel message");
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
    last_error: Arc<Mutex<Option<String>>>,
) {
    loop {
        match target_read.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if let Err(data) = server_handle.data(frontend_id, data).await {
                    record_error(&last_error, String::from_utf8_lossy(&data).to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::ExtendedData { ext, data }) => {
                if let Err(data) = server_handle.extended_data(frontend_id, ext, data).await {
                    record_error(&last_error, String::from_utf8_lossy(&data).to_string()).await;
                    break;
                }
            }
            Some(ChannelMsg::Eof) => {
                let _ = server_handle.eof(frontend_id).await;
            }
            Some(ChannelMsg::Success) => {
                let _ = server_handle.channel_success(frontend_id).await;
            }
            Some(ChannelMsg::Failure) => {
                let _ = server_handle.channel_failure(frontend_id).await;
            }
            Some(ChannelMsg::XonXoff { client_can_do }) => {
                let _ = server_handle
                    .xon_xoff_request(frontend_id, client_can_do)
                    .await;
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                let _ = server_handle
                    .exit_status_request(frontend_id, exit_status)
                    .await;
            }
            Some(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            }) => {
                let _ = server_handle
                    .exit_signal_request(
                        frontend_id,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )
                    .await;
            }
            Some(ChannelMsg::WindowAdjusted { .. }) => {}
            Some(other) => {
                warn!(?other, "ignoring unexpected target session channel message");
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
            Some(other) => {
                warn!(?other, "ignoring unexpected raw channel message");
            }
            None => {
                let _ = writer.close().await;
                break;
            }
        }
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

async fn record_error(last_error: &Arc<Mutex<Option<String>>>, message: String) {
    let mut guard = last_error.lock().await;
    if guard.is_none() {
        *guard = Some(message);
    }
}

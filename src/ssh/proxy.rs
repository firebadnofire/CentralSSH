use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, check_known_hosts_path, load_secret_key};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::time;

use crate::error::{CentralSshError, Result};

#[derive(Debug, Clone)]
struct StrictKnownHostsVerifier {
    expected_host: String,
    known_hosts_path: PathBuf,
}

#[derive(Clone)]
struct ProxyClientHandler {
    verifier: StrictKnownHostsVerifier,
}

impl client::Handler for ProxyClientHandler {
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
        .map_err(|e| russh::Error::IO(std::io::Error::other(e.to_string())))
    }
}

pub async fn proxy_session<S>(
    stream: &mut S,
    known_hosts_path: &Path,
    target_ip: &str,
    remote_user: &str,
    private_key_path: &Path,
    idle_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = Arc::new(client::Config::default());
    let handler = ProxyClientHandler {
        verifier: StrictKnownHostsVerifier {
            expected_host: target_ip.to_string(),
            known_hosts_path: known_hosts_path.to_path_buf(),
        },
    };

    let target_addr = format!("{target_ip}:22");
    let mut session = client::connect(config, target_addr, handler)
        .await
        .map_err(|e| CentralSshError::Ssh(e.to_string()))?;

    let key = load_secret_key(private_key_path, None)
        .map_err(|e| CentralSshError::Ssh(format!("failed to load private key: {e}")))?;
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));

    let auth_result = session
        .authenticate_publickey(remote_user, key)
        .await
        .map_err(|e| CentralSshError::Ssh(format!("public key auth failed: {e}")))?;

    if auth_result != client::AuthResult::Success {
        return Err(CentralSshError::Ssh(
            "target rejected public key authentication".to_string(),
        ));
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| CentralSshError::Ssh(format!("failed to open target session channel: {e}")))?;

    channel
        .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
        .await
        .map_err(|e| CentralSshError::Ssh(format!("failed to request PTY: {e}")))?;

    channel
        .request_shell(true)
        .await
        .map_err(|e| CentralSshError::Ssh(format!("failed to request shell: {e}")))?;

    let target_stream = channel.into_stream();
    let (mut upstream_reader, mut upstream_writer) = io::split(target_stream);

    let (mut local_reader, mut local_writer) = io::split(stream);

    let transfer_future = async {
        let client_to_target = io::copy(&mut local_reader, &mut upstream_writer);
        let target_to_client = io::copy(&mut upstream_reader, &mut local_writer);
        let _ = tokio::try_join!(client_to_target, target_to_client)?;
        Ok::<(), std::io::Error>(())
    };

    time::timeout(idle_timeout, transfer_future)
        .await
        .map_err(|_| CentralSshError::InputTimeout)??;

    drop(upstream_reader);
    drop(upstream_writer);
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "session complete", "en")
        .await;
    Ok(())
}

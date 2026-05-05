mod abuse;
mod app;
mod audit;
mod auth;
mod config;
mod crypto_policy;
mod error;
mod keys;
mod reload;
mod secrets;
mod ssh;

use std::path::PathBuf;
use std::sync::Arc;

use abuse::AbuseTracker;
use app::{AppState, host_key_path_from_config_dir};
use audit::AuditLogger;
use auth::AuthEngine;
use clap::Parser;
use config::{ConfigStore, DEFAULT_LISTEN, load_config_file, resolve_paths};
use error::Result;
use keys::ensure_user_key_root_directory;
use reload::install_sighup_reload_notifier;
use secrets::SecretManager;
use tracing::{info, warn};

#[derive(Debug, Parser, Clone)]
#[command(
    author,
    version,
    about = "CentralSSH hardened SSH gateway",
    long_about = "CentralSSH is an OpenSSH-compatible hardened SSH gateway. It authenticates users locally, requires target selection, and then transparently proxies SSH protocol traffic to the selected target.",
    after_help = "Troubleshooting:
  Startup error: \"I/O error: No such file or directory (os error 2)\"
    Cause: default config paths do not exist.
    Defaults:
      --config      /etc/centralssh/config.toml
      --servers     /etc/centralssh/servers.toml
      --known-hosts /etc/centralssh/known_hosts
      --user-key-root /var/lib/centralssh/keys
      --master-key /etc/centralssh/master.key
      --per-user-per-server true
      --audit-log   /var/log/centralssh/audit.jsonl
      --whitelist   disabled unless configured

  Dev quick-start (non-strict mode):
    mkdir -p ./tmp/keys ./examples
    touch ./examples/known_hosts
    CENTRALSSH_ENFORCE_STRICT_SECURITY=false centralssh --config ./examples/config.toml --servers ./examples/servers.toml --known-hosts ./examples/known_hosts --user-key-root ./tmp/keys --audit-log ./tmp/audit.jsonl

  Production mode requirements:
    - root-owned config, known_hosts, host key, and audit files
    - configured security.kek_provider and master.key
    - encrypted config secrets and encrypted outbound private keys
    - mode 600 for files
    - mode 700 for key directories

  Password policy:
    - settings.enforce_password_policy defaults to true
    - settings.min_password_policy defaults to 12
    - set false only for controlled/testing environments"
)]
struct Cli {
    #[arg(long, env = "CENTRALSSH_LISTEN")]
    listen: Option<String>,

    #[arg(long, env = "CENTRALSSH_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_SERVERS")]
    servers: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_KNOWN_HOSTS")]
    known_hosts: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_USER_KEY_ROOT")]
    user_key_root: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_AUDIT_LOG")]
    audit_log: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_MASTER_KEY")]
    master_key: Option<PathBuf>,

    #[arg(long, env = "CENTRALSSH_WHITELIST")]
    whitelist: Option<PathBuf>,

    #[arg(long, env = "PER_USER_PER_SERVER")]
    per_user_per_server: Option<bool>,

    #[arg(
        long,
        env = "CENTRALSSH_ENFORCE_STRICT_SECURITY",
        default_value_t = true
    )]
    enforce_strict_security: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("centralssh error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_names(true)
        .with_thread_ids(true)
        .compact()
        .init();

    let cli = Cli::parse();

    let seed_config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG_PATH));
    let seed_config = load_config_file(&seed_config_path)?;

    let paths = resolve_paths(
        Some(seed_config_path),
        cli.servers.clone(),
        cli.known_hosts.clone(),
        cli.user_key_root.clone(),
        cli.audit_log.clone(),
        cli.master_key.clone(),
        cli.whitelist.clone(),
        cli.per_user_per_server,
        Some(&seed_config.settings),
        Some(&seed_config.security),
    );

    let secrets = SecretManager::new(
        &seed_config.security,
        paths.master_key_path.clone(),
        cli.enforce_strict_security,
    )?;
    if seed_config.security.allow_insecure_boot.unwrap_or(false) {
        warn!(
            "CRITICAL SECURITY WARNING: allow_insecure_boot=true; startup may permit plaintext bootstrap state"
        );
    }
    if let Some(secrets) = &secrets {
        secrets.readiness_check()?;
    } else if !cli.enforce_strict_security {
        warn!(
            "non-strict security mode without KEK provider; bootstrap may create plaintext local development state"
        );
    }

    let listen = resolve_listen(cli.listen.clone(), cli.enforce_strict_security);
    if !cli.enforce_strict_security && cli.listen.is_none() {
        warn!(
            listen = %listen,
            "non-strict security mode defaulted listen address to localhost"
        );
    }

    ensure_user_key_root_directory(&paths.user_key_root)?;

    let config_store =
        ConfigStore::load(paths.clone(), cli.enforce_strict_security, secrets.clone()).await?;
    let auth = AuthEngine::new()?;
    let audit = AuditLogger::new(paths.audit_log_path.clone(), cli.enforce_strict_security)?;
    let abuse =
        AbuseTracker::from_config(&config_store.snapshot().await?.config, audit.clone()).await?;
    info!(audit_log = %audit.path().display(), "audit logger initialized");
    let reload_notify = Arc::new(tokio::sync::Notify::new());

    let app = Arc::new(AppState {
        config_store,
        auth,
        audit,
        abuse,
        secrets,
        strict_security: cli.enforce_strict_security,
        reload_notify: reload_notify.clone(),
    });

    install_sighup_reload_notifier(reload_notify)?;

    let reload_state = app.clone();
    tokio::spawn(async move {
        reload_state.reload_on_signal_loop().await;
    });

    let report = app.bootstrap().await?;
    info!(
        migrated_passwords = report.migrated_passwords,
        created_user_dirs = report.created_user_dirs,
        created_server_dirs = report.created_server_dirs,
        created_private_keys = report.created_private_keys,
        created_public_keys = report.created_public_keys,
        per_user_per_server = paths.per_user_per_server,
        "startup bootstrap completed"
    );

    let host_key_path = host_key_path_from_config_dir(&paths.config_path);
    info!(
        listen = %listen,
        host_key = %host_key_path.display(),
        "starting gateway server"
    );

    let probe_listener = std::net::TcpListener::bind(&listen)?;
    drop(probe_listener);

    ssh::run_gateway_server(&listen, &host_key_path, app, cli.enforce_strict_security).await
}

fn resolve_listen(explicit_listen: Option<String>, strict_security: bool) -> String {
    explicit_listen.unwrap_or_else(|| {
        if strict_security {
            DEFAULT_LISTEN.to_string()
        } else {
            "127.0.0.1:7788".to_string()
        }
    })
}

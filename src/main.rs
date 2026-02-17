mod app;
mod audit;
mod auth;
mod config;
mod error;
mod keys;
mod reload;
mod ssh;
mod ui;

use std::path::PathBuf;
use std::sync::Arc;

use app::{AppState, host_key_path_from_config_dir};
use audit::AuditLogger;
use auth::AuthEngine;
use clap::Parser;
use config::{ConfigStore, DEFAULT_LISTEN, load_config_file, resolve_paths};
use error::Result;
use reload::install_sighup_reload_notifier;
use tracing::{info, warn};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about = "CentralSSH hardened SSH gateway")]
struct Cli {
    #[arg(long, env = "CENTRALSSH_LISTEN", default_value = DEFAULT_LISTEN)]
    listen: String,

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

    #[arg(
        long,
        env = "CENTRALSSH_ENFORCE_STRICT_SECURITY",
        default_value_t = true
    )]
    enforce_strict_security: bool,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("centralssh error: {err}");
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
        Some(&seed_config.settings),
    );

    let config_store = ConfigStore::load(paths.clone(), cli.enforce_strict_security).await?;
    let auth = AuthEngine::new()?;
    let audit = AuditLogger::new(paths.audit_log_path.clone(), cli.enforce_strict_security)?;
    let reload_notify = Arc::new(tokio::sync::Notify::new());

    let app = Arc::new(AppState {
        config_store,
        auth,
        audit,
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
        total_users = report.key_reconciliation.len(),
        "startup bootstrap completed"
    );

    let generated_keys = report
        .key_reconciliation
        .iter()
        .filter(|entry| entry.created_keypair)
        .count();
    if generated_keys > 0 {
        warn!(
            generated_keys,
            "generated missing per-user outbound SSH keys"
        );
    }

    let host_key_path = host_key_path_from_config_dir(&paths.config_path);
    info!(listen = %cli.listen, host_key = %host_key_path.display(), "starting gateway server");

    // Fail fast if the configured listen address cannot be bound.
    let probe_listener = std::net::TcpListener::bind(&cli.listen)?;
    drop(probe_listener);

    ssh::run_gateway_server(&cli.listen, &host_key_path, app).await
}

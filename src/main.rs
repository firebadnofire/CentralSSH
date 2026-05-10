mod abuse;
mod app;
mod audit;
mod auth;
mod config;
mod crypto_policy;
mod error;
mod keys;
mod reload;
mod ssh;
mod ui;

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
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Compact,
    Json,
    Systemd,
}

impl LogFormat {
    fn from_env() -> Self {
        if let Ok(value) = std::env::var("CENTRALSSH_LOG_FORMAT") {
            match value.trim().to_ascii_lowercase().as_str() {
                "compact" => return Self::Compact,
                "json" => return Self::Json,
                "systemd" | "journal" => return Self::Systemd,
                _ => {}
            }
        }

        if std::env::var_os("JOURNAL_STREAM").is_some() {
            Self::Systemd
        } else {
            Self::Compact
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Json => "json",
            Self::Systemd => "systemd",
        }
    }
}

fn build_env_filter() -> EnvFilter {
    EnvFilter::try_from_env("CENTRALSSH_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

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
      --per-user-per-server true
      --audit-log   /var/log/centralssh/audit.jsonl
      --whitelist   disabled unless configured

  Dev quick-start (non-strict mode):
    mkdir -p ./tmp/keys ./examples
    touch ./examples/known_hosts
    CENTRALSSH_ENFORCE_STRICT_SECURITY=false centralssh --config ./examples/config.toml --servers ./examples/servers.toml --known-hosts ./examples/known_hosts --user-key-root ./tmp/keys --audit-log ./tmp/audit.jsonl

  Production mode requirements:
    - root-owned config, known_hosts, host key, and audit files
    - mode 600 for files
    - mode 700 for key directories

  Password policy:
    - settings.enforce_password_policy defaults to true
    - settings.min_password_policy defaults to 12
    - set false only for controlled/testing environments"
)]
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

    #[arg(long, env = "CENTRALSSH_WHITELIST")]
    whitelist: Option<PathBuf>,

    #[arg(long, env = "PER_USER_PER_SERVER")]
    per_user_per_server: Option<bool>,

    #[arg(long, env = "CENTRALSSH_DROP_TO_MENU")]
    drop_to_menu: Option<bool>,

    #[arg(long, env = "CENTRALSSH_HIDE_PROXY_IP")]
    hide_proxy_ip: Option<bool>,

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
    let log_format = LogFormat::from_env();
    match log_format {
        LogFormat::Compact => {
            tracing_subscriber::fmt()
                .with_env_filter(build_env_filter())
                .with_target(false)
                .with_thread_names(true)
                .with_thread_ids(true)
                .with_writer(std::io::stderr)
                .compact()
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(build_env_filter())
                .with_target(false)
                .with_writer(std::io::stderr)
                .json()
                .init();
        }
        LogFormat::Systemd => {
            tracing_subscriber::fmt()
                .with_env_filter(build_env_filter())
                .with_target(false)
                .with_thread_names(false)
                .with_thread_ids(false)
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .compact()
                .init();
        }
    }

    let cli = Cli::parse();
    info!(
        log_format = log_format.as_str(),
        journal_stream = std::env::var_os("JOURNAL_STREAM").is_some(),
        "logging configured"
    );

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
        cli.whitelist.clone(),
        cli.per_user_per_server,
        cli.drop_to_menu,
        cli.hide_proxy_ip,
        Some(&seed_config.settings),
    );
    ensure_user_key_root_directory(&paths.user_key_root)?;

    let config_store = ConfigStore::load(paths.clone(), cli.enforce_strict_security).await?;
    let auth = AuthEngine::new()?;
    let audit = AuditLogger::new(paths.audit_log_path.clone(), cli.enforce_strict_security)?;
    let abuse =
        AbuseTracker::from_config(&config_store.snapshot().await.config, audit.clone()).await?;
    info!(audit_log = %audit.path().display(), "audit logger initialized");
    let reload_notify = Arc::new(tokio::sync::Notify::new());

    let app = Arc::new(AppState {
        config_store,
        auth,
        audit,
        abuse,
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
        hide_proxy_ip = paths.hide_proxy_ip,
        "startup bootstrap completed"
    );

    let host_key_path = host_key_path_from_config_dir(&paths.config_path);
    info!(
        listen = %cli.listen,
        host_key = %host_key_path.display(),
        config = %paths.config_path.display(),
        servers = %paths.servers_path.display(),
        known_hosts = %paths.known_hosts_path.display(),
        hide_proxy_ip = paths.hide_proxy_ip,
        strict_security = cli.enforce_strict_security,
        "starting gateway server"
    );

    let probe_listener = std::net::TcpListener::bind(&cli.listen)?;
    drop(probe_listener);

    ssh::run_gateway_server(
        &cli.listen,
        &host_key_path,
        app,
        cli.enforce_strict_security,
    )
    .await
}

use std::sync::Arc;

use tokio::sync::Notify;

use crate::error::Result;

pub fn install_sighup_reload_notifier(notify: Arc<Notify>) -> Result<()> {
    #[cfg(unix)]
    {
        let mut stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                notify.notify_waiters();
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = notify;
    }

    Ok(())
}

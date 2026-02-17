use std::fmt::Write as _;
use std::time::Duration;

use qrcode::QrCode;
use qrcode::render::unicode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use crate::error::{CentralSshError, Result};

pub async fn write_text<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
    max_len: usize,
) -> Result<String> {
    let mut output = String::new();

    let read_future = async {
        let mut buf = [0u8; 1];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(CentralSshError::ChannelClosed);
            }

            let byte = buf[0];
            match byte {
                b'\n' => break,
                b'\r' => continue,
                _ => {
                    if output.len() >= max_len {
                        return Err(CentralSshError::InvalidConfig(
                            "input length exceeds limit".to_string(),
                        ));
                    }
                    output.push(byte as char);
                }
            }
        }

        Ok::<String, CentralSshError>(output)
    };

    time::timeout(timeout, read_future)
        .await
        .map_err(|_| CentralSshError::InputTimeout)?
}

pub async fn prompt_line<S>(
    stream: &mut S,
    prompt: &str,
    timeout: Duration,
    max_len: usize,
) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_text(stream, prompt).await?;
    read_line(stream, timeout, max_len).await
}

pub fn render_enrollment_qr(url: &str) -> Result<String> {
    let qr = QrCode::new(url.as_bytes())
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to generate QR: {e}")))?;

    Ok(qr
        .render::<unicode::Dense1x2>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build())
}

pub fn render_gateway_banner() -> String {
    "\r\nCentralSSH Gateway\r\n==================\r\n\r\n".to_string()
}

pub fn render_server_menu(username: &str, entries: &[(String, String)]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\r\nCentralSSH Gateway");
    let _ = writeln!(out, "User: {username}");
    let _ = writeln!(out);
    let _ = writeln!(out, "Select a server:\r");

    for (idx, (name, ip)) in entries.iter().enumerate() {
        let _ = writeln!(out, "{} ) {} ({})", idx + 1, name, ip);
    }

    let _ = writeln!(out);
    let _ = write!(out, "Enter selection (or 'q' to quit): ");
    out.replace('\n', "\r\n")
}

pub fn safe_error_message(error: &CentralSshError) -> &'static str {
    match error {
        CentralSshError::RateLimitExceeded => "Rate limit exceeded. Try again later.",
        CentralSshError::AuthenticationFailed => "Authentication failed.",
        CentralSshError::TotpInvalid => "Invalid TOTP code.",
        CentralSshError::AuthorizationDenied => "Authorization denied.",
        CentralSshError::InputTimeout => "Session timed out waiting for input.",
        _ => "Operation failed.",
    }
}

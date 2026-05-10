use std::fmt::Write as _;
use std::time::Duration;

use qrcode::QrCode;
use qrcode::types::Color;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use crate::error::{CentralSshError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMode {
    Visible,
    Hidden,
}

pub async fn write_text<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_line<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    timeout: Duration,
    max_len: usize,
    echo_mode: EchoMode,
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
                b'\n' => {
                    // If the previous prompt consumed CR from a CRLF pair, ignore the
                    // leftover LF so the next prompt does not auto-submit an empty line.
                    if output.is_empty() {
                        continue;
                    }
                    break;
                }
                b'\r' => break,
                0x03 => return Err(CentralSshError::InputCanceled),
                0x08 | 0x7f => {
                    if output.pop().is_some() && matches!(echo_mode, EchoMode::Visible) {
                        stream.write_all(b"\x08 \x08").await?;
                        stream.flush().await?;
                    }
                }
                _ => {
                    if output.len() >= max_len {
                        return Err(CentralSshError::InvalidConfig(
                            "input length exceeds limit".to_string(),
                        ));
                    }
                    output.push(byte as char);

                    if matches!(echo_mode, EchoMode::Visible) {
                        stream.write_all(&[byte]).await?;
                        stream.flush().await?;
                    }
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
    echo_mode: EchoMode,
) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_text(stream, prompt).await?;
    let line = read_line(stream, timeout, max_len, echo_mode).await;
    let _ = write_text(stream, "\r\n").await;
    line
}

pub fn render_enrollment_qr(url: &str) -> Result<String> {
    let qr = QrCode::new(url.as_bytes())
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to generate QR: {e}")))?;
    let colors = qr.to_colors();
    let width = qr.width();
    let quiet_zone = 4usize;

    // Use ANSI background colors with two-space modules for a scanner-friendly
    // QR image regardless of terminal font glyph support.
    let mut out = String::new();
    for y in 0..(width + (quiet_zone * 2)) {
        for x in 0..(width + (quiet_zone * 2)) {
            let src_x = x as isize - quiet_zone as isize;
            let src_y = y as isize - quiet_zone as isize;

            let is_dark =
                if src_x >= 0 && src_y >= 0 && (src_x as usize) < width && (src_y as usize) < width
                {
                    let idx = (src_y as usize) * width + (src_x as usize);
                    colors[idx] == Color::Dark
                } else {
                    false
                };

            if is_dark {
                out.push_str("\x1b[40m  \x1b[0m");
            } else {
                out.push_str("\x1b[47m  \x1b[0m");
            }
        }
        out.push_str("\r\n");
    }

    Ok(out)
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
    let _ = write!(out, "Enter selection (or 'Q' to quit): ");
    out.replace('\n', "\r\n")
}

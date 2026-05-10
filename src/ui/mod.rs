use std::fmt::Write as _;

fn render_server_entry(idx: usize, name: &str, ip: &str, hide_proxy_ip: bool) -> String {
    if hide_proxy_ip {
        format!("{} ) {}", idx + 1, name)
    } else {
        format!("{} ) {} ({})", idx + 1, name, ip)
    }
}

pub fn render_server_menu(
    username: &str,
    entries: &[(String, String)],
    hide_proxy_ip: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\r\nCentralSSH Gateway");
    let _ = writeln!(out, "User: {username}");
    let _ = writeln!(out);
    let _ = writeln!(out, "Select a server:\r");

    for (idx, (name, ip)) in entries.iter().enumerate() {
        let _ = writeln!(out, "{}", render_server_entry(idx, name, ip, hide_proxy_ip));
    }

    let _ = writeln!(out);
    let _ = write!(out, "Enter selection (or 'Q' to quit): ");
    out.replace('\n', "\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_server_menu_shows_ips_by_default() {
        let rendered = render_server_menu(
            "alice",
            &[("server".to_string(), "192.168.86.54".to_string())],
            false,
        );

        assert!(rendered.contains("1 ) server (192.168.86.54)"));
    }

    #[test]
    fn render_server_menu_hides_ips_when_enabled() {
        let rendered = render_server_menu(
            "alice",
            &[("server".to_string(), "192.168.86.54".to_string())],
            true,
        );

        assert!(rendered.contains("1 ) server"));
        assert!(!rendered.contains("192.168.86.54"));
    }
}

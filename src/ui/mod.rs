use std::fmt::Write as _;

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

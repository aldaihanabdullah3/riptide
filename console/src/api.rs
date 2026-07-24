/// REST API client for the C2 server.
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CommandRecord {
    pub id: String,
    pub module: String,
    pub action: String,
    pub args: serde_json::Value,
    pub created_at: String,
    pub delivered_at: Option<String>,
    pub completed_at: Option<String>,
    pub status: String,
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub port: u16,
    pub protocol: String,
    pub active: bool,
}

pub struct C2Client {
    base_url: String,
    client: reqwest::Client,
}

impl C2Client {
    pub fn new(base_url: &str, no_tls_verify: bool) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(no_tls_verify)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("create http client");
        C2Client { base_url: base_url.trim_end_matches('/').to_string(), client }
    }

    pub async fn list_sessions(&self) -> Result<SessionListResponse, String> {
        let url = format!("{}/api/v1/sessions", self.base_url);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(format!("HTTP {}", resp.status())); }
        resp.json().await.map_err(|e| e.to_string())
    }

    /// Find a session by hostname or implant_id substring.
    pub async fn find_session(&self, query: &str) -> Option<SessionInfo> {
        if let Ok(resp) = self.list_sessions().await {
            resp.sessions.into_iter().find(|s| {
                s.hostname.contains(query) || s.implant_id.contains(query)
            })
        } else { None }
    }

    /// Shortcut: queue a command. Returns command_id or error string.
    pub async fn queue(&self, session_id: &str, module: &str, action: &str,
                       args: &serde_json::Value) -> Result<String, String> {
        let url = format!("{}/api/v1/sessions/{}/commands", self.base_url, session_id);
        let body = serde_json::json!({"module": module, "action": action, "args": args});
        let resp = self.client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("HTTP error: {}", err_body));
        }
        let r: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(r["command_id"].as_str().unwrap_or("?").to_string())
    }

    /// Get the result data for a command, or None if still pending.
    pub async fn command_result(&self, session_id: &str, command_id: &str) -> Option<serde_json::Value> {
        let url = format!("{}/api/v1/sessions/{}/commands/{}", self.base_url, session_id, command_id);
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let cmd: serde_json::Value = resp.json().await.ok()?;
        let status = cmd.get("status")?.as_str()?;
        if status == "completed" || status == "failed" {
            cmd.get("result").cloned()
        } else { None }
    }

    // ── Listener management ──────────────────────────────────────

    pub async fn get_listeners(&self) -> Result<Vec<ListenerInfo>, String> {
        let url = format!("{}/api/v1/listeners", self.base_url);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(format!("HTTP {}", resp.status())); }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn start_listener(&self, port: u16, protocol: &str) -> Result<ListenerInfo, String> {
        let url = format!("{}/api/v1/listeners", self.base_url);
        let body = serde_json::json!({"port": port, "protocol": protocol});
        let resp = self.client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP error: {}", resp.text().await.unwrap_or_default()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn stop_listener(&self, port: u16) -> Result<(), String> {
        let url = format!("{}/api/v1/listeners/{}", self.base_url, port);
        let resp = self.client.delete(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP error: {}", resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }
}

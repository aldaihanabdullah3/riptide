/// REST API client for the C2 server.
use crate::app::{SessionInfo, SessionListResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDetailResponse {
    pub session: SessionInfo,
    pub command_history: Vec<CommandRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct QueueCommandResponse {
    pub command_id: String,
    pub module: String,
    pub action: String,
    pub status: String,
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

        C2Client {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    pub async fn list_sessions(&self) -> Result<SessionListResponse, String> {
        let url = format!("{}/api/v1/sessions", self.base_url);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn get_session(&self, id: &str) -> Result<SessionDetailResponse, String> {
        let url = format!("{}/api/v1/sessions/{}", self.base_url, id);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn get_commands(&self, session_id: &str) -> Result<Vec<CommandRecord>, String> {
        let url = format!("{}/api/v1/sessions/{}/commands", self.base_url, session_id);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn queue_command(
        &self,
        session_id: &str,
        module: &str,
        action: &str,
        args: &serde_json::Value,
    ) -> Result<QueueCommandResponse, String> {
        let url = format!("{}/api/v1/sessions/{}/commands", self.base_url, session_id);
        let body = serde_json::json!({
            "module": module,
            "action": action,
            "args": args,
        });
        let resp = self.client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("HTTP error: {}", err_body));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    // ── Listener management ──────────────────────────────────────

    pub async fn get_listeners(&self) -> Result<Vec<ListenerInfo>, String> {
        let url = format!("{}/api/v1/listeners", self.base_url);
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn start_listener(&self, port: u16, protocol: &str) -> Result<ListenerInfo, String> {
        let url = format!("{}/api/v1/listeners", self.base_url);
        let body = serde_json::json!({"port": port, "protocol": protocol});
        let resp = self.client.post(&url).json(&body).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("HTTP error: {}", err_body));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn stop_listener(&self, port: u16) -> Result<(), String> {
        let url = format!("{}/api/v1/listeners/{}", self.base_url, port);
        let resp = self.client.delete(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("HTTP error: {}", err_body));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub port: u16,
    pub protocol: String,
    pub active: bool,
}

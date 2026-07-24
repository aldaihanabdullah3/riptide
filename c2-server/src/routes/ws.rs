/// WebSocket event stream for real-time operator console updates.
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::state::AppState;

/// GET /ws/events — WebSocket upgrade for real-time C2 event stream.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to broadcast events
    let mut event_rx = state.event_tx.subscribe();

    // Send initial state: current session list
    let sessions = state.list_sessions().await;
    let init_event = serde_json::json!({
        "type": "init",
        "data": {
            "sessions": sessions,
        }
    });
    let init_msg = serde_json::to_string(&init_event).unwrap_or_default();
    if sender.send(Message::Text(init_msg.into())).await.is_err() {
        return;
    }

    // Main event loop
    loop {
        tokio::select! {
            // Incoming WebSocket messages (pings, close)
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = sender.send(Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }

            // Broadcast events from C2 server
            event = event_rx.recv() => {
                match event {
                    Ok(event) => {
                        let line = event.to_line();
                        if sender.send(Message::Text(line.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let warn = serde_json::json!({
                            "type": "warning",
                            "data": {"message": format!("lagged: {} events dropped", n)}
                        });
                        let _ = sender.send(Message::Text(
                            serde_json::to_string(&warn).unwrap_or_default().into()
                        )).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

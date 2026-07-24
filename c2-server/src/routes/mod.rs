pub mod api;
pub mod beacon;
pub mod upload;
pub mod ws;

use crate::state::AppState;
use std::sync::Arc;

/// Build the implant-facing router (beacon, upload, result routes).
/// Used by both main.rs (if ever needed at startup) and the listener API.
pub fn build_implant_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/beacon", axum::routing::get(beacon::beacon_get).post(beacon::beacon_post))
        .route("/upload", axum::routing::post(upload::upload))
        .route("/result", axum::routing::post(upload::submit_result))
        .with_state(state)
}

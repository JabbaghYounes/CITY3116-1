mod routes;
mod ws;

use ids_common::config::AppConfig;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;

use ids_common::types::Alert;

/// Shared application state accessible from all handlers.
pub struct AppState {
    pub alerts: Arc<RwLock<Vec<Alert>>>,
    pub alert_tx: broadcast::Sender<Alert>,
    pub config: Arc<RwLock<AppConfig>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Initialise tracing ──────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ids_dashboard=info,tower_http=info".into()),
        )
        .init();

    // ── Load configuration ──────────────────────────────────────────────
    let config = match AppConfig::load(Path::new("config.toml")) {
        Ok(cfg) => {
            info!("Loaded configuration from config.toml");
            cfg
        }
        Err(e) => {
            info!("Could not load config.toml ({e}), using defaults");
            AppConfig::default()
        }
    };

    let host = config.dashboard.host.clone();
    let port = config.dashboard.port;

    // ── Build shared state ──────────────────────────────────────────────
    let (alert_tx, _) = broadcast::channel::<Alert>(1024);

    let state = Arc::new(AppState {
        alerts: Arc::new(RwLock::new(Vec::new())),
        alert_tx,
        config: Arc::new(RwLock::new(config)),
    });

    // ── Build the Axum router ───────────────────────────────────────────
    let app = routes::build_router(state);

    // ── Start the server ────────────────────────────────────────────────
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("CPS IDS/IPS Dashboard listening on http://{addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

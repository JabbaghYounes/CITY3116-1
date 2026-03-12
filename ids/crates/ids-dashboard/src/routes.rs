use crate::ws::ws_handler;
use crate::AppState;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ids_common::types::AlertSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use uuid::Uuid;

// ─── Query parameters for alert listing ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub severity: Option<String>,
    pub source: Option<String>,
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PaginatedAlerts {
    page: usize,
    per_page: usize,
    total: usize,
    total_pages: usize,
    alerts: Vec<ids_common::types::Alert>,
}

#[derive(Serialize)]
struct StatsResponse {
    total_alerts: usize,
    alerts_by_severity: HashMap<String, usize>,
    alerts_by_source: AlertsBySource,
    alerts_by_category: HashMap<String, usize>,
    recent_alerts_per_minute: f64,
}

#[derive(Serialize)]
struct AlertsBySource {
    network: usize,
    host: usize,
}

#[derive(Serialize)]
struct ModelInfo {
    name: String,
    model_type: String,
    accuracy: f64,
    precision: f64,
    recall: f64,
    f1_score: f64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

// ─── Router builder ─────────────────────────────────────────────────────────

pub fn build_router(state: Arc<AppState>) -> Router {
    // Resolve the static directory relative to the executable or workspace
    let static_dir = std::env::current_dir()
        .unwrap_or_default()
        .join("crates/ids-dashboard/src/static");

    let serve_dir = ServeDir::new(&static_dir);

    Router::new()
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/stats", get(get_stats))
        .route("/api/models", get(get_models))
        .route("/api/config", get(get_config))
        .route("/api/health", get(health))
        .route("/ws/alerts", get(ws_handler))
        .fallback_service(serve_dir)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertQuery>,
) -> impl IntoResponse {
    let alerts = state.alerts.read().await;

    // Apply filters
    let filtered: Vec<_> = alerts
        .iter()
        .filter(|a| {
            if let Some(ref sev) = params.severity {
                let severity_str = format!("{:?}", a.severity);
                if severity_str.to_lowercase() != sev.to_lowercase() {
                    return false;
                }
            }
            if let Some(ref src) = params.source {
                match src.to_lowercase().as_str() {
                    "network" => {
                        if a.source != AlertSource::Network {
                            return false;
                        }
                    }
                    "host" => {
                        if a.source != AlertSource::Host {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
            true
        })
        .cloned()
        .collect();

    let total = filtered.len();
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(50).clamp(1, 200);
    let total_pages = if total == 0 {
        1
    } else {
        (total + per_page - 1) / per_page
    };

    let start = (page - 1) * per_page;
    let page_alerts: Vec<_> = filtered.into_iter().skip(start).take(per_page).collect();

    Json(PaginatedAlerts {
        page,
        per_page,
        total,
        total_pages,
        alerts: page_alerts,
    })
}

async fn get_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let alerts = state.alerts.read().await;
    match alerts.iter().find(|a| a.id == id) {
        Some(alert) => Ok(Json(alert.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let alerts = state.alerts.read().await;

    let total_alerts = alerts.len();

    // Alerts by severity
    let mut by_severity: HashMap<String, usize> = HashMap::new();
    for sev in &["Low", "Medium", "High", "Critical"] {
        by_severity.insert(sev.to_string(), 0);
    }
    for alert in alerts.iter() {
        let key = format!("{:?}", alert.severity);
        *by_severity.entry(key).or_insert(0) += 1;
    }

    // Alerts by source
    let network = alerts
        .iter()
        .filter(|a| a.source == AlertSource::Network)
        .count();
    let host = alerts
        .iter()
        .filter(|a| a.source == AlertSource::Host)
        .count();

    // Alerts by category
    let mut by_category: HashMap<String, usize> = HashMap::new();
    for cat in &["Normal", "DoS", "Probe", "R2L", "U2R", "Unknown"] {
        by_category.insert(cat.to_string(), 0);
    }
    for alert in alerts.iter() {
        let key = format!("{:?}", alert.category);
        *by_category.entry(key).or_insert(0) += 1;
    }

    // Recent alerts per minute (last 5 minutes)
    let now = chrono::Utc::now();
    let five_min_ago = now - chrono::TimeDelta::minutes(5);
    let recent = alerts
        .iter()
        .filter(|a| a.timestamp > five_min_ago)
        .count();
    let recent_alerts_per_minute = recent as f64 / 5.0;

    Json(StatsResponse {
        total_alerts,
        alerts_by_severity: by_severity,
        alerts_by_source: AlertsBySource { network, host },
        alerts_by_category: by_category,
        recent_alerts_per_minute,
    })
}

async fn get_models() -> impl IntoResponse {
    let models = vec![
        ModelInfo {
            name: "Random Forest".into(),
            model_type: "Ensemble (Bagging)".into(),
            accuracy: 0.9542,
            precision: 0.9481,
            recall: 0.9523,
            f1_score: 0.9502,
        },
        ModelInfo {
            name: "LSTM".into(),
            model_type: "Deep Learning (RNN)".into(),
            accuracy: 0.9387,
            precision: 0.9312,
            recall: 0.9401,
            f1_score: 0.9356,
        },
        ModelInfo {
            name: "Isolation Forest".into(),
            model_type: "Anomaly Detection".into(),
            accuracy: 0.9105,
            precision: 0.8973,
            recall: 0.9198,
            f1_score: 0.9084,
        },
        ModelInfo {
            name: "Ensemble".into(),
            model_type: "Weighted Voting".into(),
            accuracy: 0.9621,
            precision: 0.9574,
            recall: 0.9608,
            f1_score: 0.9591,
        },
        ModelInfo {
            name: "Rule-based".into(),
            model_type: "Signature Matching".into(),
            accuracy: 0.8750,
            precision: 0.9100,
            recall: 0.8400,
            f1_score: 0.8736,
        },
    ];

    Json(models)
}

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    Json(config.clone())
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

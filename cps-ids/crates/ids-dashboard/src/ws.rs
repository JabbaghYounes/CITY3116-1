use crate::AppState;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{info, warn};

/// Axum handler that upgrades an HTTP connection to a WebSocket.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

/// Long-lived task for a single WebSocket client.
///
/// Subscribes to the alert broadcast channel and forwards every new
/// [`Alert`] as a JSON text frame. The loop terminates when the client
/// disconnects or the channel is lagging/closed.
async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    info!("WebSocket client connected");

    let mut rx = state.alert_tx.subscribe();

    loop {
        tokio::select! {
            // New alert from the broadcast channel
            result = rx.recv() => {
                match result {
                    Ok(alert) => {
                        match serde_json::to_string(&alert) {
                            Ok(json) => {
                                if socket.send(Message::Text(json.into())).await.is_err() {
                                    // Client disconnected
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to serialise alert: {e}");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged, skipped {n} alerts");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Broadcast channel closed, terminating WebSocket");
                        break;
                    }
                }
            }
            // Incoming message from the client (we only care about Close)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error: {e}");
                        break;
                    }
                    _ => {
                        // Ignore pings/pongs/text from client
                    }
                }
            }
        }
    }

    info!("WebSocket client disconnected");
}

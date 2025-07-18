//! # WebSocket Admin Management Module
//!
//! This module provides administrative endpoints for WebSocket connection monitoring and management.
//! It includes functionality for:
//! - Viewing active WebSocket connections
//! - Managing connection subscriptions
//! - Broadcasting messages to channels
//! - Connection statistics and monitoring
//! - Connection lifecycle management
//!
//! ## Security Considerations
//! WebSocket admin endpoints should be protected with appropriate authentication and authorization.
//! These endpoints can view and modify WebSocket connections and should only be accessible
//! to authorized administrators.

use crate::protocols::websocket::{WebSocketConnectionManager, WebSocketMessage, WebSocketStatistics};
use crate::core::error::GatewayError;

use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument};

/// WebSocket admin state
#[derive(Clone)]
pub struct WebSocketAdminState {
    /// WebSocket connection manager
    pub connection_manager: Arc<WebSocketConnectionManager>,
}

impl WebSocketAdminState {
    /// Create new WebSocket admin state
    pub fn new(connection_manager: Arc<WebSocketConnectionManager>) -> Self {
        Self {
            connection_manager,
        }
    }
}

/// WebSocket admin router
pub struct WebSocketAdminRouter;

impl WebSocketAdminRouter {
    /// Create WebSocket admin router with all endpoints
    pub fn create_router(state: WebSocketAdminState) -> Router {
        Router::new()
            .route("/websocket/connections", get(list_connections))
            .route("/websocket/connections/:connection_id", get(get_connection))
            .route("/websocket/connections/:connection_id", delete(disconnect_connection))
            .route("/websocket/connections/:connection_id/subscriptions", get(get_connection_subscriptions))
            .route("/websocket/connections/:connection_id/subscriptions", post(subscribe_connection))
            .route("/websocket/connections/:connection_id/subscriptions/:channel", delete(unsubscribe_connection))
            .route("/websocket/channels", get(list_channels))
            .route("/websocket/channels/:channel/subscribers", get(get_channel_subscribers))
            .route("/websocket/channels/:channel/broadcast", post(broadcast_to_channel))
            .route("/websocket/connections/:connection_id/send", post(send_to_connection))
            .route("/websocket/statistics", get(get_statistics))
            .route("/websocket/health", get(health_check))
            .with_state(state)
    }
}

/// Connection list response
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct ConnectionListResponse {
    pub connections: Vec<ConnectionInfo>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
}

/// Connection information for admin API
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionInfo {
    pub id: String,
    pub remote_addr: String,
    pub connected_at: String,
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub subscriptions: Vec<String>,
    pub state: String,
    pub age_seconds: u64,
    pub idle_seconds: u64,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Connection list query parameters
#[derive(Debug, Deserialize)]
pub struct ConnectionListQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub authenticated: Option<bool>,
    pub channel: Option<String>,
}

/// Channel list response
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct ChannelListResponse {
    pub channels: Vec<ChannelInfo>,
    pub total: usize,
}

/// Channel information
#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub subscriber_count: usize,
    pub subscribers: Vec<String>,
}

/// Subscription request
#[derive(Debug, Deserialize)]
pub struct SubscriptionRequest {
    pub channel: String,
}

/// Message send request
#[derive(Debug, Deserialize)]
pub struct MessageSendRequest {
    pub message: serde_json::Value,
    pub message_type: Option<String>,
}

/// Broadcast request
#[derive(Debug, Deserialize)]
pub struct BroadcastRequest {
    pub message: serde_json::Value,
    pub message_type: Option<String>,
}

/// List all WebSocket connections
#[instrument(skip(state))]
pub async fn list_connections(
    State(state): State<WebSocketAdminState>,
    Query(query): Query<ConnectionListQuery>,
) -> Result<Json<ConnectionListResponse>, GatewayError> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50).min(1000); // Cap at 1000 per page
    
    let mut connections = Vec::new();
    
    // Collect all connections
    for entry in state.connection_manager.connections.iter() {
        let connection = entry.value().read().await;
        
        // Apply filters
        if let Some(authenticated_filter) = query.authenticated {
            if connection.is_authenticated() != authenticated_filter {
                continue;
            }
        }
        
        if let Some(ref channel_filter) = query.channel {
            if !connection.subscriptions.contains(channel_filter) {
                continue;
            }
        }
        
        let connection_info = ConnectionInfo {
            id: connection.id.clone(),
            remote_addr: connection.remote_addr.to_string(),
            connected_at: format!("{:?}", connection.connected_at),
            authenticated: connection.is_authenticated(),
            user_id: connection.auth_context.as_ref().map(|auth| auth.user_id.clone()),
            subscriptions: connection.subscriptions.clone(),
            state: format!("{:?}", connection.state),
            age_seconds: connection.age().as_secs(),
            idle_seconds: connection.idle_time().as_secs(),
            metadata: connection.metadata.clone(),
        };
        
        connections.push(connection_info);
    }
    
    let total = connections.len();
    
    // Apply pagination
    let start = (page - 1) * per_page;
    let end = (start + per_page).min(total);
    let paginated_connections = if start < total {
        connections[start..end].to_vec()
    } else {
        Vec::new()
    };
    
    info!(
        total_connections = total,
        page = page,
        per_page = per_page,
        returned = paginated_connections.len(),
        "Listed WebSocket connections"
    );
    
    Ok(Json(ConnectionListResponse {
        connections: paginated_connections,
        total,
        page,
        per_page,
    }))
}

/// Get specific WebSocket connection details
#[instrument(skip(state))]
pub async fn get_connection(
    State(state): State<WebSocketAdminState>,
    Path(connection_id): Path<String>,
) -> Result<Json<ConnectionInfo>, GatewayError> {
    let connection = state.connection_manager
        .get_connection(&connection_id)
        .await
        .ok_or_else(|| GatewayError::not_found(format!("Connection {} not found", connection_id)))?;
    
    let connection = connection.read().await;
    
    let connection_info = ConnectionInfo {
        id: connection.id.clone(),
        remote_addr: connection.remote_addr.to_string(),
        connected_at: format!("{:?}", connection.connected_at),
        authenticated: connection.is_authenticated(),
        user_id: connection.auth_context.as_ref().map(|auth| auth.user_id.clone()),
        subscriptions: connection.subscriptions.clone(),
        state: format!("{:?}", connection.state),
        age_seconds: connection.age().as_secs(),
        idle_seconds: connection.idle_time().as_secs(),
        metadata: connection.metadata.clone(),
    };
    
    info!(
        connection_id = %connection_id,
        "Retrieved WebSocket connection details"
    );
    
    Ok(Json(connection_info))
}

/// Disconnect a WebSocket connection
#[instrument(skip(state))]
pub async fn disconnect_connection(
    State(state): State<WebSocketAdminState>,
    Path(connection_id): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check if connection exists
    if state.connection_manager.get_connection(&connection_id).await.is_none() {
        return Err(GatewayError::not_found(format!("Connection {} not found", connection_id)));
    }
    
    // Remove the connection
    state.connection_manager.remove_connection(&connection_id).await;
    
    info!(
        connection_id = %connection_id,
        "Disconnected WebSocket connection via admin API"
    );
    
    Ok(Json(serde_json::json!({
        "message": "Connection disconnected successfully",
        "connection_id": connection_id
    })))
}

/// Get connection subscriptions
#[instrument(skip(state))]
pub async fn get_connection_subscriptions(
    State(state): State<WebSocketAdminState>,
    Path(connection_id): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let connection = state.connection_manager
        .get_connection(&connection_id)
        .await
        .ok_or_else(|| GatewayError::not_found(format!("Connection {} not found", connection_id)))?;
    
    let connection = connection.read().await;
    
    Ok(Json(serde_json::json!({
        "connection_id": connection_id,
        "subscriptions": connection.subscriptions
    })))
}

/// Subscribe connection to a channel
#[instrument(skip(state))]
pub async fn subscribe_connection(
    State(state): State<WebSocketAdminState>,
    Path(connection_id): Path<String>,
    Json(request): Json<SubscriptionRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check if connection exists
    if state.connection_manager.get_connection(&connection_id).await.is_none() {
        return Err(GatewayError::not_found(format!("Connection {} not found", connection_id)));
    }
    
    // Subscribe to channel
    state.connection_manager.subscribe_connection(&connection_id, &request.channel).await;
    
    info!(
        connection_id = %connection_id,
        channel = %request.channel,
        "Subscribed connection to channel via admin API"
    );
    
    Ok(Json(serde_json::json!({
        "message": "Subscription successful",
        "connection_id": connection_id,
        "channel": request.channel
    })))
}

/// Unsubscribe connection from a channel
#[instrument(skip(state))]
pub async fn unsubscribe_connection(
    State(state): State<WebSocketAdminState>,
    Path((connection_id, channel)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check if connection exists
    if state.connection_manager.get_connection(&connection_id).await.is_none() {
        return Err(GatewayError::not_found(format!("Connection {} not found", connection_id)));
    }
    
    // Unsubscribe from channel
    state.connection_manager.unsubscribe_connection(&connection_id, &channel).await;
    
    info!(
        connection_id = %connection_id,
        channel = %channel,
        "Unsubscribed connection from channel via admin API"
    );
    
    Ok(Json(serde_json::json!({
        "message": "Unsubscription successful",
        "connection_id": connection_id,
        "channel": channel
    })))
}

/// List all channels
#[instrument(skip(state))]
pub async fn list_channels(
    State(state): State<WebSocketAdminState>,
) -> Result<Json<ChannelListResponse>, GatewayError> {
    let mut channels = Vec::new();
    
    for entry in state.connection_manager.subscriptions.iter() {
        let channel_name = entry.key().clone();
        let subscribers = entry.value().clone();
        
        channels.push(ChannelInfo {
            name: channel_name,
            subscriber_count: subscribers.len(),
            subscribers,
        });
    }
    
    let total = channels.len();
    
    info!(
        total_channels = total,
        "Listed WebSocket channels"
    );
    
    Ok(Json(ChannelListResponse {
        channels,
        total,
    }))
}

/// Get channel subscribers
#[instrument(skip(state))]
pub async fn get_channel_subscribers(
    State(state): State<WebSocketAdminState>,
    Path(channel): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let subscribers = state.connection_manager.subscriptions
        .get(&channel)
        .map(|entry| entry.value().clone())
        .unwrap_or_default();
    
    Ok(Json(serde_json::json!({
        "channel": channel,
        "subscriber_count": subscribers.len(),
        "subscribers": subscribers
    })))
}

/// Broadcast message to channel
#[instrument(skip(state))]
pub async fn broadcast_to_channel(
    State(state): State<WebSocketAdminState>,
    Path(channel): Path<String>,
    Json(request): Json<BroadcastRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let message = match request.message_type.as_deref() {
        Some("custom") => WebSocketMessage::Custom {
            action: "admin_broadcast".to_string(),
            payload: request.message,
        },
        Some("direct") => WebSocketMessage::Custom {
            action: "admin_message".to_string(),
            payload: request.message,
        },
        _ => WebSocketMessage::Broadcast {
            channel: channel.clone(),
            message: request.message,
        },
    };
    
    let sent_count = state.connection_manager.broadcast_to_channel(&channel, message).await;
    
    info!(
        channel = %channel,
        recipients = sent_count,
        "Broadcasted message to channel via admin API"
    );
    
    Ok(Json(serde_json::json!({
        "message": "Broadcast successful",
        "channel": channel,
        "recipients": sent_count
    })))
}

/// Send message to specific connection
#[instrument(skip(state))]
pub async fn send_to_connection(
    State(state): State<WebSocketAdminState>,
    Path(connection_id): Path<String>,
    Json(request): Json<MessageSendRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check if connection exists
    if state.connection_manager.get_connection(&connection_id).await.is_none() {
        return Err(GatewayError::not_found(format!("Connection {} not found", connection_id)));
    }
    
    let message = match request.message_type.as_deref() {
        Some("custom") => WebSocketMessage::Custom {
            action: "admin_message".to_string(),
            payload: request.message,
        },
        Some("direct") => WebSocketMessage::Direct {
            target: connection_id.clone(),
            message: request.message,
        },
        _ => WebSocketMessage::Custom {
            action: "admin_notification".to_string(),
            payload: request.message,
        },
    };
    
    state.connection_manager.send_to_connection(&connection_id, message).await
        .map_err(|e| GatewayError::internal(format!("Failed to send message: {}", e)))?;
    
    info!(
        connection_id = %connection_id,
        "Sent message to connection via admin API"
    );
    
    Ok(Json(serde_json::json!({
        "message": "Message sent successfully",
        "connection_id": connection_id
    })))
}

/// Get WebSocket statistics
#[instrument(skip(state))]
pub async fn get_statistics(
    State(state): State<WebSocketAdminState>,
) -> Result<Json<WebSocketStatistics>, GatewayError> {
    let stats = state.connection_manager.get_statistics().await;
    
    info!(
        total_connections = stats.total_connections,
        authenticated_connections = stats.authenticated_connections,
        total_channels = stats.total_channels,
        "Retrieved WebSocket statistics"
    );
    
    Ok(Json(stats))
}

/// WebSocket health check
#[instrument(skip(state))]
pub async fn health_check(
    State(state): State<WebSocketAdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let stats = state.connection_manager.get_statistics().await;
    
    let health_status = if stats.total_connections > 0 {
        "healthy"
    } else {
        "idle"
    };
    
    Ok(Json(serde_json::json!({
        "status": health_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "connections": stats.total_connections,
        "channels": stats.total_channels,
        "service": "websocket"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use axum_test::TestServer;
    use axum::http::StatusCode;

    async fn create_test_state() -> WebSocketAdminState {
        let config = WebSocketConfig::default();
        let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
        WebSocketAdminState::new(connection_manager)
    }

    #[tokio::test]
    async fn test_list_connections_empty() {
        let state = create_test_state().await;
        let app = WebSocketAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/websocket/connections").await;
        response.assert_status_ok();
        
        let body: ConnectionListResponse = response.json();
        assert_eq!(body.total, 0);
        assert!(body.connections.is_empty());
    }

    #[tokio::test]
    async fn test_get_statistics() {
        let state = create_test_state().await;
        let app = WebSocketAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/websocket/statistics").await;
        response.assert_status_ok();
        
        let body: WebSocketStatistics = response.json();
        assert_eq!(body.total_connections, 0);
        assert_eq!(body.authenticated_connections, 0);
        assert_eq!(body.total_channels, 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let state = create_test_state().await;
        let app = WebSocketAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/websocket/health").await;
        response.assert_status_ok();
        
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "idle");
        assert_eq!(body["connections"], 0);
        assert_eq!(body["service"], "websocket");
    }

    #[tokio::test]
    async fn test_get_nonexistent_connection() {
        let state = create_test_state().await;
        let app = WebSocketAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/websocket/connections/nonexistent").await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_channels_empty() {
        let state = create_test_state().await;
        let app = WebSocketAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/websocket/channels").await;
        response.assert_status_ok();
        
        let body: ChannelListResponse = response.json();
        assert_eq!(body.total, 0);
        assert!(body.channels.is_empty());
    }
}
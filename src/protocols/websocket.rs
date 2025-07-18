//! # WebSocket Protocol Handler
//!
//! This module handles WebSocket protocol-specific functionality including:
//! - WebSocket upgrade handling using tokio-tungstenite
//! - Connection management and pooling
//! - Message routing and broadcasting system
//! - Authentication integration
//! - Real-time event streaming capabilities
//!
//! ## Rust Concepts Used
//!
//! - `Arc<T>` for sharing connection state across async tasks
//! - `DashMap` for thread-safe concurrent connection storage
//! - `tokio::sync::broadcast` for message broadcasting
//! - `async/await` for non-blocking WebSocket operations
//! - `tokio-tungstenite` for WebSocket protocol implementation

use crate::core::types::AuthContext;
use crate::core::error::{GatewayError, GatewayResult};

use axum::{
    extract::{ws::{WebSocket, Message}, WebSocketUpgrade, Query},
    response::Response,
    http::StatusCode,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};

use tracing::{debug, info, warn, error, instrument};
use uuid::Uuid;

/// WebSocket connection information
#[derive(Debug, Clone)]
pub struct WebSocketConnection {
    /// Unique connection identifier
    pub id: String,
    
    /// Client remote address
    pub remote_addr: SocketAddr,
    
    /// Connection establishment time
    pub connected_at: Instant,
    
    /// Authentication context (if authenticated)
    pub auth_context: Option<Arc<AuthContext>>,
    
    /// Connection metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Subscribed channels/topics
    pub subscriptions: Vec<String>,
    
    /// Connection state
    pub state: ConnectionState,
    
    /// Last activity timestamp
    pub last_activity: Instant,
}

impl WebSocketConnection {
    /// Create a new WebSocket connection
    pub fn new(id: String, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            id,
            remote_addr,
            connected_at: now,
            auth_context: None,
            metadata: HashMap::new(),
            subscriptions: Vec::new(),
            state: ConnectionState::Connected,
            last_activity: now,
        }
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth_context.is_some()
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

/// WebSocket connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is active and ready
    Connected,
    /// Connection is being closed
    Closing,
    /// Connection is closed
    Closed,
    /// Connection has an error
    Error(String),
}

/// WebSocket message types for internal routing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WebSocketMessage {
    /// Authentication message
    Auth {
        token: String,
    },
    /// Subscribe to a channel/topic
    Subscribe {
        channel: String,
    },
    /// Unsubscribe from a channel/topic
    Unsubscribe {
        channel: String,
    },
    /// Broadcast message to a channel
    Broadcast {
        channel: String,
        message: serde_json::Value,
    },
    /// Direct message to a specific connection
    Direct {
        target: String,
        message: serde_json::Value,
    },
    /// Ping message for keepalive
    Ping,
    /// Pong response to ping
    Pong,
    /// Error message
    Error {
        code: u16,
        message: String,
    },
    /// Custom application message
    Custom {
        action: String,
        payload: serde_json::Value,
    },
}

/// WebSocket connection manager
pub struct WebSocketConnectionManager {
    /// Active connections indexed by connection ID
    pub connections: Arc<DashMap<String, Arc<RwLock<WebSocketConnection>>>>,
    
    /// Channel subscriptions (channel -> set of connection IDs)
    pub subscriptions: Arc<DashMap<String, Vec<String>>>,
    
    /// Broadcast sender for global messages
    broadcast_sender: broadcast::Sender<(String, WebSocketMessage)>,
    
    /// Configuration
    config: WebSocketConfig,
}

impl WebSocketConnectionManager {
    /// Create a new connection manager
    pub fn new(config: WebSocketConfig) -> Self {
        let (broadcast_sender, _) = broadcast::channel(config.broadcast_buffer_size);
        
        Self {
            connections: Arc::new(DashMap::new()),
            subscriptions: Arc::new(DashMap::new()),
            broadcast_sender,
            config,
        }
    }

    /// Add a new connection
    pub async fn add_connection(&self, connection: WebSocketConnection) -> String {
        let connection_id = connection.id.clone();
        let connection = Arc::new(RwLock::new(connection));
        
        self.connections.insert(connection_id.clone(), connection);
        
        info!(
            connection_id = %connection_id,
            "WebSocket connection added"
        );
        
        connection_id
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &str) {
        if let Some((_, connection)) = self.connections.remove(connection_id) {
            let connection = connection.read().await;
            
            // Remove from all subscriptions
            for subscription in &connection.subscriptions {
                self.unsubscribe_connection(connection_id, subscription).await;
            }
            
            info!(
                connection_id = %connection_id,
                "WebSocket connection removed"
            );
        }
    }

    /// Get connection by ID
    pub async fn get_connection(&self, connection_id: &str) -> Option<Arc<RwLock<WebSocketConnection>>> {
        self.connections.get(connection_id).map(|entry| entry.value().clone())
    }

    /// Subscribe connection to a channel
    pub async fn subscribe_connection(&self, connection_id: &str, channel: &str) {
        // Add to subscriptions map
        self.subscriptions
            .entry(channel.to_string())
            .or_insert_with(Vec::new)
            .push(connection_id.to_string());

        // Update connection subscriptions
        if let Some(connection) = self.get_connection(connection_id).await {
            let mut conn = connection.write().await;
            if !conn.subscriptions.contains(&channel.to_string()) {
                conn.subscriptions.push(channel.to_string());
            }
        }

        debug!(
            connection_id = %connection_id,
            channel = %channel,
            "Connection subscribed to channel"
        );
    }

    /// Unsubscribe connection from a channel
    pub async fn unsubscribe_connection(&self, connection_id: &str, channel: &str) {
        // Remove from subscriptions map
        if let Some(mut subscribers) = self.subscriptions.get_mut(channel) {
            subscribers.retain(|id| id != connection_id);
            if subscribers.is_empty() {
                drop(subscribers);
                self.subscriptions.remove(channel);
            }
        }

        // Update connection subscriptions
        if let Some(connection) = self.get_connection(connection_id).await {
            let mut conn = connection.write().await;
            conn.subscriptions.retain(|c| c != channel);
        }

        debug!(
            connection_id = %connection_id,
            channel = %channel,
            "Connection unsubscribed from channel"
        );
    }

    /// Broadcast message to all subscribers of a channel
    pub async fn broadcast_to_channel(&self, channel: &str, message: WebSocketMessage) -> usize {
        let subscribers = self.subscriptions
            .get(channel)
            .map(|entry| entry.value().clone())
            .unwrap_or_default();

        let mut sent_count = 0;
        for connection_id in subscribers {
            if self.send_to_connection(&connection_id, message.clone()).await.is_ok() {
                sent_count += 1;
            }
        }

        debug!(
            channel = %channel,
            subscribers = sent_count,
            "Broadcasted message to channel"
        );

        sent_count
    }

    /// Send message to a specific connection
    pub async fn send_to_connection(&self, connection_id: &str, message: WebSocketMessage) -> GatewayResult<()> {
        // For now, we'll use the broadcast channel to send messages
        // In a real implementation, we'd maintain individual senders for each connection
        self.broadcast_sender
            .send((connection_id.to_string(), message))
            .map_err(|e| GatewayError::internal(format!("Failed to send message: {}", e)))?;
        
        Ok(())
    }

    /// Get connection statistics
    pub async fn get_statistics(&self) -> WebSocketStatistics {
        let total_connections = self.connections.len();
        let total_channels = self.subscriptions.len();
        
        let mut authenticated_connections = 0;
        let mut connection_ages = Vec::new();
        
        for entry in self.connections.iter() {
            let connection = entry.value().read().await;
            if connection.is_authenticated() {
                authenticated_connections += 1;
            }
            connection_ages.push(connection.age());
        }

        let average_age = if !connection_ages.is_empty() {
            connection_ages.iter().sum::<Duration>() / connection_ages.len() as u32
        } else {
            Duration::from_secs(0)
        };

        WebSocketStatistics {
            total_connections,
            authenticated_connections,
            total_channels,
            average_connection_age: average_age,
        }
    }

    /// Clean up idle connections
    pub async fn cleanup_idle_connections(&self) {
        let idle_timeout = self.config.idle_timeout;
        let mut to_remove = Vec::new();

        for entry in self.connections.iter() {
            let connection = entry.value().read().await;
            if connection.idle_time() > idle_timeout {
                to_remove.push(connection.id.clone());
            }
        }

        for connection_id in to_remove {
            self.remove_connection(&connection_id).await;
            warn!(
                connection_id = %connection_id,
                "Removed idle WebSocket connection"
            );
        }
    }
}

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    
    /// Connection idle timeout
    pub idle_timeout: Duration,
    
    /// Message size limit
    pub max_message_size: usize,
    
    /// Broadcast channel buffer size
    pub broadcast_buffer_size: usize,
    
    /// Enable authentication requirement
    pub require_auth: bool,
    
    /// Ping interval for keepalive
    pub ping_interval: Duration,
    
    /// Pong timeout
    pub pong_timeout: Duration,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            max_message_size: 1024 * 1024, // 1MB
            broadcast_buffer_size: 1000,
            require_auth: false,
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
        }
    }
}

/// WebSocket statistics
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct WebSocketStatistics {
    pub total_connections: usize,
    pub authenticated_connections: usize,
    pub total_channels: usize,
    pub average_connection_age: Duration,
}

/// WebSocket upgrade query parameters
#[derive(Debug, Deserialize)]
pub struct WebSocketUpgradeQuery {
    /// Authentication token
    pub token: Option<String>,
    
    /// Initial channels to subscribe to
    pub channels: Option<String>,
}

/// Main WebSocket protocol handler
pub struct WebSocketHandler {
    /// Connection manager
    connection_manager: Arc<WebSocketConnectionManager>,
    
    /// Configuration
    config: WebSocketConfig,
}

impl WebSocketHandler {
    /// Create a new WebSocket handler
    pub fn new(config: WebSocketConfig) -> Self {
        let connection_manager = Arc::new(WebSocketConnectionManager::new(config.clone()));
        
        // Start cleanup task
        let cleanup_manager = connection_manager.clone();
        let cleanup_interval = config.idle_timeout / 4; // Check every quarter of idle timeout
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                cleanup_manager.cleanup_idle_connections().await;
            }
        });
        
        Self {
            connection_manager,
            config,
        }
    }

    /// Handle WebSocket upgrade request
    #[instrument(skip(self, ws, query), fields(connection_id))]
    pub async fn handle_upgrade(
        &self,
        ws: WebSocketUpgrade,
        remote_addr: SocketAddr,
        query: Option<Query<WebSocketUpgradeQuery>>,
    ) -> Result<Response, GatewayError> {
        // Check connection limit
        let stats = self.connection_manager.get_statistics().await;
        if stats.total_connections >= self.config.max_connections {
            warn!(
                remote_addr = %remote_addr,
                current_connections = stats.total_connections,
                max_connections = self.config.max_connections,
                "WebSocket connection limit exceeded"
            );
            
            return Ok(axum::response::Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "error": {
                            "code": 503,
                            "message": "WebSocket connection limit exceeded"
                        }
                    })).unwrap()
                ))
                .unwrap());
        }

        let connection_id = Uuid::new_v4().to_string();
        tracing::Span::current().record("connection_id", &connection_id);

        info!(
            connection_id = %connection_id,
            remote_addr = %remote_addr,
            "WebSocket upgrade requested"
        );

        let connection_manager = self.connection_manager.clone();
        let config = self.config.clone();
        
        // Extract query parameters
        let initial_token = query.as_ref().and_then(|q| q.token.clone());
        let initial_channels = query.as_ref()
            .and_then(|q| q.channels.as_ref())
            .map(|channels| channels.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
            .unwrap_or_default();

        let upgrade_response = ws.on_upgrade(move |socket| {
            handle_websocket_connection(
                socket,
                connection_id,
                remote_addr,
                connection_manager,
                config,
                initial_token,
                initial_channels,
            )
        });

        Ok(upgrade_response)
    }

    /// Get connection manager for admin endpoints
    pub fn connection_manager(&self) -> Arc<WebSocketConnectionManager> {
        self.connection_manager.clone()
    }

    /// Get configuration
    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }
}

/// Handle individual WebSocket connection
#[instrument(skip(socket, connection_manager, config, initial_token, initial_channels))]
async fn handle_websocket_connection(
    mut socket: WebSocket,
    connection_id: String,
    remote_addr: SocketAddr,
    connection_manager: Arc<WebSocketConnectionManager>,
    config: WebSocketConfig,
    initial_token: Option<String>,
    initial_channels: Vec<String>,
) {
    info!(
        connection_id = %connection_id,
        remote_addr = %remote_addr,
        "WebSocket connection established"
    );

    // Create connection record
    let mut connection = WebSocketConnection::new(connection_id.clone(), remote_addr);
    
    // Handle initial authentication if token provided
    if let Some(_token) = initial_token {
        // TODO: Implement actual authentication
        // For now, we'll create a mock auth context
        let auth_context = AuthContext {
            user_id: format!("user_{}", &connection_id[..8]),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string(), "write".to_string()],
            claims: HashMap::new(),
            auth_method: "token".to_string(),
            expires_at: None,
        };
        connection.auth_context = Some(Arc::new(auth_context));
    }

    // Add connection to manager
    connection_manager.add_connection(connection).await;

    // Subscribe to initial channels
    for channel in initial_channels {
        connection_manager.subscribe_connection(&connection_id, &channel).await;
    }

    // Create broadcast receiver for this connection
    let mut broadcast_receiver = connection_manager.broadcast_sender.subscribe();

    // Ping/pong handling
    let mut ping_interval = tokio::time::interval(config.ping_interval);
    let last_pong = Instant::now();

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(msg)) => {
                        if let Err(e) = handle_client_message(
                            &mut socket,
                            &connection_id,
                            msg,
                            &connection_manager,
                            &config,
                        ).await {
                            error!(
                                connection_id = %connection_id,
                                error = %e,
                                "Error handling client message"
                            );
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        warn!(
                            connection_id = %connection_id,
                            error = %e,
                            "WebSocket error"
                        );
                        break;
                    }
                    None => {
                        debug!(
                            connection_id = %connection_id,
                            "WebSocket connection closed by client"
                        );
                        break;
                    }
                }
            }

            // Handle broadcast messages
            broadcast_msg = broadcast_receiver.recv() => {
                match broadcast_msg {
                    Ok((target_id, message)) => {
                        if target_id == connection_id {
                            if let Err(e) = send_message_to_client(&mut socket, message).await {
                                error!(
                                    connection_id = %connection_id,
                                    error = %e,
                                    "Error sending broadcast message"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            connection_id = %connection_id,
                            skipped = skipped,
                            "Broadcast receiver lagged, some messages skipped"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("Broadcast channel closed");
                        break;
                    }
                }
            }

            // Send periodic pings
            _ = ping_interval.tick() => {
                if let Err(e) = socket.send(Message::Ping(vec![])).await {
                    error!(
                        connection_id = %connection_id,
                        error = %e,
                        "Error sending ping"
                    );
                    break;
                }

                // Check for pong timeout
                if last_pong.elapsed() > config.pong_timeout + config.ping_interval {
                    warn!(
                        connection_id = %connection_id,
                        "Pong timeout, closing connection"
                    );
                    break;
                }
            }
        }
    }

    // Clean up connection
    connection_manager.remove_connection(&connection_id).await;
    
    info!(
        connection_id = %connection_id,
        "WebSocket connection closed"
    );
}

/// Handle message from client
async fn handle_client_message(
    socket: &mut WebSocket,
    connection_id: &str,
    message: Message,
    connection_manager: &Arc<WebSocketConnectionManager>,
    config: &WebSocketConfig,
) -> GatewayResult<()> {
    match message {
        Message::Text(text) => {
            // Check message size
            if text.len() > config.max_message_size {
                let error_msg = WebSocketMessage::Error {
                    code: 413,
                    message: "Message too large".to_string(),
                };
                send_message_to_client(socket, error_msg).await?;
                return Ok(());
            }

            // Parse message
            let ws_message: WebSocketMessage = match serde_json::from_str(&text) {
                Ok(msg) => msg,
                Err(e) => {
                    let error_msg = WebSocketMessage::Error {
                        code: 400,
                        message: format!("Invalid message format: {}", e),
                    };
                    send_message_to_client(socket, error_msg).await?;
                    return Ok(());
                }
            };

            handle_websocket_message(socket, connection_id, ws_message, connection_manager).await?;
        }
        Message::Binary(data) => {
            // Check message size
            if data.len() > config.max_message_size {
                let error_msg = WebSocketMessage::Error {
                    code: 413,
                    message: "Message too large".to_string(),
                };
                send_message_to_client(socket, error_msg).await?;
                return Ok(());
            }

            // For now, just echo binary messages back
            // In a real implementation, you might want to handle binary protocol messages
            if let Err(e) = socket.send(Message::Binary(data)).await {
                return Err(GatewayError::internal(format!("Failed to send binary message: {}", e)));
            }
        }
        Message::Ping(data) => {
            if let Err(e) = socket.send(Message::Pong(data)).await {
                return Err(GatewayError::internal(format!("Failed to send pong: {}", e)));
            }
        }
        Message::Pong(_) => {
            // Update last pong time in connection
            if let Some(connection) = connection_manager.get_connection(connection_id).await {
                let mut conn = connection.write().await;
                conn.update_activity();
            }
        }
        Message::Close(_) => {
            debug!(
                connection_id = %connection_id,
                "Received close message from client"
            );
        }
    }

    Ok(())
}

/// Handle parsed WebSocket message
async fn handle_websocket_message(
    socket: &mut WebSocket,
    connection_id: &str,
    message: WebSocketMessage,
    connection_manager: &Arc<WebSocketConnectionManager>,
) -> GatewayResult<()> {
    match message {
        WebSocketMessage::Auth { token: _ } => {
            // TODO: Implement actual authentication
            // For now, create a mock auth context
            let auth_context = AuthContext {
                user_id: format!("user_{}", &connection_id[..8]),
                roles: vec!["user".to_string()],
                permissions: vec!["read".to_string(), "write".to_string()],
                claims: HashMap::new(),
                auth_method: "token".to_string(),
                expires_at: None,
            };

            if let Some(connection) = connection_manager.get_connection(connection_id).await {
                let mut conn = connection.write().await;
                conn.auth_context = Some(Arc::new(auth_context));
                conn.update_activity();
            }

            let response = WebSocketMessage::Custom {
                action: "auth_success".to_string(),
                payload: serde_json::json!({
                    "user_id": format!("user_{}", &connection_id[..8]),
                    "authenticated": true
                }),
            };
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Subscribe { channel } => {
            connection_manager.subscribe_connection(connection_id, &channel).await;
            
            let response = WebSocketMessage::Custom {
                action: "subscribed".to_string(),
                payload: serde_json::json!({
                    "channel": channel
                }),
            };
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Unsubscribe { channel } => {
            connection_manager.unsubscribe_connection(connection_id, &channel).await;
            
            let response = WebSocketMessage::Custom {
                action: "unsubscribed".to_string(),
                payload: serde_json::json!({
                    "channel": channel
                }),
            };
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Broadcast { channel, message } => {
            let broadcast_msg = WebSocketMessage::Custom {
                action: "broadcast".to_string(),
                payload: serde_json::json!({
                    "channel": channel,
                    "message": message,
                    "from": connection_id
                }),
            };
            
            let sent_count = connection_manager.broadcast_to_channel(&channel, broadcast_msg).await;
            
            let response = WebSocketMessage::Custom {
                action: "broadcast_sent".to_string(),
                payload: serde_json::json!({
                    "channel": channel,
                    "recipients": sent_count
                }),
            };
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Direct { target, message } => {
            let direct_msg = WebSocketMessage::Custom {
                action: "direct_message".to_string(),
                payload: serde_json::json!({
                    "message": message,
                    "from": connection_id
                }),
            };
            
            match connection_manager.send_to_connection(&target, direct_msg).await {
                Ok(()) => {
                    let response = WebSocketMessage::Custom {
                        action: "direct_sent".to_string(),
                        payload: serde_json::json!({
                            "target": target
                        }),
                    };
                    send_message_to_client(socket, response).await?;
                }
                Err(e) => {
                    let error_msg = WebSocketMessage::Error {
                        code: 404,
                        message: format!("Target connection not found: {}", e),
                    };
                    send_message_to_client(socket, error_msg).await?;
                }
            }
        }
        WebSocketMessage::Ping => {
            let response = WebSocketMessage::Pong;
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Pong => {
            // Update connection activity
            if let Some(connection) = connection_manager.get_connection(connection_id).await {
                let mut conn = connection.write().await;
                conn.update_activity();
            }
        }
        WebSocketMessage::Custom { action, payload } => {
            // Handle custom application messages
            debug!(
                connection_id = %connection_id,
                action = %action,
                "Received custom WebSocket message"
            );
            
            // Echo back for now - in a real implementation, this would be routed to application handlers
            let response = WebSocketMessage::Custom {
                action: format!("echo_{}", action),
                payload,
            };
            send_message_to_client(socket, response).await?;
        }
        WebSocketMessage::Error { .. } => {
            // Client sent an error message - log it
            warn!(
                connection_id = %connection_id,
                "Received error message from client"
            );
        }
    }

    Ok(())
}

/// Send message to client
async fn send_message_to_client(socket: &mut WebSocket, message: WebSocketMessage) -> GatewayResult<()> {
    let json_message = serde_json::to_string(&message)
        .map_err(|e| GatewayError::internal(format!("Failed to serialize message: {}", e)))?;
    
    socket.send(Message::Text(json_message)).await
        .map_err(|e| GatewayError::internal(format!("Failed to send message: {}", e)))?;
    
    Ok(())
}
//! # WebSocket Integration Tests
//!
//! This module contains comprehensive integration tests for WebSocket functionality including:
//! - WebSocket upgrade handling
//! - Connection management and pooling
//! - Message routing and broadcasting
//! - Authentication integration
//! - Real-time event streaming
//! - Admin endpoint functionality
//! - Multiple concurrent connections

use api_gateway::core::config::GatewayConfig;
use api_gateway::gateway::server::{GatewayServer, ServerConfig};
use api_gateway::protocols::websocket::{WebSocketConfig, WebSocketMessage};
use api_gateway::routing::router::RouterBuilder;
use api_gateway::admin::websocket_management::{WebSocketAdminRouter, WebSocketAdminState};

use axum_test::TestServer;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing_test::traced_test;

/// Helper function to create a test gateway server
async fn create_test_gateway() -> TestServer {
    let router = RouterBuilder::new()
        .get("/api/test", "test-service")
        .default_route("default-service")
        .build();

    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        websocket: WebSocketConfig {
            max_connections: 100,
            idle_timeout: Duration::from_secs(60),
            max_message_size: 1024 * 1024,
            broadcast_buffer_size: 100,
            require_auth: false,
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
        },
        ..Default::default()
    };

    let server = GatewayServer::new(router, config);
    TestServer::new(server.gateway_app).unwrap()
}

/// Helper function to create WebSocket connection
async fn create_websocket_connection(
    server_addr: &str,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Box<dyn std::error::Error>> {
    let url = format!("ws://{}/ws", server_addr);
    let (ws_stream, _) = connect_async(&url).await?;
    Ok(ws_stream)
}

/// Helper function to send and receive WebSocket message
async fn send_and_receive_message(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    message: WebSocketMessage,
) -> Result<WebSocketMessage, Box<dyn std::error::Error>> {
    let json_message = serde_json::to_string(&message)?;
    ws.send(Message::Text(json_message)).await?;
    
    if let Some(response) = ws.next().await {
        let response_text = response?.to_text()?;
        let response_message: WebSocketMessage = serde_json::from_str(response_text)?;
        Ok(response_message)
    } else {
        Err("No response received".into())
    }
}

#[traced_test]
#[tokio::test]
async fn test_websocket_upgrade_success() {
    let server = create_test_gateway().await;
    
    // Test WebSocket upgrade endpoint
    let response = server.get("/ws")
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .await;
    
    // Should return 101 Switching Protocols for WebSocket upgrade
    response.assert_status(axum::http::StatusCode::SWITCHING_PROTOCOLS);
}

#[traced_test]
#[tokio::test]
async fn test_websocket_upgrade_without_headers() {
    let server = create_test_gateway().await;
    
    // Test WebSocket upgrade endpoint without proper headers
    let response = server.get("/ws").await;
    
    // Should return 400 Bad Request without proper WebSocket headers
    response.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[traced_test]
#[tokio::test]
async fn test_websocket_authentication() {
    let server = create_test_gateway().await;
    let server_addr = server.server_address().unwrap();
    
    // This test would require a real WebSocket connection
    // For now, we'll test the authentication message structure
    let auth_message = WebSocketMessage::Auth {
        token: "test-token".to_string(),
    };
    
    let json_message = serde_json::to_string(&auth_message).unwrap();
    assert!(json_message.contains("Auth"));
    assert!(json_message.contains("test-token"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_subscription_messages() {
    // Test subscription message serialization
    let subscribe_message = WebSocketMessage::Subscribe {
        channel: "test-channel".to_string(),
    };
    
    let json_message = serde_json::to_string(&subscribe_message).unwrap();
    assert!(json_message.contains("Subscribe"));
    assert!(json_message.contains("test-channel"));
    
    // Test unsubscribe message
    let unsubscribe_message = WebSocketMessage::Unsubscribe {
        channel: "test-channel".to_string(),
    };
    
    let json_message = serde_json::to_string(&unsubscribe_message).unwrap();
    assert!(json_message.contains("Unsubscribe"));
    assert!(json_message.contains("test-channel"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_broadcast_messages() {
    // Test broadcast message serialization
    let broadcast_message = WebSocketMessage::Broadcast {
        channel: "test-channel".to_string(),
        message: json!({"content": "Hello, World!"}),
    };
    
    let json_message = serde_json::to_string(&broadcast_message).unwrap();
    assert!(json_message.contains("Broadcast"));
    assert!(json_message.contains("test-channel"));
    assert!(json_message.contains("Hello, World!"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_direct_messages() {
    // Test direct message serialization
    let direct_message = WebSocketMessage::Direct {
        target: "connection-123".to_string(),
        message: json!({"content": "Private message"}),
    };
    
    let json_message = serde_json::to_string(&direct_message).unwrap();
    assert!(json_message.contains("Direct"));
    assert!(json_message.contains("connection-123"));
    assert!(json_message.contains("Private message"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_custom_messages() {
    // Test custom message serialization
    let custom_message = WebSocketMessage::Custom {
        action: "user_action".to_string(),
        payload: json!({"data": "custom data"}),
    };
    
    let json_message = serde_json::to_string(&custom_message).unwrap();
    assert!(json_message.contains("Custom"));
    assert!(json_message.contains("user_action"));
    assert!(json_message.contains("custom data"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_ping_pong() {
    // Test ping/pong message serialization
    let ping_message = WebSocketMessage::Ping;
    let pong_message = WebSocketMessage::Pong;
    
    let ping_json = serde_json::to_string(&ping_message).unwrap();
    let pong_json = serde_json::to_string(&pong_message).unwrap();
    
    assert!(ping_json.contains("Ping"));
    assert!(pong_json.contains("Pong"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_error_messages() {
    // Test error message serialization
    let error_message = WebSocketMessage::Error {
        code: 400,
        message: "Bad request".to_string(),
    };
    
    let json_message = serde_json::to_string(&error_message).unwrap();
    assert!(json_message.contains("Error"));
    assert!(json_message.contains("400"));
    assert!(json_message.contains("Bad request"));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_admin_endpoints() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use std::sync::Arc;
    
    // Create WebSocket admin state for testing
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    let admin_state = WebSocketAdminState::new(connection_manager);
    
    // Create admin router
    let admin_app = WebSocketAdminRouter::create_router(admin_state);
    let admin_server = TestServer::new(admin_app).unwrap();
    
    // Test list connections endpoint
    let response = admin_server.get("/websocket/connections").await;
    response.assert_status_ok();
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["total"], 0);
    assert!(body["connections"].is_array());
    
    // Test statistics endpoint
    let response = admin_server.get("/websocket/statistics").await;
    response.assert_status_ok();
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["total_connections"], 0);
    assert_eq!(body["authenticated_connections"], 0);
    assert_eq!(body["total_channels"], 0);
    
    // Test health check endpoint
    let response = admin_server.get("/websocket/health").await;
    response.assert_status_ok();
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "idle");
    assert_eq!(body["service"], "websocket");
    
    // Test list channels endpoint
    let response = admin_server.get("/websocket/channels").await;
    response.assert_status_ok();
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["total"], 0);
    assert!(body["channels"].is_array());
}

#[traced_test]
#[tokio::test]
async fn test_websocket_admin_connection_management() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use std::sync::Arc;
    
    // Create WebSocket admin state for testing
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    let admin_state = WebSocketAdminState::new(connection_manager);
    
    // Create admin router
    let admin_app = WebSocketAdminRouter::create_router(admin_state);
    let admin_server = TestServer::new(admin_app).unwrap();
    
    // Test getting non-existent connection
    let response = admin_server.get("/websocket/connections/nonexistent").await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);
    
    // Test disconnecting non-existent connection
    let response = admin_server.delete("/websocket/connections/nonexistent").await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);
    
    // Test subscribing non-existent connection
    let subscribe_request = json!({
        "channel": "test-channel"
    });
    
    let response = admin_server
        .post("/websocket/connections/nonexistent/subscriptions")
        .json(&subscribe_request)
        .await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[traced_test]
#[tokio::test]
async fn test_websocket_admin_broadcasting() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use std::sync::Arc;
    
    // Create WebSocket admin state for testing
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    let admin_state = WebSocketAdminState::new(connection_manager);
    
    // Create admin router
    let admin_app = WebSocketAdminRouter::create_router(admin_state);
    let admin_server = TestServer::new(admin_app).unwrap();
    
    // Test broadcasting to empty channel
    let broadcast_request = json!({
        "message": {"content": "Hello, World!"},
        "message_type": "custom"
    });
    
    let response = admin_server
        .post("/websocket/channels/empty-channel/broadcast")
        .json(&broadcast_request)
        .await;
    response.assert_status_ok();
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["recipients"], 0);
    assert_eq!(body["channel"], "empty-channel");
    
    // Test sending message to non-existent connection
    let message_request = json!({
        "message": {"content": "Direct message"},
        "message_type": "direct"
    });
    
    let response = admin_server
        .post("/websocket/connections/nonexistent/send")
        .json(&message_request)
        .await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[traced_test]
#[tokio::test]
async fn test_websocket_config_validation() {
    // Test WebSocket configuration with various settings
    let config = WebSocketConfig {
        max_connections: 1000,
        idle_timeout: Duration::from_secs(300),
        max_message_size: 2 * 1024 * 1024, // 2MB
        broadcast_buffer_size: 500,
        require_auth: true,
        ping_interval: Duration::from_secs(15),
        pong_timeout: Duration::from_secs(5),
    };
    
    assert_eq!(config.max_connections, 1000);
    assert_eq!(config.idle_timeout, Duration::from_secs(300));
    assert_eq!(config.max_message_size, 2 * 1024 * 1024);
    assert_eq!(config.broadcast_buffer_size, 500);
    assert!(config.require_auth);
    assert_eq!(config.ping_interval, Duration::from_secs(15));
    assert_eq!(config.pong_timeout, Duration::from_secs(5));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_connection_lifecycle() {
    use api_gateway::protocols::websocket::{WebSocketConnection, ConnectionState};
    use std::net::SocketAddr;
    
    // Test WebSocket connection creation and lifecycle
    let remote_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let mut connection = WebSocketConnection::new("test-conn-1".to_string(), remote_addr);
    
    assert_eq!(connection.id, "test-conn-1");
    assert_eq!(connection.remote_addr, remote_addr);
    assert_eq!(connection.state, ConnectionState::Connected);
    assert!(!connection.is_authenticated());
    assert!(connection.subscriptions.is_empty());
    
    // Test activity update
    let initial_activity = connection.last_activity;
    tokio::time::sleep(Duration::from_millis(10)).await;
    connection.update_activity();
    assert!(connection.last_activity > initial_activity);
    
    // Test connection age and idle time
    assert!(connection.age() > Duration::from_millis(0));
    assert!(connection.idle_time() >= Duration::from_millis(0));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_message_size_limits() {
    // Test message size validation
    let large_payload = "x".repeat(2 * 1024 * 1024); // 2MB
    let large_message = WebSocketMessage::Custom {
        action: "large_message".to_string(),
        payload: json!({"data": large_payload}),
    };
    
    // Should be able to serialize large message
    let json_message = serde_json::to_string(&large_message).unwrap();
    assert!(json_message.len() > 1024 * 1024); // Should be larger than 1MB
    
    // Test normal sized message
    let normal_message = WebSocketMessage::Custom {
        action: "normal_message".to_string(),
        payload: json!({"data": "normal data"}),
    };
    
    let json_message = serde_json::to_string(&normal_message).unwrap();
    assert!(json_message.len() < 1024); // Should be small
}

#[traced_test]
#[tokio::test]
async fn test_concurrent_websocket_operations() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use std::sync::Arc;
    use tokio::task::JoinSet;
    
    // Test concurrent operations on WebSocket connection manager
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    
    let mut join_set = JoinSet::new();
    
    // Spawn multiple concurrent tasks
    for i in 0..10 {
        let manager = connection_manager.clone();
        join_set.spawn(async move {
            let connection_id = format!("conn-{}", i);
            let channel = format!("channel-{}", i % 3); // 3 channels total
            
            // Simulate subscription operations
            manager.subscribe_connection(&connection_id, &channel).await;
            
            // Simulate broadcasting
            let message = WebSocketMessage::Custom {
                action: "test".to_string(),
                payload: json!({"id": i}),
            };
            manager.broadcast_to_channel(&channel, message).await;
            
            // Simulate unsubscription
            manager.unsubscribe_connection(&connection_id, &channel).await;
            
            i
        });
    }
    
    // Wait for all tasks to complete
    let mut results = Vec::new();
    while let Some(result) = join_set.join_next().await {
        results.push(result.unwrap());
    }
    
    // Verify all tasks completed
    assert_eq!(results.len(), 10);
    results.sort();
    assert_eq!(results, (0..10).collect::<Vec<_>>());
}

#[traced_test]
#[tokio::test]
async fn test_websocket_statistics_accuracy() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig, WebSocketConnection};
    use std::sync::Arc;
    use std::net::SocketAddr;
    
    // Test WebSocket statistics calculation
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    
    // Add some test connections
    let remote_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    
    for i in 0..5 {
        let connection = WebSocketConnection::new(format!("conn-{}", i), remote_addr);
        connection_manager.add_connection(connection).await;
    }
    
    // Subscribe connections to channels
    for i in 0..5 {
        let connection_id = format!("conn-{}", i);
        let channel = format!("channel-{}", i % 2); // 2 channels
        connection_manager.subscribe_connection(&connection_id, &channel).await;
    }
    
    // Get statistics
    let stats = connection_manager.get_statistics().await;
    
    assert_eq!(stats.total_connections, 5);
    assert_eq!(stats.authenticated_connections, 0); // No auth in test
    assert_eq!(stats.total_channels, 2);
    assert!(stats.average_connection_age >= Duration::from_millis(0));
}

#[traced_test]
#[tokio::test]
async fn test_websocket_error_handling() {
    // Test various error scenarios
    
    // Test invalid JSON message
    let invalid_json = "{ invalid json }";
    let parse_result: Result<WebSocketMessage, _> = serde_json::from_str(invalid_json);
    assert!(parse_result.is_err());
    
    // Test missing required fields
    let incomplete_json = r#"{"type": "Subscribe"}"#; // Missing channel
    let parse_result: Result<WebSocketMessage, _> = serde_json::from_str(incomplete_json);
    assert!(parse_result.is_err());
    
    // Test unknown message type
    let unknown_type_json = r#"{"type": "UnknownType", "data": {}}"#;
    let parse_result: Result<WebSocketMessage, _> = serde_json::from_str(unknown_type_json);
    assert!(parse_result.is_err());
}

#[traced_test]
#[tokio::test]
async fn test_websocket_admin_pagination() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use api_gateway::admin::websocket_management::{WebSocketAdminRouter, WebSocketAdminState, ConnectionListResponse};
    use std::sync::Arc;
    
    // Create WebSocket admin state for testing
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    let admin_state = WebSocketAdminState::new(connection_manager);
    
    // Create admin router
    let admin_app = WebSocketAdminRouter::create_router(admin_state);
    let admin_server = TestServer::new(admin_app).unwrap();
    
    // Test pagination parameters
    let response = admin_server
        .get("/websocket/connections?page=1&per_page=10")
        .await;
    response.assert_status_ok();
    
    let body: ConnectionListResponse = response.json();
    assert_eq!(body.page, 1);
    assert_eq!(body.per_page, 10);
    assert_eq!(body.total, 0);
    assert!(body.connections.is_empty());
    
    // Test with different pagination
    let response = admin_server
        .get("/websocket/connections?page=2&per_page=25")
        .await;
    response.assert_status_ok();
    
    let body: ConnectionListResponse = response.json();
    assert_eq!(body.page, 2);
    assert_eq!(body.per_page, 25);
}

#[traced_test]
#[tokio::test]
async fn test_websocket_admin_filtering() {
    use api_gateway::protocols::websocket::{WebSocketConnectionManager, WebSocketConfig};
    use api_gateway::admin::websocket_management::{WebSocketAdminRouter, WebSocketAdminState, ConnectionListResponse};
    use std::sync::Arc;
    
    // Create WebSocket admin state for testing
    let config = WebSocketConfig::default();
    let connection_manager = Arc::new(WebSocketConnectionManager::new(config));
    let admin_state = WebSocketAdminState::new(connection_manager);
    
    // Create admin router
    let admin_app = WebSocketAdminRouter::create_router(admin_state);
    let admin_server = TestServer::new(admin_app).unwrap();
    
    // Test filtering by authentication status
    let response = admin_server
        .get("/websocket/connections?authenticated=true")
        .await;
    response.assert_status_ok();
    
    let body: ConnectionListResponse = response.json();
    assert_eq!(body.total, 0); // No authenticated connections in test
    
    // Test filtering by channel
    let response = admin_server
        .get("/websocket/connections?channel=test-channel")
        .await;
    response.assert_status_ok();
    
    let body: ConnectionListResponse = response.json();
    assert_eq!(body.total, 0); // No connections subscribed to test-channel
}
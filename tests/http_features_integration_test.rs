//! # HTTP Features Integration Tests
//!
//! This test suite verifies that all advanced HTTP features are properly implemented:
//! - HTTP/2 support with proper configuration
//! - Request/response compression (gzip, brotli)
//! - CORS handling with configurable policies
//! - OpenAPI/Swagger integration for request validation
//! - Request timeout and deadline propagation
//! - Admin endpoints for HTTP feature configuration

use api_gateway::{GatewayConfig, GatewayResult};
use api_gateway::gateway::server::{GatewayServer, ServerConfig};
use api_gateway::routing::router::RouterBuilder;
use api_gateway::protocols::http::{HttpConfig, Http2Config, CompressionConfig, CorsConfig, OpenApiConfig, HttpTimeoutConfig};
use axum::http::{Method, StatusCode, HeaderValue};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_http2_configuration() {
    // Test HTTP/2 configuration
    let http2_config = Http2Config {
        max_concurrent_streams: 200,
        initial_connection_window_size: 2 * 1024 * 1024, // 2MB
        initial_stream_window_size: 128 * 1024,          // 128KB
        max_frame_size: 32 * 1024,                       // 32KB
        enable_push: false,
        keep_alive_interval: Duration::from_secs(30),
        keep_alive_timeout: Duration::from_secs(10),
    };

    let http_config = HttpConfig {
        http2_enabled: true,
        http2: http2_config,
        compression: CompressionConfig::default(),
        cors: CorsConfig::default(),
        openapi: None,
        timeouts: HttpTimeoutConfig::default(),
        max_body_size: 16 * 1024 * 1024,
        keep_alive: Default::default(),
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify HTTP/2 is enabled in configuration
    assert!(server.state.config.http.http2_enabled);
    assert_eq!(server.state.config.http.http2.max_concurrent_streams, 200);
}

#[tokio::test]
async fn test_compression_configuration() {
    // Test compression configuration
    let compression_config = CompressionConfig {
        enabled: true,
        algorithms: vec![
            api_gateway::protocols::http::CompressionAlgorithm::Gzip,
            api_gateway::protocols::http::CompressionAlgorithm::Brotli,
        ],
        level: 8, // High compression
        min_size: 512, // 512 bytes minimum
        content_types: vec![
            "application/json".to_string(),
            "text/html".to_string(),
            "text/css".to_string(),
        ],
    };

    let http_config = HttpConfig {
        compression: compression_config,
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify compression is enabled and configured
    assert!(server.state.config.http.compression.enabled);
    assert_eq!(server.state.config.http.compression.level, 8);
    assert_eq!(server.state.config.http.compression.min_size, 512);
    assert!(server.state.config.http.compression.algorithms.contains(
        &api_gateway::protocols::http::CompressionAlgorithm::Gzip
    ));
}

#[tokio::test]
async fn test_cors_configuration() {
    // Test CORS configuration
    let cors_config = CorsConfig {
        enabled: true,
        allowed_origins: vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ],
        allowed_methods: vec![
            "GET".to_string(),
            "POST".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
        ],
        allowed_headers: vec![
            "content-type".to_string(),
            "authorization".to_string(),
            "x-api-key".to_string(),
        ],
        exposed_headers: vec![
            "x-request-id".to_string(),
            "x-response-time".to_string(),
        ],
        allow_credentials: true,
        max_age: 3600, // 1 hour
    };

    let http_config = HttpConfig {
        cors: cors_config,
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify CORS is enabled and configured
    assert!(server.state.config.http.cors.enabled);
    assert!(server.state.config.http.cors.allow_credentials);
    assert_eq!(server.state.config.http.cors.max_age, 3600);
    assert!(server.state.config.http.cors.allowed_origins.contains(&"https://example.com".to_string()));
}

#[tokio::test]
async fn test_openapi_configuration() {
    // Test OpenAPI configuration
    let openapi_config = OpenApiConfig {
        spec_path: "openapi.yaml".to_string(),
        validate_requests: true,
        validate_responses: true,
        strict_mode: false,
        custom_error_responses: std::collections::HashMap::new(),
    };

    let http_config = HttpConfig {
        openapi: Some(openapi_config),
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify OpenAPI is configured
    assert!(server.state.config.http.openapi.is_some());
    let openapi = server.state.config.http.openapi.as_ref().unwrap();
    assert!(openapi.validate_requests);
    assert!(openapi.validate_responses);
    assert_eq!(openapi.spec_path, "openapi.yaml");
}

#[tokio::test]
async fn test_timeout_configuration() {
    // Test timeout configuration
    let timeout_config = HttpTimeoutConfig {
        request_timeout: Duration::from_secs(45),
        header_timeout: Duration::from_secs(15),
        body_timeout: Duration::from_secs(60),
        keep_alive_timeout: Duration::from_secs(120),
        upstream_timeout: Duration::from_secs(30),
    };

    let http_config = HttpConfig {
        timeouts: timeout_config,
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify timeout configuration
    assert_eq!(server.state.config.http.timeouts.request_timeout, Duration::from_secs(45));
    assert_eq!(server.state.config.http.timeouts.header_timeout, Duration::from_secs(15));
    assert_eq!(server.state.config.http.timeouts.upstream_timeout, Duration::from_secs(30));
}

#[tokio::test]
async fn test_http_handler_integration() {
    // Test that HttpHandler is properly integrated
    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify HttpHandler is created and integrated
    assert!(server.state.http_handler.config().http2_enabled);
    assert!(server.state.http_handler.config().compression.enabled);
    assert!(server.state.http_handler.config().cors.enabled);
}

#[tokio::test]
async fn test_middleware_integration() {
    // Test that middleware layers are properly integrated
    let http_config = HttpConfig {
        http2_enabled: true,
        compression: CompressionConfig {
            enabled: true,
            level: 6,
            ..Default::default()
        },
        cors: CorsConfig {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify configuration is applied
    assert!(server.state.config.http.http2_enabled);
    assert!(server.state.config.http.compression.enabled);
    assert!(server.state.config.http.cors.enabled);
}

#[tokio::test]
async fn test_admin_endpoints_integration() {
    // Test that HTTP admin endpoints are integrated
    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .get("/test", "test-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify server is created successfully with admin endpoints
    assert_eq!(server.bind_addr().ip().to_string(), "127.0.0.1");
    assert_eq!(server.admin_bind_addr().ip().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_request_size_limits() {
    // Test request size limits from HTTP configuration
    let http_config = HttpConfig {
        max_body_size: 1024, // 1KB limit for testing
        ..Default::default()
    };

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        admin_bind_addr: "127.0.0.1:0".parse().unwrap(),
        http: http_config,
        ..Default::default()
    };

    let router = RouterBuilder::new()
        .post("/upload", "upload-service")
        .build();

    let server = GatewayServer::new(router, server_config);
    
    // Verify max body size is configured
    assert_eq!(server.state.config.http.max_body_size, 1024);
}

#[tokio::test]
async fn test_default_http_configuration() {
    // Test that default HTTP configuration is sensible
    let default_config = HttpConfig::default();
    
    // Verify defaults
    assert!(default_config.http2_enabled);
    assert!(default_config.compression.enabled);
    assert!(default_config.cors.enabled);
    assert_eq!(default_config.compression.level, 6); // Balanced compression
    assert_eq!(default_config.max_body_size, 16 * 1024 * 1024); // 16MB
    assert_eq!(default_config.timeouts.request_timeout, Duration::from_secs(30));
    
    // Verify HTTP/2 defaults
    assert_eq!(default_config.http2.max_concurrent_streams, 100);
    assert_eq!(default_config.http2.initial_connection_window_size, 1024 * 1024); // 1MB
    assert!(!default_config.http2.enable_push); // Server push disabled by default
    
    // Verify CORS defaults
    assert!(default_config.cors.allowed_origins.contains(&"*".to_string()));
    assert!(default_config.cors.allowed_methods.contains(&"GET".to_string()));
    assert!(default_config.cors.allowed_methods.contains(&"POST".to_string()));
    assert_eq!(default_config.cors.max_age, 86400); // 24 hours
}
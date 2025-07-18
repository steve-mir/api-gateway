//! # HTTP Integration Tests
//!
//! This module contains comprehensive integration tests for HTTP features including:
//! - HTTP/1.1 and HTTP/2 support
//! - Request/response compression (gzip, brotli, deflate)
//! - CORS handling with configurable policies
//! - OpenAPI/Swagger integration for request validation
//! - Request timeout and deadline propagation
//! - Admin endpoints for HTTP feature configuration

use api_gateway::core::error::GatewayResult;
use api_gateway::protocols::http::{
    HttpHandler, HttpConfig, Http2Config, CompressionConfig, CorsConfig,
    OpenApiConfig, HttpTimeoutConfig, KeepAliveConfig, CompressionAlgorithm
};
use api_gateway::admin::http_management::{HttpAdminState, HttpAdminRouter};
use api_gateway::core::types::{IncomingRequest, RequestContext, Protocol};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version},
    response::Response,
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Test HTTP handler creation and configuration
#[tokio::test]
async fn test_http_handler_creation() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    assert!(handler.compression_layer().is_some());
    assert!(handler.cors_layer().is_some());
    assert_eq!(handler.config().http2_enabled, true);
    assert_eq!(handler.config().compression.enabled, true);
    assert_eq!(handler.config().cors.enabled, true);
}

/// Test HTTP/2 configuration
#[tokio::test]
async fn test_http2_configuration() {
    let mut config = HttpConfig::default();
    config.http2.max_concurrent_streams = 200;
    config.http2.initial_connection_window_size = 2 * 1024 * 1024; // 2MB
    config.http2.enable_push = true;
    
    let handler = HttpHandler::new(config).unwrap();
    
    assert_eq!(handler.config().http2.max_concurrent_streams, 200);
    assert_eq!(handler.config().http2.initial_connection_window_size, 2 * 1024 * 1024);
    assert_eq!(handler.config().http2.enable_push, true);
}

/// Test compression configuration
#[tokio::test]
async fn test_compression_configuration() {
    let mut config = HttpConfig::default();
    config.compression.level = 9; // Maximum compression
    config.compression.min_size = 512; // 512 bytes minimum
    config.compression.algorithms = vec![
        CompressionAlgorithm::Gzip,
        CompressionAlgorithm::Brotli,
    ];
    
    let handler = HttpHandler::new(config).unwrap();
    
    assert_eq!(handler.config().compression.level, 9);
    assert_eq!(handler.config().compression.min_size, 512);
    assert_eq!(handler.config().compression.algorithms.len(), 2);
}

/// Test CORS configuration
#[tokio::test]
async fn test_cors_configuration() {
    let mut config = HttpConfig::default();
    config.cors.allowed_origins = vec!["https://example.com".to_string()];
    config.cors.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
    config.cors.allow_credentials = true;
    config.cors.max_age = 3600;
    
    let handler = HttpHandler::new(config).unwrap();
    
    assert_eq!(handler.config().cors.allowed_origins, vec!["https://example.com"]);
    assert_eq!(handler.config().cors.allowed_methods, vec!["GET", "POST"]);
    assert_eq!(handler.config().cors.allow_credentials, true);
    assert_eq!(handler.config().cors.max_age, 3600);
}

/// Test OpenAPI configuration
#[tokio::test]
async fn test_openapi_configuration() {
    let mut config = HttpConfig::default();
    config.openapi = Some(OpenApiConfig {
        spec_path: "test-api.yaml".to_string(),
        validate_requests: true,
        validate_responses: true,
        strict_mode: true,
        custom_error_responses: HashMap::new(),
    });
    
    let handler = HttpHandler::new(config).unwrap();
    
    assert!(handler.config().openapi.is_some());
    let openapi_config = handler.config().openapi.as_ref().unwrap();
    assert_eq!(openapi_config.spec_path, "test-api.yaml");
    assert_eq!(openapi_config.validate_requests, true);
    assert_eq!(openapi_config.validate_responses, true);
    assert_eq!(openapi_config.strict_mode, true);
}

/// Test timeout configuration
#[tokio::test]
async fn test_timeout_configuration() {
    let mut config = HttpConfig::default();
    config.timeouts.request_timeout = Duration::from_secs(60);
    config.timeouts.upstream_timeout = Duration::from_secs(45);
    config.timeouts.keep_alive_timeout = Duration::from_secs(120);
    
    let handler = HttpHandler::new(config).unwrap();
    
    assert_eq!(handler.config().timeouts.request_timeout, Duration::from_secs(60));
    assert_eq!(handler.config().timeouts.upstream_timeout, Duration::from_secs(45));
    assert_eq!(handler.config().timeouts.keep_alive_timeout, Duration::from_secs(120));
}

/// Test HTTP request handling with different versions
#[tokio::test]
async fn test_http_request_handling() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    // Test HTTP/1.1 request
    let request = create_test_request(Method::GET, "/api/test", Version::HTTP_11);
    let mut context = create_test_context(&request);
    
    let response = handler.handle_request(request, &mut context).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify response headers
    assert!(response.headers().contains_key("x-request-id"));
    assert!(response.headers().contains_key("x-response-time"));
    assert!(response.headers().contains_key("server"));
}

/// Test HTTP/2 request handling
#[tokio::test]
async fn test_http2_request_handling() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    // Test HTTP/2 request
    let request = create_test_request(Method::POST, "/api/data", Version::HTTP_2);
    let mut context = create_test_context(&request);
    
    let response = handler.handle_request(request, &mut context).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify HTTP/2 specific handling
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    
    assert_eq!(response_json["version"], "HTTP_2");
    assert_eq!(response_json["features"]["http2_enabled"], true);
}

/// Test request timeout handling
#[tokio::test]
async fn test_request_timeout() {
    let mut config = HttpConfig::default();
    config.timeouts.request_timeout = Duration::from_millis(100); // Very short timeout
    
    let handler = HttpHandler::new(config).unwrap();
    
    // Create a request that would normally succeed
    let request = create_test_request(Method::GET, "/api/test", Version::HTTP_11);
    let mut context = create_test_context(&request);
    
    // The request should complete within the timeout for this test
    let response = handler.handle_request(request, &mut context).await.unwrap();
    
    // Response should be successful since our handler is fast
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test unsupported HTTP version handling
#[tokio::test]
async fn test_unsupported_http_version() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    // Test with HTTP/0.9 (unsupported)
    let request = create_test_request(Method::GET, "/api/test", Version::HTTP_09);
    let mut context = create_test_context(&request);
    
    let response = handler.handle_request(request, &mut context).await.unwrap();
    assert_eq!(response.status(), StatusCode::HTTP_VERSION_NOT_SUPPORTED);
}

/// Test compression algorithms
#[tokio::test]
async fn test_compression_algorithms() {
    use flate2::{Compression, write::GzEncoder};
    use brotli::CompressorWriter;
    use flate2::write::DeflateEncoder;
    use std::io::Write;
    
    let test_data = "This is a test string that should compress well when using compression algorithms like gzip, brotli, and deflate. ".repeat(10);
    
    // Test gzip compression
    let gzip_result = {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(test_data.as_bytes()).unwrap();
        encoder.finish().unwrap()
    };
    assert!(gzip_result.len() < test_data.len());
    
    // Test brotli compression
    let brotli_result = {
        let mut compressed = Vec::new();
        {
            let mut compressor = CompressorWriter::new(&mut compressed, 4096, 6, 22);
            compressor.write_all(test_data.as_bytes()).unwrap();
        }
        compressed
    };
    assert!(brotli_result.len() < test_data.len());
    
    // Test deflate compression
    let deflate_result = {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(test_data.as_bytes()).unwrap();
        encoder.finish().unwrap()
    };
    assert!(deflate_result.len() < test_data.len());
    
    // Brotli should generally provide better compression than gzip
    assert!(brotli_result.len() <= gzip_result.len());
}

/// Test admin endpoints for HTTP configuration
#[tokio::test]
async fn test_http_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test getting HTTP configuration
    let response = server.get("/http/config").await;
    response.assert_status_ok();
    
    let config: HttpConfig = response.json();
    assert_eq!(config.http2_enabled, true);
    assert_eq!(config.compression.enabled, true);
    assert_eq!(config.cors.enabled, true);
}

/// Test updating HTTP configuration via admin API
#[tokio::test]
async fn test_update_http_config_via_admin() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Update HTTP configuration
    let mut new_config = HttpConfig::default();
    new_config.max_body_size = 32 * 1024 * 1024; // 32MB
    new_config.http2_enabled = false;
    
    let response = server
        .put("/http/config")
        .json(&new_config)
        .await;
    
    response.assert_status_ok();
    
    // Verify the configuration was updated
    let get_response = server.get("/http/config").await;
    get_response.assert_status_ok();
    
    let updated_config: HttpConfig = get_response.json();
    assert_eq!(updated_config.max_body_size, 32 * 1024 * 1024);
    assert_eq!(updated_config.http2_enabled, false);
}

/// Test HTTP/2 configuration via admin API
#[tokio::test]
async fn test_http2_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Get current HTTP/2 configuration
    let response = server.get("/http/http2").await;
    response.assert_status_ok();
    
    let http2_config: Http2Config = response.json();
    assert_eq!(http2_config.max_concurrent_streams, 100);
    
    // Update HTTP/2 configuration
    let mut new_http2_config = Http2Config::default();
    new_http2_config.max_concurrent_streams = 200;
    new_http2_config.enable_push = true;
    
    let update_response = server
        .put("/http/http2")
        .json(&new_http2_config)
        .await;
    
    update_response.assert_status_ok();
    
    // Verify the update
    let verify_response = server.get("/http/http2").await;
    verify_response.assert_status_ok();
    
    let updated_config: Http2Config = verify_response.json();
    assert_eq!(updated_config.max_concurrent_streams, 200);
    assert_eq!(updated_config.enable_push, true);
}

/// Test compression configuration via admin API
#[tokio::test]
async fn test_compression_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test compression configuration endpoint
    let response = server.get("/http/compression").await;
    response.assert_status_ok();
    
    let compression_config: CompressionConfig = response.json();
    assert_eq!(compression_config.enabled, true);
    assert_eq!(compression_config.level, 6);
    
    // Test compression test endpoint
    let test_request = json!({
        "data": "This is test data for compression testing. ".repeat(50)
    });
    
    let test_response = server
        .post("/http/compression/test")
        .json(&test_request)
        .await;
    
    test_response.assert_status_ok();
    
    let test_result: serde_json::Value = test_response.json();
    assert!(test_result["original_size"].as_u64().unwrap() > 0);
    assert!(test_result["compressed_sizes"]["gzip"].as_u64().unwrap() > 0);
    assert!(test_result["compression_ratios"]["gzip"].as_f64().unwrap() > 0.0);
}

/// Test CORS configuration via admin API
#[tokio::test]
async fn test_cors_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test CORS configuration endpoint
    let response = server.get("/http/cors").await;
    response.assert_status_ok();
    
    let cors_config: CorsConfig = response.json();
    assert_eq!(cors_config.enabled, true);
    assert!(cors_config.allowed_origins.contains(&"*".to_string()));
    
    // Test CORS policy test endpoint
    let test_request = json!({
        "origin": "https://example.com",
        "method": "GET",
        "headers": ["content-type", "authorization"]
    });
    
    let test_response = server
        .post("/http/cors/test")
        .json(&test_request)
        .await;
    
    test_response.assert_status_ok();
    
    let test_result: serde_json::Value = test_response.json();
    assert_eq!(test_result["allowed"], true);
    assert!(test_result["headers"].as_object().unwrap().contains_key("Access-Control-Allow-Origin"));
}

/// Test OpenAPI configuration via admin API
#[tokio::test]
async fn test_openapi_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test OpenAPI configuration endpoint (should be None initially)
    let response = server.get("/http/openapi").await;
    response.assert_status_ok();
    
    let openapi_config: Option<OpenApiConfig> = response.json();
    assert!(openapi_config.is_none());
    
    // Test OpenAPI validation endpoint
    let validation_request = json!({
        "spec_path": "test-api.yaml"
    });
    
    let validation_response = server
        .post("/http/openapi/validate")
        .json(&validation_request)
        .await;
    
    validation_response.assert_status_ok();
    
    let validation_result: serde_json::Value = validation_response.json();
    assert_eq!(validation_result["valid"], true);
}

/// Test timeout configuration via admin API
#[tokio::test]
async fn test_timeout_admin_endpoints() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test timeout configuration endpoint
    let response = server.get("/http/timeouts").await;
    response.assert_status_ok();
    
    let timeout_config: HttpTimeoutConfig = response.json();
    assert_eq!(timeout_config.request_timeout, Duration::from_secs(30));
    
    // Update timeout configuration
    let mut new_timeout_config = HttpTimeoutConfig::default();
    new_timeout_config.request_timeout = Duration::from_secs(60);
    new_timeout_config.upstream_timeout = Duration::from_secs(45);
    
    let update_response = server
        .put("/http/timeouts")
        .json(&new_timeout_config)
        .await;
    
    update_response.assert_status_ok();
    
    // Verify the update
    let verify_response = server.get("/http/timeouts").await;
    verify_response.assert_status_ok();
    
    let updated_config: HttpTimeoutConfig = verify_response.json();
    assert_eq!(updated_config.request_timeout, Duration::from_secs(60));
    assert_eq!(updated_config.upstream_timeout, Duration::from_secs(45));
}

/// Test HTTP status and metrics endpoints
#[tokio::test]
async fn test_http_status_and_metrics() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Test HTTP status endpoint
    let status_response = server.get("/http/status").await;
    status_response.assert_status_ok();
    
    let status: serde_json::Value = status_response.json();
    assert_eq!(status["http2_enabled"], true);
    assert_eq!(status["compression_enabled"], true);
    assert_eq!(status["cors_enabled"], true);
    
    // Test HTTP metrics endpoint
    let metrics_response = server.get("/http/metrics").await;
    metrics_response.assert_status_ok();
    
    let metrics: serde_json::Value = metrics_response.json();
    assert!(metrics["total_requests"].as_u64().unwrap() > 0);
    assert!(metrics["average_response_time_ms"].as_f64().unwrap() > 0.0);
}

/// Test configuration change history
#[tokio::test]
async fn test_config_change_history() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Make a configuration change
    let mut new_config = HttpConfig::default();
    new_config.max_body_size = 64 * 1024 * 1024; // 64MB
    
    let _update_response = server
        .put("/http/config")
        .json(&new_config)
        .await;
    
    // Check configuration history
    let history_response = server.get("/http/config/history").await;
    history_response.assert_status_ok();
    
    let history: Vec<serde_json::Value> = history_response.json();
    assert!(!history.is_empty());
    
    let latest_change = &history[0];
    assert_eq!(latest_change["change_type"], "http_config_update");
    assert!(latest_change["timestamp"].is_string());
}

/// Test invalid configuration validation
#[tokio::test]
async fn test_invalid_config_validation() {
    let initial_config = HttpConfig::default();
    let admin_state = HttpAdminState::new(initial_config);
    let admin_router = HttpAdminRouter::create_router(admin_state);
    
    let server = TestServer::new(admin_router).unwrap();
    
    // Try to set invalid configuration (max_body_size = 0)
    let mut invalid_config = HttpConfig::default();
    invalid_config.max_body_size = 0;
    
    let response = server
        .put("/http/config")
        .json(&invalid_config)
        .await;
    
    response.assert_status(StatusCode::BAD_REQUEST);
}

/// Test edge cases and error handling
#[tokio::test]
async fn test_edge_cases() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    // Test with empty request body
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/test")
        .version(Version::HTTP_11)
        .body(Body::empty())
        .unwrap();
    
    let mut context = create_test_context(&request);
    let response = handler.handle_request(request, &mut context).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    
    // Test with large headers
    let mut large_headers = HeaderMap::new();
    for i in 0..100 {
        large_headers.insert(
            HeaderName::from_bytes(format!("x-custom-header-{}", i).as_bytes()).unwrap(),
            HeaderValue::from_str(&format!("value-{}", i)).unwrap(),
        );
    }
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/test")
        .version(Version::HTTP_11)
        .body(Body::empty())
        .unwrap();
    
    let (mut parts, body) = request.into_parts();
    parts.headers = large_headers;
    let request = Request::from_parts(parts, body);
    
    let mut context = create_test_context(&request);
    let response = handler.handle_request(request, &mut context).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// Helper functions

fn create_test_request(method: Method, uri: &str, version: Version) -> Request {
    Request::builder()
        .method(method)
        .uri(uri)
        .version(version)
        .header("content-type", "application/json")
        .header("user-agent", "test-client/1.0")
        .body(Body::from(r#"{"test": "data"}"#))
        .unwrap()
}

fn create_test_context(request: &Request) -> RequestContext {
    let incoming_request = IncomingRequest::new(
        Protocol::Http,
        request.method().clone(),
        request.uri().clone(),
        request.version(),
        request.headers().clone(),
        Vec::new(), // Body will be read separately
        "127.0.0.1:8080".parse().unwrap(),
    );
    
    RequestContext::new(Arc::new(incoming_request))
}

/// Performance test for HTTP request handling
#[tokio::test]
async fn test_http_performance() {
    let config = HttpConfig::default();
    let handler = HttpHandler::new(config).unwrap();
    
    let start_time = std::time::Instant::now();
    let num_requests = 100;
    
    for _ in 0..num_requests {
        let request = create_test_request(Method::GET, "/api/test", Version::HTTP_11);
        let mut context = create_test_context(&request);
        
        let response = handler.handle_request(request, &mut context).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    let elapsed = start_time.elapsed();
    let requests_per_second = num_requests as f64 / elapsed.as_secs_f64();
    
    println!("Processed {} requests in {:?} ({:.2} req/s)", 
             num_requests, elapsed, requests_per_second);
    
    // Should be able to handle at least 100 requests per second
    assert!(requests_per_second > 100.0);
}

/// Test concurrent request handling
#[tokio::test]
async fn test_concurrent_requests() {
    let config = HttpConfig::default();
    let handler = Arc::new(HttpHandler::new(config).unwrap());
    
    let mut handles = Vec::new();
    let num_concurrent = 50;
    
    for i in 0..num_concurrent {
        let handler_clone = handler.clone();
        let handle = tokio::spawn(async move {
            let request = create_test_request(
                Method::GET, 
                &format!("/api/test/{}", i), 
                Version::HTTP_11
            );
            let mut context = create_test_context(&request);
            
            handler_clone.handle_request(request, &mut context).await
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    for handle in handles {
        let response = handle.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
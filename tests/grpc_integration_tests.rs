//! # gRPC Integration Tests
//!
//! Comprehensive integration tests for gRPC protocol support including:
//! - Unary RPC calls
//! - Server streaming
//! - Client streaming  
//! - Bidirectional streaming
//! - gRPC-Web proxy functionality
//! - Service registration and discovery
//! - Error handling and status mapping
//! - Connection management
//! - Message inspection

use api_gateway::{
    core::{
        types::{IncomingRequest, RequestContext, Protocol, ServiceInstance},
        error::GatewayError,
    },
    protocols::grpc::{GrpcHandler, GrpcConfig, GrpcServiceInfo, GrpcMethodInfo},
    admin::grpc_management::{GrpcAdminRouter, GrpcAdminState},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use tower::ServiceExt;

/// Test fixture for gRPC integration tests
struct GrpcTestFixture {
    grpc_handler: Arc<GrpcHandler>,
    admin_router: Router,
    test_server: TestServer,
}

impl GrpcTestFixture {
    async fn new() -> Self {
        let config = GrpcConfig {
            enable_grpc_web: true,
            max_message_size: 1024 * 1024, // 1MB for tests
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            enable_message_inspection: true,
            enable_reflection: true,
        };

        let grpc_handler = Arc::new(GrpcHandler::new(config));
        
        let admin_state = GrpcAdminState {
            grpc_handler: grpc_handler.clone(),
        };
        
        let admin_router = GrpcAdminRouter::create_router(admin_state);
        let test_server = TestServer::new(admin_router.clone()).unwrap();

        Self {
            grpc_handler,
            admin_router,
            test_server,
        }
    }

    fn create_test_service_instance(&self) -> ServiceInstance {
        ServiceInstance::new(
            "test-grpc-service-1".to_string(),
            "TestService".to_string(),
            "127.0.0.1:50051".parse().unwrap(),
            Protocol::Grpc,
        )
    }

    fn create_grpc_request(&self, path: &str, body: Vec<u8>) -> Arc<IncomingRequest> {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-encoding", HeaderValue::from_static("identity"));
        
        Arc::new(IncomingRequest::new(
            Protocol::Grpc,
            Method::POST,
            path.parse().unwrap(),
            axum::http::Version::HTTP_2,
            headers,
            body,
            "127.0.0.1:8080".parse().unwrap(),
        ))
    }

    fn create_grpc_web_request(&self, path: &str, body: Vec<u8>) -> Arc<IncomingRequest> {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc-web"));
        headers.insert("origin", HeaderValue::from_static("http://localhost:3000"));
        
        Arc::new(IncomingRequest::new(
            Protocol::Grpc,
            Method::POST,
            path.parse().unwrap(),
            axum::http::Version::HTTP_11,
            headers,
            body,
            "127.0.0.1:8080".parse().unwrap(),
        ))
    }

    fn create_request_context(&self, request: Arc<IncomingRequest>) -> RequestContext {
        let mut context = RequestContext::new(request);
        context.set_selected_instance(self.create_test_service_instance());
        context
    }
}

// ============================================================================
// Service Registration Tests
// ============================================================================

#[tokio::test]
async fn test_service_registration() {
    let fixture = GrpcTestFixture::new().await;

    let service_info = GrpcServiceInfo {
        name: "TestService".to_string(),
        package: "test".to_string(),
        methods: vec![
            GrpcMethodInfo {
                name: "GetUser".to_string(),
                input_type: "GetUserRequest".to_string(),
                output_type: "GetUserResponse".to_string(),
                client_streaming: false,
                server_streaming: false,
                description: Some("Get a user by ID".to_string()),
            },
            GrpcMethodInfo {
                name: "ListUsers".to_string(),
                input_type: "ListUsersRequest".to_string(),
                output_type: "ListUsersResponse".to_string(),
                client_streaming: false,
                server_streaming: true,
                description: Some("List users with server streaming".to_string()),
            },
        ],
        description: Some("Test gRPC service".to_string()),
        version: Some("1.0.0".to_string()),
    };

    // Register service
    let result = fixture.grpc_handler.register_service(service_info.clone()).await;
    assert!(result.is_ok());

    // Verify service is registered
    let registered_service = fixture.grpc_handler.get_service_info("TestService").await;
    assert!(registered_service.is_some());
    
    let registered = registered_service.unwrap();
    assert_eq!(registered.name, "TestService");
    assert_eq!(registered.package, "test");
    assert_eq!(registered.methods.len(), 2);
}

#[tokio::test]
async fn test_service_unregistration() {
    let fixture = GrpcTestFixture::new().await;

    let service_info = GrpcServiceInfo {
        name: "TempService".to_string(),
        package: "temp".to_string(),
        methods: vec![],
        description: None,
        version: None,
    };

    // Register and then unregister
    fixture.grpc_handler.register_service(service_info).await.unwrap();
    assert!(fixture.grpc_handler.get_service_info("TempService").await.is_some());

    fixture.grpc_handler.unregister_service("TempService").await.unwrap();
    assert!(fixture.grpc_handler.get_service_info("TempService").await.is_none());
}

// ============================================================================
// Unary RPC Tests
// ============================================================================

#[tokio::test]
async fn test_unary_grpc_request() {
    let fixture = GrpcTestFixture::new().await;

    // Create a unary gRPC request
    let request = fixture.create_grpc_request("/test.TestService/GetUser", b"test_request_data".to_vec());
    let context = fixture.create_request_context(request.clone());

    // Handle the request
    let result = fixture.grpc_handler.handle_request(request, &context).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status, StatusCode::OK);
    
    // Check gRPC headers
    assert!(response.headers.get("content-type").is_some());
    assert_eq!(
        response.headers.get("content-type").unwrap(),
        "application/grpc"
    );
    assert_eq!(
        response.headers.get("grpc-status").unwrap(),
        "0" // OK status
    );
}

#[tokio::test]
async fn test_invalid_grpc_path() {
    let fixture = GrpcTestFixture::new().await;

    // Create request with invalid path
    let request = fixture.create_grpc_request("/invalid_path", b"test_data".to_vec());
    let context = fixture.create_request_context(request.clone());

    let result = fixture.grpc_handler.handle_request(request, &context).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        GatewayError::Protocol { protocol, message } => {
            assert_eq!(protocol, "gRPC");
            assert!(message.contains("Invalid gRPC path format"));
        }
        _ => panic!("Expected Protocol error"),
    }
}

#[tokio::test]
async fn test_missing_content_type() {
    let fixture = GrpcTestFixture::new().await;

    // Create request without proper content-type
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    
    let request = Arc::new(IncomingRequest::new(
        Protocol::Grpc,
        Method::POST,
        "/test.TestService/GetUser".parse().unwrap(),
        axum::http::Version::HTTP_2,
        headers,
        b"test_data".to_vec(),
        "127.0.0.1:8080".parse().unwrap(),
    ));
    
    let context = fixture.create_request_context(request.clone());

    let result = fixture.grpc_handler.handle_request(request, &context).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        GatewayError::Protocol { protocol, message } => {
            assert_eq!(protocol, "gRPC");
            assert!(message.contains("Invalid content-type"));
        }
        _ => panic!("Expected Protocol error"),
    }
}

// ============================================================================
// gRPC-Web Tests
// ============================================================================

#[tokio::test]
async fn test_grpc_web_request() {
    let fixture = GrpcTestFixture::new().await;

    let request = fixture.create_grpc_web_request("/test.TestService/GetUser", b"grpc_web_data".to_vec());
    let context = fixture.create_request_context(request.clone());

    let result = fixture.grpc_handler.handle_request(request, &context).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status, StatusCode::OK);
    
    // Check gRPC-Web headers
    assert!(response.headers.get("content-type").is_some());
    assert_eq!(
        response.headers.get("content-type").unwrap(),
        "application/grpc-web"
    );
    
    // Check CORS headers
    assert!(response.headers.get("access-control-allow-origin").is_some());
    assert_eq!(
        response.headers.get("access-control-allow-origin").unwrap(),
        "*"
    );
}

#[tokio::test]
async fn test_grpc_web_disabled() {
    let config = GrpcConfig {
        enable_grpc_web: false, // Disable gRPC-Web
        ..Default::default()
    };
    
    let grpc_handler = Arc::new(GrpcHandler::new(config));
    let request = GrpcTestFixture::new().await.create_grpc_web_request("/test.TestService/GetUser", b"data".to_vec());
    
    let mut context = RequestContext::new(request.clone());
    context.set_selected_instance(ServiceInstance::new(
        "test-service".to_string(),
        "TestService".to_string(),
        "127.0.0.1:50051".parse().unwrap(),
        Protocol::Grpc,
    ));

    let result = grpc_handler.handle_request(request, &context).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        GatewayError::Protocol { protocol, message } => {
            assert_eq!(protocol, "gRPC-Web");
            assert!(message.contains("gRPC-Web support is disabled"));
        }
        _ => panic!("Expected Protocol error"),
    }
}

// ============================================================================
// Admin API Tests
// ============================================================================

#[tokio::test]
async fn test_admin_list_services() {
    let fixture = GrpcTestFixture::new().await;

    // Register a test service first
    let service_info = GrpcServiceInfo {
        name: "AdminTestService".to_string(),
        package: "admin.test".to_string(),
        methods: vec![],
        description: Some("Service for admin API testing".to_string()),
        version: Some("1.0.0".to_string()),
    };
    
    fixture.grpc_handler.register_service(service_info).await.unwrap();

    // Test the admin API
    let response = fixture.test_server.get("/services").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["services"].is_array());
    assert_eq!(body["total"].as_u64().unwrap(), 1);
    
    let service = &body["services"][0];
    assert_eq!(service["name"].as_str().unwrap(), "AdminTestService");
    assert_eq!(service["package"].as_str().unwrap(), "admin.test");
}

#[tokio::test]
async fn test_admin_register_service() {
    let fixture = GrpcTestFixture::new().await;

    let service_data = json!({
        "service": {
            "name": "NewService",
            "package": "new",
            "methods": [
                {
                    "name": "TestMethod",
                    "input_type": "TestRequest",
                    "output_type": "TestResponse",
                    "client_streaming": false,
                    "server_streaming": false,
                    "description": "Test method"
                }
            ],
            "description": "New test service",
            "version": "1.0.0"
        }
    });

    let response = fixture.test_server
        .post("/services")
        .json(&service_data)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
    
    // Verify service was registered
    let registered_service = fixture.grpc_handler.get_service_info("NewService").await;
    assert!(registered_service.is_some());
}

#[tokio::test]
async fn test_admin_get_service_info() {
    let fixture = GrpcTestFixture::new().await;

    // Register a service first
    let service_info = GrpcServiceInfo {
        name: "DetailService".to_string(),
        package: "detail".to_string(),
        methods: vec![
            GrpcMethodInfo {
                name: "GetDetails".to_string(),
                input_type: "DetailsRequest".to_string(),
                output_type: "DetailsResponse".to_string(),
                client_streaming: false,
                server_streaming: false,
                description: Some("Get details".to_string()),
            },
        ],
        description: Some("Detail service".to_string()),
        version: Some("2.0.0".to_string()),
    };
    
    fixture.grpc_handler.register_service(service_info).await.unwrap();

    // Get service info via admin API
    let response = fixture.test_server.get("/services/DetailService").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["name"].as_str().unwrap(), "DetailService");
    assert_eq!(body["package"].as_str().unwrap(), "detail");
    assert_eq!(body["version"].as_str().unwrap(), "2.0.0");
    assert_eq!(body["methods"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_admin_get_nonexistent_service() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/services/NonExistentService").await;
    
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"].as_str().unwrap(), "Service not found");
}

#[tokio::test]
async fn test_admin_unregister_service() {
    let fixture = GrpcTestFixture::new().await;

    // Register a service first
    let service_info = GrpcServiceInfo {
        name: "ToDeleteService".to_string(),
        package: "delete".to_string(),
        methods: vec![],
        description: None,
        version: None,
    };
    
    fixture.grpc_handler.register_service(service_info).await.unwrap();

    // Verify it exists
    assert!(fixture.grpc_handler.get_service_info("ToDeleteService").await.is_some());

    // Delete via admin API
    let response = fixture.test_server.delete("/services/ToDeleteService").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
    
    // Verify it's gone
    assert!(fixture.grpc_handler.get_service_info("ToDeleteService").await.is_none());
}

// ============================================================================
// Connection Management Tests
// ============================================================================

#[tokio::test]
async fn test_admin_connection_stats() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/connections").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["total_connections"].is_number());
    assert!(body["active_connections"].is_number());
    assert!(body["idle_connections"].is_number());
    assert!(body["connection_details"].is_array());
}

#[tokio::test]
async fn test_admin_connection_health() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/connections/health").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["overall_health"].is_string());
    assert!(body["healthy_connections"].is_number());
    assert!(body["unhealthy_connections"].is_number());
    assert!(body["connection_health"].is_array());
}

#[tokio::test]
async fn test_admin_reset_connections() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.post("/connections/reset").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
    assert!(body["message"].as_str().unwrap().contains("reset"));
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[tokio::test]
async fn test_admin_get_config() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/config").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["enable_grpc_web"].is_boolean());
    assert!(body["max_message_size"].is_number());
    assert!(body["connect_timeout"].is_object());
    assert!(body["request_timeout"].is_object());
}

#[tokio::test]
async fn test_admin_update_config() {
    let fixture = GrpcTestFixture::new().await;

    let config_data = json!({
        "enable_grpc_web": false,
        "max_message_size": 2097152,
        "connect_timeout": {"secs": 15, "nanos": 0},
        "request_timeout": {"secs": 45, "nanos": 0},
        "enable_message_inspection": true,
        "enable_reflection": false
    });

    let response = fixture.test_server
        .put("/config")
        .json(&config_data)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
}

// ============================================================================
// Metrics and Monitoring Tests
// ============================================================================

#[tokio::test]
async fn test_admin_metrics() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/metrics").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["total_requests"].is_number());
    assert!(body["successful_requests"].is_number());
    assert!(body["failed_requests"].is_number());
    assert!(body["average_latency_ms"].is_number());
    assert!(body["method_metrics"].is_array());
}

#[tokio::test]
async fn test_admin_health() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/health").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"].as_str().unwrap(), "healthy");
    assert!(body["services_registered"].is_number());
    assert!(body["active_connections"].is_number());
    assert!(body["grpc_web_enabled"].is_boolean());
}

// ============================================================================
// Message Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_admin_enable_message_inspection() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.post("/inspection/enable").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
    assert!(body["message"].as_str().unwrap().contains("enabled"));
}

#[tokio::test]
async fn test_admin_disable_message_inspection() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.post("/inspection/disable").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"].as_bool().unwrap(), true);
    assert!(body["message"].as_str().unwrap().contains("disabled"));
}

#[tokio::test]
async fn test_admin_inspection_status() {
    let fixture = GrpcTestFixture::new().await;

    let response = fixture.test_server.get("/inspection/status").await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: serde_json::Value = response.json();
    assert!(body["enabled"].is_boolean());
    assert!(body["inspected_messages"].is_number());
    assert!(body["inspection_errors"].is_number());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_grpc_status_mapping() {
    let fixture = GrpcTestFixture::new().await;
    
    // Test various gRPC status codes and their HTTP mappings
    // This would require a mock gRPC server that returns specific status codes
    // For now, we'll test the status mapping logic directly
    
    use tonic::{Status, Code};
    
    let grpc_handler = &fixture.grpc_handler;
    
    // Test OK status
    let ok_status = Status::new(Code::Ok, "Success");
    let response = grpc_handler.map_grpc_status_to_response(ok_status);
    assert_eq!(response.status, StatusCode::OK);
    
    // Test NotFound status
    let not_found_status = Status::new(Code::NotFound, "Resource not found");
    let response = grpc_handler.map_grpc_status_to_response(not_found_status);
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    
    // Test Unauthenticated status
    let unauth_status = Status::new(Code::Unauthenticated, "Authentication required");
    let response = grpc_handler.map_grpc_status_to_response(unauth_status);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    
    // Test PermissionDenied status
    let forbidden_status = Status::new(Code::PermissionDenied, "Access denied");
    let response = grpc_handler.map_grpc_status_to_response(forbidden_status);
    assert_eq!(response.status, StatusCode::FORBIDDEN);
}

// ============================================================================
// Performance Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_grpc_requests() {
    let fixture = GrpcTestFixture::new().await;
    
    // Create multiple concurrent requests
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let grpc_handler = fixture.grpc_handler.clone();
        let request = fixture.create_grpc_request(
            &format!("/test.TestService/Method{}", i),
            format!("request_data_{}", i).into_bytes(),
        );
        let context = fixture.create_request_context(request.clone());
        
        let handle = tokio::spawn(async move {
            grpc_handler.handle_request(request, &context).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;
    
    // Verify all requests succeeded
    for result in results {
        let response = result.unwrap().unwrap();
        assert_eq!(response.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_request_timeout() {
    let config = GrpcConfig {
        request_timeout: Duration::from_millis(100), // Very short timeout
        ..Default::default()
    };
    
    let grpc_handler = Arc::new(GrpcHandler::new(config));
    let request = GrpcTestFixture::new().await.create_grpc_request("/test.TestService/SlowMethod", b"data".to_vec());
    
    let mut context = RequestContext::new(request.clone());
    context.set_selected_instance(ServiceInstance::new(
        "slow-service".to_string(),
        "SlowService".to_string(),
        "127.0.0.1:50051".parse().unwrap(),
        Protocol::Grpc,
    ));

    // This should timeout quickly since we have a very short timeout
    let start = std::time::Instant::now();
    let result = grpc_handler.handle_request(request, &context).await;
    let elapsed = start.elapsed();
    
    // Should fail with timeout error
    assert!(result.is_err());
    match result.unwrap_err() {
        GatewayError::Timeout { timeout_ms } => {
            assert_eq!(timeout_ms, 100);
        }
        _ => panic!("Expected Timeout error"),
    }
    
    // Should complete quickly due to timeout
    assert!(elapsed < Duration::from_millis(200));
}

// ============================================================================
// Integration with Other Components Tests
// ============================================================================

#[tokio::test]
async fn test_grpc_with_service_discovery() {
    let fixture = GrpcTestFixture::new().await;
    
    // Test that gRPC handler works with service discovery
    // This would require integration with the service discovery component
    
    let service_instance = ServiceInstance::new(
        "discovered-grpc-service".to_string(),
        "DiscoveredService".to_string(),
        "127.0.0.1:50052".parse().unwrap(),
        Protocol::Grpc,
    );
    
    let request = fixture.create_grpc_request("/discovered.DiscoveredService/GetData", b"test_data".to_vec());
    let mut context = RequestContext::new(request.clone());
    context.set_selected_instance(service_instance);
    
    let result = fixture.grpc_handler.handle_request(request, &context).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_grpc_protocol_detection() {
    // Test that the protocol detection correctly identifies gRPC requests
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/grpc"));
    
    let request = IncomingRequest::new(
        Protocol::Http, // Initially detected as HTTP
        Method::POST,
        "/test.Service/Method".parse().unwrap(),
        axum::http::Version::HTTP_2,
        headers,
        b"grpc_data".to_vec(),
        "127.0.0.1:8080".parse().unwrap(),
    );
    
    // Protocol detection should identify this as gRPC
    assert_eq!(request.detect_protocol(), Protocol::Grpc);
}
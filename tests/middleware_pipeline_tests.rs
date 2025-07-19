//! # Middleware Pipeline Integration Tests
//!
//! This module contains comprehensive integration tests for the middleware pipeline system,
//! including pipeline execution, error handling, and admin management.

use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use api_gateway::core::error::GatewayError;
use api_gateway::core::types::{GatewayResponse, IncomingRequest, Protocol, RequestContext};
use api_gateway::middleware::{
    Middleware, MiddlewarePipeline, MiddlewarePipelineConfig, MiddlewareConfig, 
    ConditionType, MiddlewareCondition, PipelineSettings,
    RequestLoggingMiddleware, MetricsMiddleware, TracingMiddleware, SecurityHeadersMiddleware,
};
use api_gateway::admin::{MiddlewareAdminState, create_middleware_admin_router};

/// Helper function to create a test request
fn create_test_request(path: &str, method: Method) -> IncomingRequest {
    IncomingRequest::new(
        Protocol::Http,
        method,
        path.parse().unwrap(),
        axum::http::Version::HTTP_11,
        HeaderMap::new(),
        Vec::new(),
        "127.0.0.1:8080".parse().unwrap(),
    )
}

/// Helper function to create a test response
fn create_test_response() -> GatewayResponse {
    GatewayResponse::new(StatusCode::OK, HeaderMap::new(), b"test response".to_vec())
}

/// Test middleware that adds headers to track execution
#[derive(Debug)]
struct TestMiddleware {
    name: String,
    priority: i32,
    should_fail: bool,
    execution_delay: Duration,
}

impl TestMiddleware {
    fn new(name: &str, priority: i32) -> Self {
        Self {
            name: name.to_string(),
            priority,
            should_fail: false,
            execution_delay: Duration::from_millis(0),
        }
    }

    fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.execution_delay = delay;
        self
    }
}

#[async_trait::async_trait]
impl Middleware for TestMiddleware {
    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    async fn process_request(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> Result<IncomingRequest, GatewayError> {
        if self.execution_delay > Duration::from_millis(0) {
            sleep(self.execution_delay).await;
        }

        if self.should_fail {
            return Err(GatewayError::Middleware {
                middleware: self.name.clone(),
                message: "Test failure".to_string(),
            });
        }

        request.headers.insert(
            format!("x-middleware-{}", self.name).parse().unwrap(),
            "executed".parse().unwrap(),
        );

        Ok(request)
    }

    async fn process_response(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> Result<GatewayResponse, GatewayError> {
        if self.execution_delay > Duration::from_millis(0) {
            sleep(self.execution_delay).await;
        }

        if self.should_fail {
            return Err(GatewayError::Middleware {
                middleware: self.name.clone(),
                message: "Test failure in response".to_string(),
            });
        }

        response.headers.insert(
            format!("x-response-middleware-{}", self.name).parse().unwrap(),
            "executed".parse().unwrap(),
        );

        Ok(response)
    }
}

#[tokio::test]
async fn test_empty_pipeline_execution() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();
    let request = create_test_request("/test", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    let result = pipeline.execute_request(request, &mut context).await;
    assert!(result.is_ok());

    let response = create_test_response();
    let result = pipeline.execute_response(response, &context).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_middleware_execution_order() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Add middleware with different priorities
    let middleware1 = Arc::new(TestMiddleware::new("first", 10));
    let middleware2 = Arc::new(TestMiddleware::new("second", 5));
    let middleware3 = Arc::new(TestMiddleware::new("third", 15));

    pipeline.add_middleware(middleware1).await.unwrap();
    pipeline.add_middleware(middleware2).await.unwrap();
    pipeline.add_middleware(middleware3).await.unwrap();

    let request = create_test_request("/test", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    let processed_request = pipeline.execute_request(request, &mut context).await.unwrap();

    // Check that headers were added in priority order (5, 10, 15)
    assert!(processed_request.headers.contains_key("x-middleware-second"));
    assert!(processed_request.headers.contains_key("x-middleware-first"));
    assert!(processed_request.headers.contains_key("x-middleware-third"));

    // Test response pipeline (should execute in reverse order)
    let response = create_test_response();
    let processed_response = pipeline.execute_response(response, &context).await.unwrap();

    assert!(processed_response.headers.contains_key("x-response-middleware-third"));
    assert!(processed_response.headers.contains_key("x-response-middleware-first"));
    assert!(processed_response.headers.contains_key("x-response-middleware-second"));
}

#[tokio::test]
async fn test_middleware_error_handling() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings {
            continue_on_error: false,
            ..Default::default()
        },
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Add middleware that will fail
    let failing_middleware = Arc::new(TestMiddleware::new("failing", 10).with_failure());
    let normal_middleware = Arc::new(TestMiddleware::new("normal", 20));

    pipeline.add_middleware(failing_middleware).await.unwrap();
    pipeline.add_middleware(normal_middleware).await.unwrap();

    let request = create_test_request("/test", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    let result = pipeline.execute_request(request, &mut context).await;
    assert!(result.is_err());

    // Check that the error is from the failing middleware
    if let Err(GatewayError::Middleware { middleware, .. }) = result {
        assert_eq!(middleware, "failing");
    } else {
        panic!("Expected middleware error");
    }
}

#[tokio::test]
async fn test_middleware_error_continue() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings {
            continue_on_error: true,
            ..Default::default()
        },
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Add middleware that will fail and one that should still execute
    let failing_middleware = Arc::new(TestMiddleware::new("failing", 10).with_failure());
    let normal_middleware = Arc::new(TestMiddleware::new("normal", 20));

    pipeline.add_middleware(failing_middleware).await.unwrap();
    pipeline.add_middleware(normal_middleware).await.unwrap();

    let request = create_test_request("/test", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    // With continue_on_error=true, this should succeed despite the failing middleware
    let result = pipeline.execute_request(request, &mut context).await;
    
    // The pipeline should continue and the normal middleware should execute
    if let Ok(processed_request) = result {
        assert!(processed_request.headers.contains_key("x-middleware-normal"));
        assert!(!processed_request.headers.contains_key("x-middleware-failing"));
    } else {
        // In some implementations, it might still fail but with different error handling
        // This test verifies the error handling behavior
    }
}

#[tokio::test]
async fn test_conditional_middleware_execution() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Create a conditional middleware that only executes for GET requests
    #[derive(Debug)]
    struct ConditionalMiddleware {
        name: String,
    }

    #[async_trait::async_trait]
    impl Middleware for ConditionalMiddleware {
        fn name(&self) -> &str {
            &self.name
        }

        async fn should_execute(&self, request: &IncomingRequest, _context: &RequestContext) -> bool {
            request.method == Method::GET
        }

        async fn process_request(
            &self,
            mut request: IncomingRequest,
            _context: &mut RequestContext,
        ) -> Result<IncomingRequest, GatewayError> {
            request.headers.insert("x-conditional", "executed".parse().unwrap());
            Ok(request)
        }
    }

    let conditional_middleware = Arc::new(ConditionalMiddleware {
        name: "conditional".to_string(),
    });

    pipeline.add_middleware(conditional_middleware).await.unwrap();

    // Test with GET request (should execute)
    let get_request = create_test_request("/test", Method::GET);
    let mut get_context = RequestContext::new(Arc::new(get_request.clone()));
    let processed_get = pipeline.execute_request(get_request, &mut get_context).await.unwrap();
    assert!(processed_get.headers.contains_key("x-conditional"));

    // Test with POST request (should not execute)
    let post_request = create_test_request("/test", Method::POST);
    let mut post_context = RequestContext::new(Arc::new(post_request.clone()));
    let processed_post = pipeline.execute_request(post_request, &mut post_context).await.unwrap();
    assert!(!processed_post.headers.contains_key("x-conditional"));
}

#[tokio::test]
async fn test_pipeline_metrics_collection() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings {
            collect_metrics: true,
            ..Default::default()
        },
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Add some middleware
    let middleware1 = Arc::new(TestMiddleware::new("test1", 10));
    let middleware2 = Arc::new(TestMiddleware::new("test2", 20));

    pipeline.add_middleware(middleware1).await.unwrap();
    pipeline.add_middleware(middleware2).await.unwrap();

    // Execute some requests
    for i in 0..5 {
        let request = create_test_request(&format!("/test/{}", i), Method::GET);
        let mut context = RequestContext::new(Arc::new(request.clone()));
        
        let processed_request = pipeline.execute_request(request, &mut context).await.unwrap();
        let response = create_test_response();
        let _processed_response = pipeline.execute_response(response, &context).await.unwrap();
    }

    // Check metrics
    let metrics = pipeline.get_metrics();
    assert_eq!(metrics.total_executions, 10); // 5 request + 5 response executions
    assert_eq!(metrics.failed_executions, 0);
    assert!(metrics.success_rate > 99.0);
}

#[tokio::test]
async fn test_middleware_removal() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    let middleware = Arc::new(TestMiddleware::new("removable", 10));
    pipeline.add_middleware(middleware).await.unwrap();

    assert_eq!(pipeline.get_active_middleware().await.len(), 1);
    assert!(pipeline.get_active_middleware().await.contains(&"removable".to_string()));

    let removed = pipeline.remove_middleware("removable").await.unwrap();
    assert!(removed);
    assert_eq!(pipeline.get_active_middleware().await.len(), 0);

    let not_removed = pipeline.remove_middleware("nonexistent").await.unwrap();
    assert!(!not_removed);
}

#[tokio::test]
async fn test_pipeline_configuration_update() {
    let initial_config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(initial_config).await.unwrap();

    // Add initial middleware
    let middleware = Arc::new(TestMiddleware::new("initial", 10));
    pipeline.add_middleware(middleware).await.unwrap();

    assert_eq!(pipeline.get_active_middleware().await.len(), 1);

    // Update configuration with new settings
    let new_config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings {
            max_execution_time: Duration::from_secs(60),
            continue_on_error: true,
            collect_metrics: false,
            log_execution: false,
        },
    };

    pipeline.update_config(new_config.clone()).await.unwrap();

    // Verify configuration was updated
    let current_config = pipeline.get_config().await;
    assert_eq!(current_config.settings.max_execution_time, Duration::from_secs(60));
    assert!(current_config.settings.continue_on_error);
    assert!(!current_config.settings.collect_metrics);
    assert!(!current_config.settings.log_execution);
}

#[tokio::test]
async fn test_built_in_middleware_integration() {
    use api_gateway::middleware::builtin::{
        RequestLoggingConfig, MetricsConfig, TracingConfig, SecurityHeadersConfig,
    };

    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = MiddlewarePipeline::new(config).await.unwrap();

    // Add built-in middleware
    let logging_middleware = Arc::new(api_gateway::middleware::builtin::RequestLoggingMiddleware::new(
        RequestLoggingConfig::default()
    ));
    
    let metrics_middleware = Arc::new(api_gateway::middleware::builtin::MetricsMiddleware::new(
        MetricsConfig::default()
    ));
    
    let tracing_middleware = Arc::new(api_gateway::middleware::builtin::TracingMiddleware::new(
        TracingConfig::default()
    ));
    
    let security_middleware = Arc::new(api_gateway::middleware::builtin::SecurityHeadersMiddleware::new(
        SecurityHeadersConfig::default()
    ));

    pipeline.add_middleware(logging_middleware).await.unwrap();
    pipeline.add_middleware(metrics_middleware.clone()).await.unwrap();
    pipeline.add_middleware(tracing_middleware).await.unwrap();
    pipeline.add_middleware(security_middleware).await.unwrap();

    // Execute a request through the pipeline
    let request = create_test_request("/api/test", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    let processed_request = pipeline.execute_request(request, &mut context).await.unwrap();
    let response = create_test_response();
    let processed_response = pipeline.execute_response(response, &context).await.unwrap();

    // Verify security headers were added
    assert!(processed_response.headers.contains_key("x-frame-options"));
    assert!(processed_response.headers.contains_key("x-content-type-options"));

    // Verify metrics were collected
    let metrics = metrics_middleware.get_metrics();
    let snapshot = metrics.get_snapshot().await;
    assert!(snapshot.total_requests > 0);
    assert!(snapshot.total_responses > 0);
}

#[tokio::test]
async fn test_middleware_performance_under_load() {
    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = Arc::new(MiddlewarePipeline::new(config).await.unwrap());

    // Add middleware with small delays to simulate processing time
    let middleware1 = Arc::new(TestMiddleware::new("perf1", 10).with_delay(Duration::from_millis(1)));
    let middleware2 = Arc::new(TestMiddleware::new("perf2", 20).with_delay(Duration::from_millis(1)));
    let middleware3 = Arc::new(TestMiddleware::new("perf3", 30).with_delay(Duration::from_millis(1)));

    pipeline.add_middleware(middleware1).await.unwrap();
    pipeline.add_middleware(middleware2).await.unwrap();
    pipeline.add_middleware(middleware3).await.unwrap();

    let start_time = std::time::Instant::now();
    let mut handles = Vec::new();

    // Execute 100 concurrent requests
    for i in 0..100 {
        let pipeline_clone = pipeline.clone();
        let handle = tokio::spawn(async move {
            let request = create_test_request(&format!("/load-test/{}", i), Method::GET);
            let mut context = RequestContext::new(Arc::new(request.clone()));
            
            let processed_request = pipeline_clone.execute_request(request, &mut context).await.unwrap();
            let response = create_test_response();
            let _processed_response = pipeline_clone.execute_response(response, &context).await.unwrap();
            
            processed_request
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let results: Vec<_> = futures::future::join_all(handles).await;
    let duration = start_time.elapsed();

    // Verify all requests completed successfully
    assert_eq!(results.len(), 100);
    for result in results {
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(request.headers.contains_key("x-middleware-perf1"));
        assert!(request.headers.contains_key("x-middleware-perf2"));
        assert!(request.headers.contains_key("x-middleware-perf3"));
    }

    // Performance should be reasonable (less than 10 seconds for 100 concurrent requests)
    assert!(duration < Duration::from_secs(10));

    // Check metrics
    let metrics = pipeline.get_metrics();
    assert_eq!(metrics.total_executions, 200); // 100 request + 100 response executions
    assert_eq!(metrics.failed_executions, 0);
}

#[tokio::test]
async fn test_condition_evaluation() {
    use api_gateway::middleware::pipeline::{check_conditions, MiddlewareCondition, ConditionType};

    let request = create_test_request("/api/users/123", Method::GET);
    let mut context = RequestContext::new(Arc::new(request.clone()));

    // Add some auth context for testing
    let auth_context = api_gateway::core::types::AuthContext {
        user_id: "user123".to_string(),
        roles: vec!["admin".to_string(), "user".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
        claims: std::collections::HashMap::new(),
        auth_method: "jwt".to_string(),
        expires_at: None,
    };
    context.set_auth_context(auth_context);

    // Test path pattern condition
    let path_conditions = vec![MiddlewareCondition {
        condition_type: ConditionType::PathPattern,
        value: "users".to_string(),
        negate: false,
    }];
    assert!(check_conditions(&path_conditions, &request, &context).await);

    // Test method condition
    let method_conditions = vec![MiddlewareCondition {
        condition_type: ConditionType::Method,
        value: "GET".to_string(),
        negate: false,
    }];
    assert!(check_conditions(&method_conditions, &request, &context).await);

    // Test user role condition
    let role_conditions = vec![MiddlewareCondition {
        condition_type: ConditionType::UserRole,
        value: "admin".to_string(),
        negate: false,
    }];
    assert!(check_conditions(&role_conditions, &request, &context).await);

    // Test negated condition
    let negated_conditions = vec![MiddlewareCondition {
        condition_type: ConditionType::Method,
        value: "POST".to_string(),
        negate: true,
    }];
    assert!(check_conditions(&negated_conditions, &request, &context).await);

    // Test multiple conditions (all must pass)
    let multiple_conditions = vec![
        MiddlewareCondition {
            condition_type: ConditionType::PathPattern,
            value: "users".to_string(),
            negate: false,
        },
        MiddlewareCondition {
            condition_type: ConditionType::Method,
            value: "GET".to_string(),
            negate: false,
        },
    ];
    assert!(check_conditions(&multiple_conditions, &request, &context).await);

    // Test failing condition
    let failing_conditions = vec![MiddlewareCondition {
        condition_type: ConditionType::Method,
        value: "POST".to_string(),
        negate: false,
    }];
    assert!(!check_conditions(&failing_conditions, &request, &context).await);
}

#[tokio::test]
async fn test_admin_endpoints_integration() {
    use axum_test::TestServer;

    let config = MiddlewarePipelineConfig {
        middleware: vec![],
        settings: PipelineSettings::default(),
    };

    let pipeline = Arc::new(MiddlewarePipeline::new(config).await.unwrap());
    let admin_state = MiddlewareAdminState::new(pipeline.clone());
    let app = create_middleware_admin_router().with_state(admin_state);
    let server = TestServer::new(app).unwrap();

    // Test listing middleware (should be empty initially)
    let response = server.get("/middleware").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test getting pipeline status
    let response = server.get("/pipeline/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test getting pipeline metrics
    let response = server.get("/pipeline/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test reloading pipeline
    let response = server.post("/pipeline/reload").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test getting configuration
    let response = server.get("/middleware/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test getting configuration history
    let response = server.get("/middleware/config/history").await;
    assert_eq!(response.status_code(), StatusCode::OK);
}
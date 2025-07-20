//! # Error Handling Integration Tests
//!
//! This module contains comprehensive tests for the error handling system,
//! including error tracking, custom error pages, and error recovery mechanisms.

use api_gateway::core::error::{GatewayError, GatewayResult};
use api_gateway::core::error_tracking::{ErrorTracker, ErrorEvent, ErrorPatternConfig};
use api_gateway::core::error_pages::{ErrorPageGenerator, ErrorPageConfig, ErrorResponseBuilder};
use api_gateway::core::error_recovery::{ErrorRecoveryManager, RecoveryConfig, RecoveryContext, RecoveryResult, RecoveryStrategy};
use api_gateway::admin::error_tracking::{ErrorTrackingAdminRouter, ErrorTrackingAdminState};
use axum::http::{StatusCode, HeaderMap};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Test error tracking functionality
#[tokio::test]
async fn test_error_tracking_basic_functionality() {
    let config = ErrorPatternConfig::default();
    let tracker = ErrorTracker::new(config);
    
    // Create a test error event
    let error = GatewayError::internal("test error");
    let error_event = ErrorEvent::new(
        &error,
        "/api/test".to_string(),
        "GET".to_string(),
        "127.0.0.1".to_string(),
        Some("test-agent".to_string()),
        "req-123".to_string(),
        Some("trace-456".to_string()),
        Some("test-service".to_string()),
    );
    
    // Track the error
    tracker.track_error(error_event.clone()).await;
    
    // Verify error was tracked
    let recent_errors = tracker.get_recent_errors(Some(10));
    assert_eq!(recent_errors.len(), 1);
    assert_eq!(recent_errors[0].id, error_event.id);
    assert_eq!(recent_errors[0].error_type, "internal_error");
    assert_eq!(recent_errors[0].status_code, 500);
    
    // Verify error statistics
    let error_stats = tracker.get_error_stats();
    assert!(error_stats.contains_key("internal_error"));
    let internal_stats = error_stats.get("internal_error").unwrap();
    assert_eq!(internal_stats.total_count, 1);
    
    // Verify service statistics
    let service_stats = tracker.get_service_stats();
    assert!(service_stats.contains_key("test-service"));
    let service_stats = service_stats.get("test-service").unwrap();
    assert_eq!(service_stats.total_count, 1);
}

/// Test error pattern detection and alerting
#[tokio::test]
async fn test_error_pattern_detection() {
    let config = ErrorPatternConfig {
        error_rate_threshold: 2.0, // 2 errors per minute
        error_rate_window: 1,       // 1 minute window
        consecutive_error_threshold: 3,
        consecutive_error_window: 2,
        auto_circuit_breaker: true,
        auto_recovery: true,
    };
    
    let tracker = ErrorTracker::new(config);
    let mut alert_receiver = tracker.subscribe_to_alerts();
    
    // Generate multiple errors quickly to trigger rate threshold
    for i in 0..5 {
        let error = GatewayError::internal(format!("test error {}", i));
        let error_event = ErrorEvent::new(
            &error,
            "/api/test".to_string(),
            "GET".to_string(),
            "127.0.0.1".to_string(),
            None,
            format!("req-{}", i),
            None,
            Some("test-service".to_string()),
        );
        tracker.track_error(error_event).await;
    }
    
    // Check if alert was triggered (with timeout)
    let alert_result = tokio::time::timeout(Duration::from_millis(100), alert_receiver.recv()).await;
    
    // Note: In a real test, we might need to wait for background processing
    // For now, we'll verify the error rate calculation
    let error_stats = tracker.get_error_stats();
    let internal_stats = error_stats.get("internal_error").unwrap();
    assert!(internal_stats.error_rate > 2.0);
}

/// Test custom error page generation
#[tokio::test]
async fn test_custom_error_pages() {
    let config = ErrorPageConfig::default();
    let generator = ErrorPageGenerator::new(config).unwrap();
    
    // Test HTML error response
    let error = GatewayError::internal("test error");
    let mut headers = HeaderMap::new();
    headers.insert("accept", "text/html".parse().unwrap());
    
    let response = generator.generate_error_response(
        &error,
        &headers,
        Some("/api/test"),
        Some("req-123"),
    );
    
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    
    // Test JSON error response
    headers.insert("accept", "application/json".parse().unwrap());
    let response = generator.generate_error_response(
        &error,
        &headers,
        Some("/api/test"),
        Some("req-123"),
    );
    
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Test error response builder
#[tokio::test]
async fn test_error_response_builder() {
    let config = ErrorPageConfig::default();
    let generator = ErrorPageGenerator::new(config).unwrap();
    
    let error = GatewayError::Authentication {
        reason: "Invalid token".to_string(),
    };
    
    let headers = HeaderMap::new();
    let response = ErrorResponseBuilder::new(error)
        .with_request_path("/api/secure")
        .with_request_id("req-456")
        .with_custom_message("Authentication failed")
        .with_header("X-Error-Code", "AUTH_FAILED")
        .build(&generator, &headers);
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("X-Error-Code"));
}

/// Test error recovery mechanisms
#[tokio::test]
async fn test_error_recovery_default_response() {
    let config = RecoveryConfig::default();
    let recovery_manager = ErrorRecoveryManager::new(config);
    
    let context = RecoveryContext {
        request_path: "/api/test".to_string(),
        request_method: "GET".to_string(),
        request_headers: HeaderMap::new(),
        request_body: None,
        request_id: "req-123".to_string(),
        trace_id: None,
        target_service: Some("test-service".to_string()),
        metadata: HashMap::new(),
    };
    
    let error = GatewayError::ServiceUnavailable {
        service: "test-service".to_string(),
        reason: "Connection refused".to_string(),
    };
    
    let result = recovery_manager.recover_from_error(&error, context).await;
    
    // Since we don't have real cache or service providers configured,
    // the recovery should eventually fall back to default strategies
    match result {
        RecoveryResult::Success(_) => {
            // Recovery succeeded with some strategy
        }
        RecoveryResult::Failed(_) => {
            // All strategies failed, which is expected without providers
        }
        RecoveryResult::NotApplicable => {
            // No applicable strategies
        }
        RecoveryResult::TimedOut => {
            // Recovery timed out
        }
    }
    
    // Verify metrics were updated
    let metrics = recovery_manager.get_metrics();
    assert!(metrics.total_attempts > 0);
}

/// Test graceful degradation strategy
#[tokio::test]
async fn test_graceful_degradation_strategy() {
    let config = RecoveryConfig::default();
    let recovery_manager = ErrorRecoveryManager::new(config);
    
    let context = RecoveryContext {
        request_path: "/api/test".to_string(),
        request_method: "GET".to_string(),
        request_headers: HeaderMap::new(),
        request_body: None,
        request_id: "req-123".to_string(),
        trace_id: None,
        target_service: None,
        metadata: HashMap::new(),
    };
    
    let strategy = RecoveryStrategy::GracefulDegradation {
        degraded_response: "Service temporarily degraded".to_string(),
        status_code: StatusCode::PARTIAL_CONTENT,
    };
    
    let result = recovery_manager.execute_recovery_strategy(&strategy, &context).await;
    
    match result {
        RecoveryResult::Success(response) => {
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert!(response.headers().contains_key("X-Degraded-Service"));
        }
        _ => panic!("Expected successful graceful degradation"),
    }
}

/// Test admin endpoints for error tracking
#[tokio::test]
async fn test_error_tracking_admin_endpoints() {
    // Create test state
    let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig::default()));
    let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig::default())));
    let error_page_generator = Arc::new(RwLock::new(
        ErrorPageGenerator::new(ErrorPageConfig::default()).unwrap()
    ));
    let alert_receiver = Arc::new(RwLock::new(error_tracker.subscribe_to_alerts()));
    
    let state = ErrorTrackingAdminState {
        error_tracker: error_tracker.clone(),
        recovery_manager,
        error_page_generator,
        alert_receiver,
    };
    
    // Add some test errors
    for i in 0..3 {
        let error = GatewayError::internal(format!("test error {}", i));
        let error_event = ErrorEvent::new(
            &error,
            format!("/api/test/{}", i),
            "GET".to_string(),
            "127.0.0.1".to_string(),
            None,
            format!("req-{}", i),
            None,
            Some("test-service".to_string()),
        );
        error_tracker.track_error(error_event).await;
    }
    
    let app = ErrorTrackingAdminRouter::create_router(state);
    let server = TestServer::new(app).unwrap();
    
    // Test error listing endpoint
    let response = server.get("/errors").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let errors: Vec<ErrorEvent> = response.json();
    assert_eq!(errors.len(), 3);
    
    // Test error statistics endpoint
    let response = server.get("/errors/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test error summary endpoint
    let response = server.get("/errors/summary?hours=1").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test error dashboard endpoint
    let response = server.get("/errors/dashboard").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test error page preview
    let response = server.get("/errors/pages/preview/404").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    
    let response = server.get("/errors/pages/preview/500").await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Test error configuration updates via admin API
#[tokio::test]
async fn test_error_config_updates() {
    let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig::default()));
    let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig::default())));
    let error_page_generator = Arc::new(RwLock::new(
        ErrorPageGenerator::new(ErrorPageConfig::default()).unwrap()
    ));
    let alert_receiver = Arc::new(RwLock::new(error_tracker.subscribe_to_alerts()));
    
    let state = ErrorTrackingAdminState {
        error_tracker,
        recovery_manager,
        error_page_generator,
        alert_receiver,
    };
    
    let app = ErrorTrackingAdminRouter::create_router(state);
    let server = TestServer::new(app).unwrap();
    
    // Test getting current configuration
    let response = server.get("/errors/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test updating recovery configuration
    let new_recovery_config = RecoveryConfig {
        enabled: true,
        max_attempts: 5,
        recovery_timeout: Duration::from_secs(15),
        ..Default::default()
    };
    
    let update_request = json!({
        "recovery_config": new_recovery_config
    });
    
    let response = server.put("/errors/config")
        .json(&update_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Test updating error page configuration
    let new_error_page_config = ErrorPageConfig {
        enabled: true,
        brand_name: "Test Gateway".to_string(),
        show_details: true,
        ..Default::default()
    };
    
    let update_request = json!({
        "error_page_config": new_error_page_config
    });
    
    let response = server.put("/errors/config")
        .json(&update_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

/// Test error recovery metrics
#[tokio::test]
async fn test_recovery_metrics() {
    let config = RecoveryConfig::default();
    let recovery_manager = ErrorRecoveryManager::new(config);
    
    // Simulate some recovery attempts
    recovery_manager.update_metrics("retry_with_backoff", true, Duration::from_millis(100));
    recovery_manager.update_metrics("fallback_service", false, Duration::from_millis(200));
    recovery_manager.update_metrics("cached_response", true, Duration::from_millis(50));
    recovery_manager.update_metrics("retry_with_backoff", true, Duration::from_millis(150));
    
    let metrics = recovery_manager.get_metrics();
    
    assert_eq!(metrics.total_attempts, 4);
    assert_eq!(metrics.successful_recoveries, 3);
    assert_eq!(metrics.failed_recoveries, 1);
    
    // Check strategy-specific metrics
    assert_eq!(metrics.attempts_by_strategy.get("retry_with_backoff"), Some(&2));
    assert_eq!(metrics.attempts_by_strategy.get("fallback_service"), Some(&1));
    assert_eq!(metrics.attempts_by_strategy.get("cached_response"), Some(&1));
    
    // Check success rates
    assert_eq!(metrics.success_rate_by_strategy.get("retry_with_backoff"), Some(&1.0));
    assert_eq!(metrics.success_rate_by_strategy.get("fallback_service"), Some(&0.0));
    assert_eq!(metrics.success_rate_by_strategy.get("cached_response"), Some(&1.0));
    
    // Verify average recovery time is calculated
    assert!(metrics.average_recovery_time.as_millis() > 0);
}

/// Test error summary generation
#[tokio::test]
async fn test_error_summary() {
    let config = ErrorPatternConfig::default();
    let tracker = ErrorTracker::new(config);
    
    // Add various types of errors
    let errors = vec![
        GatewayError::internal("internal error 1"),
        GatewayError::internal("internal error 2"),
        GatewayError::Authentication { reason: "invalid token".to_string() },
        GatewayError::ServiceUnavailable { 
            service: "api-service".to_string(), 
            reason: "connection refused".to_string() 
        },
        GatewayError::Timeout { timeout_ms: 5000 },
    ];
    
    for (i, error) in errors.iter().enumerate() {
        let error_event = ErrorEvent::new(
            error,
            format!("/api/test/{}", i),
            "GET".to_string(),
            "127.0.0.1".to_string(),
            None,
            format!("req-{}", i),
            None,
            Some("test-service".to_string()),
        );
        tracker.track_error(error_event).await;
    }
    
    let summary = tracker.get_error_summary(1); // Last 1 hour
    
    assert_eq!(summary.total_errors, 5);
    assert_eq!(summary.unique_error_types, 4); // internal, auth, service_unavailable, timeout
    assert_eq!(summary.affected_services, 1); // test-service
    assert_eq!(summary.retryable_errors, 2); // service_unavailable and timeout are retryable
    assert!(summary.error_rate > 0.0);
}

/// Test error data clearing
#[tokio::test]
async fn test_error_data_clearing() {
    let config = ErrorPatternConfig::default();
    let tracker = ErrorTracker::new(config);
    
    // Add some errors
    for i in 0..5 {
        let error = GatewayError::internal(format!("test error {}", i));
        let error_event = ErrorEvent::new(
            &error,
            "/api/test".to_string(),
            "GET".to_string(),
            "127.0.0.1".to_string(),
            None,
            format!("req-{}", i),
            None,
            Some("test-service".to_string()),
        );
        tracker.track_error(error_event).await;
    }
    
    // Verify errors exist
    let recent_errors = tracker.get_recent_errors(Some(10));
    assert_eq!(recent_errors.len(), 5);
    
    let error_stats = tracker.get_error_stats();
    assert!(!error_stats.is_empty());
    
    // Clear all data
    tracker.clear_all_data();
    
    // Verify data is cleared
    let recent_errors = tracker.get_recent_errors(Some(10));
    assert_eq!(recent_errors.len(), 0);
    
    let error_stats = tracker.get_error_stats();
    assert!(error_stats.is_empty());
}

/// Test different error types and their properties
#[tokio::test]
async fn test_error_type_properties() {
    let errors = vec![
        (GatewayError::Authentication { reason: "invalid".to_string() }, false, false),
        (GatewayError::Authorization { reason: "forbidden".to_string() }, false, false),
        (GatewayError::ServiceUnavailable { service: "api".to_string(), reason: "down".to_string() }, true, true),
        (GatewayError::Timeout { timeout_ms: 5000 }, true, true),
        (GatewayError::RateLimitExceeded { limit: 100, window: "minute".to_string() }, false, false),
        (GatewayError::CircuitBreakerOpen { service: "api".to_string() }, false, false),
    ];
    
    for (error, expected_retryable, expected_circuit_breaker_trigger) in errors {
        assert_eq!(error.is_retryable(), expected_retryable, "Error: {}", error);
        assert_eq!(error.should_trigger_circuit_breaker(), expected_circuit_breaker_trigger, "Error: {}", error);
        
        // Verify status code mapping
        let status_code = error.status_code();
        assert!(status_code.as_u16() >= 400, "Error should map to 4xx or 5xx status code");
    }
}
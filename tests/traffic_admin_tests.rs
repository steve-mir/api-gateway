//! # Traffic Admin API Tests
//!
//! Comprehensive tests for the traffic management admin endpoints.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use axum_test::TestServer;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

use gateway::admin::{AdminRouter, AdminState, RuntimeConfigManager, ConfigAudit, TrafficAdminState};
use gateway::core::config::GatewayConfig;
use gateway::traffic::{TrafficManager, TrafficConfig, BackpressureConfig, ThrottleConfig, PriorityConfig, ShutdownConfig};

async fn create_test_server() -> TestServer {
    // Create traffic manager with test configuration
    let traffic_config = TrafficConfig {
        queue: BackpressureConfig {
            max_queue_size: 1000,
            backpressure_threshold: 0.8,
            timeout: std::time::Duration::from_secs(30),
            priority_levels: 3,
        },
        shaping: ThrottleConfig {
            global_rps_limit: Some(100),
            per_client_rps_limit: Some(10),
            burst_size: 20,
            window_size: std::time::Duration::from_secs(1),
        },
        priority: PriorityConfig {
            enabled: true,
            default_priority: 2,
            rules: vec![],
        },
        shutdown: ShutdownConfig {
            grace_period: std::time::Duration::from_secs(30),
            drain_timeout: std::time::Duration::from_secs(10),
            force_timeout: std::time::Duration::from_secs(60),
        },
        splitting: vec![],
    };

    let traffic_manager = Arc::new(
        TrafficManager::new(traffic_config)
            .await
            .expect("Failed to create traffic manager")
    );

    // Create admin components
    let config_manager = Arc::new(
        RuntimeConfigManager::new(GatewayConfig::default())
            .await
            .expect("Failed to create config manager")
    );
    
    let audit = Arc::new(
        ConfigAudit::new()
            .await
            .expect("Failed to create audit")
    );

    // Create admin state with traffic management enabled
    let admin_state = AdminState {
        config_manager,
        audit,
        service_management: None,
        load_balancer: None,
        traffic_management: Some(TrafficAdminState {
            traffic_manager,
        }),
    };

    // Create router
    let app = AdminRouter::create_router(admin_state);
    TestServer::new(app).expect("Failed to create test server")
}

#[tokio::test]
async fn test_get_traffic_config() {
    let server = create_test_server().await;

    let response = server.get("/traffic/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("config").is_some());
    assert!(body.get("last_modified").is_some());

    let config = &body["config"];
    assert!(config.get("queue").is_some());
    assert!(config.get("shaping").is_some());
    assert!(config.get("priority").is_some());
    assert!(config.get("shutdown").is_some());
}

#[tokio::test]
async fn test_update_traffic_config() {
    let server = create_test_server().await;

    let update_request = json!({
        "config": {
            "queue": {
                "max_queue_size": 2000,
                "backpressure_threshold": 0.9,
                "timeout": "45s",
                "priority_levels": 3
            },
            "shaping": {
                "global_rps_limit": 200,
                "per_client_rps_limit": 20,
                "burst_size": 40,
                "window_size": "1s"
            },
            "priority": {
                "enabled": true,
                "default_priority": 2,
                "rules": []
            },
            "shutdown": {
                "grace_period": "45s",
                "drain_timeout": "15s",
                "force_timeout": "90s"
            },
            "splitting": []
        },
        "changed_by": "test-user",
        "description": "Test configuration update"
    });

    let response = server
        .put("/traffic/config")
        .json(&update_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body.get("change_id").is_some());
    assert_eq!(body["message"], "Traffic configuration updated successfully");
}

#[tokio::test]
async fn test_validate_traffic_config() {
    let server = create_test_server().await;

    // Test valid configuration
    let valid_config = json!({
        "queue": {
            "max_queue_size": 1000,
            "backpressure_threshold": 0.8,
            "timeout": "30s",
            "priority_levels": 3
        },
        "shaping": {
            "global_rps_limit": 100,
            "per_client_rps_limit": 10,
            "burst_size": 20,
            "window_size": "1s"
        },
        "priority": {
            "enabled": true,
            "default_priority": 2,
            "rules": []
        },
        "shutdown": {
            "grace_period": "30s",
            "drain_timeout": "10s",
            "force_timeout": "60s"
        },
        "splitting": []
    });

    let response = server
        .post("/traffic/config/validate")
        .json(&valid_config)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["valid"], true);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0);

    // Test invalid configuration
    let invalid_config = json!({
        "queue": {
            "max_queue_size": 0,  // Invalid: must be > 0
            "backpressure_threshold": 1.5,  // Invalid: must be <= 1.0
            "timeout": "30s",
            "priority_levels": 3
        },
        "shaping": {
            "global_rps_limit": 0,  // Invalid: must be > 0
            "per_client_rps_limit": 10,
            "burst_size": 20,
            "window_size": "1s"
        },
        "priority": {
            "enabled": true,
            "default_priority": 2,
            "rules": []
        },
        "shutdown": {
            "grace_period": "30s",
            "drain_timeout": "10s",
            "force_timeout": "60s"
        },
        "splitting": []
    });

    let response = server
        .post("/traffic/config/validate")
        .json(&invalid_config)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["valid"], false);
    assert!(body["errors"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_queue_management() {
    let server = create_test_server().await;

    // Test get queue config
    let response = server.get("/traffic/queue/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("config").is_some());

    // Test update queue config
    let update_request = json!({
        "config": {
            "max_queue_size": 1500,
            "backpressure_threshold": 0.85,
            "timeout": "35s",
            "priority_levels": 3
        },
        "changed_by": "test-user"
    });

    let response = server
        .put("/traffic/queue/config")
        .json(&update_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test get queue metrics
    let response = server.get("/traffic/queue/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("metrics").is_some());

    // Test queue actions
    let action_request = json!({
        "changed_by": "test-user",
        "reason": "Test pause"
    });

    // Test pause queue
    let response = server
        .post("/traffic/queue/pause")
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test resume queue
    let response = server
        .post("/traffic/queue/resume")
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test clear queue
    let response = server
        .post("/traffic/queue/clear")
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body.get("affected_count").is_some());
}

#[tokio::test]
async fn test_traffic_shaping() {
    let server = create_test_server().await;

    // Test get shaping config
    let response = server.get("/traffic/shaping/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("config").is_some());

    // Test update shaping config
    let update_request = json!({
        "config": {
            "global_rps_limit": 150,
            "per_client_rps_limit": 15,
            "burst_size": 30,
            "window_size": "1s"
        },
        "changed_by": "test-user"
    });

    let response = server
        .put("/traffic/shaping/config")
        .json(&update_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test get shaping metrics
    let response = server.get("/traffic/shaping/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("metrics").is_some());

    // Test reset shaping counters
    let reset_request = json!({
        "changed_by": "test-user"
    });

    let response = server
        .post("/traffic/shaping/reset")
        .json(&reset_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_priority_management() {
    let server = create_test_server().await;

    // Test get priority config
    let response = server.get("/traffic/priority/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("config").is_some());

    // Test get priority rules (initially empty)
    let response = server.get("/traffic/priority/rules").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("rules").is_some());

    // Test add priority rule
    let rule_request = json!({
        "rule": {
            "id": "test-rule",
            "name": "Test Priority Rule",
            "condition": "headers.priority == \"high\"",
            "priority": 1,
            "enabled": true
        },
        "changed_by": "test-user"
    });

    let response = server
        .post("/traffic/priority/rules")
        .json(&rule_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["rule_id"], "test-rule");

    // Test update priority rule
    let update_rule_request = json!({
        "rule": {
            "id": "test-rule",
            "name": "Updated Test Priority Rule",
            "condition": "headers.priority == \"high\"",
            "priority": 0,
            "enabled": true
        },
        "changed_by": "test-user"
    });

    let response = server
        .put("/traffic/priority/rules/test-rule")
        .json(&update_rule_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test delete priority rule
    let response = server
        .delete("/traffic/priority/rules/test-rule?changed_by=test-user")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_ab_testing() {
    let server = create_test_server().await;

    // Test get A/B tests (initially empty)
    let response = server.get("/traffic/ab-tests").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("tests").is_some());

    // Test create A/B test
    let test_request = json!({
        "config": {
            "name": "homepage-test",
            "description": "Testing new homepage design",
            "variants": [
                {
                    "name": "control",
                    "weight": 50,
                    "upstream": "homepage-v1"
                },
                {
                    "name": "treatment",
                    "weight": 50,
                    "upstream": "homepage-v2"
                }
            ],
            "traffic_allocation": 100,
            "duration": "7d"
        },
        "changed_by": "test-user"
    });

    let response = server
        .post("/traffic/ab-tests")
        .json(&test_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body.get("test_id").is_some());

    let test_id = body["test_id"].as_str().unwrap();

    // Test get specific A/B test
    let response = server.get(&format!("/traffic/ab-tests/{}", test_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("test").is_some());

    // Test start A/B test
    let action_request = json!({
        "changed_by": "test-user"
    });

    let response = server
        .post(&format!("/traffic/ab-tests/{}/start", test_id))
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test get A/B test metrics
    let response = server
        .get(&format!("/traffic/ab-tests/{}/metrics", test_id))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("metrics").is_some());

    // Test stop A/B test
    let response = server
        .post(&format!("/traffic/ab-tests/{}/stop", test_id))
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test delete A/B test
    let response = server
        .delete(&format!("/traffic/ab-tests/{}?changed_by=test-user", test_id))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_traffic_splitting() {
    let server = create_test_server().await;

    // Test get traffic splits (initially empty)
    let response = server.get("/traffic/splits").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("splits").is_some());

    // Test create traffic split
    let split_request = json!({
        "config": {
            "id": "canary-deployment",
            "name": "Canary Deployment",
            "description": "Gradual rollout of new version",
            "enabled": true,
            "variants": [
                {
                    "name": "stable",
                    "weight": 90,
                    "upstream": "app-v1"
                },
                {
                    "name": "canary",
                    "weight": 10,
                    "upstream": "app-v2"
                }
            ]
        },
        "changed_by": "test-user"
    });

    let response = server
        .post("/traffic/splits")
        .json(&split_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body.get("split_id").is_some());

    let split_id = body["split_id"].as_str().unwrap();

    // Test get specific traffic split
    let response = server.get(&format!("/traffic/splits/{}", split_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("split").is_some());

    // Test disable traffic split
    let action_request = json!({
        "changed_by": "test-user"
    });

    let response = server
        .post(&format!("/traffic/splits/{}/disable", split_id))
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test enable traffic split
    let response = server
        .post(&format!("/traffic/splits/{}/enable", split_id))
        .json(&action_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test delete traffic split
    let response = server
        .delete(&format!("/traffic/splits/{}?changed_by=test-user", split_id))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_graceful_shutdown() {
    let server = create_test_server().await;

    // Test get shutdown config
    let response = server.get("/traffic/shutdown/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("config").is_some());

    // Test get shutdown status
    let response = server.get("/traffic/shutdown/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("status").is_some());

    // Test update shutdown config
    let update_request = json!({
        "config": {
            "grace_period": "45s",
            "drain_timeout": "15s",
            "force_timeout": "90s"
        },
        "changed_by": "test-user"
    });

    let response = server
        .put("/traffic/shutdown/config")
        .json(&update_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Test drain connections
    let drain_request = json!({
        "timeout": "10s",
        "changed_by": "test-user"
    });

    let response = server
        .post("/traffic/shutdown/drain")
        .json(&drain_request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body.get("drained_count").is_some());
}

#[tokio::test]
async fn test_overall_status_and_metrics() {
    let server = create_test_server().await;

    // Test get traffic status
    let response = server.get("/traffic/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("status").is_some());

    let status = &body["status"];
    assert!(status.get("queue_status").is_some());
    assert!(status.get("shaping_status").is_some());
    assert!(status.get("priority_status").is_some());
    assert!(status.get("shutdown_status").is_some());

    // Test get traffic metrics
    let response = server.get("/traffic/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("metrics").is_some());

    let metrics = &body["metrics"];
    assert!(metrics.get("queue_metrics").is_some());
    assert!(metrics.get("shaping_metrics").is_some());
    assert!(metrics.get("overall_stats").is_some());

    // Test get traffic health
    let response = server.get("/traffic/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body.get("health").is_some());

    let health = &body["health"];
    assert!(health.get("overall_health").is_some());
    assert!(health.get("queue_health").is_some());
    assert!(health.get("shaping_health").is_some());
    assert!(health.get("priority_health").is_some());
    assert!(health.get("shutdown_health").is_some());
}

#[tokio::test]
async fn test_error_handling() {
    let server = create_test_server().await;

    // Test 404 for non-existent A/B test
    let response = server.get("/traffic/ab-tests/non-existent-test").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let body: Value = response.json();
    assert!(body.get("error").is_some());

    // Test 404 for non-existent traffic split
    let response = server.get("/traffic/splits/non-existent-split").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let body: Value = response.json();
    assert!(body.get("error").is_some());

    // Test invalid JSON in request body
    let response = server
        .put("/traffic/config")
        .header("content-type", "application/json")
        .text("invalid json")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}
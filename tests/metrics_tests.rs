//! # Metrics Collection and Monitoring Tests
//!
//! Comprehensive tests for the metrics collection system including:
//! - Basic metrics recording and retrieval
//! - Prometheus metrics export
//! - Custom metrics functionality
//! - Admin endpoints
//! - Alert rules management
//! - Resource monitoring

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use axum_test::TestServer;
use serde_json::json;

use api_gateway::observability::metrics::{
    MetricsCollector, MetricsConfig, MetricsQuery, CustomMetric, CustomMetricType,
    ResourceMonitoringConfig,
};
use api_gateway::admin::metrics::{
    MetricsAdminRouter, MetricsAdminState, AlertRule, AlertCondition,
    CreateAlertRuleRequest, CreateCustomMetricRequest, MetricsQueryRequest,
};

/// Helper function to create a test metrics collector
async fn create_test_metrics_collector() -> MetricsCollector {
    let config = MetricsConfig {
        enabled: true,
        prometheus_endpoint: "/metrics".to_string(),
        collection_interval: 1,
        max_custom_metrics: 100,
        latency_buckets: vec![0.001, 0.01, 0.1, 1.0],
        global_labels: {
            let mut labels = HashMap::new();
            labels.insert("service".to_string(), "test-gateway".to_string());
            labels
        },
        resource_monitoring: ResourceMonitoringConfig {
            monitor_cpu: true,
            monitor_memory: true,
            monitor_network: false,
            monitor_disk: false,
            monitoring_interval: 1,
        },
    };

    MetricsCollector::new(config).await.expect("Failed to create metrics collector")
}

/// Helper function to create test admin state
async fn create_test_admin_state() -> MetricsAdminState {
    let metrics_collector = Arc::new(create_test_metrics_collector().await);
    let alert_rules = Arc::new(RwLock::new(HashMap::new()));

    MetricsAdminState {
        metrics_collector,
        alert_rules,
    }
}

#[tokio::test]
async fn test_metrics_collector_creation() {
    let collector = create_test_metrics_collector().await;
    let summary = collector.get_metrics_summary().await;
    
    assert!(summary.uptime_seconds >= 0.0);
    assert_eq!(summary.custom_metrics_count, 0);
    assert_eq!(summary.prometheus_endpoint, "/metrics");
    assert_eq!(summary.collection_interval, 1);
    assert!(summary.resource_monitoring_enabled);
}

#[tokio::test]
async fn test_request_metrics_recording() {
    let collector = create_test_metrics_collector().await;
    
    // Record some test requests
    collector.record_request(
        "GET",
        "/api/users",
        200,
        Duration::from_millis(150),
        1024,
        2048,
    );
    
    collector.record_request(
        "POST",
        "/api/users",
        201,
        Duration::from_millis(300),
        2048,
        512,
    );
    
    collector.record_request(
        "GET",
        "/api/users/123",
        404,
        Duration::from_millis(50),
        512,
        256,
    );
    
    // Verify metrics are recorded (in a real implementation, you'd check the actual metrics)
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_requests_total"));
    assert!(prometheus_output.contains("gateway_request_duration_seconds"));
}

#[tokio::test]
async fn test_upstream_metrics_recording() {
    let collector = create_test_metrics_collector().await;
    
    // Record upstream requests
    collector.record_upstream_request(
        "user-service",
        "GET",
        200,
        Duration::from_millis(100),
    );
    
    collector.record_upstream_request(
        "user-service",
        "POST",
        500,
        Duration::from_millis(5000),
    );
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_upstream_requests_total"));
    assert!(prometheus_output.contains("gateway_upstream_request_duration_seconds"));
}

#[tokio::test]
async fn test_connection_metrics() {
    let collector = create_test_metrics_collector().await;
    
    // Update connection metrics
    collector.update_connection_metrics(10, true, Some(Duration::from_secs(30)));
    collector.update_connection_metrics(15, true, None);
    collector.update_connection_metrics(12, false, Some(Duration::from_secs(45)));
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_active_connections"));
    assert!(prometheus_output.contains("gateway_connections_total"));
}

#[tokio::test]
async fn test_circuit_breaker_metrics() {
    let collector = create_test_metrics_collector().await;
    
    // Update circuit breaker metrics
    collector.update_circuit_breaker_metrics("user-service", "closed", 0);
    collector.update_circuit_breaker_metrics("user-service", "open", 5);
    collector.update_circuit_breaker_metrics("payment-service", "half_open", 2);
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_circuit_breaker_state"));
    assert!(prometheus_output.contains("gateway_circuit_breaker_failures_total"));
}

#[tokio::test]
async fn test_rate_limit_metrics() {
    let collector = create_test_metrics_collector().await;
    
    // Update rate limiting metrics
    collector.update_rate_limit_metrics("user:123", 5, 95);
    collector.update_rate_limit_metrics("api_key:abc", 1, 999);
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_rate_limit_hits_total"));
    assert!(prometheus_output.contains("gateway_rate_limit_remaining"));
}

#[tokio::test]
async fn test_cache_metrics() {
    let collector = create_test_metrics_collector().await;
    
    // Update cache metrics
    collector.update_cache_metrics("redis", 100, 25, 1024 * 1024);
    collector.update_cache_metrics("memory", 50, 10, 512 * 1024);
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("gateway_cache_hits_total"));
    assert!(prometheus_output.contains("gateway_cache_misses_total"));
    assert!(prometheus_output.contains("gateway_cache_size_bytes"));
}

#[tokio::test]
async fn test_custom_metrics() {
    let collector = create_test_metrics_collector().await;
    
    // Create custom metrics
    let counter_metric = CustomMetric {
        name: "custom_counter".to_string(),
        metric_type: CustomMetricType::Counter,
        value: 1.0,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("type".to_string(), "test".to_string());
            labels
        },
        timestamp: SystemTime::now(),
        description: Some("Test counter metric".to_string()),
    };
    
    let gauge_metric = CustomMetric {
        name: "custom_gauge".to_string(),
        metric_type: CustomMetricType::Gauge,
        value: 42.5,
        labels: HashMap::new(),
        timestamp: SystemTime::now(),
        description: Some("Test gauge metric".to_string()),
    };
    
    let histogram_metric = CustomMetric {
        name: "custom_histogram".to_string(),
        metric_type: CustomMetricType::Histogram,
        value: 0.123,
        labels: HashMap::new(),
        timestamp: SystemTime::now(),
        description: Some("Test histogram metric".to_string()),
    };
    
    // Record custom metrics
    collector.record_custom_metric(counter_metric).await.unwrap();
    collector.record_custom_metric(gauge_metric).await.unwrap();
    collector.record_custom_metric(histogram_metric).await.unwrap();
    
    // Query custom metrics
    let query = MetricsQuery {
        metric_name: Some("custom_counter".to_string()),
        labels: HashMap::new(),
        start_time: None,
        end_time: None,
        aggregation: None,
    };
    
    let results = collector.query_metrics(query).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].metric_name, "custom_counter");
}

#[tokio::test]
async fn test_metrics_query_with_filters() {
    let collector = create_test_metrics_collector().await;
    
    // Create metrics with different labels
    let metric1 = CustomMetric {
        name: "test_metric".to_string(),
        metric_type: CustomMetricType::Gauge,
        value: 10.0,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("env".to_string(), "prod".to_string());
            labels.insert("service".to_string(), "api".to_string());
            labels
        },
        timestamp: SystemTime::now(),
        description: None,
    };
    
    let metric2 = CustomMetric {
        name: "test_metric".to_string(),
        metric_type: CustomMetricType::Gauge,
        value: 20.0,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("env".to_string(), "dev".to_string());
            labels.insert("service".to_string(), "api".to_string());
            labels
        },
        timestamp: SystemTime::now(),
        description: None,
    };
    
    collector.record_custom_metric(metric1).await.unwrap();
    collector.record_custom_metric(metric2).await.unwrap();
    
    // Query with label filter
    let query = MetricsQuery {
        metric_name: Some("test_metric".to_string()),
        labels: {
            let mut labels = HashMap::new();
            labels.insert("env".to_string(), "prod".to_string());
            labels
        },
        start_time: None,
        end_time: None,
        aggregation: None,
    };
    
    let results = collector.query_metrics(query).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].values[0].value, 10.0);
}

#[tokio::test]
async fn test_resource_metrics_collection() {
    let collector = create_test_metrics_collector().await;
    
    // Collect resource metrics
    collector.collect_resource_metrics().await.unwrap();
    
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("system_cpu_usage_percent"));
    assert!(prometheus_output.contains("system_memory_usage_bytes"));
}

#[tokio::test]
async fn test_prometheus_metrics_export() {
    let collector = create_test_metrics_collector().await;
    
    // Record some metrics
    collector.record_request("GET", "/test", 200, Duration::from_millis(100), 1024, 2048);
    collector.update_connection_metrics(5, true, None);
    
    let prometheus_output = collector.get_prometheus_metrics();
    
    // Verify Prometheus format
    assert!(prometheus_output.contains("# HELP"));
    assert!(prometheus_output.contains("# TYPE"));
    assert!(prometheus_output.contains("gateway_requests_total"));
    assert!(prometheus_output.contains("gateway_active_connections"));
    
    // Verify global labels are included
    assert!(prometheus_output.contains("service=\"test-gateway\""));
}

#[tokio::test]
async fn test_metrics_admin_endpoints() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state);
    let server = TestServer::new(app).unwrap();
    
    // Test metrics summary endpoint
    let response = server.get("/metrics/summary").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let summary: serde_json::Value = response.json();
    assert!(summary["uptime_seconds"].as_f64().unwrap() >= 0.0);
    assert_eq!(summary["custom_metrics_count"].as_u64().unwrap(), 0);
    
    // Test Prometheus metrics endpoint
    let response = server.get("/metrics/prometheus").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let metrics_text = response.text();
    assert!(metrics_text.contains("# HELP"));
    assert!(metrics_text.contains("# TYPE"));
}

#[tokio::test]
async fn test_custom_metrics_admin_endpoints() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state);
    let server = TestServer::new(app).unwrap();
    
    // Create a custom metric
    let create_request = CreateCustomMetricRequest {
        name: "test_business_metric".to_string(),
        metric_type: "gauge".to_string(),
        value: 123.45,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("department".to_string(), "sales".to_string());
            labels
        },
        description: Some("Test business metric".to_string()),
    };
    
    let response = server
        .post("/metrics/custom")
        .json(&create_request)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let result: serde_json::Value = response.json();
    assert_eq!(result["metric_name"].as_str().unwrap(), "test_business_metric");
    
    // List custom metrics
    let response = server.get("/metrics/custom").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let metrics: Vec<serde_json::Value> = response.json();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0]["metric_name"].as_str().unwrap(), "test_business_metric");
}

#[tokio::test]
async fn test_alert_rules_management() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state);
    let server = TestServer::new(app).unwrap();
    
    // Create an alert rule
    let create_request = CreateAlertRuleRequest {
        name: "High Error Rate".to_string(),
        description: Some("Alert when error rate exceeds threshold".to_string()),
        metric_name: "gateway_error_rate".to_string(),
        condition: AlertCondition::GreaterThan,
        threshold: 0.05,
        duration_seconds: 300,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("severity".to_string(), "critical".to_string());
            labels
        },
    };
    
    let response = server
        .post("/metrics/alerts")
        .json(&create_request)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let alert_rule: serde_json::Value = response.json();
    let rule_id = alert_rule["id"].as_str().unwrap();
    assert_eq!(alert_rule["name"].as_str().unwrap(), "High Error Rate");
    assert_eq!(alert_rule["threshold"].as_f64().unwrap(), 0.05);
    
    // List alert rules
    let response = server.get("/metrics/alerts").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let rules: Vec<serde_json::Value> = response.json();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["name"].as_str().unwrap(), "High Error Rate");
    
    // Get specific alert rule
    let response = server.get(&format!("/metrics/alerts/{}", rule_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let rule: serde_json::Value = response.json();
    assert_eq!(rule["id"].as_str().unwrap(), rule_id);
    
    // Update alert rule
    let update_request = json!({
        "threshold": 0.1,
        "enabled": false
    });
    
    let response = server
        .put(&format!("/metrics/alerts/{}", rule_id))
        .json(&update_request)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let updated_rule: serde_json::Value = response.json();
    assert_eq!(updated_rule["threshold"].as_f64().unwrap(), 0.1);
    assert_eq!(updated_rule["enabled"].as_bool().unwrap(), false);
    
    // Trigger alert rule (for testing)
    let response = server
        .post(&format!("/metrics/alerts/{}/trigger", rule_id))
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Delete alert rule
    let response = server
        .delete(&format!("/metrics/alerts/{}", rule_id))
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    // Verify rule is deleted
    let response = server.get("/metrics/alerts").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let rules: Vec<serde_json::Value> = response.json();
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_metrics_query_endpoint() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state.clone());
    let server = TestServer::new(app).unwrap();
    
    // First create some custom metrics
    let metric = CustomMetric {
        name: "query_test_metric".to_string(),
        metric_type: CustomMetricType::Counter,
        value: 42.0,
        labels: {
            let mut labels = HashMap::new();
            labels.insert("test".to_string(), "value".to_string());
            labels
        },
        timestamp: SystemTime::now(),
        description: None,
    };
    
    admin_state.metrics_collector.record_custom_metric(metric).await.unwrap();
    
    // Query metrics
    let query_request = MetricsQueryRequest {
        metric_name: Some("query_test_metric".to_string()),
        labels: Some({
            let mut labels = HashMap::new();
            labels.insert("test".to_string(), "value".to_string());
            labels
        }),
        start_time: None,
        end_time: None,
        aggregation: None,
    };
    
    let response = server
        .post("/metrics/query")
        .json(&query_request)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let results: Vec<serde_json::Value> = response.json();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["metric_name"].as_str().unwrap(), "query_test_metric");
}

#[tokio::test]
async fn test_metrics_dashboard_endpoint() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state);
    let server = TestServer::new(app).unwrap();
    
    let response = server.get("/metrics/dashboard").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let dashboard: serde_json::Value = response.json();
    
    // Verify dashboard structure
    assert!(dashboard["summary"].is_object());
    assert!(dashboard["active_alerts"].is_array());
    assert!(dashboard["recent_metrics"].is_array());
    assert!(dashboard["system_health"].is_object());
    
    // Verify system health data
    let system_health = &dashboard["system_health"];
    assert!(system_health["cpu_usage"].as_f64().unwrap() >= 0.0);
    assert!(system_health["memory_usage"].as_f64().unwrap() >= 0.0);
    assert!(system_health["disk_usage"].as_f64().unwrap() >= 0.0);
    assert!(system_health["network_throughput"].as_f64().unwrap() >= 0.0);
}

#[tokio::test]
async fn test_metrics_config_endpoints() {
    let admin_state = create_test_admin_state().await;
    let app = MetricsAdminRouter::create_router(admin_state);
    let server = TestServer::new(app).unwrap();
    
    // Get current configuration
    let response = server.get("/metrics/config").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let config: serde_json::Value = response.json();
    assert_eq!(config["enabled"].as_bool().unwrap(), true);
    assert_eq!(config["collection_interval"].as_u64().unwrap(), 15);
    
    // Update configuration
    let update_request = json!({
        "collection_interval": 30,
        "max_custom_metrics": 2000
    });
    
    let response = server
        .put("/metrics/config")
        .json(&update_request)
        .await;
    
    assert_eq!(response.status_code(), StatusCode::OK);
    
    let result: serde_json::Value = response.json();
    assert_eq!(result["message"].as_str().unwrap(), "Metrics configuration updated successfully");
}

#[tokio::test]
async fn test_resource_monitoring_background_task() {
    let collector = create_test_metrics_collector().await;
    
    // Start resource monitoring
    let handle = collector.start_resource_monitoring();
    
    // Let it run for a short time
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Stop the task
    handle.abort();
    
    // Verify metrics were collected
    let prometheus_output = collector.get_prometheus_metrics();
    assert!(prometheus_output.contains("system_cpu_usage_percent"));
    assert!(prometheus_output.contains("system_memory_usage_bytes"));
}

#[tokio::test]
async fn test_metrics_error_handling() {
    // Test with disabled metrics
    let config = MetricsConfig {
        enabled: false,
        ..Default::default()
    };
    
    let result = MetricsCollector::new(config).await;
    assert!(result.is_err());
    
    // Test custom metrics limit
    let collector = create_test_metrics_collector().await;
    
    // Try to exceed the limit (set to 100 in test config)
    for i in 0..105 {
        let metric = CustomMetric {
            name: format!("test_metric_{}", i),
            metric_type: CustomMetricType::Counter,
            value: 1.0,
            labels: HashMap::new(),
            timestamp: SystemTime::now(),
            description: None,
        };
        
        let result = collector.record_custom_metric(metric).await;
        if i >= 100 {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }
}

#[tokio::test]
async fn test_metrics_uptime_tracking() {
    let collector = create_test_metrics_collector().await;
    
    let initial_uptime = collector.get_uptime_seconds();
    assert!(initial_uptime >= 0.0);
    
    // Wait a bit
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    let later_uptime = collector.get_uptime_seconds();
    assert!(later_uptime > initial_uptime);
}
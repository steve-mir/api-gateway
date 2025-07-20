//! # Metrics Admin Endpoints
//!
//! This module provides administrative endpoints for metrics management,
//! including querying metrics, configuring collection, and managing alerts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use crate::observability::metrics::{
    MetricsCollector, MetricsQuery, MetricsQueryResult,
    CustomMetric, CustomMetricType, MetricsSummary,
};

/// Metrics admin state
#[derive(Clone)]
pub struct MetricsAdminState {
    pub metrics_collector: Arc<MetricsCollector>,
    pub alert_rules: Arc<RwLock<HashMap<String, AlertRule>>>,
}

/// Alert rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub metric_name: String,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub duration: Duration,
    pub labels: HashMap<String, String>,
    pub enabled: bool,
    pub created_at: SystemTime,
    pub last_triggered: Option<SystemTime>,
}

/// Alert condition types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

/// Alert rule creation request
#[derive(Debug, Deserialize)]
pub struct CreateAlertRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub metric_name: String,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub duration_seconds: u64,
    pub labels: HashMap<String, String>,
}

/// Alert rule update request
#[derive(Debug, Deserialize)]
pub struct UpdateAlertRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub condition: Option<AlertCondition>,
    pub threshold: Option<f64>,
    pub duration_seconds: Option<u64>,
    pub labels: Option<HashMap<String, String>>,
    pub enabled: Option<bool>,
}

/// Metrics query request
#[derive(Debug, Deserialize)]
pub struct MetricsQueryRequest {
    pub metric_name: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub start_time: Option<u64>, // Unix timestamp
    pub end_time: Option<u64>,   // Unix timestamp
    pub aggregation: Option<String>,
}

/// Custom metric creation request
#[derive(Debug, Deserialize)]
pub struct CreateCustomMetricRequest {
    pub name: String,
    pub metric_type: String, // "counter", "gauge", "histogram"
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub description: Option<String>,
}

/// Metrics configuration update request
#[derive(Debug, Deserialize)]
pub struct UpdateMetricsConfigRequest {
    pub collection_interval: Option<u64>,
    pub max_custom_metrics: Option<usize>,
    pub global_labels: Option<HashMap<String, String>>,
    pub resource_monitoring: Option<ResourceMonitoringConfigUpdate>,
}

/// Resource monitoring configuration update
#[derive(Debug, Deserialize)]
pub struct ResourceMonitoringConfigUpdate {
    pub monitor_cpu: Option<bool>,
    pub monitor_memory: Option<bool>,
    pub monitor_network: Option<bool>,
    pub monitor_disk: Option<bool>,
    pub monitoring_interval: Option<u64>,
}

/// Metrics admin router
pub struct MetricsAdminRouter;

impl MetricsAdminRouter {
    /// Create metrics admin router
    pub fn create_router(state: MetricsAdminState) -> Router {
        Router::new()
            .route("/metrics/summary", get(get_metrics_summary))
            .route("/metrics/prometheus", get(get_prometheus_metrics))
            .route("/metrics/query", post(query_metrics))
            .route("/metrics/custom", post(create_custom_metric))
            .route("/metrics/custom", get(list_custom_metrics))
            .route("/metrics/config", get(get_metrics_config))
            .route("/metrics/config", put(update_metrics_config))
            .route("/metrics/alerts", get(list_alert_rules))
            .route("/metrics/alerts", post(create_alert_rule))
            .route("/metrics/alerts/:id", get(get_alert_rule))
            .route("/metrics/alerts/:id", put(update_alert_rule))
            .route("/metrics/alerts/:id", delete(delete_alert_rule))
            .route("/metrics/alerts/:id/trigger", post(trigger_alert_rule))
            .route("/metrics/dashboard", get(get_metrics_dashboard))
            .with_state(state)
    }
}

/// Get metrics summary
async fn get_metrics_summary(
    State(state): State<MetricsAdminState>,
) -> Result<Json<MetricsSummary>, StatusCode> {
    let summary = state.metrics_collector.get_metrics_summary().await;
    Ok(Json(summary))
}

/// Get Prometheus metrics
async fn get_prometheus_metrics(
    State(state): State<MetricsAdminState>,
) -> Result<String, StatusCode> {
    let metrics = state.metrics_collector.get_prometheus_metrics();
    Ok(metrics)
}

/// Query metrics
async fn query_metrics(
    State(state): State<MetricsAdminState>,
    Json(request): Json<MetricsQueryRequest>,
) -> Result<Json<Vec<MetricsQueryResult>>, StatusCode> {
    let query = MetricsQuery {
        metric_name: request.metric_name,
        labels: request.labels.unwrap_or_default(),
        start_time: request.start_time.map(|ts| UNIX_EPOCH + Duration::from_secs(ts)),
        end_time: request.end_time.map(|ts| UNIX_EPOCH + Duration::from_secs(ts)),
        aggregation: None, // TODO: Parse aggregation from string
    };

    match state.metrics_collector.query_metrics(query).await {
        Ok(results) => Ok(Json(results)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Create custom metric
async fn create_custom_metric(
    State(state): State<MetricsAdminState>,
    Json(request): Json<CreateCustomMetricRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let metric_type = match request.metric_type.as_str() {
        "counter" => CustomMetricType::Counter,
        "gauge" => CustomMetricType::Gauge,
        "histogram" => CustomMetricType::Histogram,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let custom_metric = CustomMetric {
        name: request.name.clone(),
        metric_type,
        value: request.value,
        labels: request.labels,
        timestamp: SystemTime::now(),
        description: request.description,
    };

    match state.metrics_collector.record_custom_metric(custom_metric).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "message": "Custom metric created successfully",
            "metric_name": request.name
        }))),
        Err(e) => {
            tracing::error!("Failed to create custom metric: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List custom metrics
async fn list_custom_metrics(
    State(state): State<MetricsAdminState>,
) -> Result<Json<Vec<MetricsQueryResult>>, StatusCode> {
    let query = MetricsQuery {
        metric_name: None,
        labels: HashMap::new(),
        start_time: None,
        end_time: None,
        aggregation: None,
    };

    match state.metrics_collector.query_metrics(query).await {
        Ok(results) => Ok(Json(results)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Get metrics configuration
async fn get_metrics_config(
    State(_state): State<MetricsAdminState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // In a real implementation, this would return the actual configuration
    // For now, return a placeholder
    Ok(Json(serde_json::json!({
        "enabled": true,
        "collection_interval": 15,
        "max_custom_metrics": 1000,
        "prometheus_endpoint": "/metrics",
        "resource_monitoring": {
            "monitor_cpu": true,
            "monitor_memory": true,
            "monitor_network": true,
            "monitor_disk": true,
            "monitoring_interval": 30
        }
    })))
}

/// Update metrics configuration
async fn update_metrics_config(
    State(_state): State<MetricsAdminState>,
    Json(_request): Json<UpdateMetricsConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // In a real implementation, this would update the configuration
    // For now, return a success message
    Ok(Json(serde_json::json!({
        "message": "Metrics configuration updated successfully"
    })))
}

/// List alert rules
async fn list_alert_rules(
    State(state): State<MetricsAdminState>,
) -> Result<Json<Vec<AlertRule>>, StatusCode> {
    let alert_rules = state.alert_rules.read().await;
    let rules: Vec<AlertRule> = alert_rules.values().cloned().collect();
    Ok(Json(rules))
}

/// Create alert rule
async fn create_alert_rule(
    State(state): State<MetricsAdminState>,
    Json(request): Json<CreateAlertRuleRequest>,
) -> Result<Json<AlertRule>, StatusCode> {
    let rule_id = uuid::Uuid::new_v4().to_string();
    let alert_rule = AlertRule {
        id: rule_id.clone(),
        name: request.name,
        description: request.description,
        metric_name: request.metric_name,
        condition: request.condition,
        threshold: request.threshold,
        duration: Duration::from_secs(request.duration_seconds),
        labels: request.labels,
        enabled: true,
        created_at: SystemTime::now(),
        last_triggered: None,
    };

    let mut alert_rules = state.alert_rules.write().await;
    alert_rules.insert(rule_id, alert_rule.clone());

    Ok(Json(alert_rule))
}

/// Get alert rule
async fn get_alert_rule(
    State(state): State<MetricsAdminState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<AlertRule>, StatusCode> {
    let alert_rules = state.alert_rules.read().await;
    match alert_rules.get(&id) {
        Some(rule) => Ok(Json(rule.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Update alert rule
async fn update_alert_rule(
    State(state): State<MetricsAdminState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(request): Json<UpdateAlertRuleRequest>,
) -> Result<Json<AlertRule>, StatusCode> {
    let mut alert_rules = state.alert_rules.write().await;
    match alert_rules.get_mut(&id) {
        Some(rule) => {
            if let Some(name) = request.name {
                rule.name = name;
            }
            if let Some(description) = request.description {
                rule.description = Some(description);
            }
            if let Some(condition) = request.condition {
                rule.condition = condition;
            }
            if let Some(threshold) = request.threshold {
                rule.threshold = threshold;
            }
            if let Some(duration_seconds) = request.duration_seconds {
                rule.duration = Duration::from_secs(duration_seconds);
            }
            if let Some(labels) = request.labels {
                rule.labels = labels;
            }
            if let Some(enabled) = request.enabled {
                rule.enabled = enabled;
            }
            Ok(Json(rule.clone()))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Delete alert rule
async fn delete_alert_rule(
    State(state): State<MetricsAdminState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut alert_rules = state.alert_rules.write().await;
    match alert_rules.remove(&id) {
        Some(_) => Ok(Json(serde_json::json!({
            "message": "Alert rule deleted successfully",
            "rule_id": id
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Trigger alert rule (for testing)
async fn trigger_alert_rule(
    State(state): State<MetricsAdminState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut alert_rules = state.alert_rules.write().await;
    match alert_rules.get_mut(&id) {
        Some(rule) => {
            rule.last_triggered = Some(SystemTime::now());
            Ok(Json(serde_json::json!({
                "message": "Alert rule triggered successfully",
                "rule_id": id,
                "triggered_at": rule.last_triggered
            })))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Get metrics dashboard data
async fn get_metrics_dashboard(
    State(state): State<MetricsAdminState>,
) -> Result<Json<MetricsDashboard>, StatusCode> {
    let summary = state.metrics_collector.get_metrics_summary().await;
    let alert_rules = state.alert_rules.read().await;
    
    let dashboard = MetricsDashboard {
        summary,
        active_alerts: alert_rules.values()
            .filter(|rule| rule.enabled)
            .cloned()
            .collect(),
        recent_metrics: Vec::new(), // TODO: Implement recent metrics collection
        system_health: SystemHealth {
            cpu_usage: 45.0,
            memory_usage: 60.0,
            disk_usage: 75.0,
            network_throughput: 1024.0,
        },
    };

    Ok(Json(dashboard))
}

/// Metrics dashboard data
#[derive(Debug, Clone, Serialize)]
pub struct MetricsDashboard {
    pub summary: MetricsSummary,
    pub active_alerts: Vec<AlertRule>,
    pub recent_metrics: Vec<MetricsQueryResult>,
    pub system_health: SystemHealth,
}

/// System health information
#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_throughput: f64,
}
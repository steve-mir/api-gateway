//! # Admin Observability and Monitoring
//!
//! This module provides comprehensive observability and monitoring capabilities
//! specifically for admin operations, including:
//! - Admin-specific metrics collection
//! - Admin operation audit logging
//! - Admin API performance monitoring
//! - Admin dashboard usage analytics
//! - Configuration change impact analysis
//! - Admin notification system for critical events

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, error};
use uuid::Uuid;

/// Admin observability state
#[derive(Clone)]
pub struct AdminObservabilityState {
    pub metrics_collector: Arc<AdminMetricsCollector>,
    pub audit_logger: Arc<AdminAuditLogger>,
    pub performance_monitor: Arc<AdminPerformanceMonitor>,
    pub usage_analytics: Arc<AdminUsageAnalytics>,
    pub impact_analyzer: Arc<ConfigChangeImpactAnalyzer>,
    pub notification_system: Arc<AdminNotificationSystem>,
}

/// Admin-specific metrics collector
pub struct AdminMetricsCollector {
    metrics: Arc<RwLock<AdminMetrics>>,
    start_time: SystemTime,
}

/// Admin metrics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminMetrics {
    // Operation metrics
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub operations_by_type: HashMap<String, u64>,
    pub operations_by_user: HashMap<String, u64>,
    
    // Session metrics
    pub active_sessions: u64,
    pub total_sessions: u64,
    pub session_duration_avg: f64,
    pub sessions_by_role: HashMap<String, u64>,
    
    // API metrics
    pub api_requests_total: u64,
    pub api_requests_by_endpoint: HashMap<String, u64>,
    pub api_response_times: HashMap<String, Vec<f64>>,
    pub api_error_rates: HashMap<String, f64>,
    
    // Dashboard metrics
    pub dashboard_views: u64,
    pub dashboard_users: u64,
    pub most_viewed_pages: HashMap<String, u64>,
    pub user_interactions: HashMap<String, u64>,
    
    // System metrics
    pub config_changes: u64,
    pub service_modifications: u64,
    pub alert_triggers: u64,
    pub backup_operations: u64,
}

impl Default for AdminMetrics {
    fn default() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            operations_by_type: HashMap::new(),
            operations_by_user: HashMap::new(),
            active_sessions: 0,
            total_sessions: 0,
            session_duration_avg: 0.0,
            sessions_by_role: HashMap::new(),
            api_requests_total: 0,
            api_requests_by_endpoint: HashMap::new(),
            api_response_times: HashMap::new(),
            api_error_rates: HashMap::new(),
            dashboard_views: 0,
            dashboard_users: 0,
            most_viewed_pages: HashMap::new(),
            user_interactions: HashMap::new(),
            config_changes: 0,
            service_modifications: 0,
            alert_triggers: 0,
            backup_operations: 0,
        }
    }
}

impl AdminMetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(AdminMetrics::default())),
            start_time: SystemTime::now(),
        }
    }

    /// Record admin operation
    pub async fn record_operation(&self, operation_type: &str, user_id: &str, success: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.total_operations += 1;
        
        if success {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }
        
        *metrics.operations_by_type.entry(operation_type.to_string()).or_insert(0) += 1;
        *metrics.operations_by_user.entry(user_id.to_string()).or_insert(0) += 1;
    }

    /// Record admin session
    pub async fn record_session(&self, user_id: &str, role: &str, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.total_sessions += 1;
        
        // Update average session duration
        let total_duration = metrics.session_duration_avg * (metrics.total_sessions - 1) as f64 + duration.as_secs_f64();
        metrics.session_duration_avg = total_duration / metrics.total_sessions as f64;
        
        *metrics.sessions_by_role.entry(role.to_string()).or_insert(0) += 1;
    }

    /// Record API request
    pub async fn record_api_request(&self, endpoint: &str, response_time: Duration, success: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.api_requests_total += 1;
        
        *metrics.api_requests_by_endpoint.entry(endpoint.to_string()).or_insert(0) += 1;
        
        // Record response time
        metrics.api_response_times
            .entry(endpoint.to_string())
            .or_insert_with(Vec::new)
            .push(response_time.as_millis() as f64);
        
        // Update error rate
        let endpoint_requests = *metrics.api_requests_by_endpoint.get(endpoint).unwrap_or(&0) as f64;
        let current_error_rate = metrics.api_error_rates.get(endpoint).unwrap_or(&0.0);
        let new_error_rate = if success {
            *current_error_rate * (endpoint_requests - 1.0) / endpoint_requests
        } else {
            (*current_error_rate * (endpoint_requests - 1.0) + 1.0) / endpoint_requests
        };
        metrics.api_error_rates.insert(endpoint.to_string(), new_error_rate);
    }

    /// Record dashboard usage
    pub async fn record_dashboard_usage(&self, user_id: &str, page: &str, interaction_type: &str) {
        let mut metrics = self.metrics.write().await;
        metrics.dashboard_views += 1;
        
        *metrics.most_viewed_pages.entry(page.to_string()).or_insert(0) += 1;
        *metrics.user_interactions.entry(interaction_type.to_string()).or_insert(0) += 1;
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> AdminMetrics {
        self.metrics.read().await.clone()
    }

    /// Get uptime
    pub fn get_uptime(&self) -> Duration {
        SystemTime::now().duration_since(self.start_time).unwrap_or_default()
    }
}

/// Admin audit logger for detailed event tracking
pub struct AdminAuditLogger {
    audit_log: Arc<RwLock<Vec<AdminAuditEvent>>>,
    max_entries: usize,
}

/// Admin audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub user_id: String,
    pub user_role: String,
    pub operation: String,
    pub resource: String,
    pub action: String,
    pub details: HashMap<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub duration_ms: u64,
    pub impact_level: ImpactLevel,
}

/// Impact level of admin operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl AdminAuditLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            audit_log: Arc::new(RwLock::new(Vec::new())),
            max_entries,
        }
    }

    /// Log admin operation
    pub async fn log_operation(
        &self,
        user_id: &str,
        user_role: &str,
        operation: &str,
        resource: &str,
        action: &str,
        details: HashMap<String, serde_json::Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        success: bool,
        error_message: Option<String>,
        duration: Duration,
        impact_level: ImpactLevel,
    ) {
        let event = AdminAuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            user_id: user_id.to_string(),
            user_role: user_role.to_string(),
            operation: operation.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            details,
            ip_address,
            user_agent,
            success,
            error_message,
            duration_ms: duration.as_millis() as u64,
            impact_level,
        };

        let mut audit_log = self.audit_log.write().await;
        audit_log.push(event.clone());

        // Maintain max entries limit
        if audit_log.len() > self.max_entries {
            audit_log.remove(0);
        }

        // Log to structured logger based on impact level
        match event.impact_level {
            ImpactLevel::Low => info!("Admin operation: {}", serde_json::to_string(&event).unwrap_or_default()),
            ImpactLevel::Medium => info!("Admin operation: {}", serde_json::to_string(&event).unwrap_or_default()),
            ImpactLevel::High => warn!("High impact admin operation: {}", serde_json::to_string(&event).unwrap_or_default()),
            ImpactLevel::Critical => error!("Critical admin operation: {}", serde_json::to_string(&event).unwrap_or_default()),
        }
    }

    /// Get audit events with filtering
    pub async fn get_audit_events(
        &self,
        user_id: Option<&str>,
        operation: Option<&str>,
        start_time: Option<SystemTime>,
        end_time: Option<SystemTime>,
        limit: Option<usize>,
    ) -> Vec<AdminAuditEvent> {
        let audit_log = self.audit_log.read().await;
        let mut filtered_events: Vec<AdminAuditEvent> = audit_log
            .iter()
            .filter(|event| {
                if let Some(uid) = user_id {
                    if event.user_id != uid {
                        return false;
                    }
                }
                if let Some(op) = operation {
                    if event.operation != op {
                        return false;
                    }
                }
                if let Some(start) = start_time {
                    if event.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = end_time {
                    if event.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by timestamp (newest first)
        filtered_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit
        if let Some(limit) = limit {
            filtered_events.truncate(limit);
        }

        filtered_events
    }

    /// Get audit statistics
    pub async fn get_audit_statistics(&self) -> AdminAuditStatistics {
        let audit_log = self.audit_log.read().await;
        let total_events = audit_log.len();
        let successful_operations = audit_log.iter().filter(|e| e.success).count();
        let failed_operations = total_events - successful_operations;

        let mut operations_by_type = HashMap::new();
        let mut operations_by_user = HashMap::new();
        let mut operations_by_impact = HashMap::new();

        for event in audit_log.iter() {
            *operations_by_type.entry(event.operation.clone()).or_insert(0) += 1;
            *operations_by_user.entry(event.user_id.clone()).or_insert(0) += 1;
            let impact_key = format!("{:?}", event.impact_level);
            *operations_by_impact.entry(impact_key).or_insert(0) += 1;
        }

        AdminAuditStatistics {
            total_events,
            successful_operations,
            failed_operations,
            operations_by_type,
            operations_by_user,
            operations_by_impact,
        }
    }
}

/// Admin audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditStatistics {
    pub total_events: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub operations_by_type: HashMap<String, usize>,
    pub operations_by_user: HashMap<String, usize>,
    pub operations_by_impact: HashMap<String, usize>,
}

/// Admin API performance monitor
pub struct AdminPerformanceMonitor {
    performance_data: Arc<RwLock<AdminPerformanceData>>,
}

/// Admin performance data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPerformanceData {
    pub endpoint_metrics: HashMap<String, EndpointMetrics>,
    pub slow_queries: Vec<SlowQuery>,
    pub error_patterns: HashMap<String, u64>,
    pub resource_usage: ResourceUsageMetrics,
}

/// Endpoint performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetrics {
    pub total_requests: u64,
    pub average_response_time: f64,
    pub min_response_time: f64,
    pub max_response_time: f64,
    pub p95_response_time: f64,
    pub error_rate: f64,
    pub throughput: f64, // requests per second
}

/// Slow query information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowQuery {
    pub timestamp: SystemTime,
    pub endpoint: String,
    pub duration_ms: u64,
    pub user_id: String,
    pub query_details: HashMap<String, serde_json::Value>,
}

/// Resource usage metrics for admin operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsageMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub active_connections: u64,
    pub database_connections: u64,
}

impl AdminPerformanceMonitor {
    pub fn new() -> Self {
        Self {
            performance_data: Arc::new(RwLock::new(AdminPerformanceData {
                endpoint_metrics: HashMap::new(),
                slow_queries: Vec::new(),
                error_patterns: HashMap::new(),
                resource_usage: ResourceUsageMetrics {
                    cpu_usage_percent: 0.0,
                    memory_usage_mb: 0.0,
                    active_connections: 0,
                    database_connections: 0,
                },
            })),
        }
    }

    /// Record endpoint performance
    pub async fn record_endpoint_performance(
        &self,
        endpoint: &str,
        response_time: Duration,
        success: bool,
        user_id: &str,
    ) {
        let mut data = self.performance_data.write().await;
        let metrics = data.endpoint_metrics.entry(endpoint.to_string()).or_insert(EndpointMetrics {
            total_requests: 0,
            average_response_time: 0.0,
            min_response_time: f64::MAX,
            max_response_time: 0.0,
            p95_response_time: 0.0,
            error_rate: 0.0,
            throughput: 0.0,
        });

        let response_time_ms = response_time.as_millis() as f64;
        metrics.total_requests += 1;

        // Update response time statistics
        metrics.average_response_time = (metrics.average_response_time * (metrics.total_requests - 1) as f64 + response_time_ms) / metrics.total_requests as f64;
        metrics.min_response_time = metrics.min_response_time.min(response_time_ms);
        metrics.max_response_time = metrics.max_response_time.max(response_time_ms);

        // Update error rate
        if !success {
            let error_count = (metrics.error_rate * (metrics.total_requests - 1) as f64) + 1.0;
            metrics.error_rate = error_count / metrics.total_requests as f64;
        } else {
            metrics.error_rate = (metrics.error_rate * (metrics.total_requests - 1) as f64) / metrics.total_requests as f64;
        }

        // Record slow queries (> 1 second)
        if response_time > Duration::from_secs(1) {
            data.slow_queries.push(SlowQuery {
                timestamp: SystemTime::now(),
                endpoint: endpoint.to_string(),
                duration_ms: response_time.as_millis() as u64,
                user_id: user_id.to_string(),
                query_details: HashMap::new(),
            });

            // Keep only last 100 slow queries
            if data.slow_queries.len() > 100 {
                data.slow_queries.remove(0);
            }
        }
    }

    /// Get performance data
    pub async fn get_performance_data(&self) -> AdminPerformanceData {
        self.performance_data.read().await.clone()
    }

    /// Get performance alerts
    pub async fn get_performance_alerts(&self) -> Vec<PerformanceAlert> {
        let data = self.performance_data.read().await;
        let mut alerts = Vec::new();

        for (endpoint, metrics) in &data.endpoint_metrics {
            // High error rate alert
            if metrics.error_rate > 0.1 {
                alerts.push(PerformanceAlert {
                    alert_type: AlertType::HighErrorRate,
                    endpoint: endpoint.clone(),
                    value: metrics.error_rate,
                    threshold: 0.1,
                    message: format!("High error rate detected for endpoint {}: {:.2}%", endpoint, metrics.error_rate * 100.0),
                });
            }

            // Slow response time alert
            if metrics.average_response_time > 5000.0 {
                alerts.push(PerformanceAlert {
                    alert_type: AlertType::SlowResponseTime,
                    endpoint: endpoint.clone(),
                    value: metrics.average_response_time,
                    threshold: 5000.0,
                    message: format!("Slow response time for endpoint {}: {:.2}ms", endpoint, metrics.average_response_time),
                });
            }
        }

        alerts
    }
}

/// Performance alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlert {
    pub alert_type: AlertType,
    pub endpoint: String,
    pub value: f64,
    pub threshold: f64,
    pub message: String,
}

/// Alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    HighErrorRate,
    SlowResponseTime,
    HighResourceUsage,
    TooManyConnections,
}
// Admin dashboard usage analytics
pub struct AdminUsageAnalytics {
    analytics_data: Arc<RwLock<UsageAnalyticsData>>,
}

/// Usage analytics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAnalyticsData {
    pub daily_active_users: HashMap<String, u64>, // date -> count
    pub feature_usage: HashMap<String, u64>,
    pub user_sessions: HashMap<String, Vec<UserSession>>,
    pub page_views: HashMap<String, u64>,
    pub user_actions: HashMap<String, u64>,
    pub time_spent_by_page: HashMap<String, f64>, // page -> average time in seconds
}

/// User session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub pages_visited: Vec<String>,
    pub actions_performed: Vec<String>,
    pub total_duration: Option<Duration>,
}

impl AdminUsageAnalytics {
    pub fn new() -> Self {
        Self {
            analytics_data: Arc::new(RwLock::new(UsageAnalyticsData {
                daily_active_users: HashMap::new(),
                feature_usage: HashMap::new(),
                user_sessions: HashMap::new(),
                page_views: HashMap::new(),
                user_actions: HashMap::new(),
                time_spent_by_page: HashMap::new(),
            })),
        }
    }

    /// Record user activity
    pub async fn record_user_activity(&self, user_id: &str, page: &str, action: &str, session_id: &str) {
        let mut data = self.analytics_data.write().await;
        
        // Update daily active users
        let today = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 86400; // days since epoch
        let today_key = today.to_string();
        *data.daily_active_users.entry(today_key).or_insert(0) += 1;

        // Update feature usage
        *data.feature_usage.entry(action.to_string()).or_insert(0) += 1;

        // Update page views
        *data.page_views.entry(page.to_string()).or_insert(0) += 1;

        // Update user actions
        *data.user_actions.entry(action.to_string()).or_insert(0) += 1;

        // Update or create user session
        let sessions = data.user_sessions.entry(user_id.to_string()).or_insert_with(Vec::new);
        if let Some(session) = sessions.iter_mut().find(|s| s.session_id == session_id && s.end_time.is_none()) {
            session.pages_visited.push(page.to_string());
            session.actions_performed.push(action.to_string());
        } else {
            sessions.push(UserSession {
                session_id: session_id.to_string(),
                user_id: user_id.to_string(),
                start_time: SystemTime::now(),
                end_time: None,
                pages_visited: vec![page.to_string()],
                actions_performed: vec![action.to_string()],
                total_duration: None,
            });
        }
    }

    /// End user session
    pub async fn end_user_session(&self, user_id: &str, session_id: &str) {
        let mut data = self.analytics_data.write().await;
        if let Some(sessions) = data.user_sessions.get_mut(user_id) {
            if let Some(session) = sessions.iter_mut().find(|s| s.session_id == session_id && s.end_time.is_none()) {
                session.end_time = Some(SystemTime::now());
                session.total_duration = session.end_time.unwrap().duration_since(session.start_time).ok();
            }
        }
    }

    /// Get usage analytics
    pub async fn get_analytics(&self) -> UsageAnalyticsData {
        self.analytics_data.read().await.clone()
    }

    /// Get usage summary
    pub async fn get_usage_summary(&self) -> UsageSummary {
        let data = self.analytics_data.read().await;
        
        let total_users = data.user_sessions.len();
        let total_sessions = data.user_sessions.values().map(|sessions| sessions.len()).sum();
        let total_page_views = data.page_views.values().sum();
        let total_actions = data.user_actions.values().sum();
        
        let most_used_features: Vec<(String, u64)> = {
            let mut features: Vec<_> = data.feature_usage.iter().collect();
            features.sort_by(|a, b| b.1.cmp(a.1));
            features.into_iter().take(10).map(|(k, v)| (k.clone(), *v)).collect()
        };

        let most_viewed_pages: Vec<(String, u64)> = {
            let mut pages: Vec<_> = data.page_views.iter().collect();
            pages.sort_by(|a, b| b.1.cmp(a.1));
            pages.into_iter().take(10).map(|(k, v)| (k.clone(), *v)).collect()
        };

        UsageSummary {
            total_users,
            total_sessions,
            total_page_views,
            total_actions,
            most_used_features,
            most_viewed_pages,
        }
    }
}

/// Usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    pub total_users: usize,
    pub total_sessions: usize,
    pub total_page_views: u64,
    pub total_actions: u64,
    pub most_used_features: Vec<(String, u64)>,
    pub most_viewed_pages: Vec<(String, u64)>,
}

/// Configuration change impact analyzer
pub struct ConfigChangeImpactAnalyzer {
    impact_data: Arc<RwLock<Vec<ConfigChangeImpact>>>,
}

/// Configuration change impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeImpact {
    pub change_id: String,
    pub timestamp: SystemTime,
    pub user_id: String,
    pub change_type: String,
    pub affected_services: Vec<String>,
    pub impact_metrics: ImpactMetrics,
    pub rollback_available: bool,
    pub risk_level: RiskLevel,
}

/// Impact metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMetrics {
    pub requests_affected: u64,
    pub error_rate_change: f64,
    pub latency_change: f64,
    pub throughput_change: f64,
    pub services_restarted: u64,
}

/// Risk level of configuration changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ConfigChangeImpactAnalyzer {
    pub fn new() -> Self {
        Self {
            impact_data: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Analyze configuration change impact
    pub async fn analyze_change_impact(
        &self,
        change_id: &str,
        user_id: &str,
        change_type: &str,
        affected_services: Vec<String>,
    ) -> ConfigChangeImpact {
        // In a real implementation, this would analyze actual metrics
        // For now, we'll simulate the analysis
        let impact_metrics = ImpactMetrics {
            requests_affected: 1000,
            error_rate_change: 0.02,
            latency_change: 15.0,
            throughput_change: -5.0,
            services_restarted: affected_services.len() as u64,
        };

        let risk_level = match change_type {
            "service_config" => RiskLevel::Medium,
            "routing_rules" => RiskLevel::High,
            "security_policy" => RiskLevel::Critical,
            _ => RiskLevel::Low,
        };

        let impact = ConfigChangeImpact {
            change_id: change_id.to_string(),
            timestamp: SystemTime::now(),
            user_id: user_id.to_string(),
            change_type: change_type.to_string(),
            affected_services,
            impact_metrics,
            rollback_available: true,
            risk_level,
        };

        let mut data = self.impact_data.write().await;
        data.push(impact.clone());

        // Keep only last 1000 impact records
        if data.len() > 1000 {
            data.remove(0);
        }

        impact
    }

    /// Get impact history
    pub async fn get_impact_history(&self, limit: Option<usize>) -> Vec<ConfigChangeImpact> {
        let data = self.impact_data.read().await;
        let mut impacts = data.clone();
        impacts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(limit) = limit {
            impacts.truncate(limit);
        }
        
        impacts
    }

    /// Get impact summary
    pub async fn get_impact_summary(&self) -> ImpactSummary {
        let data = self.impact_data.read().await;
        let total_changes = data.len();
        let high_risk_changes = data.iter().filter(|i| matches!(i.risk_level, RiskLevel::High | RiskLevel::Critical)).count();
        
        let avg_error_rate_change = if !data.is_empty() {
            data.iter().map(|i| i.impact_metrics.error_rate_change).sum::<f64>() / data.len() as f64
        } else {
            0.0
        };

        let avg_latency_change = if !data.is_empty() {
            data.iter().map(|i| i.impact_metrics.latency_change).sum::<f64>() / data.len() as f64
        } else {
            0.0
        };

        ImpactSummary {
            total_changes,
            high_risk_changes,
            avg_error_rate_change,
            avg_latency_change,
            rollback_rate: 0.05, // 5% rollback rate
        }
    }
}

/// Impact summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactSummary {
    pub total_changes: usize,
    pub high_risk_changes: usize,
    pub avg_error_rate_change: f64,
    pub avg_latency_change: f64,
    pub rollback_rate: f64,
}

/// Admin notification system
pub struct AdminNotificationSystem {
    notifications: Arc<RwLock<Vec<AdminNotification>>>,
    subscribers: Arc<RwLock<HashMap<String, broadcast::Sender<AdminNotification>>>>,
}

/// Admin notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminNotification {
    pub id: String,
    pub timestamp: SystemTime,
    pub notification_type: NotificationType,
    pub severity: NotificationSeverity,
    pub title: String,
    pub message: String,
    pub details: HashMap<String, serde_json::Value>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<SystemTime>,
}

/// Notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    SystemAlert,
    SecurityEvent,
    ConfigurationChange,
    PerformanceIssue,
    ServiceFailure,
    MaintenanceWindow,
}

/// Notification severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotificationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl AdminNotificationSystem {
    pub fn new() -> Self {
        Self {
            notifications: Arc::new(RwLock::new(Vec::new())),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Send notification
    pub async fn send_notification(&self, notification: AdminNotification) {
        // Store notification
        let mut notifications = self.notifications.write().await;
        notifications.push(notification.clone());

        // Keep only last 10000 notifications
        if notifications.len() > 10000 {
            notifications.remove(0);
        }
        drop(notifications);

        // Send to subscribers
        let subscribers = self.subscribers.read().await;
        for sender in subscribers.values() {
            let _ = sender.send(notification.clone());
        }
    }

    /// Subscribe to notifications
    pub async fn subscribe(&self, user_id: &str) -> broadcast::Receiver<AdminNotification> {
        let mut subscribers = self.subscribers.write().await;
        let (sender, receiver) = broadcast::channel(1000);
        subscribers.insert(user_id.to_string(), sender);
        receiver
    }

    /// Get notifications
    pub async fn get_notifications(
        &self,
        severity: Option<NotificationSeverity>,
        acknowledged: Option<bool>,
        limit: Option<usize>,
    ) -> Vec<AdminNotification> {
        let notifications = self.notifications.read().await;
        let mut filtered: Vec<AdminNotification> = notifications
            .iter()
            .filter(|n| {
                if let Some(sev) = &severity {
                    if !matches!((&n.severity, sev), 
                        (NotificationSeverity::Info, NotificationSeverity::Info) |
                        (NotificationSeverity::Warning, NotificationSeverity::Warning) |
                        (NotificationSeverity::Error, NotificationSeverity::Error) |
                        (NotificationSeverity::Critical, NotificationSeverity::Critical)
                    ) {
                        return false;
                    }
                }
                if let Some(ack) = acknowledged {
                    if n.acknowledged != ack {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(limit) = limit {
            filtered.truncate(limit);
        }
        
        filtered
    }

    /// Acknowledge notification
    pub async fn acknowledge_notification(&self, notification_id: &str, user_id: &str) -> Result<(), String> {
        let mut notifications = self.notifications.write().await;
        if let Some(notification) = notifications.iter_mut().find(|n| n.id == notification_id) {
            notification.acknowledged = true;
            notification.acknowledged_by = Some(user_id.to_string());
            notification.acknowledged_at = Some(SystemTime::now());
            Ok(())
        } else {
            Err("Notification not found".to_string())
        }
    }
}

/// Admin observability router
pub struct AdminObservabilityRouter;

impl AdminObservabilityRouter {
    /// Create admin observability router
    pub fn create_router(state: AdminObservabilityState) -> Router {
        Router::new()
            // Metrics endpoints
            .route("/observability/metrics", get(get_admin_metrics))
            .route("/observability/metrics/summary", get(get_metrics_summary))
            
            // Audit endpoints
            .route("/observability/audit", get(get_audit_events))
            .route("/observability/audit/statistics", get(get_audit_statistics))
            
            // Performance endpoints
            .route("/observability/performance", get(get_performance_data))
            .route("/observability/performance/alerts", get(get_performance_alerts))
            
            // Usage analytics endpoints
            .route("/observability/analytics", get(get_usage_analytics))
            .route("/observability/analytics/summary", get(get_usage_summary))
            
            // Impact analysis endpoints
            .route("/observability/impact", get(get_impact_history))
            .route("/observability/impact/summary", get(get_impact_summary))
            
            // Notification endpoints
            .route("/observability/notifications", get(get_notifications))
            .route("/observability/notifications/:id/acknowledge", put(acknowledge_notification))
            .route("/observability/notifications/subscribe", get(subscribe_to_notifications))
            
            .with_state(state)
    }
}

// Request/Response types for API endpoints
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub user_id: Option<String>,
    pub operation: Option<String>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct NotificationQueryParams {
    pub severity: Option<String>,
    pub acknowledged: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeNotificationRequest {
    pub user_id: String,
}

// API endpoint handlers
async fn get_admin_metrics(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<AdminMetrics>, StatusCode> {
    let metrics = state.metrics_collector.get_metrics().await;
    Ok(Json(metrics))
}

async fn get_metrics_summary(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let metrics = state.metrics_collector.get_metrics().await;
    let uptime = state.metrics_collector.get_uptime();
    
    Ok(Json(serde_json::json!({
        "uptime_seconds": uptime.as_secs(),
        "total_operations": metrics.total_operations,
        "success_rate": if metrics.total_operations > 0 {
            metrics.successful_operations as f64 / metrics.total_operations as f64
        } else {
            0.0
        },
        "active_sessions": metrics.active_sessions,
        "api_requests_total": metrics.api_requests_total,
        "dashboard_views": metrics.dashboard_views
    })))
}

async fn get_audit_events(
    State(state): State<AdminObservabilityState>,
    axum::extract::Query(params): axum::extract::Query<AuditQueryParams>,
) -> Result<Json<Vec<AdminAuditEvent>>, StatusCode> {
    let start_time = params.start_time.map(|ts| UNIX_EPOCH + Duration::from_secs(ts));
    let end_time = params.end_time.map(|ts| UNIX_EPOCH + Duration::from_secs(ts));
    
    let events = state.audit_logger.get_audit_events(
        params.user_id.as_deref(),
        params.operation.as_deref(),
        start_time,
        end_time,
        params.limit,
    ).await;
    
    Ok(Json(events))
}

async fn get_audit_statistics(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<AdminAuditStatistics>, StatusCode> {
    let statistics = state.audit_logger.get_audit_statistics().await;
    Ok(Json(statistics))
}

async fn get_performance_data(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<AdminPerformanceData>, StatusCode> {
    let data = state.performance_monitor.get_performance_data().await;
    Ok(Json(data))
}

async fn get_performance_alerts(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<Vec<PerformanceAlert>>, StatusCode> {
    let alerts = state.performance_monitor.get_performance_alerts().await;
    Ok(Json(alerts))
}

async fn get_usage_analytics(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<UsageAnalyticsData>, StatusCode> {
    let analytics = state.usage_analytics.get_analytics().await;
    Ok(Json(analytics))
}

async fn get_usage_summary(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<UsageSummary>, StatusCode> {
    let summary = state.usage_analytics.get_usage_summary().await;
    Ok(Json(summary))
}

async fn get_impact_history(
    State(state): State<AdminObservabilityState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<Vec<ConfigChangeImpact>>, StatusCode> {
    let limit = params.get("limit").and_then(|s| s.parse().ok());
    let history = state.impact_analyzer.get_impact_history(limit).await;
    Ok(Json(history))
}

async fn get_impact_summary(
    State(state): State<AdminObservabilityState>,
) -> Result<Json<ImpactSummary>, StatusCode> {
    let summary = state.impact_analyzer.get_impact_summary().await;
    Ok(Json(summary))
}

async fn get_notifications(
    State(state): State<AdminObservabilityState>,
    axum::extract::Query(params): axum::extract::Query<NotificationQueryParams>,
) -> Result<Json<Vec<AdminNotification>>, StatusCode> {
    let severity = params.severity.as_ref().and_then(|s| match s.as_str() {
        "info" => Some(NotificationSeverity::Info),
        "warning" => Some(NotificationSeverity::Warning),
        "error" => Some(NotificationSeverity::Error),
        "critical" => Some(NotificationSeverity::Critical),
        _ => None,
    });
    
    let notifications = state.notification_system.get_notifications(
        severity,
        params.acknowledged,
        params.limit,
    ).await;
    
    Ok(Json(notifications))
}

async fn acknowledge_notification(
    State(state): State<AdminObservabilityState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(request): Json<AcknowledgeNotificationRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.notification_system.acknowledge_notification(&id, &request.user_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "message": "Notification acknowledged successfully",
            "notification_id": id
        }))),
        Err(e) => {
            error!("Failed to acknowledge notification: {}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn subscribe_to_notifications(
    State(state): State<AdminObservabilityState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user_id = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let _receiver = state.notification_system.subscribe(user_id).await;
    
    // In a real implementation, this would set up a WebSocket or SSE connection
    Ok(Json(serde_json::json!({
        "message": "Subscribed to notifications successfully",
        "user_id": user_id
    })))
}
//! # Admin Observability Tests
//!
//! Comprehensive tests for admin observability and monitoring features

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

use api_gateway::admin::observability::{
    AdminObservabilityState, AdminMetricsCollector, AdminAuditLogger, AdminPerformanceMonitor,
    AdminUsageAnalytics, ConfigChangeImpactAnalyzer, AdminNotificationSystem,
    ImpactLevel, NotificationType, NotificationSeverity, AdminNotification, AlertType,
};

/// Test admin metrics collection
#[tokio::test]
async fn test_admin_metrics_collection() {
    let metrics_collector = Arc::new(AdminMetricsCollector::new());

    // Record some operations
    metrics_collector.record_operation("config_update", "admin1", true).await;
    metrics_collector.record_operation("service_restart", "admin1", false).await;
    metrics_collector.record_operation("config_update", "admin2", true).await;

    // Record sessions
    metrics_collector.record_session("admin1", "super_admin", Duration::from_secs(300)).await;
    metrics_collector.record_session("admin2", "admin", Duration::from_secs(150)).await;

    // Record API requests
    metrics_collector.record_api_request("/admin/config", Duration::from_millis(200), true).await;
    metrics_collector.record_api_request("/admin/services", Duration::from_millis(500), false).await;

    // Record dashboard usage
    metrics_collector.record_dashboard_usage("admin1", "dashboard", "view").await;
    metrics_collector.record_dashboard_usage("admin1", "services", "edit").await;

    // Get metrics and verify
    let metrics = metrics_collector.get_metrics().await;
    
    assert_eq!(metrics.total_operations, 3);
    assert_eq!(metrics.successful_operations, 2);
    assert_eq!(metrics.failed_operations, 1);
    assert_eq!(metrics.total_sessions, 2);
    assert_eq!(metrics.api_requests_total, 2);
    assert_eq!(metrics.dashboard_views, 2);
    
    // Check operations by type
    assert_eq!(metrics.operations_by_type.get("config_update"), Some(&2));
    assert_eq!(metrics.operations_by_type.get("service_restart"), Some(&1));
    
    // Check operations by user
    assert_eq!(metrics.operations_by_user.get("admin1"), Some(&2));
    assert_eq!(metrics.operations_by_user.get("admin2"), Some(&1));
    
    // Check API requests by endpoint
    assert_eq!(metrics.api_requests_by_endpoint.get("/admin/config"), Some(&1));
    assert_eq!(metrics.api_requests_by_endpoint.get("/admin/services"), Some(&1));
    
    // Verify uptime is reasonable (should be at least some nanoseconds)
    let uptime = metrics_collector.get_uptime();
    assert!(uptime.as_nanos() > 0);
}

/// Test admin audit logging
#[tokio::test]
async fn test_admin_audit_logging() {
    let audit_logger = Arc::new(AdminAuditLogger::new(1000));

    // Log some operations
    let mut details = HashMap::new();
    details.insert("config_key".to_string(), serde_json::json!("gateway.timeout"));
    details.insert("old_value".to_string(), serde_json::json!(30));
    details.insert("new_value".to_string(), serde_json::json!(60));

    audit_logger.log_operation(
        "admin1",
        "super_admin",
        "config_update",
        "gateway_config",
        "update",
        details.clone(),
        Some("192.168.1.100".to_string()),
        Some("Mozilla/5.0".to_string()),
        true,
        None,
        Duration::from_millis(150),
        ImpactLevel::Medium,
    ).await;

    audit_logger.log_operation(
        "admin2",
        "admin",
        "service_restart",
        "user_service",
        "restart",
        HashMap::new(),
        Some("192.168.1.101".to_string()),
        Some("curl/7.68.0".to_string()),
        false,
        Some("Service not found".to_string()),
        Duration::from_millis(50),
        ImpactLevel::High,
    ).await;

    // Test filtering by user
    let admin1_events = audit_logger.get_audit_events(
        Some("admin1"),
        None,
        None,
        None,
        None,
    ).await;
    assert_eq!(admin1_events.len(), 1);
    assert_eq!(admin1_events[0].user_id, "admin1");
    assert_eq!(admin1_events[0].operation, "config_update");
    assert!(admin1_events[0].success);

    // Test filtering by operation
    let config_events = audit_logger.get_audit_events(
        None,
        Some("config_update"),
        None,
        None,
        None,
    ).await;
    assert_eq!(config_events.len(), 1);
    assert_eq!(config_events[0].operation, "config_update");

    // Test filtering with limit
    let limited_events = audit_logger.get_audit_events(
        None,
        None,
        None,
        None,
        Some(1),
    ).await;
    assert_eq!(limited_events.len(), 1);

    // Get audit statistics
    let stats = audit_logger.get_audit_statistics().await;
    assert_eq!(stats.total_events, 2);
    assert_eq!(stats.successful_operations, 1);
    assert_eq!(stats.failed_operations, 1);
    assert_eq!(stats.operations_by_type.get("config_update"), Some(&1));
    assert_eq!(stats.operations_by_type.get("service_restart"), Some(&1));
    assert_eq!(stats.operations_by_user.get("admin1"), Some(&1));
    assert_eq!(stats.operations_by_user.get("admin2"), Some(&1));
}

/// Test admin performance monitoring
#[tokio::test]
async fn test_admin_performance_monitoring() {
    let performance_monitor = Arc::new(AdminPerformanceMonitor::new());

    // Record some endpoint performance
    performance_monitor.record_endpoint_performance(
        "/admin/config",
        Duration::from_millis(200),
        true,
        "admin1",
    ).await;

    performance_monitor.record_endpoint_performance(
        "/admin/config",
        Duration::from_millis(300),
        true,
        "admin1",
    ).await;

    performance_monitor.record_endpoint_performance(
        "/admin/services",
        Duration::from_millis(6000), // Slow query - above 5000ms threshold
        false,
        "admin2",
    ).await;

    // Get performance data
    let data = performance_monitor.get_performance_data().await;
    
    // Check endpoint metrics
    let config_metrics = data.endpoint_metrics.get("/admin/config").unwrap();
    assert_eq!(config_metrics.total_requests, 2);
    assert_eq!(config_metrics.average_response_time, 250.0);
    assert_eq!(config_metrics.min_response_time, 200.0);
    assert_eq!(config_metrics.max_response_time, 300.0);
    assert_eq!(config_metrics.error_rate, 0.0);

    let services_metrics = data.endpoint_metrics.get("/admin/services").unwrap();
    assert_eq!(services_metrics.total_requests, 1);
    assert_eq!(services_metrics.average_response_time, 6000.0);
    assert_eq!(services_metrics.error_rate, 1.0);

    // Check slow queries
    assert_eq!(data.slow_queries.len(), 1);
    assert_eq!(data.slow_queries[0].endpoint, "/admin/services");
    assert_eq!(data.slow_queries[0].duration_ms, 6000);
    assert_eq!(data.slow_queries[0].user_id, "admin2");

    // Get performance alerts
    let alerts = performance_monitor.get_performance_alerts().await;
    assert!(!alerts.is_empty());
    
    // Should have both error rate and slow response time alerts for /admin/services
    let services_alerts: Vec<_> = alerts.iter().filter(|a| a.endpoint == "/admin/services").collect();
    assert!(!services_alerts.is_empty());
    
    // Find the slow response time alert
    let slow_alert = services_alerts.iter().find(|a| matches!(a.alert_type, AlertType::SlowResponseTime)).unwrap();
    assert_eq!(slow_alert.value, 6000.0);
    assert_eq!(slow_alert.threshold, 5000.0);
    
    // Find the high error rate alert
    let error_alert = services_alerts.iter().find(|a| matches!(a.alert_type, AlertType::HighErrorRate)).unwrap();
    assert_eq!(error_alert.value, 1.0); // 100% error rate
    assert_eq!(error_alert.threshold, 0.1); // 10% threshold
}

/// Test admin usage analytics
#[tokio::test]
async fn test_admin_usage_analytics() {
    let usage_analytics = Arc::new(AdminUsageAnalytics::new());

    // Record user activities
    usage_analytics.record_user_activity("admin1", "dashboard", "view", "session1").await;
    usage_analytics.record_user_activity("admin1", "services", "edit", "session1").await;
    usage_analytics.record_user_activity("admin2", "dashboard", "view", "session2").await;
    usage_analytics.record_user_activity("admin1", "config", "update", "session1").await;

    // End a session
    usage_analytics.end_user_session("admin1", "session1").await;

    // Get analytics data
    let analytics = usage_analytics.get_analytics().await;
    
    // Check feature usage
    assert_eq!(analytics.feature_usage.get("view"), Some(&2));
    assert_eq!(analytics.feature_usage.get("edit"), Some(&1));
    assert_eq!(analytics.feature_usage.get("update"), Some(&1));

    // Check page views
    assert_eq!(analytics.page_views.get("dashboard"), Some(&2));
    assert_eq!(analytics.page_views.get("services"), Some(&1));
    assert_eq!(analytics.page_views.get("config"), Some(&1));

    // Check user sessions
    assert_eq!(analytics.user_sessions.len(), 2);
    let admin1_sessions = analytics.user_sessions.get("admin1").unwrap();
    assert_eq!(admin1_sessions.len(), 1);
    assert!(admin1_sessions[0].end_time.is_some());
    assert!(admin1_sessions[0].total_duration.is_some());

    // Get usage summary
    let summary = usage_analytics.get_usage_summary().await;
    assert_eq!(summary.total_users, 2);
    assert_eq!(summary.total_sessions, 2);
    assert_eq!(summary.total_page_views, 4);
    assert_eq!(summary.total_actions, 4);
    assert!(!summary.most_used_features.is_empty());
    assert!(!summary.most_viewed_pages.is_empty());
}

/// Test configuration change impact analysis
#[tokio::test]
async fn test_config_change_impact_analysis() {
    let impact_analyzer = Arc::new(ConfigChangeImpactAnalyzer::new());

    // Analyze some configuration changes
    let impact1 = impact_analyzer.analyze_change_impact(
        "change1",
        "admin1",
        "service_config",
        vec!["user-service".to_string(), "auth-service".to_string()],
    ).await;

    let impact2 = impact_analyzer.analyze_change_impact(
        "change2",
        "admin2",
        "security_policy",
        vec!["gateway".to_string()],
    ).await;

    // Verify impact analysis
    assert_eq!(impact1.change_id, "change1");
    assert_eq!(impact1.user_id, "admin1");
    assert_eq!(impact1.change_type, "service_config");
    assert_eq!(impact1.affected_services.len(), 2);
    assert!(impact1.rollback_available);

    assert_eq!(impact2.change_id, "change2");
    assert_eq!(impact2.user_id, "admin2");
    assert_eq!(impact2.change_type, "security_policy");
    assert_eq!(impact2.affected_services.len(), 1);

    // Get impact history
    let history = impact_analyzer.get_impact_history(Some(10)).await;
    assert_eq!(history.len(), 2);
    
    // Should be sorted by timestamp (newest first)
    assert!(history[0].timestamp >= history[1].timestamp);

    // Get impact summary
    let summary = impact_analyzer.get_impact_summary().await;
    assert_eq!(summary.total_changes, 2);
    assert_eq!(summary.high_risk_changes, 1); // security_policy is critical
    assert!(summary.avg_error_rate_change > 0.0);
    assert!(summary.avg_latency_change > 0.0);
}

/// Test admin notification system
#[tokio::test]
async fn test_admin_notification_system() {
    let notification_system = Arc::new(AdminNotificationSystem::new());

    // Create some notifications
    let notification1 = AdminNotification {
        id: "notif1".to_string(),
        timestamp: SystemTime::now(),
        notification_type: NotificationType::SystemAlert,
        severity: NotificationSeverity::Warning,
        title: "High CPU Usage".to_string(),
        message: "CPU usage is above 80%".to_string(),
        details: HashMap::new(),
        acknowledged: false,
        acknowledged_by: None,
        acknowledged_at: None,
    };

    let notification2 = AdminNotification {
        id: "notif2".to_string(),
        timestamp: SystemTime::now(),
        notification_type: NotificationType::SecurityEvent,
        severity: NotificationSeverity::Critical,
        title: "Failed Login Attempts".to_string(),
        message: "Multiple failed login attempts detected".to_string(),
        details: HashMap::new(),
        acknowledged: false,
        acknowledged_by: None,
        acknowledged_at: None,
    };

    // Send notifications
    notification_system.send_notification(notification1.clone()).await;
    notification_system.send_notification(notification2.clone()).await;

    // Get all notifications
    let all_notifications = notification_system.get_notifications(None, None, None).await;
    assert_eq!(all_notifications.len(), 2);

    // Filter by severity
    let critical_notifications = notification_system.get_notifications(
        Some(NotificationSeverity::Critical),
        None,
        None,
    ).await;
    assert_eq!(critical_notifications.len(), 1);
    assert_eq!(critical_notifications[0].severity, NotificationSeverity::Critical);

    // Filter by acknowledged status
    let unacknowledged = notification_system.get_notifications(
        None,
        Some(false),
        None,
    ).await;
    assert_eq!(unacknowledged.len(), 2);

    // Acknowledge a notification
    let result = notification_system.acknowledge_notification("notif1", "admin1").await;
    assert!(result.is_ok());

    // Check acknowledged notifications
    let acknowledged = notification_system.get_notifications(
        None,
        Some(true),
        None,
    ).await;
    assert_eq!(acknowledged.len(), 1);
    assert_eq!(acknowledged[0].id, "notif1");
    assert_eq!(acknowledged[0].acknowledged_by, Some("admin1".to_string()));
    assert!(acknowledged[0].acknowledged_at.is_some());

    // Test subscription (basic test - in real implementation would use WebSocket/SSE)
    let _receiver = notification_system.subscribe("admin1").await;
    // In a real test, you would verify that new notifications are received
}

/// Test admin observability state integration
#[tokio::test]
async fn test_admin_observability_state_integration() {
    // Create all components
    let metrics_collector = Arc::new(AdminMetricsCollector::new());
    let audit_logger = Arc::new(AdminAuditLogger::new(1000));
    let performance_monitor = Arc::new(AdminPerformanceMonitor::new());
    let usage_analytics = Arc::new(AdminUsageAnalytics::new());
    let impact_analyzer = Arc::new(ConfigChangeImpactAnalyzer::new());
    let notification_system = Arc::new(AdminNotificationSystem::new());

    // Create observability state
    let _observability_state = AdminObservabilityState {
        metrics_collector: metrics_collector.clone(),
        audit_logger: audit_logger.clone(),
        performance_monitor: performance_monitor.clone(),
        usage_analytics: usage_analytics.clone(),
        impact_analyzer: impact_analyzer.clone(),
        notification_system: notification_system.clone(),
    };

    // Simulate some admin activity
    metrics_collector.record_operation("config_update", "admin1", true).await;
    
    audit_logger.log_operation(
        "admin1",
        "super_admin",
        "config_update",
        "gateway_config",
        "update",
        HashMap::new(),
        Some("192.168.1.100".to_string()),
        None,
        true,
        None,
        Duration::from_millis(100),
        ImpactLevel::Medium,
    ).await;

    performance_monitor.record_endpoint_performance(
        "/admin/config",
        Duration::from_millis(100),
        true,
        "admin1",
    ).await;

    usage_analytics.record_user_activity("admin1", "config", "update", "session1").await;

    let _impact = impact_analyzer.analyze_change_impact(
        "change1",
        "admin1",
        "config_update",
        vec!["gateway".to_string()],
    ).await;

    let notification = AdminNotification {
        id: "notif1".to_string(),
        timestamp: SystemTime::now(),
        notification_type: NotificationType::ConfigurationChange,
        severity: NotificationSeverity::Info,
        title: "Configuration Updated".to_string(),
        message: "Gateway configuration has been updated".to_string(),
        details: HashMap::new(),
        acknowledged: false,
        acknowledged_by: None,
        acknowledged_at: None,
    };
    notification_system.send_notification(notification).await;

    // Verify all components have recorded the activity
    let metrics = metrics_collector.get_metrics().await;
    assert_eq!(metrics.total_operations, 1);

    let audit_events = audit_logger.get_audit_events(None, None, None, None, None).await;
    assert_eq!(audit_events.len(), 1);

    let performance_data = performance_monitor.get_performance_data().await;
    assert!(!performance_data.endpoint_metrics.is_empty());

    let analytics = usage_analytics.get_analytics().await;
    assert!(!analytics.feature_usage.is_empty());

    let impact_history = impact_analyzer.get_impact_history(None).await;
    assert_eq!(impact_history.len(), 1);

    let notifications = notification_system.get_notifications(None, None, None).await;
    assert_eq!(notifications.len(), 1);
}

/// Test concurrent access to observability components
#[tokio::test]
async fn test_concurrent_observability_access() {
    let metrics_collector = Arc::new(AdminMetricsCollector::new());
    let audit_logger = Arc::new(AdminAuditLogger::new(1000));

    // Spawn multiple tasks that concurrently access the components
    let mut handles = Vec::new();

    for i in 0..10 {
        let metrics = metrics_collector.clone();
        let audit = audit_logger.clone();
        
        let handle = tokio::spawn(async move {
            let user_id = format!("admin{}", i);
            
            // Record metrics
            metrics.record_operation("test_operation", &user_id, true).await;
            metrics.record_api_request("/admin/test", Duration::from_millis(100), true).await;
            
            // Log audit event
            audit.log_operation(
                &user_id,
                "admin",
                "test_operation",
                "test_resource",
                "test_action",
                HashMap::new(),
                None,
                None,
                true,
                None,
                Duration::from_millis(50),
                ImpactLevel::Low,
            ).await;
            
            // Small delay to simulate real work
            sleep(Duration::from_millis(10)).await;
        });
        
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all operations were recorded correctly
    let metrics = metrics_collector.get_metrics().await;
    assert_eq!(metrics.total_operations, 10);
    assert_eq!(metrics.api_requests_total, 10);

    let audit_events = audit_logger.get_audit_events(None, None, None, None, None).await;
    assert_eq!(audit_events.len(), 10);
}
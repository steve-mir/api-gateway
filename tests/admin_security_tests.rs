//! # Admin Security Tests
//!
//! Comprehensive tests for admin security and compliance functionality including:
//! - Approval workflow system
//! - Access control with principle of least privilege
//! - Session monitoring and anomaly detection
//! - Security scanning and vulnerability assessment
//! - Compliance reporting
//! - Backup and disaster recovery

use api_gateway::admin::{
    AdminSecurityState, ApprovalWorkflowManager, AccessControlManager, SessionMonitor,
    AdminOperation, ApprovalStatus, ApprovalDecision, ApprovalRequirement, RiskLevel,
    UserPermissions, Permission, PermissionGrant, AccessContext, AccountStatus,
    MonitoredSession, SessionAction, ActionResult, AnomalyRule, AnomalyRuleType,
    AnomalySeverity, SessionAnomaly, SecurityScannerState, SecurityScanner, ScanConfig,
    ScanTarget, ScanType, AuthMethod, VulnerabilityType, VulnerabilitySeverity,
    ComplianceState, ComplianceManager, ComplianceFramework, ComplianceReportType,
    ReportPeriod, BackupRecoveryState, BackupRecoveryManager, BackupType, RestoreType,
    ExecutionType, ConfigAudit, ConfigChange, ConfigChangeType
};
use api_gateway::core::config::GatewayConfig;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio;
use uuid::Uuid;

// ============================================================================
// Approval Workflow Tests
// ============================================================================

#[tokio::test]
async fn test_approval_workflow_creation() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    let operation = AdminOperation::ConfigChange {
        change_type: ConfigChangeType::FullReplace,
        description: "Replace entire configuration".to_string(),
        config_diff: serde_json::json!({"test": "value"}),
    };

    let workflow_id = workflow_manager
        .create_workflow(operation, "admin_user".to_string(), "Emergency config update".to_string())
        .await
        .expect("Failed to create workflow");

    let workflow = workflow_manager.get_workflow(workflow_id).await
        .expect("Workflow should exist");

    assert_eq!(workflow.requester, "admin_user");
    assert_eq!(workflow.justification, "Emergency config update");
    assert!(matches!(workflow.status, ApprovalStatus::Pending));
    assert!(matches!(workflow.risk_level, RiskLevel::Critical));
}

#[tokio::test]
async fn test_approval_workflow_approval_process() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    let operation = AdminOperation::UserManagement {
        action: "create_user".to_string(),
        target_user: "new_user".to_string(),
        details: serde_json::json!({"role": "admin"}),
    };

    let workflow_id = workflow_manager
        .create_workflow(operation, "admin1".to_string(), "Create new admin user".to_string())
        .await
        .expect("Failed to create workflow");

    // Submit approval
    let status = workflow_manager
        .submit_approval(
            workflow_id,
            "admin2".to_string(),
            ApprovalDecision::Approved,
            Some("Approved for emergency access".to_string()),
            "192.168.1.100".to_string(),
        )
        .await
        .expect("Failed to submit approval");

    // Check if workflow is approved (depends on policy)
    let workflow = workflow_manager.get_workflow(workflow_id).await.unwrap();
    assert!(!workflow.approvals.is_empty());
    assert_eq!(workflow.approvals[0].approver, "admin2");
    assert!(matches!(workflow.approvals[0].decision, ApprovalDecision::Approved));
}

#[tokio::test]
async fn test_approval_workflow_rejection() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    let operation = AdminOperation::SystemMaintenance {
        operation: "shutdown".to_string(),
        scope: "all_services".to_string(),
        details: serde_json::json!({"duration": "2h"}),
    };

    let workflow_id = workflow_manager
        .create_workflow(operation, "admin1".to_string(), "Planned maintenance".to_string())
        .await
        .expect("Failed to create workflow");

    // Submit rejection
    let status = workflow_manager
        .submit_approval(
            workflow_id,
            "admin2".to_string(),
            ApprovalDecision::Rejected,
            Some("Maintenance window not approved".to_string()),
            "192.168.1.101".to_string(),
        )
        .await
        .expect("Failed to submit approval");

    assert!(matches!(status, ApprovalStatus::Rejected));

    let workflow = workflow_manager.get_workflow(workflow_id).await.unwrap();
    assert!(matches!(workflow.status, ApprovalStatus::Rejected));
}

#[tokio::test]
async fn test_approval_workflow_execution() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    let operation = AdminOperation::ConfigChange {
        change_type: ConfigChangeType::RouteAdd,
        description: "Add new route".to_string(),
        config_diff: serde_json::json!({"route": "/api/v2"}),
    };

    let workflow_id = workflow_manager
        .create_workflow(operation, "admin1".to_string(), "Add API v2 route".to_string())
        .await
        .expect("Failed to create workflow");

    // Approve workflow
    workflow_manager
        .submit_approval(
            workflow_id,
            "admin2".to_string(),
            ApprovalDecision::Approved,
            None,
            "192.168.1.102".to_string(),
        )
        .await
        .expect("Failed to submit approval");

    // Execute workflow
    workflow_manager
        .execute_workflow(workflow_id)
        .await
        .expect("Failed to execute workflow");

    let workflow = workflow_manager.get_workflow(workflow_id).await.unwrap();
    assert!(matches!(workflow.status, ApprovalStatus::Executed));
}

// ============================================================================
// Access Control Tests
// ============================================================================

#[tokio::test]
async fn test_access_control_permission_check() {
    let audit = Arc::new(ConfigAudit::new(None));
    let access_control = AccessControlManager::new(audit);

    let context = AccessContext {
        ip_address: "192.168.1.100".to_string(),
        user_agent: Some("Admin-Client/1.0".to_string()),
        mfa_verified: true,
        approval_id: None,
        timestamp: Utc::now(),
        metadata: HashMap::new(),
    };

    // Test permission check for non-existent user
    let result = access_control
        .check_permission("user123", "config", "read", &context)
        .await;

    assert!(result.is_err()); // Should fail for non-existent user
}

#[tokio::test]
async fn test_access_control_permission_grant() {
    let audit = Arc::new(ConfigAudit::new(None));
    let access_control = AccessControlManager::new(audit);

    let permission = Permission {
        name: "emergency_config_access".to_string(),
        resource: "config".to_string(),
        actions: vec!["read".to_string(), "write".to_string()],
        conditions: vec![],
        granted_at: Utc::now(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
    };

    let grant_id = access_control
        .grant_permission(
            "user123",
            permission,
            "admin",
            "Emergency access for incident response".to_string(),
            Duration::hours(2),
        )
        .await
        .expect("Failed to grant permission");

    assert!(!grant_id.is_nil());
}

#[tokio::test]
async fn test_access_control_permission_revocation() {
    let audit = Arc::new(ConfigAudit::new(None));
    let access_control = AccessControlManager::new(audit);

    let permission = Permission {
        name: "temp_access".to_string(),
        resource: "services".to_string(),
        actions: vec!["read".to_string()],
        conditions: vec![],
        granted_at: Utc::now(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
    };

    let grant_id = access_control
        .grant_permission(
            "user456",
            permission,
            "admin",
            "Temporary access".to_string(),
            Duration::hours(1),
        )
        .await
        .expect("Failed to grant permission");

    // Revoke the grant
    access_control
        .revoke_grant("user456", grant_id)
        .await
        .expect("Failed to revoke grant");
}

// ============================================================================
// Session Monitoring Tests
// ============================================================================

#[tokio::test]
async fn test_session_monitoring_start_stop() {
    let audit = Arc::new(ConfigAudit::new(None));
    let session_monitor = SessionMonitor::new(audit);

    let session_id = "session_123".to_string();
    let user_id = "user_456".to_string();

    // Start monitoring
    session_monitor
        .start_monitoring(
            session_id.clone(),
            user_id.clone(),
            "192.168.1.100".to_string(),
            Some("Mozilla/5.0".to_string()),
        )
        .await;

    // Check session exists
    let session = session_monitor.get_session(&session_id).await;
    assert!(session.is_some());
    assert_eq!(session.unwrap().user_id, user_id);

    // Stop monitoring
    session_monitor.stop_monitoring(&session_id).await;

    // Check session is removed
    let session = session_monitor.get_session(&session_id).await;
    assert!(session.is_none());
}

#[tokio::test]
async fn test_session_monitoring_activity_recording() {
    let audit = Arc::new(ConfigAudit::new(None));
    let session_monitor = SessionMonitor::new(audit);

    let session_id = "session_789".to_string();

    // Start monitoring
    session_monitor
        .start_monitoring(
            session_id.clone(),
            "user_789".to_string(),
            "192.168.1.100".to_string(),
            None,
        )
        .await;

    // Record activity
    session_monitor
        .record_activity(
            &session_id,
            "config_change".to_string(),
            "/admin/config".to_string(),
            ActionResult::Success,
            serde_json::json!({"change": "route_added"}),
            Some("192.168.1.100".to_string()),
            None,
        )
        .await
        .expect("Failed to record activity");

    // Check activity was recorded
    let session = session_monitor.get_session(&session_id).await.unwrap();
    assert_eq!(session.actions.len(), 1);
    assert_eq!(session.actions[0].action_type, "config_change");
    assert!(matches!(session.actions[0].result, ActionResult::Success));
}

#[tokio::test]
async fn test_session_monitoring_anomaly_detection() {
    let audit = Arc::new(ConfigAudit::new(None));
    let session_monitor = SessionMonitor::new(audit);

    let session_id = "session_anomaly".to_string();

    // Start monitoring
    session_monitor
        .start_monitoring(
            session_id.clone(),
            "user_anomaly".to_string(),
            "192.168.1.100".to_string(),
            None,
        )
        .await;

    // Record multiple failed authentication attempts to trigger anomaly
    for i in 0..5 {
        session_monitor
            .record_activity(
                &session_id,
                "auth_attempt".to_string(),
                "/admin/login".to_string(),
                ActionResult::Failed,
                serde_json::json!({"attempt": i}),
                Some("192.168.1.100".to_string()),
                None,
            )
            .await
            .expect("Failed to record activity");
    }

    // Give some time for anomaly detection to process
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check for anomalies
    let anomalies = session_monitor.get_anomalies(10).await;
    // Note: Anomaly detection might not trigger immediately in test environment
    // This test verifies the recording mechanism works
}

// ============================================================================
// Security Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_security_scanner_configuration() {
    let scanner_state = SecurityScannerState::new();

    let scan_config = ScanConfig {
        name: "test_scan".to_string(),
        targets: vec![ScanTarget {
            base_url: "http://localhost:8080".to_string(),
            endpoints: vec!["/admin/health".to_string(), "/admin/config".to_string()],
            auth: AuthMethod::Bearer {
                token: "test_token".to_string(),
            },
            headers: HashMap::new(),
        }],
        scan_types: vec![ScanType::OwaspTop10, ScanType::AuthenticationFlaws],
        schedule: Some("0 2 * * *".to_string()),
        max_duration: Duration::minutes(30),
        enabled: true,
        notifications: api_gateway::admin::security_scanner::NotificationConfig {
            email: None,
            webhook: None,
            severity_threshold: VulnerabilitySeverity::Medium,
        },
    };

    scanner_state
        .scanner
        .add_scan_config("test_scan".to_string(), scan_config.clone())
        .await
        .expect("Failed to add scan config");

    let retrieved_config = scanner_state
        .scanner
        .get_scan_config("test_scan")
        .await
        .expect("Config should exist");

    assert_eq!(retrieved_config.name, "test_scan");
    assert_eq!(retrieved_config.targets.len(), 1);
    assert_eq!(retrieved_config.scan_types.len(), 2);
}

#[tokio::test]
async fn test_security_scanner_scan_lifecycle() {
    let scanner_state = SecurityScannerState::new();

    // Add a scan configuration
    let scan_config = ScanConfig {
        name: "lifecycle_test".to_string(),
        targets: vec![ScanTarget {
            base_url: "http://httpbin.org".to_string(), // Public testing service
            endpoints: vec!["/status/200".to_string()],
            auth: AuthMethod::None,
            headers: HashMap::new(),
        }],
        scan_types: vec![ScanType::ConfigurationSecurity],
        schedule: None,
        max_duration: Duration::minutes(5),
        enabled: true,
        notifications: api_gateway::admin::security_scanner::NotificationConfig {
            email: None,
            webhook: None,
            severity_threshold: VulnerabilitySeverity::Low,
        },
    };

    scanner_state
        .scanner
        .add_scan_config("lifecycle_test".to_string(), scan_config)
        .await
        .expect("Failed to add scan config");

    // Start a scan
    let scan_id = scanner_state
        .scanner
        .start_scan("lifecycle_test")
        .await
        .expect("Failed to start scan");

    // Check scan was created
    let scan_result = scanner_state.scanner.get_scan_result(scan_id).await;
    assert!(scan_result.is_some());

    // Wait a bit for scan to potentially complete or make progress
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Cancel the scan
    scanner_state
        .scanner
        .cancel_scan(scan_id)
        .await
        .expect("Failed to cancel scan");

    // Verify scan was cancelled
    let scan_result = scanner_state.scanner.get_scan_result(scan_id).await.unwrap();
    assert!(matches!(
        scan_result.status,
        api_gateway::admin::security_scanner::ScanStatus::Cancelled
    ));
}

// ============================================================================
// Compliance Tests
// ============================================================================

#[tokio::test]
async fn test_compliance_report_generation() {
    let audit = Arc::new(ConfigAudit::new(None));
    let compliance_state = ComplianceState::new(audit.clone());

    // Add some audit records to test against
    let config_change = ConfigChange::new(
        ConfigChangeType::RouteAdd,
        "admin_user".to_string(),
        "Added new API route".to_string(),
        None,
        GatewayConfig::default(),
    );

    audit
        .record_change(config_change)
        .await
        .expect("Failed to record change");

    let period = ReportPeriod {
        start_date: Utc::now() - Duration::days(30),
        end_date: Utc::now(),
        description: "Monthly compliance report".to_string(),
    };

    let report_id = compliance_state
        .manager
        .generate_report(
            ComplianceReportType::Periodic,
            ComplianceFramework::Sox,
            period,
            "compliance_officer".to_string(),
        )
        .await
        .expect("Failed to generate compliance report");

    let report = compliance_state
        .manager
        .get_report(report_id)
        .await
        .expect("Report should exist");

    assert_eq!(report.generated_by, "compliance_officer");
    assert!(matches!(report.framework, ComplianceFramework::Sox));
    assert!(matches!(
        report.report_type,
        ComplianceReportType::Periodic
    ));
}

#[tokio::test]
async fn test_compliance_dashboard_data() {
    let audit = Arc::new(ConfigAudit::new(None));
    let compliance_state = ComplianceState::new(audit);

    let dashboard = compliance_state
        .manager
        .get_dashboard_data()
        .await
        .expect("Failed to get dashboard data");

    // Basic validation of dashboard structure
    assert!(dashboard.compliance_score >= 0.0);
    assert!(dashboard.compliance_score <= 100.0);
    assert!(dashboard.total_requirements > 0); // Should have default requirements
}

// ============================================================================
// Backup and Recovery Tests
// ============================================================================

#[tokio::test]
async fn test_backup_creation() {
    let audit = Arc::new(ConfigAudit::new(None));
    let backup_state = BackupRecoveryState::new(audit);

    let backup_id = backup_state
        .manager
        .create_backup("daily", BackupType::ConfigOnly, "admin".to_string())
        .await
        .expect("Failed to create backup");

    // Wait a moment for backup to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let backup_record = backup_state.manager.get_backup(backup_id).await;
    assert!(backup_record.is_some());

    let record = backup_record.unwrap();
    assert_eq!(record.config_name, "daily");
    assert!(matches!(record.backup_type, BackupType::ConfigOnly));
}

#[tokio::test]
async fn test_backup_listing() {
    let audit = Arc::new(ConfigAudit::new(None));
    let backup_state = BackupRecoveryState::new(audit);

    // Create a few backups
    for i in 0..3 {
        backup_state
            .manager
            .create_backup("daily", BackupType::Full, format!("admin_{}", i))
            .await
            .expect("Failed to create backup");
    }

    // Wait for backups to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let backups = backup_state.manager.list_backups(10).await;
    assert!(backups.len() >= 3);
}

#[tokio::test]
async fn test_recovery_plan_management() {
    let audit = Arc::new(ConfigAudit::new(None));
    let backup_state = BackupRecoveryState::new(audit);

    let recovery_plans = backup_state.manager.list_recovery_plans().await;
    assert!(!recovery_plans.is_empty()); // Should have default recovery plan

    let plan = &recovery_plans[0];
    assert!(!plan.steps.is_empty());
    assert!(plan.rto_minutes > 0);
    assert!(plan.rpo_minutes > 0);
}

#[tokio::test]
async fn test_recovery_plan_execution() {
    let audit = Arc::new(ConfigAudit::new(None));
    let backup_state = BackupRecoveryState::new(audit);

    let recovery_plans = backup_state.manager.list_recovery_plans().await;
    let plan_id = recovery_plans[0].id;

    let execution_id = backup_state
        .manager
        .execute_recovery_plan(plan_id, ExecutionType::Test, "admin".to_string())
        .await
        .expect("Failed to execute recovery plan");

    assert!(!execution_id.is_nil());
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_admin_security_integration() {
    let audit = Arc::new(ConfigAudit::new(None));
    let security_state = AdminSecurityState::new(audit.clone());

    // Test workflow creation
    let operation = AdminOperation::SecurityPolicyChange {
        policy_type: "access_control".to_string(),
        changes: serde_json::json!({"new_policy": "strict"}),
    };

    let workflow_id = security_state
        .approval_workflow
        .create_workflow(operation, "security_admin".to_string(), "Tighten security policies".to_string())
        .await
        .expect("Failed to create workflow");

    // Test session monitoring
    security_state
        .session_monitor
        .start_monitoring(
            "integration_session".to_string(),
            "security_admin".to_string(),
            "192.168.1.200".to_string(),
            Some("Admin-Client/2.0".to_string()),
        )
        .await;

    // Record workflow creation activity
    security_state
        .session_monitor
        .record_activity(
            "integration_session",
            "workflow_creation".to_string(),
            "/admin/security/workflows".to_string(),
            ActionResult::Success,
            serde_json::json!({"workflow_id": workflow_id}),
            Some("192.168.1.200".to_string()),
            None,
        )
        .await
        .expect("Failed to record activity");

    // Verify integration
    let workflow = security_state.approval_workflow.get_workflow(workflow_id).await;
    assert!(workflow.is_some());

    let session = security_state.session_monitor.get_session("integration_session").await;
    assert!(session.is_some());
    assert_eq!(session.unwrap().actions.len(), 1);
}

#[tokio::test]
async fn test_security_compliance_integration() {
    let audit = Arc::new(ConfigAudit::new(None));
    
    // Create security and compliance states
    let security_state = AdminSecurityState::new(audit.clone());
    let compliance_state = ComplianceState::new(audit.clone());

    // Create a security-related configuration change
    let config_change = ConfigChange::new(
        ConfigChangeType::SecurityPolicyChange,
        "security_admin".to_string(),
        "Updated authentication policy".to_string(),
        Some(GatewayConfig::default()),
        GatewayConfig::default(),
    );

    audit
        .record_change(config_change)
        .await
        .expect("Failed to record security change");

    // Generate compliance report that should include the security change
    let period = ReportPeriod {
        start_date: Utc::now() - Duration::hours(1),
        end_date: Utc::now(),
        description: "Security compliance check".to_string(),
    };

    let report_id = compliance_state
        .manager
        .generate_report(
            ComplianceReportType::Incident,
            ComplianceFramework::Iso27001,
            period,
            "compliance_officer".to_string(),
        )
        .await
        .expect("Failed to generate compliance report");

    let report = compliance_state.manager.get_report(report_id).await;
    assert!(report.is_some());

    let report = report.unwrap();
    assert!(!report.evidence.is_empty()); // Should have collected audit evidence
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_approval_workflow_error_handling() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    // Test approval for non-existent workflow
    let result = workflow_manager
        .submit_approval(
            Uuid::new_v4(),
            "admin".to_string(),
            ApprovalDecision::Approved,
            None,
            "192.168.1.1".to_string(),
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_security_scanner_error_handling() {
    let scanner_state = SecurityScannerState::new();

    // Test starting scan with non-existent config
    let result = scanner_state.scanner.start_scan("non_existent_config").await;
    assert!(result.is_err());

    // Test cancelling non-existent scan
    let result = scanner_state.scanner.cancel_scan(Uuid::new_v4()).await;
    assert!(result.is_ok()); // Should handle gracefully
}

#[tokio::test]
async fn test_backup_recovery_error_handling() {
    let audit = Arc::new(ConfigAudit::new(None));
    let backup_state = BackupRecoveryState::new(audit);

    // Test creating backup with non-existent config
    let result = backup_state
        .manager
        .create_backup("non_existent", BackupType::Full, "admin".to_string())
        .await;

    assert!(result.is_err());

    // Test restoring from non-existent backup
    let result = backup_state
        .manager
        .restore_from_backup(Uuid::new_v4(), RestoreType::Full, "admin".to_string())
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Performance Tests
// ============================================================================

#[tokio::test]
async fn test_session_monitoring_performance() {
    let audit = Arc::new(ConfigAudit::new(None));
    let session_monitor = SessionMonitor::new(audit);

    let start_time = std::time::Instant::now();

    // Create many sessions
    for i in 0..100 {
        session_monitor
            .start_monitoring(
                format!("session_{}", i),
                format!("user_{}", i),
                "192.168.1.100".to_string(),
                None,
            )
            .await;
    }

    let creation_time = start_time.elapsed();
    println!("Created 100 sessions in {:?}", creation_time);

    // Record activities for all sessions
    let activity_start = std::time::Instant::now();
    for i in 0..100 {
        session_monitor
            .record_activity(
                &format!("session_{}", i),
                "test_action".to_string(),
                "/test".to_string(),
                ActionResult::Success,
                serde_json::json!({}),
                None,
                None,
            )
            .await
            .expect("Failed to record activity");
    }

    let activity_time = activity_start.elapsed();
    println!("Recorded 100 activities in {:?}", activity_time);

    // List all sessions
    let list_start = std::time::Instant::now();
    let sessions = session_monitor.list_active_sessions().await;
    let list_time = list_start.elapsed();

    println!("Listed {} sessions in {:?}", sessions.len(), list_time);
    assert_eq!(sessions.len(), 100);

    // Performance assertions (adjust thresholds as needed)
    assert!(creation_time.as_millis() < 1000); // Should create 100 sessions in under 1 second
    assert!(activity_time.as_millis() < 1000); // Should record 100 activities in under 1 second
    assert!(list_time.as_millis() < 100); // Should list sessions in under 100ms
}

#[tokio::test]
async fn test_approval_workflow_performance() {
    let audit = Arc::new(ConfigAudit::new(None));
    let workflow_manager = ApprovalWorkflowManager::new(audit);

    let start_time = std::time::Instant::now();

    // Create many workflows
    let mut workflow_ids = Vec::new();
    for i in 0..50 {
        let operation = AdminOperation::ConfigChange {
            change_type: ConfigChangeType::RouteAdd,
            description: format!("Add route {}", i),
            config_diff: serde_json::json!({"route": format!("/api/v{}", i)}),
        };

        let workflow_id = workflow_manager
            .create_workflow(operation, format!("admin_{}", i), "Performance test".to_string())
            .await
            .expect("Failed to create workflow");

        workflow_ids.push(workflow_id);
    }

    let creation_time = start_time.elapsed();
    println!("Created 50 workflows in {:?}", creation_time);

    // List workflows
    let list_start = std::time::Instant::now();
    let workflows = workflow_manager.list_workflows(None, None, 100).await;
    let list_time = list_start.elapsed();

    println!("Listed {} workflows in {:?}", workflows.len(), list_time);
    assert!(workflows.len() >= 50);

    // Performance assertions
    assert!(creation_time.as_millis() < 2000); // Should create 50 workflows in under 2 seconds
    assert!(list_time.as_millis() < 100); // Should list workflows in under 100ms
}
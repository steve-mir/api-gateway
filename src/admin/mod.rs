//! # Admin Module
//!
//! This module provides administrative endpoints for runtime configuration management.
//! It includes functionality for:
//! - Viewing current configuration
//! - Modifying configuration at runtime
//! - Configuration change audit trail
//! - Configuration rollback capabilities
//!
//! ## Security Considerations
//! Admin endpoints should be protected with appropriate authentication and authorization.
//! These endpoints can modify the gateway's behavior and should only be accessible
//! to authorized administrators.
//!
//! ## Usage Example
//! ```rust
//! use std::sync::Arc;
//! use crate::admin::{ConfigAudit, RuntimeConfigManager, AdminRouter, endpoints::AdminState};
//! use crate::core::config::GatewayConfig;
//!
//! // Create audit trail
//! let audit = Arc::new(ConfigAudit::new(Some("audit.log".into())));
//!
//! // Create runtime config manager
//! let config = GatewayConfig::default();
//! let config_manager = Arc::new(RuntimeConfigManager::new(config, audit.clone()));
//!
//! // Create admin router
//! let admin_state = AdminState { config_manager, audit };
//! let admin_router = AdminRouter::create_router(admin_state);
//! ```

pub mod endpoints;
pub mod audit;
pub mod config_manager;
pub mod service_management;
pub mod deployment;
pub mod load_balancer;
pub mod health;
pub mod middleware;
pub mod rate_limiting;
pub mod circuit_breaker;
pub mod transformation;
pub mod grpc_management;
pub mod websocket_management;
pub mod http_management;
pub mod k8s_management;
pub mod metrics;
pub mod logging;
pub mod tracing;
pub mod error_tracking;
pub mod observability;
pub mod security;
pub mod security_scanner;
pub mod compliance;
pub mod backup_recovery;
pub mod performance;

pub use endpoints::{AdminRouter, AdminState};
pub use audit::{ConfigAudit, ConfigChange, ConfigChangeType, AuditStatistics};
pub use config_manager::{RuntimeConfigManager, ConfigChangeEvent};
pub use service_management::{ServiceManagementRouter, ServiceManagementState, ServicePersistence};
pub use deployment::{
    DeploymentRouter, DeploymentState, ServiceVersionManager, BlueGreenDeploymentManager,
    FeatureFlagManager, ServiceMeshIntegration, TenantConfigManager, ServiceVersion,
    BlueGreenDeployment, FeatureFlag, ServiceMeshConfig, Tenant, EvaluationContext
};
pub use load_balancer::{LoadBalancerAdminRouter, LoadBalancerAdminState};
pub use health::{HealthAdminRouter, HealthAdminState};
pub use middleware::{MiddlewareAdminState, create_middleware_admin_router};
pub use rate_limiting::{RateLimitAdminRouter, RateLimitAdminState};
pub use circuit_breaker::{CircuitBreakerAdminRouter, CircuitBreakerAdminState};
pub use transformation::{TransformationAdminRouter, TransformationAdminState};
pub use grpc_management::{GrpcAdminRouter, GrpcAdminState};
pub use websocket_management::{WebSocketAdminRouter, WebSocketAdminState};
pub use http_management::{HttpAdminRouter, HttpAdminState};
pub use metrics::{MetricsAdminRouter, MetricsAdminState, AlertRule, MetricsDashboard};
pub use logging::{LoggingAdminRouter, LoggingAdminState};
pub use tracing::{TracingAdminRouter, TracingAdminState};
pub use error_tracking::{ErrorTrackingAdminRouter, ErrorTrackingAdminState};
pub use observability::{
    AdminObservabilityState, AdminObservabilityRouter, AdminMetricsCollector, AdminAuditLogger,
    AdminPerformanceMonitor, AdminUsageAnalytics, ConfigChangeImpactAnalyzer, AdminNotificationSystem,
    AdminMetrics, AdminAuditEvent, ImpactLevel, NotificationType, NotificationSeverity
};
pub use security::{
    AdminSecurityState, create_admin_security_router, ApprovalWorkflowManager, AccessControlManager,
    SessionMonitor, ApprovalWorkflow, AdminOperation, ApprovalStatus, UserPermissions, MonitoredSession,
    SessionAnomaly, AccessContext
};
pub use security_scanner::{
    SecurityScannerState, create_security_scanner_router, SecurityScanner, ScanResult, Vulnerability,
    VulnerabilityType, VulnerabilitySeverity, ScanConfig, ScanType
};
pub use compliance::{
    ComplianceState, create_compliance_router, ComplianceManager, ComplianceReport, ComplianceFramework,
    ComplianceFinding, ComplianceRecommendation, ComplianceDashboard
};
pub use backup_recovery::{
    BackupRecoveryState, create_backup_recovery_router, BackupRecoveryManager, BackupRecord,
    RecoveryPlan, BackupType, RestoreType, RecoveryExecution
};
pub use k8s_management::{
    K8sResourceManager, K8sResourceOperations, K8sAdvancedOperations, K8sResourceInfo, 
    ScalingRequest, HPAConfig, PodMetrics, IngressConfig, IngressRule, IngressPath,
    ClusterInfo, NodeMetrics, NodeCondition, DeploymentRevision
};

pub use performance::{
    PerformanceAdminState, PerformanceConfig, PerformanceMonitoringConfig, 
    AutoTuningConfig, AlertThresholds, HotPathDetectionConfig,
    PerformanceMetricsCollector, PerformanceSnapshot, HotPathStats,
    PerformanceAlert, AlertType, AlertSeverity, create_performance_routes
};

// Re-export cache admin from caching module
pub use crate::caching::admin::{CacheAdminRouter, CacheAdminState};

// Re-export traffic admin from traffic module (stub implementation)
pub use crate::traffic::admin_stub::{TrafficAdminRouter, TrafficAdminState};
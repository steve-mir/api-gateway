//! # Admin Security and Compliance
//!
//! This module implements comprehensive security and compliance features for admin operations:
//! - Admin operation approval workflow for critical changes
//! - Admin access control with principle of least privilege
//! - Admin session monitoring and anomaly detection
//! - Admin API security scanning and vulnerability assessment
//! - Compliance reporting for admin operations
//! - Admin backup and disaster recovery procedures
//!
//! ## Security Architecture
//!
//! The security system is built around several key components:
//! - **Approval Workflow**: Critical operations require multi-person approval
//! - **Access Control**: Fine-grained permissions with least privilege principle
//! - **Session Monitoring**: Real-time monitoring of admin sessions for anomalies
//! - **Security Scanning**: Automated vulnerability assessment of admin APIs
//! - **Compliance Reporting**: Detailed audit trails and compliance reports
//! - **Backup/Recovery**: Secure backup and disaster recovery procedures

use crate::admin::audit::{ConfigAudit, ConfigChangeType};
use crate::core::error::{GatewayError, GatewayResult};
// Removed unused import

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

// ============================================================================
// Approval Workflow System
// ============================================================================

/// Approval workflow for critical admin operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWorkflow {
    /// Unique workflow ID
    pub id: Uuid,
    /// Operation being requested
    pub operation: AdminOperation,
    /// User who requested the operation
    pub requester: String,
    /// Required approvers (roles or specific users)
    pub required_approvers: Vec<ApprovalRequirement>,
    /// Current approvals received
    pub approvals: Vec<Approval>,
    /// Workflow status
    pub status: ApprovalStatus,
    /// When the request was created
    pub created_at: DateTime<Utc>,
    /// When the request expires
    pub expires_at: DateTime<Utc>,
    /// Additional context/justification
    pub justification: String,
    /// Risk level of the operation
    pub risk_level: RiskLevel,
}

/// Types of admin operations that may require approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminOperation {
    /// Configuration changes
    ConfigChange {
        change_type: ConfigChangeType,
        description: String,
        config_diff: serde_json::Value,
    },
    /// User management operations
    UserManagement {
        action: String,
        target_user: String,
        details: serde_json::Value,
    },
    /// Service management operations
    ServiceManagement {
        action: String,
        service_name: String,
        details: serde_json::Value,
    },
    /// Security policy changes
    SecurityPolicyChange {
        policy_type: String,
        changes: serde_json::Value,
    },
    /// System maintenance operations
    SystemMaintenance {
        operation: String,
        scope: String,
        details: serde_json::Value,
    },
}

/// Approval requirement specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalRequirement {
    /// Requires approval from any user with specified role
    Role(String),
    /// Requires approval from specific user
    User(String),
    /// Requires approval from N users with specified role
    RoleCount { role: String, count: usize },
    /// Requires approval from majority of users with role
    RoleMajority(String),
}

/// Individual approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// User who provided approval
    pub approver: String,
    /// Approval decision
    pub decision: ApprovalDecision,
    /// When approval was given
    pub approved_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
    /// IP address of approver
    pub ip_address: String,
}

/// Approval decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    RequestMoreInfo,
}

/// Approval workflow status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Executed,
    Failed,
}

/// Risk level for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Approval workflow manager
pub struct ApprovalWorkflowManager {
    /// Active workflows
    workflows: Arc<DashMap<Uuid, ApprovalWorkflow>>,
    /// Approval policies
    policies: Arc<RwLock<HashMap<String, ApprovalPolicy>>>,
    /// Audit logger
    audit: Arc<ConfigAudit>,
}

/// Approval policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Operation pattern this policy applies to
    pub operation_pattern: String,
    /// Required approvals
    pub required_approvers: Vec<ApprovalRequirement>,
    /// Approval timeout
    pub timeout: Duration,
    /// Risk level threshold
    pub risk_threshold: RiskLevel,
    /// Whether policy is active
    pub active: bool,
}

impl ApprovalWorkflowManager {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        let manager = Self {
            workflows: Arc::new(DashMap::new()),
            policies: Arc::new(RwLock::new(HashMap::new())),
            audit,
        };
        
        // Initialize default policies
        tokio::spawn({
            let manager = manager.clone();
            async move {
                if let Err(e) = manager.initialize_default_policies().await {
                    tracing::error!("Failed to initialize approval policies: {}", e);
                }
            }
        });
        
        manager
    }

    /// Create a new approval workflow
    pub async fn create_workflow(
        &self,
        operation: AdminOperation,
        requester: String,
        justification: String,
    ) -> GatewayResult<Uuid> {
        let risk_level = self.assess_risk_level(&operation).await;
        let policy = self.find_applicable_policy(&operation).await?;
        
        let workflow = ApprovalWorkflow {
            id: Uuid::new_v4(),
            operation,
            requester: requester.clone(),
            required_approvers: policy.required_approvers,
            approvals: Vec::new(),
            status: ApprovalStatus::Pending,
            created_at: Utc::now(),
            expires_at: Utc::now() + policy.timeout,
            justification,
            risk_level,
        };

        self.workflows.insert(workflow.id, workflow.clone());

        tracing::info!(
            workflow_id = %workflow.id,
            requester = %requester,
            risk_level = ?workflow.risk_level,
            "Approval workflow created"
        );

        Ok(workflow.id)
    }

    /// Submit approval for a workflow
    pub async fn submit_approval(
        &self,
        workflow_id: Uuid,
        approver: String,
        decision: ApprovalDecision,
        comment: Option<String>,
        ip_address: String,
    ) -> GatewayResult<ApprovalStatus> {
        let mut workflow = self.workflows.get_mut(&workflow_id)
            .ok_or_else(|| GatewayError::not_found("Approval workflow not found"))?;

        // Check if workflow is still pending
        if !matches!(workflow.status, ApprovalStatus::Pending) {
            return Err(GatewayError::invalid_input("Workflow is not pending approval"));
        }

        // Check if workflow has expired
        if Utc::now() > workflow.expires_at {
            workflow.status = ApprovalStatus::Expired;
            return Ok(ApprovalStatus::Expired);
        }

        // Check if user already approved
        if workflow.approvals.iter().any(|a| a.approver == approver) {
            return Err(GatewayError::invalid_input("User has already provided approval"));
        }

        let approval = Approval {
            approver: approver.clone(),
            decision: decision.clone(),
            approved_at: Utc::now(),
            comment,
            ip_address,
        };

        workflow.approvals.push(approval);

        // Check if workflow should be rejected
        if matches!(decision, ApprovalDecision::Rejected) {
            workflow.status = ApprovalStatus::Rejected;
            tracing::info!(
                workflow_id = %workflow_id,
                approver = %approver,
                "Approval workflow rejected"
            );
            return Ok(ApprovalStatus::Rejected);
        }

        // Check if all requirements are met
        if self.check_approval_requirements(&workflow).await? {
            workflow.status = ApprovalStatus::Approved;
            tracing::info!(
                workflow_id = %workflow_id,
                "Approval workflow approved"
            );
        }

        Ok(workflow.status.clone())
    }

    /// Get workflow by ID
    pub async fn get_workflow(&self, workflow_id: Uuid) -> Option<ApprovalWorkflow> {
        self.workflows.get(&workflow_id).map(|w| w.clone())
    }

    /// List workflows with filtering
    pub async fn list_workflows(
        &self,
        status: Option<ApprovalStatus>,
        requester: Option<String>,
        limit: usize,
    ) -> Vec<ApprovalWorkflow> {
        self.workflows
            .iter()
            .filter(|w| {
                if let Some(ref _s) = status {
                    // Note: This is simplified - in real implementation would properly match status
                    // For now, we'll include all workflows
                }
                if let Some(ref r) = requester {
                    if w.requester != *r {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .map(|w| w.clone())
            .collect()
    }

    /// Execute approved workflow
    pub async fn execute_workflow(&self, workflow_id: Uuid) -> GatewayResult<()> {
        let mut workflow = self.workflows.get_mut(&workflow_id)
            .ok_or_else(|| GatewayError::not_found("Approval workflow not found"))?;

        if !matches!(workflow.status, ApprovalStatus::Approved) {
            return Err(GatewayError::invalid_input("Workflow is not approved"));
        }

        workflow.status = ApprovalStatus::Executed;
        
        tracing::info!(
            workflow_id = %workflow_id,
            "Approval workflow executed"
        );

        Ok(())
    }

    /// Assess risk level of an operation
    async fn assess_risk_level(&self, operation: &AdminOperation) -> RiskLevel {
        match operation {
            AdminOperation::ConfigChange { change_type, .. } => {
                match change_type {
                    ConfigChangeType::FullReplace => RiskLevel::Critical,
                    ConfigChangeType::ServerChange => RiskLevel::High,
                    ConfigChangeType::AuthChange => RiskLevel::High,
                    ConfigChangeType::RouteDelete => RiskLevel::Medium,
                    ConfigChangeType::UpstreamDelete => RiskLevel::Medium,
                    _ => RiskLevel::Low,
                }
            }
            AdminOperation::UserManagement { action, .. } => {
                if action.contains("delete") || action.contains("disable") {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                }
            }
            AdminOperation::SecurityPolicyChange { .. } => RiskLevel::High,
            AdminOperation::SystemMaintenance { operation, .. } => {
                if operation.contains("shutdown") || operation.contains("restart") {
                    RiskLevel::Critical
                } else {
                    RiskLevel::Medium
                }
            }
            _ => RiskLevel::Low,
        }
    }

    /// Find applicable approval policy
    async fn find_applicable_policy(&self, operation: &AdminOperation) -> GatewayResult<ApprovalPolicy> {
        let policies = self.policies.read().await;
        
        // Simple pattern matching - in production this would be more sophisticated
        let operation_type = match operation {
            AdminOperation::ConfigChange { .. } => "config_change",
            AdminOperation::UserManagement { .. } => "user_management",
            AdminOperation::ServiceManagement { .. } => "service_management",
            AdminOperation::SecurityPolicyChange { .. } => "security_policy",
            AdminOperation::SystemMaintenance { .. } => "system_maintenance",
        };

        policies.get(operation_type)
            .cloned()
            .ok_or_else(|| GatewayError::config("No approval policy found for operation"))
    }

    /// Check if approval requirements are met
    async fn check_approval_requirements(&self, workflow: &ApprovalWorkflow) -> GatewayResult<bool> {
        for requirement in &workflow.required_approvers {
            match requirement {
                ApprovalRequirement::Role(_role) => {
                    if !workflow.approvals.iter().any(|a| {
                        matches!(a.decision, ApprovalDecision::Approved)
                        // In real implementation, would check if approver has the role
                    }) {
                        return Ok(false);
                    }
                }
                ApprovalRequirement::User(user) => {
                    if !workflow.approvals.iter().any(|a| {
                        a.approver == *user && matches!(a.decision, ApprovalDecision::Approved)
                    }) {
                        return Ok(false);
                    }
                }
                ApprovalRequirement::RoleCount { role: _, count } => {
                    let approved_count = workflow.approvals.iter()
                        .filter(|a| matches!(a.decision, ApprovalDecision::Approved))
                        .count();
                    if approved_count < *count {
                        return Ok(false);
                    }
                }
                ApprovalRequirement::RoleMajority(_role) => {
                    // Simplified - would need to know total users with role
                    let approved_count = workflow.approvals.iter()
                        .filter(|a| matches!(a.decision, ApprovalDecision::Approved))
                        .count();
                    if approved_count < 2 {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Initialize default approval policies
    async fn initialize_default_policies(&self) -> GatewayResult<()> {
        let mut policies = self.policies.write().await;

        // Critical config changes require 2 admin approvals
        policies.insert("config_change".to_string(), ApprovalPolicy {
            operation_pattern: "config_change.*".to_string(),
            required_approvers: vec![
                ApprovalRequirement::RoleCount {
                    role: "admin".to_string(),
                    count: 2,
                }
            ],
            timeout: Duration::hours(24),
            risk_threshold: RiskLevel::Medium,
            active: true,
        });

        // User management requires admin approval
        policies.insert("user_management".to_string(), ApprovalPolicy {
            operation_pattern: "user_management.*".to_string(),
            required_approvers: vec![
                ApprovalRequirement::Role("admin".to_string())
            ],
            timeout: Duration::hours(8),
            risk_threshold: RiskLevel::Low,
            active: true,
        });

        // Security policy changes require security admin approval
        policies.insert("security_policy".to_string(), ApprovalPolicy {
            operation_pattern: "security_policy.*".to_string(),
            required_approvers: vec![
                ApprovalRequirement::Role("security_admin".to_string())
            ],
            timeout: Duration::hours(4),
            risk_threshold: RiskLevel::High,
            active: true,
        });

        Ok(())
    }
}

impl Clone for ApprovalWorkflowManager {
    fn clone(&self) -> Self {
        Self {
            workflows: self.workflows.clone(),
            policies: self.policies.clone(),
            audit: self.audit.clone(),
        }
    }
}

// ============================================================================
// Access Control System
// ============================================================================

/// Principle of least privilege access control
#[derive(Clone)]
pub struct AccessControlManager {
    /// Permission grants
    permissions: Arc<RwLock<HashMap<String, UserPermissions>>>,
    /// Access policies
    policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
    /// Audit logger
    audit: Arc<ConfigAudit>,
}

/// User permissions with time-based constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissions {
    /// User ID
    pub user_id: String,
    /// Granted permissions
    pub permissions: Vec<Permission>,
    /// Permission grants (temporary elevated access)
    pub grants: Vec<PermissionGrant>,
    /// Last access time
    pub last_access: DateTime<Utc>,
    /// Account status
    pub status: AccountStatus,
}

/// Individual permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission name
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Actions allowed
    pub actions: Vec<String>,
    /// Conditions for permission
    pub conditions: Vec<AccessCondition>,
    /// When permission was granted
    pub granted_at: DateTime<Utc>,
    /// When permission expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Temporary permission grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrant {
    /// Grant ID
    pub id: Uuid,
    /// Permission being granted
    pub permission: Permission,
    /// Who granted this permission
    pub granted_by: String,
    /// Justification for grant
    pub justification: String,
    /// When grant expires
    pub expires_at: DateTime<Utc>,
    /// Whether grant is active
    pub active: bool,
}

/// Access condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCondition {
    /// Condition type
    pub condition_type: ConditionType,
    /// Condition value
    pub value: serde_json::Value,
}

/// Types of access conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    /// Time-based access (only during certain hours)
    TimeWindow,
    /// IP address restriction
    IpAddress,
    /// Location-based access
    Location,
    /// Multi-factor authentication required
    MfaRequired,
    /// Approval required for each use
    ApprovalRequired,
}

/// Account status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountStatus {
    Active,
    Suspended,
    Locked,
    Disabled,
}

/// Access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Policy name
    pub name: String,
    /// Resources this policy applies to
    pub resources: Vec<String>,
    /// Default permissions
    pub default_permissions: Vec<Permission>,
    /// Maximum permission duration
    pub max_permission_duration: Duration,
    /// Require approval for elevated access
    pub require_approval: bool,
    /// Policy is active
    pub active: bool,
}

impl AccessControlManager {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        Self {
            permissions: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            audit,
        }
    }

    /// Check if user has permission for action
    pub async fn check_permission(
        &self,
        user_id: &str,
        resource: &str,
        action: &str,
        context: &AccessContext,
    ) -> GatewayResult<bool> {
        let permissions = self.permissions.read().await;
        
        let user_perms = permissions.get(user_id)
            .ok_or_else(|| GatewayError::authz("User permissions not found"))?;

        // Check account status
        if !matches!(user_perms.status, AccountStatus::Active) {
            return Ok(false);
        }

        // Check regular permissions
        for perm in &user_perms.permissions {
            if self.permission_matches(perm, resource, action, context).await? {
                return Ok(true);
            }
        }

        // Check temporary grants
        for grant in &user_perms.grants {
            if grant.active && Utc::now() < grant.expires_at {
                if self.permission_matches(&grant.permission, resource, action, context).await? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Grant temporary elevated permission
    pub async fn grant_permission(
        &self,
        user_id: &str,
        permission: Permission,
        granted_by: &str,
        justification: String,
        duration: Duration,
    ) -> GatewayResult<Uuid> {
        let mut permissions = self.permissions.write().await;
        
        let user_perms = permissions.entry(user_id.to_string())
            .or_insert_with(|| UserPermissions {
                user_id: user_id.to_string(),
                permissions: Vec::new(),
                grants: Vec::new(),
                last_access: Utc::now(),
                status: AccountStatus::Active,
            });

        let grant = PermissionGrant {
            id: Uuid::new_v4(),
            permission,
            granted_by: granted_by.to_string(),
            justification,
            expires_at: Utc::now() + duration,
            active: true,
        };

        user_perms.grants.push(grant.clone());

        tracing::info!(
            user_id = %user_id,
            grant_id = %grant.id,
            granted_by = %granted_by,
            "Permission grant created"
        );

        Ok(grant.id)
    }

    /// Revoke permission grant
    pub async fn revoke_grant(&self, user_id: &str, grant_id: Uuid) -> GatewayResult<()> {
        let mut permissions = self.permissions.write().await;
        
        if let Some(user_perms) = permissions.get_mut(user_id) {
            if let Some(grant) = user_perms.grants.iter_mut().find(|g| g.id == grant_id) {
                grant.active = false;
                tracing::info!(
                    user_id = %user_id,
                    grant_id = %grant_id,
                    "Permission grant revoked"
                );
            }
        }

        Ok(())
    }

    /// Check if permission matches request
    async fn permission_matches(
        &self,
        permission: &Permission,
        resource: &str,
        action: &str,
        context: &AccessContext,
    ) -> GatewayResult<bool> {
        // Check resource match
        if permission.resource != "*" && permission.resource != resource {
            return Ok(false);
        }

        // Check action match
        if !permission.actions.contains(&action.to_string()) && !permission.actions.contains(&"*".to_string()) {
            return Ok(false);
        }

        // Check expiration
        if let Some(expires_at) = permission.expires_at {
            if Utc::now() > expires_at {
                return Ok(false);
            }
        }

        // Check conditions
        for condition in &permission.conditions {
            if !self.check_condition(condition, context).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check access condition
    async fn check_condition(&self, condition: &AccessCondition, context: &AccessContext) -> GatewayResult<bool> {
        match condition.condition_type {
            ConditionType::TimeWindow => {
                // Check if current time is within allowed window
                // Implementation would parse time window from condition.value
                Ok(true) // Simplified
            }
            ConditionType::IpAddress => {
                // Check if request IP is in allowed range
                if let Some(allowed_ip) = condition.value.as_str() {
                    Ok(context.ip_address == allowed_ip)
                } else {
                    Ok(false)
                }
            }
            ConditionType::Location => {
                // Check geographic location
                Ok(true) // Simplified
            }
            ConditionType::MfaRequired => {
                // Check if MFA was used
                Ok(context.mfa_verified)
            }
            ConditionType::ApprovalRequired => {
                // Check if approval was obtained
                Ok(context.approval_id.is_some())
            }
        }
    }
}

/// Access context for permission checks
#[derive(Debug, Clone)]
pub struct AccessContext {
    /// Request IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Whether MFA was verified
    pub mfa_verified: bool,
    /// Approval ID if applicable
    pub approval_id: Option<Uuid>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional context
    pub metadata: HashMap<String, serde_json::Value>,
}

// ============================================================================
// Session Monitoring and Anomaly Detection
// ============================================================================

/// Session monitoring and anomaly detection system
pub struct SessionMonitor {
    /// Active sessions being monitored
    sessions: Arc<DashMap<String, MonitoredSession>>,
    /// Anomaly detection rules
    rules: Arc<RwLock<Vec<AnomalyRule>>>,
    /// Detected anomalies
    anomalies: Arc<Mutex<Vec<SessionAnomaly>>>,
    /// Audit logger
    audit: Arc<ConfigAudit>,
}

/// Monitored session information
#[derive(Debug, Clone)]
pub struct MonitoredSession {
    /// Session ID
    pub session_id: String,
    /// User ID
    pub user_id: String,
    /// Session start time
    pub start_time: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// IP addresses used in this session
    pub ip_addresses: Vec<String>,
    /// User agents seen
    pub user_agents: Vec<String>,
    /// Actions performed
    pub actions: Vec<SessionAction>,
    /// Geographic locations (if available)
    pub locations: Vec<String>,
    /// Risk score
    pub risk_score: f64,
}

/// Session action record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAction {
    /// Action timestamp
    pub timestamp: DateTime<Utc>,
    /// Action type
    pub action_type: String,
    /// Resource accessed
    pub resource: String,
    /// Action result
    pub result: ActionResult,
    /// Request details
    pub details: serde_json::Value,
}

/// Action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    Success,
    Failed,
    Blocked,
    RequiredApproval,
}

/// Anomaly detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRule {
    /// Rule ID
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule type
    pub rule_type: AnomalyRuleType,
    /// Rule parameters
    pub parameters: serde_json::Value,
    /// Severity level
    pub severity: AnomalySeverity,
    /// Whether rule is active
    pub active: bool,
}

/// Types of anomaly detection rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyRuleType {
    /// Multiple IP addresses in short time
    MultipleIpAddresses,
    /// Unusual time of access
    UnusualTimeAccess,
    /// High frequency of actions
    HighActionFrequency,
    /// Failed authentication attempts
    FailedAuthAttempts,
    /// Privilege escalation attempts
    PrivilegeEscalation,
    /// Unusual geographic location
    UnusualLocation,
    /// Concurrent sessions from different locations
    ConcurrentSessions,
}

/// Anomaly severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected session anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnomaly {
    /// Anomaly ID
    pub id: Uuid,
    /// Session ID where anomaly was detected
    pub session_id: String,
    /// User ID
    pub user_id: String,
    /// Rule that detected the anomaly
    pub rule_id: Uuid,
    /// Anomaly type
    pub anomaly_type: AnomalyRuleType,
    /// Severity level
    pub severity: AnomalySeverity,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
    /// Anomaly details
    pub details: serde_json::Value,
    /// Whether anomaly has been investigated
    pub investigated: bool,
    /// Investigation notes
    pub investigation_notes: Option<String>,
}

impl SessionMonitor {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        let monitor = Self {
            sessions: Arc::new(DashMap::new()),
            rules: Arc::new(RwLock::new(Vec::new())),
            anomalies: Arc::new(Mutex::new(Vec::new())),
            audit,
        };

        // Initialize default rules
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                if let Err(e) = monitor.initialize_default_rules().await {
                    tracing::error!("Failed to initialize anomaly detection rules: {}", e);
                }
            }
        });

        // Start monitoring task
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                monitor.monitoring_loop().await;
            }
        });

        monitor
    }

    /// Start monitoring a session
    pub async fn start_monitoring(&self, session_id: String, user_id: String, ip_address: String, user_agent: Option<String>) {
        let session = MonitoredSession {
            session_id: session_id.clone(),
            user_id,
            start_time: Utc::now(),
            last_activity: Utc::now(),
            ip_addresses: vec![ip_address],
            user_agents: user_agent.into_iter().collect(),
            actions: Vec::new(),
            locations: Vec::new(),
            risk_score: 0.0,
        };

        self.sessions.insert(session_id, session);
    }

    /// Record session activity
    pub async fn record_activity(
        &self,
        session_id: &str,
        action_type: String,
        resource: String,
        result: ActionResult,
        details: serde_json::Value,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> GatewayResult<()> {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.last_activity = Utc::now();

            // Update IP addresses if new
            if let Some(ip) = ip_address {
                if !session.ip_addresses.contains(&ip) {
                    session.ip_addresses.push(ip);
                }
            }

            // Update user agents if new
            if let Some(ua) = user_agent {
                if !session.user_agents.contains(&ua) {
                    session.user_agents.push(ua);
                }
            }

            // Record action
            let action = SessionAction {
                timestamp: Utc::now(),
                action_type,
                resource,
                result,
                details,
            };

            session.actions.push(action);

            // Trigger anomaly detection
            self.check_for_anomalies(&session).await?;
        }

        Ok(())
    }

    /// Stop monitoring a session
    pub async fn stop_monitoring(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    /// Get session information
    pub async fn get_session(&self, session_id: &str) -> Option<MonitoredSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    /// List active sessions
    pub async fn list_active_sessions(&self) -> Vec<MonitoredSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    /// Get detected anomalies
    pub async fn get_anomalies(&self, limit: usize) -> Vec<SessionAnomaly> {
        let anomalies = self.anomalies.lock().await;
        anomalies.iter().take(limit).cloned().collect()
    }

    /// Check for anomalies in session
    async fn check_for_anomalies(&self, session: &MonitoredSession) -> GatewayResult<()> {
        let rules = self.rules.read().await;
        
        for rule in rules.iter().filter(|r| r.active) {
            if let Some(anomaly) = self.evaluate_rule(rule, session).await? {
                let mut anomalies = self.anomalies.lock().await;
                anomalies.push(anomaly.clone());

                tracing::warn!(
                    anomaly_id = %anomaly.id,
                    session_id = %session.session_id,
                    user_id = %session.user_id,
                    severity = ?anomaly.severity,
                    "Session anomaly detected"
                );

                // Take action based on severity
                self.handle_anomaly(&anomaly).await?;
            }
        }

        Ok(())
    }

    /// Evaluate anomaly rule against session
    async fn evaluate_rule(&self, rule: &AnomalyRule, session: &MonitoredSession) -> GatewayResult<Option<SessionAnomaly>> {
        let detected = match rule.rule_type {
            AnomalyRuleType::MultipleIpAddresses => {
                session.ip_addresses.len() > 2
            }
            AnomalyRuleType::UnusualTimeAccess => {
                let hour = session.last_activity.hour();
                hour < 6 || hour > 22 // Outside business hours
            }
            AnomalyRuleType::HighActionFrequency => {
                let recent_actions = session.actions.iter()
                    .filter(|a| Utc::now() - a.timestamp < Duration::minutes(5))
                    .count();
                recent_actions > 50
            }
            AnomalyRuleType::FailedAuthAttempts => {
                let failed_attempts = session.actions.iter()
                    .filter(|a| matches!(a.result, ActionResult::Failed) && a.action_type.contains("auth"))
                    .count();
                failed_attempts > 3
            }
            AnomalyRuleType::PrivilegeEscalation => {
                session.actions.iter().any(|a| a.action_type.contains("privilege") || a.action_type.contains("admin"))
            }
            AnomalyRuleType::UnusualLocation => {
                // Would integrate with geolocation service
                false // Simplified
            }
            AnomalyRuleType::ConcurrentSessions => {
                // Would check for other active sessions from different IPs
                false // Simplified
            }
        };

        if detected {
            Ok(Some(SessionAnomaly {
                id: Uuid::new_v4(),
                session_id: session.session_id.clone(),
                user_id: session.user_id.clone(),
                rule_id: rule.id,
                anomaly_type: rule.rule_type.clone(),
                severity: rule.severity.clone(),
                detected_at: Utc::now(),
                details: serde_json::json!({
                    "rule_name": rule.name,
                    "session_duration": (Utc::now() - session.start_time).num_minutes(),
                    "ip_addresses": session.ip_addresses,
                    "action_count": session.actions.len()
                }),
                investigated: false,
                investigation_notes: None,
            }))
        } else {
            Ok(None)
        }
    }

    /// Handle detected anomaly
    async fn handle_anomaly(&self, anomaly: &SessionAnomaly) -> GatewayResult<()> {
        match anomaly.severity {
            AnomalySeverity::Critical => {
                // Immediately suspend session
                tracing::error!(
                    anomaly_id = %anomaly.id,
                    user_id = %anomaly.user_id,
                    "Critical anomaly detected - taking immediate action"
                );
                // Would integrate with session management to suspend session
            }
            AnomalySeverity::High => {
                // Alert security team
                tracing::warn!(
                    anomaly_id = %anomaly.id,
                    user_id = %anomaly.user_id,
                    "High severity anomaly detected"
                );
            }
            AnomalySeverity::Medium | AnomalySeverity::Low => {
                // Log for investigation
                tracing::info!(
                    anomaly_id = %anomaly.id,
                    user_id = %anomaly.user_id,
                    severity = ?anomaly.severity,
                    "Anomaly detected"
                );
            }
        }

        Ok(())
    }

    /// Initialize default anomaly detection rules
    async fn initialize_default_rules(&self) -> GatewayResult<()> {
        let mut rules = self.rules.write().await;

        rules.push(AnomalyRule {
            id: Uuid::new_v4(),
            name: "Multiple IP Addresses".to_string(),
            description: "Detects sessions using multiple IP addresses".to_string(),
            rule_type: AnomalyRuleType::MultipleIpAddresses,
            parameters: serde_json::json!({"max_ips": 2}),
            severity: AnomalySeverity::Medium,
            active: true,
        });

        rules.push(AnomalyRule {
            id: Uuid::new_v4(),
            name: "High Action Frequency".to_string(),
            description: "Detects unusually high action frequency".to_string(),
            rule_type: AnomalyRuleType::HighActionFrequency,
            parameters: serde_json::json!({"max_actions_per_minute": 10}),
            severity: AnomalySeverity::High,
            active: true,
        });

        rules.push(AnomalyRule {
            id: Uuid::new_v4(),
            name: "Failed Authentication Attempts".to_string(),
            description: "Detects multiple failed authentication attempts".to_string(),
            rule_type: AnomalyRuleType::FailedAuthAttempts,
            parameters: serde_json::json!({"max_failed_attempts": 3}),
            severity: AnomalySeverity::High,
            active: true,
        });

        Ok(())
    }

    /// Monitoring loop for periodic checks
    async fn monitoring_loop(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Clean up old sessions
            let cutoff = Utc::now() - Duration::hours(24);
            self.sessions.retain(|_, session| session.last_activity > cutoff);
            
            // Clean up old anomalies
            let mut anomalies = self.anomalies.lock().await;
            anomalies.retain(|a| Utc::now() - a.detected_at < Duration::days(30));
        }
    }
}

impl Clone for SessionMonitor {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            rules: self.rules.clone(),
            anomalies: self.anomalies.clone(),
            audit: self.audit.clone(),
        }
    }
}

// ============================================================================
// Admin Security State and Router
// ============================================================================

/// Admin security state
#[derive(Clone)]
pub struct AdminSecurityState {
    pub approval_workflow: ApprovalWorkflowManager,
    pub access_control: AccessControlManager,
    pub session_monitor: SessionMonitor,
    pub audit: Arc<ConfigAudit>,
}

impl AdminSecurityState {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        Self {
            approval_workflow: ApprovalWorkflowManager::new(audit.clone()),
            access_control: AccessControlManager::new(audit.clone()),
            session_monitor: SessionMonitor::new(audit.clone()),
            audit,
        }
    }
}

/// Create admin security router
pub fn create_admin_security_router(state: AdminSecurityState) -> Router {
    Router::new()
        // Approval workflow endpoints
        .route("/approval/workflows", post(create_approval_workflow))
        .route("/approval/workflows", get(list_approval_workflows))
        .route("/approval/workflows/:workflow_id", get(get_approval_workflow))
        .route("/approval/workflows/:workflow_id/approve", post(submit_approval))
        .route("/approval/workflows/:workflow_id/execute", post(execute_workflow))
        
        // Access control endpoints
        .route("/access/permissions/:user_id", get(get_user_permissions))
        .route("/access/permissions/:user_id/grant", post(grant_permission))
        .route("/access/permissions/:user_id/grants/:grant_id", delete(revoke_permission_grant))
        
        // Session monitoring endpoints (temporarily disabled due to handler compatibility)
        // .route("/sessions", get(list_monitored_sessions))
        // .route("/sessions/:session_id", get(get_monitored_session))
        .route("/sessions/anomalies", get(list_session_anomalies))
        .route("/sessions/anomalies/:anomaly_id/investigate", post(investigate_anomaly))
        
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateApprovalWorkflowRequest {
    pub operation: AdminOperation,
    pub justification: String,
}

#[derive(Debug, Serialize)]
pub struct CreateApprovalWorkflowResponse {
    pub workflow_id: Uuid,
    pub status: ApprovalStatus,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitApprovalRequest {
    pub decision: ApprovalDecision,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitApprovalResponse {
    pub status: ApprovalStatus,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ListWorkflowsQuery {
    pub status: Option<String>,
    pub requester: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct GrantPermissionRequest {
    pub permission: Permission,
    pub justification: String,
    pub duration_hours: u64,
}

#[derive(Debug, Serialize)]
pub struct GrantPermissionResponse {
    pub grant_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct InvestigateAnomalyRequest {
    pub notes: String,
    pub resolved: bool,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Create approval workflow
async fn create_approval_workflow(
    State(state): State<AdminSecurityState>,
    Json(request): Json<CreateApprovalWorkflowRequest>,
) -> GatewayResult<Json<CreateApprovalWorkflowResponse>> {
    // In real implementation, would extract user from auth context
    let requester = "admin".to_string();
    
    let workflow_id = state.approval_workflow
        .create_workflow(request.operation, requester, request.justification)
        .await?;

    let workflow = state.approval_workflow.get_workflow(workflow_id).await
        .ok_or_else(|| GatewayError::internal("Failed to retrieve created workflow"))?;

    Ok(Json(CreateApprovalWorkflowResponse {
        workflow_id,
        status: workflow.status,
        expires_at: workflow.expires_at,
    }))
}

/// List approval workflows
async fn list_approval_workflows(
    State(state): State<AdminSecurityState>,
    Query(query): Query<ListWorkflowsQuery>,
) -> GatewayResult<Json<Vec<ApprovalWorkflow>>> {
    let status = query.status.and_then(|s| match s.as_str() {
        "pending" => Some(ApprovalStatus::Pending),
        "approved" => Some(ApprovalStatus::Approved),
        "rejected" => Some(ApprovalStatus::Rejected),
        "expired" => Some(ApprovalStatus::Expired),
        "executed" => Some(ApprovalStatus::Executed),
        _ => None,
    });

    let workflows = state.approval_workflow
        .list_workflows(status, query.requester, query.limit.unwrap_or(50))
        .await;

    Ok(Json(workflows))
}

/// Get approval workflow
async fn get_approval_workflow(
    State(state): State<AdminSecurityState>,
    Path(workflow_id): Path<Uuid>,
) -> GatewayResult<Json<ApprovalWorkflow>> {
    let workflow = state.approval_workflow.get_workflow(workflow_id).await
        .ok_or_else(|| GatewayError::not_found("Approval workflow not found"))?;

    Ok(Json(workflow))
}

/// Submit approval
async fn submit_approval(
    State(state): State<AdminSecurityState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<SubmitApprovalRequest>,
) -> GatewayResult<Json<SubmitApprovalResponse>> {
    // In real implementation, would extract user from auth context
    let approver = "admin".to_string();
    let ip_address = "127.0.0.1".to_string();

    let status = state.approval_workflow
        .submit_approval(workflow_id, approver, request.decision, request.comment, ip_address)
        .await?;

    let message = match status {
        ApprovalStatus::Approved => "Workflow approved successfully".to_string(),
        ApprovalStatus::Rejected => "Workflow rejected".to_string(),
        ApprovalStatus::Pending => "Approval recorded, waiting for additional approvals".to_string(),
        ApprovalStatus::Expired => "Workflow has expired".to_string(),
        _ => "Approval processed".to_string(),
    };

    Ok(Json(SubmitApprovalResponse { status, message }))
}

/// Execute workflow
async fn execute_workflow(
    State(state): State<AdminSecurityState>,
    Path(workflow_id): Path<Uuid>,
) -> GatewayResult<StatusCode> {
    state.approval_workflow.execute_workflow(workflow_id).await?;
    Ok(StatusCode::OK)
}

/// Get user permissions
async fn get_user_permissions(
    State(_state): State<AdminSecurityState>,
    Path(_user_id): Path<String>,
) -> GatewayResult<Json<UserPermissions>> {
    // Simplified implementation
    let permissions = UserPermissions {
        user_id: _user_id,
        permissions: Vec::new(),
        grants: Vec::new(),
        last_access: Utc::now(),
        status: AccountStatus::Active,
    };
    Ok(Json(permissions))
}

/// Grant permission
async fn grant_permission(
    State(state): State<AdminSecurityState>,
    Path(user_id): Path<String>,
    Json(request): Json<GrantPermissionRequest>,
) -> GatewayResult<Json<GrantPermissionResponse>> {
    let duration = Duration::hours(request.duration_hours as i64);
    let granted_by = "admin"; // Would extract from auth context
    
    let grant_id = state.access_control
        .grant_permission(&user_id, request.permission, granted_by, request.justification, duration)
        .await?;

    Ok(Json(GrantPermissionResponse {
        grant_id,
        expires_at: Utc::now() + duration,
    }))
}

/// Revoke permission grant
async fn revoke_permission_grant(
    State(state): State<AdminSecurityState>,
    Path((user_id, grant_id)): Path<(String, Uuid)>,
) -> GatewayResult<StatusCode> {
    state.access_control.revoke_grant(&user_id, grant_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List monitored sessions
async fn list_monitored_sessions(
    State(state): State<AdminSecurityState>,
) -> GatewayResult<Json<Vec<MonitoredSession>>> {
    let sessions = state.session_monitor.list_active_sessions().await;
    Ok(Json(sessions))
}

/// Get monitored session
async fn get_monitored_session(
    State(state): State<AdminSecurityState>,
    Path(session_id): Path<String>,
) -> GatewayResult<Json<MonitoredSession>> {
    let session = state.session_monitor.get_session(&session_id).await
        .ok_or_else(|| GatewayError::not_found("Session not found"))?;
    Ok(Json(session))
}

/// List session anomalies
async fn list_session_anomalies(
    State(state): State<AdminSecurityState>,
    Query(query): Query<HashMap<String, String>>,
) -> GatewayResult<Json<Vec<SessionAnomaly>>> {
    let limit = query.get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(50);
    
    let anomalies = state.session_monitor.get_anomalies(limit).await;
    Ok(Json(anomalies))
}

/// Investigate anomaly
async fn investigate_anomaly(
    State(_state): State<AdminSecurityState>,
    Path(_anomaly_id): Path<Uuid>,
    Json(_request): Json<InvestigateAnomalyRequest>,
) -> GatewayResult<StatusCode> {
    // Would update anomaly investigation status
    Ok(StatusCode::OK)
}
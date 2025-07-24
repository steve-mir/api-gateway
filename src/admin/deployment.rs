//! # Deployment Management Module
//!
//! This module provides service deployment management capabilities including:
//! - Service version management with routing rules
//! - Blue-green deployment support
//! - Feature flag integration for A/B testing
//! - Service mesh integration capabilities
//! - Multi-tenant configuration isolation

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{ServiceInstance, Protocol};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
// Removed unused imports
use chrono::{DateTime, Utc};

/// Deployment management state
#[derive(Clone)]
pub struct DeploymentState {
    pub version_manager: Arc<ServiceVersionManager>,
    pub deployment_manager: Arc<BlueGreenDeploymentManager>,
    pub feature_flags: Arc<FeatureFlagManager>,
    pub service_mesh: Arc<ServiceMeshIntegration>,
    pub tenant_manager: Arc<TenantConfigManager>,
}

/// Service deployment management router
pub struct DeploymentRouter;

impl DeploymentRouter {
    /// Create the deployment management router with all endpoints
    pub fn create_router(state: DeploymentState) -> Router {
        Router::new()
            // Service version management
            .route("/versions", get(list_service_versions))
            .route("/versions", post(create_service_version))
            .route("/versions/:version_id", get(get_service_version))
            .route("/versions/:version_id", put(update_service_version))
            .route("/versions/:version_id", delete(delete_service_version))
            .route("/versions/:version_id/traffic", put(update_version_traffic))
            
            // Blue-green deployment management
            .route("/deployments", get(list_deployments))
            .route("/deployments", post(create_deployment))
            .route("/deployments/:deployment_id", get(get_deployment))
            .route("/deployments/:deployment_id/promote", post(promote_deployment))
            .route("/deployments/:deployment_id/rollback", post(rollback_deployment))
            .route("/deployments/:deployment_id/abort", post(abort_deployment))
            
            // Feature flag management
            .route("/feature-flags", get(list_feature_flags))
            .route("/feature-flags", post(create_feature_flag))
            .route("/feature-flags/:flag_id", get(get_feature_flag))
            .route("/feature-flags/:flag_id", put(update_feature_flag))
            .route("/feature-flags/:flag_id", delete(delete_feature_flag))
            .route("/feature-flags/:flag_id/toggle", post(toggle_feature_flag))
            
            // Service mesh integration
            .route("/service-mesh/config", get(get_service_mesh_config))
            .route("/service-mesh/config", put(update_service_mesh_config))
            .route("/service-mesh/policies", get(list_traffic_policies))
            .route("/service-mesh/policies", post(create_traffic_policy))
            .route("/service-mesh/policies/:policy_id", delete(delete_traffic_policy))
            
            // Multi-tenant configuration
            .route("/tenants", get(list_tenants))
            .route("/tenants", post(create_tenant))
            .route("/tenants/:tenant_id", get(get_tenant))
            .route("/tenants/:tenant_id", put(update_tenant))
            .route("/tenants/:tenant_id", delete(delete_tenant))
            .route("/tenants/:tenant_id/services", get(list_tenant_services))
            .route("/tenants/:tenant_id/services", post(add_tenant_service))
            
            .with_state(state)
    }
}

// ============================================================================
// Service Version Management
// ============================================================================

/// Service version manager for handling multiple service versions
pub struct ServiceVersionManager {
    versions: RwLock<HashMap<String, ServiceVersion>>,
    routing_rules: RwLock<HashMap<String, Vec<VersionRoutingRule>>>,
}

impl ServiceVersionManager {
    pub fn new() -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
            routing_rules: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new service version
    pub async fn create_version(&self, version: ServiceVersion) -> GatewayResult<()> {
        let mut versions = self.versions.write().await;
        versions.insert(version.id.clone(), version);
        Ok(())
    }

    /// Get a service version by ID
    pub async fn get_version(&self, version_id: &str) -> Option<ServiceVersion> {
        let versions = self.versions.read().await;
        versions.get(version_id).cloned()
    }

    /// List all versions for a service
    pub async fn list_service_versions(&self, service_name: &str) -> Vec<ServiceVersion> {
        let versions = self.versions.read().await;
        versions
            .values()
            .filter(|v| v.service_name == service_name)
            .cloned()
            .collect()
    }

    /// Update traffic distribution for a version
    pub async fn update_traffic_weight(&self, version_id: &str, weight: u32) -> GatewayResult<()> {
        let mut versions = self.versions.write().await;
        if let Some(version) = versions.get_mut(version_id) {
            version.traffic_weight = weight;
            Ok(())
        } else {
            Err(GatewayError::not_found(format!("Version not found: {}", version_id)))
        }
    }

    /// Set routing rules for a service
    pub async fn set_routing_rules(&self, service_name: String, rules: Vec<VersionRoutingRule>) {
        let mut routing_rules = self.routing_rules.write().await;
        routing_rules.insert(service_name, rules);
    }

    /// Get routing rules for a service
    pub async fn get_routing_rules(&self, service_name: &str) -> Vec<VersionRoutingRule> {
        let routing_rules = self.routing_rules.read().await;
        routing_rules.get(service_name).cloned().unwrap_or_default()
    }
}

/// Service version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVersion {
    pub id: String,
    pub service_name: String,
    pub version: String,
    pub instances: Vec<ServiceInstance>,
    pub traffic_weight: u32,
    pub status: VersionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Version status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionStatus {
    Active,
    Inactive,
    Deploying,
    Failed,
    Deprecated,
}

/// Version routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRoutingRule {
    pub version_id: String,
    pub conditions: Vec<RoutingCondition>,
    pub weight: u32,
    pub priority: i32,
}

/// Routing condition for version selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingCondition {
    pub condition_type: RoutingConditionType,
    pub field: String,
    pub operator: RoutingOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingConditionType {
    Header,
    QueryParam,
    UserAttribute,
    FeatureFlag,
    Percentage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    In,
    NotIn,
}

// ============================================================================
// Blue-Green Deployment Management
// ============================================================================

/// Blue-green deployment manager
pub struct BlueGreenDeploymentManager {
    deployments: RwLock<HashMap<String, BlueGreenDeployment>>,
}

impl BlueGreenDeploymentManager {
    pub fn new() -> Self {
        Self {
            deployments: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new blue-green deployment
    pub async fn create_deployment(&self, deployment: BlueGreenDeployment) -> GatewayResult<()> {
        let mut deployments = self.deployments.write().await;
        deployments.insert(deployment.id.clone(), deployment);
        Ok(())
    }

    /// Get deployment by ID
    pub async fn get_deployment(&self, deployment_id: &str) -> Option<BlueGreenDeployment> {
        let deployments = self.deployments.read().await;
        deployments.get(deployment_id).cloned()
    }

    /// List all deployments
    pub async fn list_deployments(&self) -> Vec<BlueGreenDeployment> {
        let deployments = self.deployments.read().await;
        deployments.values().cloned().collect()
    }

    /// Promote green environment to blue (complete deployment)
    pub async fn promote_deployment(&self, deployment_id: &str) -> GatewayResult<()> {
        let mut deployments = self.deployments.write().await;
        if let Some(deployment) = deployments.get_mut(deployment_id) {
            deployment.status = DeploymentStatus::Completed;
            deployment.completed_at = Some(Utc::now());
            // Switch traffic from blue to green
            deployment.blue_traffic_percentage = 0;
            deployment.green_traffic_percentage = 100;
            Ok(())
        } else {
            Err(GatewayError::not_found(format!("Deployment not found: {}", deployment_id)))
        }
    }

    /// Rollback deployment (switch traffic back to blue)
    pub async fn rollback_deployment(&self, deployment_id: &str) -> GatewayResult<()> {
        let mut deployments = self.deployments.write().await;
        if let Some(deployment) = deployments.get_mut(deployment_id) {
            deployment.status = DeploymentStatus::RolledBack;
            deployment.completed_at = Some(Utc::now());
            // Switch traffic back to blue
            deployment.blue_traffic_percentage = 100;
            deployment.green_traffic_percentage = 0;
            Ok(())
        } else {
            Err(GatewayError::not_found(format!("Deployment not found: {}", deployment_id)))
        }
    }

    /// Gradually shift traffic from blue to green
    pub async fn shift_traffic(&self, deployment_id: &str, green_percentage: u32) -> GatewayResult<()> {
        let mut deployments = self.deployments.write().await;
        if let Some(deployment) = deployments.get_mut(deployment_id) {
            if green_percentage > 100 {
                return Err(GatewayError::validation("Traffic percentage cannot exceed 100"));
            }
            deployment.green_traffic_percentage = green_percentage;
            deployment.blue_traffic_percentage = 100 - green_percentage;
            Ok(())
        } else {
            Err(GatewayError::not_found(format!("Deployment not found: {}", deployment_id)))
        }
    }
}

/// Blue-green deployment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueGreenDeployment {
    pub id: String,
    pub service_name: String,
    pub blue_version: String,
    pub green_version: String,
    pub blue_instances: Vec<ServiceInstance>,
    pub green_instances: Vec<ServiceInstance>,
    pub blue_traffic_percentage: u32,
    pub green_traffic_percentage: u32,
    pub status: DeploymentStatus,
    pub strategy: DeploymentStrategy,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Deployment status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Created,
    InProgress,
    Completed,
    Failed,
    RolledBack,
    Aborted,
}

/// Deployment strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStrategy {
    pub strategy_type: DeploymentStrategyType,
    pub traffic_shift_duration: Option<chrono::Duration>,
    pub health_check_grace_period: chrono::Duration,
    pub rollback_on_failure: bool,
    pub success_criteria: Vec<SuccessCriterion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStrategyType {
    Immediate,
    Gradual,
    Canary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriterion {
    pub metric: String,
    pub threshold: f64,
    pub comparison: ComparisonOperator,
    pub duration: chrono::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Equal,
    NotEqual,
}

// ============================================================================
// Feature Flag Management
// ============================================================================

/// Feature flag manager for A/B testing and feature toggles
pub struct FeatureFlagManager {
    flags: RwLock<HashMap<String, FeatureFlag>>,
}

impl FeatureFlagManager {
    pub fn new() -> Self {
        Self {
            flags: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new feature flag
    pub async fn create_flag(&self, flag: FeatureFlag) -> GatewayResult<()> {
        let mut flags = self.flags.write().await;
        flags.insert(flag.id.clone(), flag);
        Ok(())
    }

    /// Get feature flag by ID
    pub async fn get_flag(&self, flag_id: &str) -> Option<FeatureFlag> {
        let flags = self.flags.read().await;
        flags.get(flag_id).cloned()
    }

    /// List all feature flags
    pub async fn list_flags(&self) -> Vec<FeatureFlag> {
        let flags = self.flags.read().await;
        flags.values().cloned().collect()
    }

    /// Toggle feature flag
    pub async fn toggle_flag(&self, flag_id: &str) -> GatewayResult<bool> {
        let mut flags = self.flags.write().await;
        if let Some(flag) = flags.get_mut(flag_id) {
            flag.enabled = !flag.enabled;
            Ok(flag.enabled)
        } else {
            Err(GatewayError::not_found(format!("Feature flag not found: {}", flag_id)))
        }
    }

    /// Evaluate feature flag for a user/request
    pub async fn evaluate_flag(&self, flag_id: &str, context: &EvaluationContext) -> bool {
        let flags = self.flags.read().await;
        if let Some(flag) = flags.get(flag_id) {
            if !flag.enabled {
                return false;
            }

            // Evaluate targeting rules
            for rule in &flag.targeting_rules {
                if self.evaluate_targeting_rule(rule, context) {
                    return rule.enabled;
                }
            }

            // Default to flag's default value
            flag.default_enabled
        } else {
            false
        }
    }

    fn evaluate_targeting_rule(&self, rule: &TargetingRule, context: &EvaluationContext) -> bool {
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, context) {
                return false;
            }
        }
        true
    }

    fn evaluate_condition(&self, condition: &FlagCondition, context: &EvaluationContext) -> bool {
        let value = match &condition.attribute {
            attr if attr == "user_id" => context.user_id.as_deref(),
            attr if attr == "tenant_id" => context.tenant_id.as_deref(),
            attr if attr == "user_role" => context.user_role.as_deref(),
            attr => context.custom_attributes.get(attr).map(|s| s.as_str()),
        };

        if let Some(value) = value {
            match condition.operator {
                FlagOperator::Equals => value == condition.value,
                FlagOperator::NotEquals => value != condition.value,
                FlagOperator::Contains => value.contains(&condition.value),
                FlagOperator::In => condition.value.split(',').any(|v| v.trim() == value),
                FlagOperator::Percentage => {
                    // Simple hash-based percentage evaluation
                    let hash = std::collections::hash_map::DefaultHasher::new();
                    use std::hash::{Hash, Hasher};
                    let mut hasher = hash;
                    value.hash(&mut hasher);
                    let hash_value = hasher.finish();
                    let percentage: f64 = condition.value.parse().unwrap_or(0.0);
                    ((hash_value % 100) as f64) < percentage
                }
            }
        } else {
            false
        }
    }
}

/// Feature flag definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub default_enabled: bool,
    pub targeting_rules: Vec<TargetingRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Targeting rule for feature flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetingRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<FlagCondition>,
    pub enabled: bool,
    pub priority: i32,
}

/// Condition for feature flag evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagCondition {
    pub attribute: String,
    pub operator: FlagOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlagOperator {
    Equals,
    NotEquals,
    Contains,
    In,
    Percentage,
}

/// Context for feature flag evaluation
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub user_role: Option<String>,
    pub custom_attributes: HashMap<String, String>,
}

// ============================================================================
// Service Mesh Integration
// ============================================================================

/// Service mesh integration for advanced traffic management
pub struct ServiceMeshIntegration {
    config: RwLock<ServiceMeshConfig>,
    traffic_policies: RwLock<HashMap<String, TrafficPolicy>>,
}

impl ServiceMeshIntegration {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(ServiceMeshConfig::default()),
            traffic_policies: RwLock::new(HashMap::new()),
        }
    }

    /// Get service mesh configuration
    pub async fn get_config(&self) -> ServiceMeshConfig {
        self.config.read().await.clone()
    }

    /// Update service mesh configuration
    pub async fn update_config(&self, config: ServiceMeshConfig) {
        let mut current_config = self.config.write().await;
        *current_config = config;
    }

    /// Create traffic policy
    pub async fn create_traffic_policy(&self, policy: TrafficPolicy) -> GatewayResult<()> {
        let mut policies = self.traffic_policies.write().await;
        policies.insert(policy.id.clone(), policy);
        Ok(())
    }

    /// List traffic policies
    pub async fn list_traffic_policies(&self) -> Vec<TrafficPolicy> {
        let policies = self.traffic_policies.read().await;
        policies.values().cloned().collect()
    }

    /// Delete traffic policy
    pub async fn delete_traffic_policy(&self, policy_id: &str) -> GatewayResult<()> {
        let mut policies = self.traffic_policies.write().await;
        if policies.remove(policy_id).is_some() {
            Ok(())
        } else {
            Err(GatewayError::not_found(format!("Traffic policy not found: {}", policy_id)))
        }
    }
}

/// Service mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeshConfig {
    pub enabled: bool,
    pub mesh_type: ServiceMeshType,
    pub mtls_enabled: bool,
    pub observability_enabled: bool,
    pub circuit_breaker_enabled: bool,
    pub retry_policy_enabled: bool,
    pub load_balancing_policy: LoadBalancingPolicy,
}

impl Default for ServiceMeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mesh_type: ServiceMeshType::Istio,
            mtls_enabled: true,
            observability_enabled: true,
            circuit_breaker_enabled: true,
            retry_policy_enabled: true,
            load_balancing_policy: LoadBalancingPolicy::RoundRobin,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceMeshType {
    Istio,
    Linkerd,
    Consul,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingPolicy {
    RoundRobin,
    LeastConnection,
    Random,
    WeightedRoundRobin,
}

/// Traffic policy for service mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPolicy {
    pub id: String,
    pub name: String,
    pub service_name: String,
    pub rules: Vec<TrafficRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRule {
    pub match_conditions: Vec<TrafficMatchCondition>,
    pub destination: TrafficDestination,
    pub weight: u32,
    pub timeout: Option<chrono::Duration>,
    pub retry_policy: Option<RetryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMatchCondition {
    pub condition_type: TrafficMatchType,
    pub field: String,
    pub value: String,
    pub operator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficMatchType {
    Header,
    Path,
    Method,
    QueryParam,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDestination {
    pub service: String,
    pub version: Option<String>,
    pub subset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub per_try_timeout: chrono::Duration,
    pub retry_on: Vec<String>,
}

// ============================================================================
// Multi-Tenant Configuration Management
// ============================================================================

/// Multi-tenant configuration manager
pub struct TenantConfigManager {
    tenants: RwLock<HashMap<String, Tenant>>,
    tenant_services: RwLock<HashMap<String, Vec<TenantService>>>,
}

impl TenantConfigManager {
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            tenant_services: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new tenant
    pub async fn create_tenant(&self, tenant: Tenant) -> GatewayResult<()> {
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }

    /// Get tenant by ID
    pub async fn get_tenant(&self, tenant_id: &str) -> Option<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.get(tenant_id).cloned()
    }

    /// List all tenants
    pub async fn list_tenants(&self) -> Vec<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.values().cloned().collect()
    }

    /// Add service to tenant
    pub async fn add_tenant_service(&self, tenant_id: String, service: TenantService) -> GatewayResult<()> {
        let mut tenant_services = self.tenant_services.write().await;
        tenant_services.entry(tenant_id).or_insert_with(Vec::new).push(service);
        Ok(())
    }

    /// List services for a tenant
    pub async fn list_tenant_services(&self, tenant_id: &str) -> Vec<TenantService> {
        let tenant_services = self.tenant_services.read().await;
        tenant_services.get(tenant_id).cloned().unwrap_or_default()
    }
}

/// Tenant configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub description: String,
    pub config: TenantConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Tenant-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    pub rate_limits: HashMap<String, u32>,
    pub allowed_protocols: Vec<Protocol>,
    pub auth_config: TenantAuthConfig,
    pub observability_config: TenantObservabilityConfig,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantAuthConfig {
    pub auth_required: bool,
    pub allowed_auth_methods: Vec<String>,
    pub jwt_config: Option<TenantJwtConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantJwtConfig {
    pub issuer: String,
    pub audience: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantObservabilityConfig {
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub logging_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_requests_per_second: u32,
    pub max_concurrent_connections: u32,
    pub max_request_size: usize,
    pub max_response_size: usize,
}

/// Tenant service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantService {
    pub service_name: String,
    pub tenant_id: String,
    pub config_overrides: HashMap<String, serde_json::Value>,
    pub access_permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// API Endpoint Implementations
// ============================================================================

// Service Version Management Endpoints
async fn list_service_versions(
    State(state): State<DeploymentState>,
    Query(params): Query<ListVersionsParams>,
) -> Result<Json<ListVersionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let versions = if let Some(service_name) = params.service_name {
        state.version_manager.list_service_versions(&service_name).await
    } else {
        // Return all versions if no service specified
        let all_versions = state.version_manager.versions.read().await;
        all_versions.values().cloned().collect()
    };

    Ok(Json(ListVersionsResponse { versions }))
}

async fn create_service_version(
    State(state): State<DeploymentState>,
    Json(request): Json<CreateVersionRequest>,
) -> Result<Json<ServiceVersion>, (StatusCode, Json<ErrorResponse>)> {
    let version = ServiceVersion {
        id: request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        service_name: request.service_name,
        version: request.version,
        instances: request.instances,
        traffic_weight: request.traffic_weight.unwrap_or(0),
        status: VersionStatus::Inactive,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: request.metadata.unwrap_or_default(),
    };

    state.version_manager.create_version(version.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to create version".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(version))
}

async fn get_service_version(
    State(state): State<DeploymentState>,
    Path(version_id): Path<String>,
) -> Result<Json<ServiceVersion>, (StatusCode, Json<ErrorResponse>)> {
    match state.version_manager.get_version(&version_id).await {
        Some(version) => Ok(Json(version)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Version not found".to_string(),
                details: None,
            }),
        )),
    }
}

async fn update_service_version(
    State(state): State<DeploymentState>,
    Path(version_id): Path<String>,
    Json(request): Json<UpdateVersionRequest>,
) -> Result<Json<ServiceVersion>, (StatusCode, Json<ErrorResponse>)> {
    let mut versions = state.version_manager.versions.write().await;
    if let Some(version) = versions.get_mut(&version_id) {
        if let Some(instances) = request.instances {
            version.instances = instances;
        }
        if let Some(traffic_weight) = request.traffic_weight {
            version.traffic_weight = traffic_weight;
        }
        if let Some(status) = request.status {
            version.status = status;
        }
        if let Some(metadata) = request.metadata {
            version.metadata = metadata;
        }
        version.updated_at = Utc::now();
        
        Ok(Json(version.clone()))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Version not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn delete_service_version(
    State(state): State<DeploymentState>,
    Path(version_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut versions = state.version_manager.versions.write().await;
    if versions.remove(&version_id).is_some() {
        Ok(Json(OperationResponse {
            success: true,
            message: "Version deleted successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Version not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn update_version_traffic(
    State(state): State<DeploymentState>,
    Path(version_id): Path<String>,
    Json(request): Json<UpdateTrafficRequest>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.version_manager.update_traffic_weight(&version_id, request.weight).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to update traffic weight".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(OperationResponse {
        success: true,
        message: "Traffic weight updated successfully".to_string(),
    }))
}

// Blue-Green Deployment Endpoints
async fn list_deployments(
    State(state): State<DeploymentState>,
) -> Result<Json<ListDeploymentsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let deployments = state.deployment_manager.list_deployments().await;
    Ok(Json(ListDeploymentsResponse { deployments }))
}

async fn create_deployment(
    State(state): State<DeploymentState>,
    Json(request): Json<CreateDeploymentRequest>,
) -> Result<Json<BlueGreenDeployment>, (StatusCode, Json<ErrorResponse>)> {
    let deployment = BlueGreenDeployment {
        id: request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        service_name: request.service_name,
        blue_version: request.blue_version,
        green_version: request.green_version,
        blue_instances: request.blue_instances,
        green_instances: request.green_instances,
        blue_traffic_percentage: 100,
        green_traffic_percentage: 0,
        status: DeploymentStatus::Created,
        strategy: request.strategy,
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        metadata: request.metadata.unwrap_or_default(),
    };

    state.deployment_manager.create_deployment(deployment.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to create deployment".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(deployment))
}

async fn get_deployment(
    State(state): State<DeploymentState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<BlueGreenDeployment>, (StatusCode, Json<ErrorResponse>)> {
    match state.deployment_manager.get_deployment(&deployment_id).await {
        Some(deployment) => Ok(Json(deployment)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Deployment not found".to_string(),
                details: None,
            }),
        )),
    }
}

async fn promote_deployment(
    State(state): State<DeploymentState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.deployment_manager.promote_deployment(&deployment_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to promote deployment".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(OperationResponse {
        success: true,
        message: "Deployment promoted successfully".to_string(),
    }))
}

async fn rollback_deployment(
    State(state): State<DeploymentState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.deployment_manager.rollback_deployment(&deployment_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to rollback deployment".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(OperationResponse {
        success: true,
        message: "Deployment rolled back successfully".to_string(),
    }))
}

async fn abort_deployment(
    State(state): State<DeploymentState>,
    Path(deployment_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut deployments = state.deployment_manager.deployments.write().await;
    if let Some(deployment) = deployments.get_mut(&deployment_id) {
        deployment.status = DeploymentStatus::Aborted;
        deployment.completed_at = Some(Utc::now());
        Ok(Json(OperationResponse {
            success: true,
            message: "Deployment aborted successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Deployment not found".to_string(),
                details: None,
            }),
        ))
    }
}

// Feature Flag Endpoints
async fn list_feature_flags(
    State(state): State<DeploymentState>,
) -> Result<Json<ListFlagsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let flags = state.feature_flags.list_flags().await;
    Ok(Json(ListFlagsResponse { flags }))
}

async fn create_feature_flag(
    State(state): State<DeploymentState>,
    Json(request): Json<CreateFlagRequest>,
) -> Result<Json<FeatureFlag>, (StatusCode, Json<ErrorResponse>)> {
    let flag = FeatureFlag {
        id: request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: request.name,
        description: request.description,
        enabled: request.enabled.unwrap_or(false),
        default_enabled: request.default_enabled.unwrap_or(false),
        targeting_rules: request.targeting_rules.unwrap_or_default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: request.metadata.unwrap_or_default(),
    };

    state.feature_flags.create_flag(flag.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to create feature flag".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(flag))
}

async fn get_feature_flag(
    State(state): State<DeploymentState>,
    Path(flag_id): Path<String>,
) -> Result<Json<FeatureFlag>, (StatusCode, Json<ErrorResponse>)> {
    match state.feature_flags.get_flag(&flag_id).await {
        Some(flag) => Ok(Json(flag)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Feature flag not found".to_string(),
                details: None,
            }),
        )),
    }
}

async fn update_feature_flag(
    State(state): State<DeploymentState>,
    Path(flag_id): Path<String>,
    Json(request): Json<UpdateFlagRequest>,
) -> Result<Json<FeatureFlag>, (StatusCode, Json<ErrorResponse>)> {
    let mut flags = state.feature_flags.flags.write().await;
    if let Some(flag) = flags.get_mut(&flag_id) {
        if let Some(name) = request.name {
            flag.name = name;
        }
        if let Some(description) = request.description {
            flag.description = description;
        }
        if let Some(enabled) = request.enabled {
            flag.enabled = enabled;
        }
        if let Some(default_enabled) = request.default_enabled {
            flag.default_enabled = default_enabled;
        }
        if let Some(targeting_rules) = request.targeting_rules {
            flag.targeting_rules = targeting_rules;
        }
        if let Some(metadata) = request.metadata {
            flag.metadata = metadata;
        }
        flag.updated_at = Utc::now();
        
        Ok(Json(flag.clone()))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Feature flag not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn delete_feature_flag(
    State(state): State<DeploymentState>,
    Path(flag_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut flags = state.feature_flags.flags.write().await;
    if flags.remove(&flag_id).is_some() {
        Ok(Json(OperationResponse {
            success: true,
            message: "Feature flag deleted successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Feature flag not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn toggle_feature_flag(
    State(state): State<DeploymentState>,
    Path(flag_id): Path<String>,
) -> Result<Json<ToggleFlagResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.feature_flags.toggle_flag(&flag_id).await {
        Ok(enabled) => Ok(Json(ToggleFlagResponse {
            flag_id,
            enabled,
            message: format!("Feature flag {} {}", if enabled { "enabled" } else { "disabled" }, "successfully"),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to toggle feature flag".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// Service Mesh Endpoints
async fn get_service_mesh_config(
    State(state): State<DeploymentState>,
) -> Result<Json<ServiceMeshConfig>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.service_mesh.get_config().await;
    Ok(Json(config))
}

async fn update_service_mesh_config(
    State(state): State<DeploymentState>,
    Json(config): Json<ServiceMeshConfig>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.service_mesh.update_config(config).await;
    Ok(Json(OperationResponse {
        success: true,
        message: "Service mesh configuration updated successfully".to_string(),
    }))
}

async fn list_traffic_policies(
    State(state): State<DeploymentState>,
) -> Result<Json<ListPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policies = state.service_mesh.list_traffic_policies().await;
    Ok(Json(ListPoliciesResponse { policies }))
}

async fn create_traffic_policy(
    State(state): State<DeploymentState>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<Json<TrafficPolicy>, (StatusCode, Json<ErrorResponse>)> {
    let policy = TrafficPolicy {
        id: request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: request.name,
        service_name: request.service_name,
        rules: request.rules,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    state.service_mesh.create_traffic_policy(policy.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to create traffic policy".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(policy))
}

async fn delete_traffic_policy(
    State(state): State<DeploymentState>,
    Path(policy_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.service_mesh.delete_traffic_policy(&policy_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to delete traffic policy".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(OperationResponse {
        success: true,
        message: "Traffic policy deleted successfully".to_string(),
    }))
}

// Multi-Tenant Endpoints
async fn list_tenants(
    State(state): State<DeploymentState>,
) -> Result<Json<ListTenantsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenants = state.tenant_manager.list_tenants().await;
    Ok(Json(ListTenantsResponse { tenants }))
}

async fn create_tenant(
    State(state): State<DeploymentState>,
    Json(request): Json<CreateTenantRequest>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = Tenant {
        id: request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: request.name,
        description: request.description,
        config: request.config,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: request.metadata.unwrap_or_default(),
    };

    state.tenant_manager.create_tenant(tenant.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to create tenant".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(tenant))
}

async fn get_tenant(
    State(state): State<DeploymentState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    match state.tenant_manager.get_tenant(&tenant_id).await {
        Some(tenant) => Ok(Json(tenant)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tenant not found".to_string(),
                details: None,
            }),
        )),
    }
}

async fn update_tenant(
    State(state): State<DeploymentState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<UpdateTenantRequest>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let mut tenants = state.tenant_manager.tenants.write().await;
    if let Some(tenant) = tenants.get_mut(&tenant_id) {
        if let Some(name) = request.name {
            tenant.name = name;
        }
        if let Some(description) = request.description {
            tenant.description = description;
        }
        if let Some(config) = request.config {
            tenant.config = config;
        }
        if let Some(metadata) = request.metadata {
            tenant.metadata = metadata;
        }
        tenant.updated_at = Utc::now();
        
        Ok(Json(tenant.clone()))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tenant not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn delete_tenant(
    State(state): State<DeploymentState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<OperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut tenants = state.tenant_manager.tenants.write().await;
    if tenants.remove(&tenant_id).is_some() {
        // Also remove tenant services
        let mut tenant_services = state.tenant_manager.tenant_services.write().await;
        tenant_services.remove(&tenant_id);
        
        Ok(Json(OperationResponse {
            success: true,
            message: "Tenant deleted successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tenant not found".to_string(),
                details: None,
            }),
        ))
    }
}

async fn list_tenant_services(
    State(state): State<DeploymentState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<ListTenantServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let services = state.tenant_manager.list_tenant_services(&tenant_id).await;
    Ok(Json(ListTenantServicesResponse { services }))
}

async fn add_tenant_service(
    State(state): State<DeploymentState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<AddTenantServiceRequest>,
) -> Result<Json<TenantService>, (StatusCode, Json<ErrorResponse>)> {
    let service = TenantService {
        service_name: request.service_name,
        tenant_id: tenant_id.clone(),
        config_overrides: request.config_overrides.unwrap_or_default(),
        access_permissions: request.access_permissions.unwrap_or_default(),
        created_at: Utc::now(),
    };

    state.tenant_manager.add_tenant_service(tenant_id, service.clone()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Failed to add tenant service".to_string(),
            details: Some(e.to_string()),
        })))?;

    Ok(Json(service))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListVersionsParams {
    service_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListVersionsResponse {
    versions: Vec<ServiceVersion>,
}

#[derive(Debug, Deserialize)]
struct CreateVersionRequest {
    id: Option<String>,
    service_name: String,
    version: String,
    instances: Vec<ServiceInstance>,
    traffic_weight: Option<u32>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateVersionRequest {
    instances: Option<Vec<ServiceInstance>>,
    traffic_weight: Option<u32>,
    status: Option<VersionStatus>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateTrafficRequest {
    weight: u32,
}

#[derive(Debug, Serialize)]
struct ListDeploymentsResponse {
    deployments: Vec<BlueGreenDeployment>,
}

#[derive(Debug, Deserialize)]
struct CreateDeploymentRequest {
    id: Option<String>,
    service_name: String,
    blue_version: String,
    green_version: String,
    blue_instances: Vec<ServiceInstance>,
    green_instances: Vec<ServiceInstance>,
    strategy: DeploymentStrategy,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct ListFlagsResponse {
    flags: Vec<FeatureFlag>,
}

#[derive(Debug, Deserialize)]
struct CreateFlagRequest {
    id: Option<String>,
    name: String,
    description: String,
    enabled: Option<bool>,
    default_enabled: Option<bool>,
    targeting_rules: Option<Vec<TargetingRule>>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateFlagRequest {
    name: Option<String>,
    description: Option<String>,
    enabled: Option<bool>,
    default_enabled: Option<bool>,
    targeting_rules: Option<Vec<TargetingRule>>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct ToggleFlagResponse {
    flag_id: String,
    enabled: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ListPoliciesResponse {
    policies: Vec<TrafficPolicy>,
}

#[derive(Debug, Deserialize)]
struct CreatePolicyRequest {
    id: Option<String>,
    name: String,
    service_name: String,
    rules: Vec<TrafficRule>,
}

#[derive(Debug, Serialize)]
struct ListTenantsResponse {
    tenants: Vec<Tenant>,
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    id: Option<String>,
    name: String,
    description: String,
    config: TenantConfig,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateTenantRequest {
    name: Option<String>,
    description: Option<String>,
    config: Option<TenantConfig>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct ListTenantServicesResponse {
    services: Vec<TenantService>,
}

#[derive(Debug, Deserialize)]
struct AddTenantServiceRequest {
    service_name: String,
    config_overrides: Option<HashMap<String, serde_json::Value>>,
    access_permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct OperationResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}
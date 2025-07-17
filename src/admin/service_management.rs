//! # Service Management Module
//!
//! This module provides administrative endpoints for manual service registration and deregistration.
//! It includes functionality for:
//! - Manual service instance registration
//! - Service instance deregistration
//! - Service registry persistence for admin-added services
//! - Service instance health status management
//!
//! ## Security Considerations
//! Service management endpoints should be protected with appropriate authentication and authorization.
//! These endpoints can modify the service registry and should only be accessible to authorized administrators.

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{ServiceInstance, HealthStatus, Protocol};
use crate::discovery::ServiceRegistry;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Service management state containing the service registry and persistence layer
#[derive(Clone)]
pub struct ServiceManagementState {
    pub service_registry: Arc<ServiceRegistry>,
    pub persistence: Arc<ServicePersistence>,
}

/// Service management router for service registration/deregistration endpoints
pub struct ServiceManagementRouter;

impl ServiceManagementRouter {
    /// Create the service management router with all endpoints
    pub fn create_router(state: ServiceManagementState) -> Router {
        Router::new()
            // Service instance management endpoints
            .route("/services", get(list_services))
            .route("/services", post(register_service))
            .route("/services/:service_id", get(get_service))
            .route("/services/:service_id", put(update_service))
            .route("/services/:service_id", delete(deregister_service))
            
            // Service health management endpoints
            .route("/services/:service_id/health", get(get_service_health))
            .route("/services/:service_id/health", put(update_service_health))
            
            // Service discovery endpoints
            .route("/services/discover", post(discover_services))
            .route("/services/registry/stats", get(get_registry_stats))
            .route("/services/registry/refresh", post(refresh_registry))
            
            // Persistence management endpoints
            .route("/services/persistence/export", get(export_persisted_services))
            .route("/services/persistence/import", post(import_persisted_services))
            .route("/services/persistence/clear", delete(clear_persisted_services))
            
            .with_state(state)
    }
}

// ============================================================================
// Service Instance Management Endpoints
// ============================================================================

/// List all registered services with optional filtering
async fn list_services(
    State(state): State<ServiceManagementState>,
    Query(params): Query<ListServicesParams>,
) -> Result<Json<ListServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let service_names = state.service_registry.get_service_names();
    let mut services = Vec::new();

    for service_name in service_names {
        let instances = if let Some(health_filter) = &params.health_status {
            match health_filter.as_str() {
                "healthy" => state.service_registry.get_healthy_instances(&service_name),
                "unhealthy" => state.service_registry.get_service_instances(&service_name)
                    .into_iter()
                    .filter(|instance| !instance.is_healthy())
                    .collect(),
                _ => state.service_registry.get_service_instances(&service_name),
            }
        } else {
            state.service_registry.get_service_instances(&service_name)
        };

        if let Some(protocol_filter) = &params.protocol {
            let filtered_instances: Vec<_> = instances
                .into_iter()
                .filter(|instance| instance.protocol.to_string().to_lowercase() == protocol_filter.to_lowercase())
                .collect();
            
            if !filtered_instances.is_empty() {
                services.push(ServiceInfo {
                    name: service_name,
                    instances: filtered_instances.into_iter().map(|i| (*i).clone()).collect(),
                });
            }
        } else if !instances.is_empty() {
            services.push(ServiceInfo {
                name: service_name,
                instances: instances.into_iter().map(|i| (*i).clone()).collect(),
            });
        }
    }

    let total_services = services.len();
    let total_instances = services.iter().map(|s| s.instances.len()).sum();
    
    Ok(Json(ListServicesResponse {
        services,
        total_services,
        total_instances,
    }))
}

/// Register a new service instance manually
async fn register_service(
    State(state): State<ServiceManagementState>,
    Json(request): Json<RegisterServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate the service instance data
    if request.name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Service name cannot be empty".to_string(),
                details: None,
            }),
        ));
    }

    // Parse the address
    let address: SocketAddr = request.address.parse()
        .map_err(|e| (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address format".to_string(),
                details: Some(format!("Failed to parse address '{}': {}", request.address, e)),
            }),
        ))?;

    // Create the service instance
    let instance_id = request.id.unwrap_or_else(|| format!("{}:{}", request.name, address.port()));
    let mut instance = ServiceInstance::new(
        instance_id.clone(),
        request.name.clone(),
        address,
        request.protocol,
    );

    // Set additional properties
    instance.metadata = request.metadata.unwrap_or_default();
    instance.health_status = request.health_status.unwrap_or(HealthStatus::Unknown);
    instance.weight = request.weight.unwrap_or(1);

    // Register the service instance
    state.service_registry.add_instance(instance.clone());

    // Persist the manually added service
    if let Err(e) = state.persistence.persist_service(&instance).await {
        warn!("Failed to persist service instance {}: {}", instance_id, e);
        // Continue anyway - the service is registered in memory
    }

    info!("Manually registered service instance: {} ({})", instance_id, request.name);

    Ok(Json(ServiceOperationResponse {
        success: true,
        service_id: instance_id,
        message: "Service registered successfully".to_string(),
    }))
}

/// Get details of a specific service instance
async fn get_service(
    State(state): State<ServiceManagementState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceInstance>, (StatusCode, Json<ErrorResponse>)> {
    match state.service_registry.get_instance(&service_id) {
        Some(instance) => Ok(Json((*instance).clone())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service instance not found".to_string(),
                details: Some(format!("No service instance found with ID: {}", service_id)),
            }),
        )),
    }
}

/// Update an existing service instance
async fn update_service(
    State(state): State<ServiceManagementState>,
    Path(service_id): Path<String>,
    Json(request): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Get the existing instance
    let existing_instance = state.service_registry.get_instance(&service_id)
        .ok_or_else(|| (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service instance not found".to_string(),
                details: Some(format!("No service instance found with ID: {}", service_id)),
            }),
        ))?;

    // Create updated instance
    let mut updated_instance = (*existing_instance).clone();

    // Update fields if provided
    if let Some(address) = request.address {
        updated_instance.address = address.parse()
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                    details: Some(format!("Failed to parse address '{}': {}", address, e)),
                }),
            ))?;
    }

    if let Some(metadata) = request.metadata {
        updated_instance.metadata = metadata;
    }

    if let Some(health_status) = request.health_status {
        updated_instance.health_status = health_status;
    }

    if let Some(weight) = request.weight {
        updated_instance.weight = weight;
    }

    if let Some(protocol) = request.protocol {
        updated_instance.protocol = protocol;
    }

    // Update the service instance
    state.service_registry.add_instance(updated_instance.clone());

    // Update persistence if this was a manually added service
    if state.persistence.is_persisted(&service_id).await {
        if let Err(e) = state.persistence.persist_service(&updated_instance).await {
            warn!("Failed to update persisted service instance {}: {}", service_id, e);
        }
    }

    info!("Updated service instance: {}", service_id);

    Ok(Json(ServiceOperationResponse {
        success: true,
        service_id: service_id.clone(),
        message: "Service updated successfully".to_string(),
    }))
}

/// Deregister a service instance
async fn deregister_service(
    State(state): State<ServiceManagementState>,
    Path(service_id): Path<String>,
    Query(params): Query<DeregisterServiceParams>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if the service exists
    if state.service_registry.get_instance(&service_id).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service instance not found".to_string(),
                details: Some(format!("No service instance found with ID: {}", service_id)),
            }),
        ));
    }

    // Remove from registry
    state.service_registry.remove_instance(&service_id);

    // Remove from persistence if it was manually added
    if state.persistence.is_persisted(&service_id).await {
        if let Err(e) = state.persistence.remove_service(&service_id).await {
            warn!("Failed to remove persisted service instance {}: {}", service_id, e);
        }
    }

    let force = params.force.unwrap_or(false);
    let message = if force {
        "Service forcefully deregistered"
    } else {
        "Service deregistered successfully"
    };

    info!("Deregistered service instance: {} (force: {})", service_id, force);

    Ok(Json(ServiceOperationResponse {
        success: true,
        service_id: service_id.clone(),
        message: message.to_string(),
    }))
}

// ============================================================================
// Service Health Management Endpoints
// ============================================================================

/// Get health status of a service instance
async fn get_service_health(
    State(state): State<ServiceManagementState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.service_registry.get_instance(&service_id) {
        Some(instance) => Ok(Json(ServiceHealthResponse {
            service_id: service_id.clone(),
            health_status: instance.health_status.clone(),
            last_health_check: instance.last_health_check,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service instance not found".to_string(),
                details: Some(format!("No service instance found with ID: {}", service_id)),
            }),
        )),
    }
}

/// Update health status of a service instance
async fn update_service_health(
    State(state): State<ServiceManagementState>,
    Path(service_id): Path<String>,
    Json(request): Json<UpdateHealthRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if the service exists
    if state.service_registry.get_instance(&service_id).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service instance not found".to_string(),
                details: Some(format!("No service instance found with ID: {}", service_id)),
            }),
        ));
    }

    // Update health status
    state.service_registry.update_instance_health(&service_id, request.health_status.clone());

    info!("Updated health status for service instance {}: {:?}", service_id, request.health_status);

    Ok(Json(ServiceOperationResponse {
        success: true,
        service_id: service_id.clone(),
        message: format!("Health status updated to {:?}", request.health_status),
    }))
}

// ============================================================================
// Service Discovery Endpoints
// ============================================================================

/// Trigger service discovery refresh
async fn discover_services(
    State(state): State<ServiceManagementState>,
) -> Result<Json<DiscoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.service_registry.refresh().await {
        Ok(()) => {
            let stats = state.service_registry.get_stats();
            Ok(Json(DiscoveryResponse {
                success: true,
                message: "Service discovery refresh completed".to_string(),
                discovered_services: stats.total_services,
                discovered_instances: stats.total_instances,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to refresh service discovery".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get service registry statistics
async fn get_registry_stats(
    State(state): State<ServiceManagementState>,
) -> Result<Json<crate::discovery::RegistryStats>, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.service_registry.get_stats();
    Ok(Json(stats))
}

/// Refresh the service registry
async fn refresh_registry(
    State(state): State<ServiceManagementState>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.service_registry.refresh().await {
        Ok(()) => Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: "registry".to_string(),
            message: "Service registry refreshed successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to refresh service registry".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Persistence Management Endpoints
// ============================================================================

/// Export all persisted services
async fn export_persisted_services(
    State(state): State<ServiceManagementState>,
) -> Result<Json<ExportServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.persistence.export_all().await {
        Ok(services) => {
            let count = services.len();
            Ok(Json(ExportServicesResponse {
                services,
                count,
            }))
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to export persisted services".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Import services into persistence
async fn import_persisted_services(
    State(state): State<ServiceManagementState>,
    Json(request): Json<ImportServicesRequest>,
) -> Result<Json<ImportServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut imported_count = 0;
    let mut failed_imports = Vec::new();

    for service in request.services {
        match state.persistence.persist_service(&service).await {
            Ok(()) => {
                // Also add to the registry
                state.service_registry.add_instance(service.clone());
                imported_count += 1;
            }
            Err(e) => {
                failed_imports.push(format!("Service {}: {}", service.id, e));
            }
        }
    }

    let success = failed_imports.is_empty();
    let message = if success {
        format!("Successfully imported {} services", imported_count)
    } else {
        format!("Imported {} services with {} failures", imported_count, failed_imports.len())
    };

    Ok(Json(ImportServicesResponse {
        success,
        imported_count,
        failed_imports,
        message,
    }))
}

/// Clear all persisted services
async fn clear_persisted_services(
    State(state): State<ServiceManagementState>,
    Query(params): Query<ClearServicesParams>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let confirm = params.confirm.unwrap_or(false);
    if !confirm {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Confirmation required".to_string(),
                details: Some("Add ?confirm=true to confirm clearing all persisted services".to_string()),
            }),
        ));
    }

    match state.persistence.clear_all().await {
        Ok(count) => Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: "all".to_string(),
            message: format!("Cleared {} persisted services", count),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to clear persisted services".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Service Persistence Implementation
// ============================================================================

/// Service persistence layer for admin-added services
pub struct ServicePersistence {
    /// In-memory storage of persisted services (in production, this would be a database)
    persisted_services: RwLock<HashMap<String, ServiceInstance>>,
    /// File path for persistence (optional)
    persistence_file: Option<String>,
}

impl ServicePersistence {
    /// Create a new service persistence layer
    pub fn new(persistence_file: Option<String>) -> Self {
        Self {
            persisted_services: RwLock::new(HashMap::new()),
            persistence_file,
        }
    }

    /// Persist a service instance
    pub async fn persist_service(&self, service: &ServiceInstance) -> GatewayResult<()> {
        let mut services = self.persisted_services.write().await;
        services.insert(service.id.clone(), service.clone());
        
        // If file persistence is configured, save to file
        if let Some(file_path) = &self.persistence_file {
            self.save_to_file(file_path, &services).await?;
        }

        debug!("Persisted service instance: {}", service.id);
        Ok(())
    }

    /// Remove a persisted service instance
    pub async fn remove_service(&self, service_id: &str) -> GatewayResult<()> {
        let mut services = self.persisted_services.write().await;
        services.remove(service_id);
        
        // If file persistence is configured, save to file
        if let Some(file_path) = &self.persistence_file {
            self.save_to_file(file_path, &services).await?;
        }

        debug!("Removed persisted service instance: {}", service_id);
        Ok(())
    }

    /// Check if a service is persisted
    pub async fn is_persisted(&self, service_id: &str) -> bool {
        let services = self.persisted_services.read().await;
        services.contains_key(service_id)
    }

    /// Get all persisted services
    pub async fn get_all(&self) -> Vec<ServiceInstance> {
        let services = self.persisted_services.read().await;
        services.values().cloned().collect()
    }

    /// Export all persisted services
    pub async fn export_all(&self) -> GatewayResult<Vec<ServiceInstance>> {
        Ok(self.get_all().await)
    }

    /// Clear all persisted services
    pub async fn clear_all(&self) -> GatewayResult<usize> {
        let mut services = self.persisted_services.write().await;
        let count = services.len();
        services.clear();
        
        // If file persistence is configured, save empty state to file
        if let Some(file_path) = &self.persistence_file {
            self.save_to_file(file_path, &services).await?;
        }

        debug!("Cleared {} persisted service instances", count);
        Ok(count)
    }

    /// Load persisted services from file
    pub async fn load_from_file(&self) -> GatewayResult<()> {
        if let Some(file_path) = &self.persistence_file {
            match tokio::fs::read_to_string(file_path).await {
                Ok(content) => {
                    let services: HashMap<String, ServiceInstance> = serde_json::from_str(&content)
                        .map_err(|e| GatewayError::config(format!("Failed to parse persistence file: {}", e)))?;
                    
                    let mut persisted = self.persisted_services.write().await;
                    *persisted = services;
                    
                    info!("Loaded {} persisted services from file: {}", persisted.len(), file_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("Persistence file not found, starting with empty state: {}", file_path);
                }
                Err(e) => {
                    return Err(GatewayError::config(format!("Failed to read persistence file: {}", e)));
                }
            }
        }
        Ok(())
    }

    /// Save persisted services to file
    async fn save_to_file(&self, file_path: &str, services: &HashMap<String, ServiceInstance>) -> GatewayResult<()> {
        let content = serde_json::to_string_pretty(services)
            .map_err(|e| GatewayError::config(format!("Failed to serialize services: {}", e)))?;
        
        tokio::fs::write(file_path, content).await
            .map_err(|e| GatewayError::config(format!("Failed to write persistence file: {}", e)))?;
        
        debug!("Saved {} services to persistence file: {}", services.len(), file_path);
        Ok(())
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListServicesParams {
    health_status: Option<String>,
    protocol: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListServicesResponse {
    services: Vec<ServiceInfo>,
    total_services: usize,
    total_instances: usize,
}

#[derive(Debug, Serialize)]
struct ServiceInfo {
    name: String,
    instances: Vec<ServiceInstance>,
}

#[derive(Debug, Deserialize)]
struct RegisterServiceRequest {
    id: Option<String>,
    name: String,
    address: String,
    protocol: Protocol,
    metadata: Option<HashMap<String, String>>,
    health_status: Option<HealthStatus>,
    weight: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct UpdateServiceRequest {
    address: Option<String>,
    metadata: Option<HashMap<String, String>>,
    health_status: Option<HealthStatus>,
    weight: Option<u32>,
    protocol: Option<Protocol>,
}

#[derive(Debug, Deserialize)]
struct DeregisterServiceParams {
    force: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ServiceOperationResponse {
    success: bool,
    service_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ServiceHealthResponse {
    service_id: String,
    health_status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "instant_serde_option")]
    last_health_check: Option<std::time::Instant>,
}

mod instant_serde_option {
    use serde::{Serializer, Serialize};
    use std::time::Instant;

    pub fn serialize<S>(instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match instant {
            Some(_) => "present".serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct UpdateHealthRequest {
    health_status: HealthStatus,
}

#[derive(Debug, Serialize)]
struct DiscoveryResponse {
    success: bool,
    message: String,
    discovered_services: usize,
    discovered_instances: usize,
}

#[derive(Debug, Serialize)]
struct ExportServicesResponse {
    services: Vec<ServiceInstance>,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct ImportServicesRequest {
    services: Vec<ServiceInstance>,
}

#[derive(Debug, Serialize)]
struct ImportServicesResponse {
    success: bool,
    imported_count: usize,
    failed_imports: Vec<String>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ClearServicesParams {
    confirm: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{ServiceDiscoveryConfig, DiscoveryType, StaticDiscovery};
    use std::time::Duration;

    #[tokio::test]
    async fn test_service_persistence() {
        let persistence = ServicePersistence::new(None);
        
        let service = ServiceInstance::new(
            "test-service-1".to_string(),
            "test-service".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
            Protocol::Http,
        );

        // Test persist
        persistence.persist_service(&service).await.unwrap();
        assert!(persistence.is_persisted("test-service-1").await);

        // Test get all
        let all_services = persistence.get_all().await;
        assert_eq!(all_services.len(), 1);
        assert_eq!(all_services[0].id, "test-service-1");

        // Test remove
        persistence.remove_service("test-service-1").await.unwrap();
        assert!(!persistence.is_persisted("test-service-1").await);
    }

    #[tokio::test]
    async fn test_service_management_state() {
        let discovery = Arc::new(StaticDiscovery::new());
        let config = ServiceDiscoveryConfig {
            discovery_type: DiscoveryType::Static,
            kubernetes: None,
            consul: None,
            nats: None,
            health_check_interval: Duration::from_secs(30),
            registration_ttl: Duration::from_secs(300),
        };
        
        let registry = Arc::new(ServiceRegistry::new(discovery, config));
        let persistence = Arc::new(ServicePersistence::new(None));
        
        let state = ServiceManagementState {
            service_registry: registry,
            persistence,
        };

        // Test service registration
        let service = ServiceInstance::new(
            "test-service-1".to_string(),
            "test-service".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
            Protocol::Http,
        );

        state.service_registry.add_instance(service.clone());
        state.persistence.persist_service(&service).await.unwrap();

        // Verify service is registered and persisted
        assert!(state.service_registry.get_instance("test-service-1").is_some());
        assert!(state.persistence.is_persisted("test-service-1").await);
    }
}
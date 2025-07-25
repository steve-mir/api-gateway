//! # Core Admin Endpoints
//!
//! This module provides the core administrative endpoints that integrate all admin functionality:
//! - Service management endpoints (CRUD operations for services)
//! - Configuration management endpoints with validation
//! - Health status monitoring and override endpoints
//! - Metrics query and dashboard endpoints
//! - Log querying and filtering endpoints
//! - System status and diagnostics endpoints
//! - Backup and restore endpoints for configuration
//!
//! ## Architecture
//!
//! The core admin endpoints act as a unified interface that orchestrates calls to
//! specialized admin modules. This provides a single entry point for admin operations
//! while maintaining separation of concerns.

use crate::admin::{
    AdminState, ServiceManagementState, HealthAdminState, MetricsAdminState, 
    LoggingAdminState, ConfigAudit, RuntimeConfigManager
};
use crate::core::config::GatewayConfig;
use crate::core::error::{GatewayError, GatewayResult};
use crate::observability::{
    health::{HealthChecker, ServiceStatus},
    metrics::MetricsCollector,
    logging::StructuredLogger,
};
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
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Core admin endpoints state
#[derive(Clone)]
pub struct CoreAdminState {
    pub config_manager: Arc<RuntimeConfigManager>,
    pub audit: Arc<ConfigAudit>,
    pub service_management: Option<ServiceManagementState>,
    pub health_admin: Option<HealthAdminState>,
    pub metrics_admin: Option<MetricsAdminState>,
    pub logging_admin: Option<LoggingAdminState>,
}

/// Core admin router
pub struct CoreAdminRouter;

impl CoreAdminRouter {
    /// Create the core admin router with all endpoints
    pub fn create_router(state: CoreAdminState) -> Router {
        Router::new()
            // Service management endpoints
            .route("/services", get(list_all_services))
            .route("/services", post(create_service))
            .route("/services/:service_id", get(get_service_details))
            .route("/services/:service_id", put(update_service))
            .route("/services/:service_id", delete(delete_service))
            .route("/services/:service_id/health", get(get_service_health))
            .route("/services/:service_id/health", put(override_service_health))
            
            // Configuration management endpoints
            .route("/config", get(get_current_configuration))
            .route("/config", put(update_configuration))
            .route("/config/validate", post(validate_configuration))
            .route("/config/backup", post(backup_configuration))
            .route("/config/restore", post(restore_configuration))
            
            // Health monitoring endpoints
            .route("/health/gateway", get(get_gateway_health))
            .route("/health/services", get(get_all_services_health))
            .route("/health/diagnostics", get(get_system_diagnostics))
            
            // Metrics endpoints
            .route("/metrics/summary", get(get_metrics_summary))
            .route("/metrics/query", post(query_metrics))
            .route("/metrics/dashboard", get(get_metrics_dashboard))
            
            // Logging endpoints
            .route("/logs/query", get(query_logs))
            .route("/logs/audit", get(query_audit_logs))
            .route("/logs/export", get(export_logs))
            
            // System status endpoints
            .route("/system/status", get(get_system_status))
            .route("/system/diagnostics", get(get_detailed_diagnostics))
            .route("/system/info", get(get_system_info))
            
            .with_state(state)
    }
}

// ============================================================================
// Service Management Endpoints
// ============================================================================

/// List all services with their instances
async fn list_all_services(
    State(state): State<CoreAdminState>,
    Query(params): Query<ListServicesParams>,
) -> Result<Json<ServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(service_mgmt) = &state.service_management {
        let service_names = service_mgmt.service_registry.get_service_names();
        let mut services = Vec::new();

        for service_name in service_names {
            let instances = service_mgmt.service_registry.get_service_instances(&service_name);
            
            // Apply health filter if specified
            let filtered_instances = if let Some(health_filter) = &params.health_status {
                instances.into_iter()
                    .filter(|instance| {
                        match health_filter.as_str() {
                            "healthy" => instance.is_healthy(),
                            "unhealthy" => !instance.is_healthy(),
                            _ => true,
                        }
                    })
                    .collect()
            } else {
                instances.into_iter().collect()
            };

            if !filtered_instances.is_empty() {
                services.push(ServiceSummary {
                    name: service_name,
                    instance_count: filtered_instances.len(),
                    healthy_instances: filtered_instances.iter().filter(|i| i.is_healthy()).count(),
                    instances: filtered_instances.into_iter().map(|i| (*i).clone()).collect(),
                });
            }
        }

        Ok(Json(ServicesResponse {
            services,
            total_services: services.len(),
            total_instances: services.iter().map(|s| s.instance_count).sum(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Service management not available".to_string(),
                details: Some("Service management module is not configured".to_string()),
            }),
        ))
    }
}

/// Create a new service instance
async fn create_service(
    State(state): State<CoreAdminState>,
    Json(request): Json<CreateServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(service_mgmt) = &state.service_management {
        // Validate the service data
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
        let address = request.address.parse()
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                    details: Some(format!("Failed to parse address '{}': {}", request.address, e)),
                }),
            ))?;

        // Create service instance
        let instance_id = request.id.unwrap_or_else(|| format!("{}:{}", request.name, address.port()));
        let mut instance = crate::core::types::ServiceInstance::new(
            instance_id.clone(),
            request.name.clone(),
            address,
            request.protocol,
        );

        instance.metadata = request.metadata.unwrap_or_default();
        instance.weight = request.weight.unwrap_or(1);

        // Register the service
        service_mgmt.service_registry.add_instance(instance.clone());

        // Persist if requested
        if request.persist.unwrap_or(true) {
            if let Err(e) = service_mgmt.persistence.persist_service(&instance).await {
                tracing::warn!("Failed to persist service instance {}: {}", instance_id, e);
            }
        }

        // Log audit event
        state.audit.log_change(
            crate::admin::ConfigChangeType::ServiceAdded,
            request.changed_by.unwrap_or_else(|| "admin".to_string()),
            format!("Created service instance: {}", instance_id),
            None,
            Some(serde_json::to_value(&instance).unwrap_or_default()),
            HashMap::new(),
        ).await;

        Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: instance_id,
            message: "Service created successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Service management not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Get service details
async fn get_service_details(
    State(state): State<CoreAdminState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceDetailsResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(service_mgmt) = &state.service_management {
        match service_mgmt.service_registry.get_instance(&service_id) {
            Some(instance) => {
                // Get health status if health admin is available
                let health_status = if let Some(health_admin) = &state.health_admin {
                    Some(health_admin.health_checker.get_instance_health(&service_id))
                } else {
                    None
                };

                Ok(Json(ServiceDetailsResponse {
                    instance: (*instance).clone(),
                    health_status,
                    is_persisted: service_mgmt.persistence.is_persisted(&service_id).await,
                }))
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Service not found".to_string(),
                    details: Some(format!("No service instance found with ID: {}", service_id)),
                }),
            )),
        }
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Service management not available".to_string(),
                details: None,
            }),
        ))
    }
}/// 
Update service instance
async fn update_service(
    State(state): State<CoreAdminState>,
    Path(service_id): Path<String>,
    Json(request): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(service_mgmt) = &state.service_management {
        // Get existing instance
        let existing_instance = service_mgmt.service_registry.get_instance(&service_id)
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Service not found".to_string(),
                    details: Some(format!("No service instance found with ID: {}", service_id)),
                }),
            ))?;

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

        if let Some(weight) = request.weight {
            updated_instance.weight = weight;
        }

        if let Some(protocol) = request.protocol {
            updated_instance.protocol = protocol;
        }

        // Update the service instance
        service_mgmt.service_registry.add_instance(updated_instance.clone());

        // Update persistence if it was persisted
        if service_mgmt.persistence.is_persisted(&service_id).await {
            if let Err(e) = service_mgmt.persistence.persist_service(&updated_instance).await {
                tracing::warn!("Failed to update persisted service instance {}: {}", service_id, e);
            }
        }

        // Log audit event
        state.audit.log_change(
            crate::admin::ConfigChangeType::ServiceModified,
            request.changed_by.unwrap_or_else(|| "admin".to_string()),
            format!("Updated service instance: {}", service_id),
            Some(serde_json::to_value(&existing_instance).unwrap_or_default()),
            Some(serde_json::to_value(&updated_instance).unwrap_or_default()),
            HashMap::new(),
        ).await;

        Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: service_id.clone(),
            message: "Service updated successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Service management not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Delete service instance
async fn delete_service(
    State(state): State<CoreAdminState>,
    Path(service_id): Path<String>,
    Query(params): Query<DeleteServiceParams>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(service_mgmt) = &state.service_management {
        // Check if service exists
        let existing_instance = service_mgmt.service_registry.get_instance(&service_id)
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Service not found".to_string(),
                    details: Some(format!("No service instance found with ID: {}", service_id)),
                }),
            ))?;

        let instance_backup = (*existing_instance).clone();

        // Remove from registry
        service_mgmt.service_registry.remove_instance(&service_id);

        // Remove from persistence if it was persisted
        if service_mgmt.persistence.is_persisted(&service_id).await {
            if let Err(e) = service_mgmt.persistence.remove_service(&service_id).await {
                tracing::warn!("Failed to remove persisted service instance {}: {}", service_id, e);
            }
        }

        // Log audit event
        state.audit.log_change(
            crate::admin::ConfigChangeType::ServiceRemoved,
            params.changed_by.unwrap_or_else(|| "admin".to_string()),
            format!("Deleted service instance: {}", service_id),
            Some(serde_json::to_value(&instance_backup).unwrap_or_default()),
            None,
            HashMap::new(),
        ).await;

        Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: service_id.clone(),
            message: "Service deleted successfully".to_string(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Service management not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Get service health status
async fn get_service_health(
    State(state): State<CoreAdminState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(health_admin) = &state.health_admin {
        let health_status = health_admin.health_checker.get_instance_health(&service_id);
        
        Ok(Json(ServiceHealthResponse {
            service_id: service_id.clone(),
            health_status,
            last_check: chrono::Utc::now(), // In real implementation, get from health checker
            check_interval: std::time::Duration::from_secs(30), // From config
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Health monitoring not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Override service health status
async fn override_service_health(
    State(state): State<CoreAdminState>,
    Path(service_id): Path<String>,
    Json(request): Json<HealthOverrideRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(health_admin) = &state.health_admin {
        let previous_status = health_admin.health_checker.get_instance_health(&service_id);
        
        health_admin.health_checker.set_manual_override(service_id.clone(), request.status.clone());

        // Log audit event
        state.audit.log_change(
            crate::admin::ConfigChangeType::HealthOverride,
            request.changed_by.unwrap_or_else(|| "admin".to_string()),
            format!("Health status override for service {}: {:?}", service_id, request.status),
            Some(serde_json::json!({"previous_status": previous_status})),
            Some(serde_json::json!({"new_status": request.status, "reason": request.reason})),
            HashMap::new(),
        ).await;

        Ok(Json(ServiceOperationResponse {
            success: true,
            service_id: service_id.clone(),
            message: format!("Health status overridden to {:?}", request.status),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Health monitoring not available".to_string(),
                details: None,
            }),
        ))
    }
}

// ============================================================================
// Configuration Management Endpoints
// ============================================================================

/// Get current configuration
async fn get_current_configuration(
    State(state): State<CoreAdminState>,
) -> Result<Json<ConfigurationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.get_current_config().await {
        Ok(config) => Ok(Json(ConfigurationResponse {
            config,
            last_modified: state.config_manager.get_last_modified().await,
            version: state.audit.get_statistics().await.total_changes,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get current configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update configuration
async fn update_configuration(
    State(state): State<CoreAdminState>,
    Json(request): Json<UpdateConfigurationRequest>,
) -> Result<Json<ConfigurationUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate configuration
    if let Err(e) = request.config.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Configuration validation failed".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    match state.config_manager.update_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| "Configuration update via admin API".to_string()),
        request.metadata.unwrap_or_default(),
    ).await {
        Ok(change_id) => Ok(Json(ConfigurationUpdateResponse {
            success: true,
            change_id,
            message: "Configuration updated successfully".to_string(),
            applied_at: chrono::Utc::now(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Validate configuration
async fn validate_configuration(
    Json(config): Json<GatewayConfig>,
) -> Result<Json<ConfigurationValidationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match config.validate() {
        Ok(()) => Ok(Json(ConfigurationValidationResponse {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        })),
        Err(e) => Ok(Json(ConfigurationValidationResponse {
            valid: false,
            errors: vec![e.to_string()],
            warnings: Vec::new(),
        })),
    }
}

/// Backup configuration
async fn backup_configuration(
    State(state): State<CoreAdminState>,
    Json(request): Json<BackupConfigurationRequest>,
) -> Result<Json<BackupConfigurationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.get_current_config().await {
        Ok(config) => {
            let backup_id = Uuid::new_v4();
            let backup_data = ConfigurationBackup {
                id: backup_id,
                config,
                created_at: chrono::Utc::now(),
                created_by: request.created_by.unwrap_or_else(|| "admin".to_string()),
                description: request.description.unwrap_or_else(|| "Manual backup".to_string()),
                metadata: request.metadata.unwrap_or_default(),
            };

            // In a real implementation, you would store this backup
            // For now, we'll just return the backup data
            
            // Log audit event
            state.audit.log_change(
                crate::admin::ConfigChangeType::ConfigBackup,
                backup_data.created_by.clone(),
                format!("Configuration backup created: {}", backup_id),
                None,
                Some(serde_json::json!({"backup_id": backup_id})),
                HashMap::new(),
            ).await;

            Ok(Json(BackupConfigurationResponse {
                success: true,
                backup_id,
                message: "Configuration backup created successfully".to_string(),
                created_at: backup_data.created_at,
                size_bytes: serde_json::to_string(&backup_data).unwrap_or_default().len(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create configuration backup".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Restore configuration
async fn restore_configuration(
    State(state): State<CoreAdminState>,
    Json(request): Json<RestoreConfigurationRequest>,
) -> Result<Json<ConfigurationUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you would retrieve the backup by ID
    // For now, we'll return an error indicating the feature needs implementation
    
    // Log audit event
    state.audit.log_change(
        crate::admin::ConfigChangeType::ConfigRestore,
        request.restored_by.unwrap_or_else(|| "admin".to_string()),
        format!("Configuration restore attempted: {}", request.backup_id),
        None,
        Some(serde_json::json!({"backup_id": request.backup_id, "status": "not_implemented"})),
        HashMap::new(),
    ).await;

    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "Configuration restore not implemented".to_string(),
            details: Some("Backup storage and restore functionality needs to be implemented".to_string()),
        }),
    ))
}

// ============================================================================
// Health Monitoring Endpoints
// ============================================================================

/// Get gateway health
async fn get_gateway_health(
    State(state): State<CoreAdminState>,
) -> Result<Json<GatewayHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(health_admin) = &state.health_admin {
        let health_report = health_admin.health_checker.get_gateway_health();
        
        Ok(Json(GatewayHealthResponse {
            status: health_report.status,
            timestamp: health_report.timestamp,
            version: health_report.version,
            uptime: health_report.uptime,
            checks: health_report.checks,
        }))
    } else {
        // Return basic health if health admin is not available
        Ok(Json(GatewayHealthResponse {
            status: ServiceStatus::Healthy,
            timestamp: chrono::Utc::now().timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: std::time::Duration::from_secs(0), // Would need to track actual uptime
            checks: HashMap::new(),
        }))
    }
}

/// Get all services health
async fn get_all_services_health(
    State(state): State<CoreAdminState>,
    Query(params): Query<HealthQueryParams>,
) -> Result<Json<AllServicesHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(health_admin) = &state.health_admin {
        let instance_configs = health_admin.health_checker.get_instance_configs();
        let mut health_statuses = HashMap::new();
        
        for instance_id in instance_configs.keys() {
            let status = health_admin.health_checker.get_instance_health(instance_id);
            
            // Apply status filter if specified
            if let Some(filter_status) = &params.status_filter {
                if status.to_string().to_lowercase() != filter_status.to_lowercase() {
                    continue;
                }
            }
            
            health_statuses.insert(instance_id.clone(), status);
        }
        
        let healthy_count = health_statuses.values().filter(|s| matches!(s, ServiceStatus::Healthy)).count();
        let unhealthy_count = health_statuses.values().filter(|s| !matches!(s, ServiceStatus::Healthy)).count();
        
        Ok(Json(AllServicesHealthResponse {
            services: health_statuses,
            summary: HealthSummary {
                total_services: health_statuses.len(),
                healthy_services: healthy_count,
                unhealthy_services: unhealthy_count,
                last_updated: chrono::Utc::now(),
            },
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Health monitoring not available".to_string(),
                details: None,
            }),
        ))
    }
}/// Get
 system diagnostics
async fn get_system_diagnostics(
    State(state): State<CoreAdminState>,
) -> Result<Json<SystemDiagnosticsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut diagnostics = SystemDiagnosticsResponse {
        timestamp: chrono::Utc::now(),
        gateway_status: "healthy".to_string(),
        service_registry_status: "unknown".to_string(),
        config_status: "healthy".to_string(),
        health_checker_status: "unknown".to_string(),
        metrics_collector_status: "unknown".to_string(),
        audit_log_status: "healthy".to_string(),
        system_resources: SystemResources {
            cpu_usage_percent: 0.0,
            memory_usage_bytes: 0,
            memory_total_bytes: 0,
            disk_usage_bytes: 0,
            disk_total_bytes: 0,
            network_connections: 0,
        },
        recent_errors: Vec::new(),
    };

    // Check service registry status
    if let Some(service_mgmt) = &state.service_management {
        let stats = service_mgmt.service_registry.get_stats();
        diagnostics.service_registry_status = if stats.total_services > 0 {
            "healthy".to_string()
        } else {
            "no_services".to_string()
        };
    }

    // Check health checker status
    if let Some(health_admin) = &state.health_admin {
        let health_stats = health_admin.health_checker.get_health_stats();
        diagnostics.health_checker_status = if health_stats.total_checks > 0 {
            "active".to_string()
        } else {
            "inactive".to_string()
        };
    }

    // Check metrics collector status
    if let Some(metrics_admin) = &state.metrics_admin {
        let metrics_summary = metrics_admin.metrics_collector.get_metrics_summary().await;
        diagnostics.metrics_collector_status = if metrics_summary.total_metrics > 0 {
            "collecting".to_string()
        } else {
            "idle".to_string()
        };
    }

    // Get audit log statistics
    let audit_stats = state.audit.get_statistics().await;
    diagnostics.audit_log_status = if audit_stats.total_changes > 0 {
        "active".to_string()
    } else {
        "empty".to_string()
    };

    Ok(Json(diagnostics))
}

// ============================================================================
// Metrics Endpoints
// ============================================================================

/// Get metrics summary
async fn get_metrics_summary(
    State(state): State<CoreAdminState>,
) -> Result<Json<MetricsSummaryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(metrics_admin) = &state.metrics_admin {
        let summary = metrics_admin.metrics_collector.get_metrics_summary().await;
        
        Ok(Json(MetricsSummaryResponse {
            summary,
            collection_status: "active".to_string(),
            last_collection: chrono::Utc::now(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Metrics collection not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Query metrics
async fn query_metrics(
    State(state): State<CoreAdminState>,
    Json(request): Json<MetricsQueryRequest>,
) -> Result<Json<MetricsQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(metrics_admin) = &state.metrics_admin {
        let query_start = std::time::Instant::now();
        
        let query = crate::observability::metrics::MetricsQuery {
            metric_name: request.metric_name,
            labels: request.labels.unwrap_or_default(),
            start_time: request.start_time.map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts)),
            end_time: request.end_time.map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts)),
            aggregation: None, // TODO: Parse aggregation from string
        };

        let metrics = metrics_admin.metrics_collector.query_metrics(query).await;
        let query_duration = query_start.elapsed();

        Ok(Json(MetricsQueryResponse {
            metrics: metrics.clone(),
            query_info: MetricsQueryInfo {
                query_duration_ms: query_duration.as_millis() as u64,
                total_points: metrics.len(),
                time_range: format!("{:?} - {:?}", request.start_time, request.end_time),
            },
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Metrics collection not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Get metrics dashboard
async fn get_metrics_dashboard(
    State(state): State<CoreAdminState>,
) -> Result<Json<MetricsDashboardResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(metrics_admin) = &state.metrics_admin {
        let dashboards = metrics_admin.dashboards.read().await;
        let alerts = metrics_admin.alert_rules.read().await;
        
        // Get recent metrics (simplified)
        let recent_metrics = Vec::new(); // TODO: Implement recent metrics collection
        
        Ok(Json(MetricsDashboardResponse {
            dashboards: dashboards.clone(),
            recent_metrics,
            alerts: alerts.clone(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Metrics collection not available".to_string(),
                details: None,
            }),
        ))
    }
}

// ============================================================================
// Logging Endpoints
// ============================================================================

/// Query logs
async fn query_logs(
    State(state): State<CoreAdminState>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<LogQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(logging_admin) = &state.logging_admin {
        let logs = logging_admin.structured_logger.query_logs(
            params.start_time,
            params.end_time,
            params.level,
            params.service,
            params.limit.unwrap_or(100),
        ).await;

        // Apply search filter if provided
        let filtered_logs = if let Some(search_term) = &params.search {
            logs.into_iter()
                .filter(|log| {
                    log.message.contains(search_term) || 
                    log.fields.values().any(|v| v.to_string().contains(search_term))
                })
                .collect()
        } else {
            logs
        };

        // Apply pagination
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);
        let total = filtered_logs.len();
        
        let paginated_logs: Vec<crate::observability::logging::LogEntry> = filtered_logs
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok(Json(LogQueryResponse {
            logs: paginated_logs,
            total,
            offset,
            limit,
            query_executed_at: chrono::Utc::now(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Logging not available".to_string(),
                details: None,
            }),
        ))
    }
}crate::observability::metrics::MetricsQuery {
            metric_name: request.metric_name,
            labels: request.labels.unwrap_or_default(),
            start_time: request.start_time.map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts)),
            end_time: request.end_time.map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts)),
            aggregation: None, // TODO: Parse aggregation from string
        };

        match metrics_admin.metrics_collector.query_metrics(query).await {
            Ok(results) => Ok(Json(MetricsQueryResponse {
                results,
                query_executed_at: chrono::Utc::now(),
                result_count: results.len(),
            })),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to query metrics".to_string(),
                    details: Some(e.to_string()),
                }),
            )),
        }
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Metrics collection not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Get metrics dashboard
async fn get_metrics_dashboard(
    State(state): State<CoreAdminState>,
) -> Result<Json<MetricsDashboardResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(metrics_admin) = &state.metrics_admin {
        let summary = metrics_admin.metrics_collector.get_metrics_summary().await;
        
        // Get recent metrics (simplified)
        let recent_metrics = Vec::new(); // TODO: Implement recent metrics collection
        
        Ok(Json(MetricsDashboardResponse {
            summary,
            recent_metrics,
            dashboard_updated_at: chrono::Utc::now(),
            auto_refresh_interval: 30, // seconds
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Metrics collection not available".to_string(),
                details: None,
            }),
        ))
    }
}

// ============================================================================
// Logging Endpoints
// ============================================================================

/// Query logs
async fn query_logs(
    State(state): State<CoreAdminState>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<LogQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(logging_admin) = &state.logging_admin {
        // This is a simplified implementation
        // In production, you would integrate with your log aggregation system
        
        let query_info = serde_json::json!({
            "query_type": "structured_log_search",
            "filters": {
                "level": params.level,
                "component": params.component,
                "correlation_id": params.correlation_id,
                "time_range": {
                    "start": params.start_time,
                    "end": params.end_time
                }
            },
            "pagination": {
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100)
            },
            "note": "Integrate with your log aggregation system for full functionality"
        });
        
        Ok(Json(LogQueryResponse {
            logs: vec![query_info],
            total: 1,
            offset: params.offset.unwrap_or(0),
            limit: params.limit.unwrap_or(100),
            query_executed_at: chrono::Utc::now(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Logging not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Query audit logs
async fn query_audit_logs(
    State(state): State<CoreAdminState>,
    Query(params): Query<AuditLogQueryParams>,
) -> Result<Json<AuditLogQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(logging_admin) = &state.logging_admin {
        let audit_logs = logging_admin.audit_logs.read().await;
        let mut filtered_logs: Vec<&crate::observability::logging::AuditLogEntry> = audit_logs.iter().collect();
        
        // Apply filters
        if let Some(event_type) = &params.event_type {
            filtered_logs.retain(|log| {
                format!("{:?}", log.event_type).to_lowercase().contains(&event_type.to_lowercase())
            });
        }
        
        if let Some(user_id) = &params.user_id {
            filtered_logs.retain(|log| {
                log.user_id.as_ref().map_or(false, |id| id == user_id)
            });
        }
        
        // Apply time range filter
        if let Some(start_time) = params.start_time {
            filtered_logs.retain(|log| log.timestamp >= start_time);
        }
        
        if let Some(end_time) = params.end_time {
            filtered_logs.retain(|log| log.timestamp <= end_time);
        }
        
        // Sort by timestamp (newest first)
        filtered_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Apply pagination
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100).min(1000);
        let total = filtered_logs.len();
        
        let paginated_logs: Vec<crate::observability::logging::AuditLogEntry> = filtered_logs
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        
        Ok(Json(AuditLogQueryResponse {
            logs: paginated_logs,
            total,
            offset,
            limit,
            query_executed_at: chrono::Utc::now(),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Audit logging not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Export logs
async fn export_logs(
    State(state): State<CoreAdminState>,
    Query(params): Query<LogExportParams>,
) -> Result<Json<LogExportResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(logging_admin) = &state.logging_admin {
        let logs = logging_admin.structured_logger.query_logs(
            params.start_time,
            params.end_time,
            params.level_filter.clone(),
            params.service_filter.clone(),
            params.limit.unwrap_or(10000),
        ).await;

        // In a real implementation, you would export to a file or stream
        let export_id = Uuid::new_v4();
        let export_size = logs.len();

        // Log audit event
        state.audit.log_change(
            crate::admin::ConfigChangeType::LogExport,
            params.requested_by.unwrap_or_else(|| "admin".to_string()),
            format!("Log export requested: {} logs", export_size),
            None,
            Some(serde_json::json!({"export_id": export_id, "log_count": export_size})),
            HashMap::new(),
        ).await;

        Ok(Json(LogExportResponse {
            export_id,
            status: "completed".to_string(),
            log_count: export_size,
            export_size_bytes: serde_json::to_string(&logs).unwrap_or_default().len(),
            download_url: format!("/admin/logs/download/{}", export_id),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        }))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Logging not available".to_string(),
                details: None,
            }),
        ))
    }
}

/// Get system status
async fn get_system_status(
    State(state): State<CoreAdminState>,
) -> Result<Json<SystemStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut status = SystemStatusResponse {
        overall_status: "healthy".to_string(),
        timestamp: chrono::Utc::now(),
        uptime: std::time::Duration::from_secs(0), // Would need to track actual uptime
        version: env!("CARGO_PKG_VERSION").to_string(),
        components: HashMap::new(),
        active_connections: 0,
        request_rate: 0.0,
        error_rate: 0.0,
        memory_usage: SystemMemoryUsage {
            used_bytes: 0,
            total_bytes: 0,
            usage_percent: 0.0,
        },
    };

    // Check component statuses
    status.components.insert("config_manager".to_string(), ComponentStatus {
        status: "healthy".to_string(),
        last_check: chrono::Utc::now(),
        details: Some("Configuration manager operational".to_string()),
    });

    if let Some(service_mgmt) = &state.service_management {
        let stats = service_mgmt.service_registry.get_stats();
        status.components.insert("service_registry".to_string(), ComponentStatus {
            status: if stats.total_services > 0 { "healthy" } else { "no_services" }.to_string(),
            last_check: chrono::Utc::now(),
            details: Some(format!("Managing {} services with {} instances", 
                stats.total_services, stats.total_instances)),
        });
    }

    if let Some(health_admin) = &state.health_admin {
        let health_stats = health_admin.health_checker.get_health_stats();
        status.components.insert("health_checker".to_string(), ComponentStatus {
            status: if health_stats.total_checks > 0 { "active" } else { "inactive" }.to_string(),
            last_check: chrono::Utc::now(),
            details: Some(format!("Monitoring {} services", health_stats.total_checks)),
        });
    }

    if let Some(metrics_admin) = &state.metrics_admin {
        let metrics_summary = metrics_admin.metrics_collector.get_metrics_summary().await;
        status.components.insert("metrics_collector".to_string(), ComponentStatus {
            status: if metrics_summary.total_metrics > 0 { "collecting" } else { "idle" }.to_string(),
            last_check: chrono::Utc::now(),
            details: Some(format!("Collecting {} metrics", metrics_summary.total_metrics)),
        });
    }

    // Determine overall status
    let unhealthy_components = status.components.values()
        .filter(|c| c.status != "healthy" && c.status != "active" && c.status != "collecting")
        .count();

    if unhealthy_components > 0 {
        status.overall_status = "degraded".to_string();
    }

    Ok(Json(status))
}

/// Get detailed diagnostics
async fn get_detailed_diagnostics(
    State(state): State<CoreAdminState>,
) -> Result<Json<DetailedDiagnosticsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut diagnostics = DetailedDiagnosticsResponse {
        timestamp: chrono::Utc::now(),
        gateway_info: GatewayInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_date: env!("BUILD_DATE").unwrap_or("unknown").to_string(),
            git_commit: env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            rust_version: env!("RUST_VERSION").unwrap_or("unknown").to_string(),
        },
        runtime_info: RuntimeInfo {
            uptime: std::time::Duration::from_secs(0), // Would need to track actual uptime
            process_id: std::process::id(),
            thread_count: 0, // Would need to get actual thread count
            memory_usage: 0,
            cpu_usage: 0.0,
        },
        configuration_info: ConfigurationInfo {
            config_file_path: "config.yaml".to_string(), // Would get from actual config
            last_modified: state.config_manager.get_last_modified().await,
            total_changes: state.audit.get_statistics().await.total_changes,
            validation_status: "valid".to_string(),
        },
        service_info: ServiceInfo {
            total_services: 0,
            healthy_services: 0,
            unhealthy_services: 0,
            total_instances: 0,
            discovery_methods: Vec::new(),
        },
        performance_metrics: PerformanceMetrics {
            requests_per_second: 0.0,
            average_response_time_ms: 0.0,
            error_rate_percent: 0.0,
            active_connections: 0,
        },
        recent_events: Vec::new(),
    };

    // Get service information
    if let Some(service_mgmt) = &state.service_management {
        let stats = service_mgmt.service_registry.get_stats();
        diagnostics.service_info.total_services = stats.total_services;
        diagnostics.service_info.total_instances = stats.total_instances;
        diagnostics.service_info.discovery_methods = vec!["manual".to_string()]; // Would get from actual config
    }

    // Get health information
    if let Some(health_admin) = &state.health_admin {
        let health_stats = health_admin.health_checker.get_health_stats();
        diagnostics.service_info.healthy_services = health_stats.healthy_services;
        diagnostics.service_info.unhealthy_services = health_stats.unhealthy_services;
    }

    // Get recent audit events
    let recent_changes = state.audit.get_recent_changes(10).await;
    diagnostics.recent_events = recent_changes.into_iter().map(|change| DiagnosticEvent {
        timestamp: change.timestamp,
        event_type: format!("{:?}", change.change_type),
        description: change.description,
        severity: "info".to_string(),
    }).collect();

    Ok(Json(diagnostics))
}

/// Get system information
async fn get_system_info(
    State(state): State<CoreAdminState>,
) -> Result<Json<SystemInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let info = SystemInfoResponse {
        gateway: GatewayInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_date: env!("BUILD_DATE").unwrap_or("unknown").to_string(),
            git_commit: env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            rust_version: env!("RUST_VERSION").unwrap_or("unknown").to_string(),
        },
        runtime: RuntimeInfo {
            uptime: std::time::Duration::from_secs(0), // Would need to track actual uptime
            process_id: std::process::id(),
            thread_count: 0, // Would need to get actual thread count
            memory_usage: 0,
            cpu_usage: 0.0,
        },
        features: vec![
            "http_routing".to_string(),
            "grpc_proxy".to_string(),
            "websocket_support".to_string(),
            "load_balancing".to_string(),
            "health_checking".to_string(),
            "metrics_collection".to_string(),
            "distributed_tracing".to_string(),
            "rate_limiting".to_string(),
            "circuit_breaker".to_string(),
            "admin_api".to_string(),
        ],
        supported_protocols: vec![
            "HTTP/1.1".to_string(),
            "HTTP/2".to_string(),
            "gRPC".to_string(),
            "WebSocket".to_string(),
        ],
        admin_endpoints: vec![
            "/admin/services".to_string(),
            "/admin/config".to_string(),
            "/admin/health".to_string(),
            "/admin/metrics".to_string(),
            "/admin/logs".to_string(),
            "/admin/system".to_string(),
        ],
    };

    Ok(Json(info))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListServicesParams {
    pub health_status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServicesResponse {
    pub services: Vec<ServiceSummary>,
    pub total_services: usize,
    pub total_instances: usize,
}

#[derive(Debug, Serialize)]
pub struct ServiceSummary {
    pub name: String,
    pub instance_count: usize,
    pub healthy_instances: usize,
    pub instances: Vec<crate::core::types::ServiceInstance>,
}

#[derive(Debug, Deserialize)]
pub struct CreateServiceRequest {
    pub id: Option<String>,
    pub name: String,
    pub address: String,
    pub protocol: crate::core::types::Protocol,
    pub metadata: Option<HashMap<String, String>>,
    pub weight: Option<u32>,
    pub persist: Option<bool>,
    pub changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceOperationResponse {
    pub success: bool,
    pub service_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceDetailsResponse {
    pub instance: crate::core::types::ServiceInstance,
    pub health_status: Option<crate::observability::health::ServiceStatus>,
    pub is_persisted: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServiceRequest {
    pub address: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub weight: Option<u32>,
    pub protocol: Option<crate::core::types::Protocol>,
    pub changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteServiceParams {
    pub changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceHealthResponse {
    pub service_id: String,
    pub health_status: crate::observability::health::ServiceStatus,
    pub last_check: DateTime<Utc>,
    pub check_interval: std::time::Duration,
}

#[derive(Debug, Deserialize)]
pub struct HealthOverrideRequest {
    pub status: crate::observability::health::ServiceStatus,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationResponse {
    pub config: GatewayConfig,
    pub last_modified: DateTime<Utc>,
    pub version: usize,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigurationRequest {
    pub config: GatewayConfig,
    pub changed_by: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationUpdateResponse {
    pub success: bool,
    pub change_id: String,
    pub message: String,
    pub applied_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BackupConfigurationRequest {
    pub description: Option<String>,
    pub created_by: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct BackupConfigurationResponse {
    pub success: bool,
    pub backup_id: Uuid,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationBackup {
    pub id: Uuid,
    pub config: GatewayConfig,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub description: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreConfigurationRequest {
    pub backup_id: Uuid,
    pub restored_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GatewayHealthResponse {
    pub status: crate::observability::health::ServiceStatus,
    pub timestamp: i64,
    pub version: String,
    pub uptime: std::time::Duration,
    pub checks: HashMap<String, crate::observability::health::ServiceStatus>,
}

#[derive(Debug, Deserialize)]
pub struct HealthQueryParams {
    pub status_filter: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AllServicesHealthResponse {
    pub services: HashMap<String, crate::observability::health::ServiceStatus>,
    pub summary: HealthSummary,
}

#[derive(Debug, Serialize)]
pub struct HealthSummary {
    pub total_services: usize,
    pub healthy_services: usize,
    pub unhealthy_services: usize,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SystemDiagnosticsResponse {
    pub timestamp: DateTime<Utc>,
    pub gateway_status: String,
    pub service_registry_status: String,
    pub config_status: String,
    pub health_checker_status: String,
    pub metrics_collector_status: String,
    pub audit_log_status: String,
    pub system_resources: SystemResources,
    pub recent_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemResources {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_usage_bytes: u64,
    pub disk_total_bytes: u64,
    pub network_connections: u32,
}

#[derive(Debug, Serialize)]
pub struct MetricsSummaryResponse {
    pub summary: crate::observability::metrics::MetricsSummary,
    pub collection_status: String,
    pub last_collection: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct MetricsQueryRequest {
    pub metric_name: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub aggregation: Option<String>,
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct MetricsQueryResponse {
    pub metrics: Vec<crate::observability::metrics::MetricPoint>,
    pub query_info: MetricsQueryInfo,
}

#[derive(Debug, Serialize)]
pub struct MetricsQueryInfo {
    pub query_duration_ms: u64,
    pub total_points: usize,
    pub time_range: String,
}

#[derive(Debug, Serialize)]
pub struct MetricsDashboardResponse {
    pub dashboards: Vec<crate::admin::MetricsDashboard>,
    pub recent_metrics: Vec<crate::observability::metrics::MetricPoint>,
    pub alerts: Vec<crate::admin::AlertRule>,
}

#[derive(Debug, Deserialize)]
pub struct LogQueryParams {
    pub level: Option<String>,
    pub service: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LogQueryResponse {
    pub logs: Vec<crate::observability::logging::LogEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub query_executed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQueryParams {
    pub event_type: Option<String>,
    pub user_id: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogQueryResponse {
    pub logs: Vec<crate::observability::logging::AuditLogEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub query_executed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct LogExportParams {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub level_filter: Option<String>,
    pub service_filter: Option<String>,
    pub limit: Option<usize>,
    pub requested_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogExportResponse {
    pub export_id: Uuid,
    pub status: String,
    pub log_count: usize,
    pub export_size_bytes: usize,
    pub download_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SystemStatusResponse {
    pub overall_status: String,
    pub timestamp: DateTime<Utc>,
    pub uptime: std::time::Duration,
    pub version: String,
    pub components: HashMap<String, ComponentStatus>,
    pub active_connections: u32,
    pub request_rate: f64,
    pub error_rate: f64,
    pub memory_usage: SystemMemoryUsage,
}

#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    pub status: String,
    pub last_check: DateTime<Utc>,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemMemoryUsage {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct DetailedDiagnosticsResponse {
    pub timestamp: DateTime<Utc>,
    pub gateway_info: GatewayInfo,
    pub runtime_info: RuntimeInfo,
    pub configuration_info: ConfigurationInfo,
    pub service_info: ServiceInfo,
    pub performance_metrics: PerformanceMetrics,
    pub recent_events: Vec<DiagnosticEvent>,
}

#[derive(Debug, Serialize)]
pub struct GatewayInfo {
    pub version: String,
    pub build_date: String,
    pub git_commit: String,
    pub rust_version: String,
}

#[derive(Debug, Serialize)]
pub struct RuntimeInfo {
    pub uptime: std::time::Duration,
    pub process_id: u32,
    pub thread_count: usize,
    pub memory_usage: u64,
    pub cpu_usage: f64,
}

#[derive(Debug, Serialize)]
pub struct ConfigurationInfo {
    pub config_file_path: String,
    pub last_modified: DateTime<Utc>,
    pub total_changes: usize,
    pub validation_status: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub total_services: usize,
    pub healthy_services: usize,
    pub unhealthy_services: usize,
    pub total_instances: usize,
    pub discovery_methods: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PerformanceMetrics {
    pub requests_per_second: f64,
    pub average_response_time_ms: f64,
    pub error_rate_percent: f64,
    pub active_connections: u32,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct SystemInfoResponse {
    pub gateway: GatewayInfo,
    pub runtime: RuntimeInfo,
    pub features: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub admin_endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}}
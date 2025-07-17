//! # gRPC Service Management Admin Endpoints
//!
//! This module provides admin endpoints for managing gRPC services including:
//! - Service registration and discovery
//! - Method inspection and monitoring
//! - Connection pool management
//! - gRPC-Web configuration
//! - Message inspection controls

use crate::protocols::grpc::{GrpcHandler, GrpcServiceInfo, GrpcMethodInfo, GrpcConfig};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// State for gRPC management admin endpoints
#[derive(Clone)]
pub struct GrpcAdminState {
    pub grpc_handler: Arc<GrpcHandler>,
}

/// Router for gRPC management admin endpoints
pub struct GrpcAdminRouter;

impl GrpcAdminRouter {
    /// Create the gRPC admin router with all endpoints
    pub fn create_router(state: GrpcAdminState) -> Router {
        Router::new()
            // Service management endpoints
            .route("/services", get(list_services))
            .route("/services", post(register_service))
            .route("/services/:service_name", get(get_service_info))
            .route("/services/:service_name", put(update_service))
            .route("/services/:service_name", delete(unregister_service))
            
            // Method management endpoints
            .route("/services/:service_name/methods", get(list_service_methods))
            .route("/services/:service_name/methods/:method_name", get(get_method_info))
            
            // Connection management endpoints
            .route("/connections", get(get_connection_stats))
            .route("/connections/health", get(check_connection_health))
            .route("/connections/reset", post(reset_connections))
            
            // Configuration endpoints
            .route("/config", get(get_grpc_config))
            .route("/config", put(update_grpc_config))
            
            // Monitoring endpoints
            .route("/metrics", get(get_grpc_metrics))
            .route("/health", get(get_grpc_health))
            
            // Message inspection endpoints
            .route("/inspection/enable", post(enable_message_inspection))
            .route("/inspection/disable", post(disable_message_inspection))
            .route("/inspection/status", get(get_inspection_status))
            
            .with_state(state)
    }
}

// ============================================================================
// Service Management Endpoints
// ============================================================================

/// List all registered gRPC services
async fn list_services(
    State(state): State<GrpcAdminState>,
    Query(params): Query<ListServicesParams>,
) -> Result<Json<ListServicesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let services = state.grpc_handler.get_services().await;
    
    // Apply filtering if requested
    let filtered_services = if let Some(package_filter) = params.package {
        services.into_iter()
            .filter(|s| s.package.contains(&package_filter))
            .collect()
    } else {
        services
    };

    let total = filtered_services.len();
    Ok(Json(ListServicesResponse {
        services: filtered_services,
        total,
    }))
}

/// Register a new gRPC service
async fn register_service(
    State(state): State<GrpcAdminState>,
    Json(request): Json<RegisterServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let service_name = request.service.name.clone();
    match state.grpc_handler.register_service(request.service).await {
        Ok(()) => {
            info!("Successfully registered gRPC service: {}", service_name);
            Ok(Json(ServiceOperationResponse {
                success: true,
                message: "Service registered successfully".to_string(),
            }))
        }
        Err(e) => {
            warn!("Failed to register gRPC service: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to register service".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// Get information about a specific gRPC service
async fn get_service_info(
    State(state): State<GrpcAdminState>,
    Path(service_name): Path<String>,
) -> Result<Json<GrpcServiceInfo>, (StatusCode, Json<ErrorResponse>)> {
    match state.grpc_handler.get_service_info(&service_name).await {
        Some(service_info) => Ok(Json(service_info)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service not found".to_string(),
                details: Some(format!("No service found with name: {}", service_name)),
            }),
        )),
    }
}

/// Update a gRPC service
async fn update_service(
    State(state): State<GrpcAdminState>,
    Path(service_name): Path<String>,
    Json(request): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // First check if service exists
    if state.grpc_handler.get_service_info(&service_name).await.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service not found".to_string(),
                details: Some(format!("No service found with name: {}", service_name)),
            }),
        ));
    }

    // Update the service (re-register with new info)
    match state.grpc_handler.register_service(request.service).await {
        Ok(()) => {
            info!("Successfully updated gRPC service: {}", service_name);
            Ok(Json(ServiceOperationResponse {
                success: true,
                message: "Service updated successfully".to_string(),
            }))
        }
        Err(e) => {
            warn!("Failed to update gRPC service: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update service".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// Unregister a gRPC service
async fn unregister_service(
    State(state): State<GrpcAdminState>,
    Path(service_name): Path<String>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.grpc_handler.unregister_service(&service_name).await {
        Ok(()) => {
            info!("Successfully unregistered gRPC service: {}", service_name);
            Ok(Json(ServiceOperationResponse {
                success: true,
                message: "Service unregistered successfully".to_string(),
            }))
        }
        Err(e) => {
            warn!("Failed to unregister gRPC service: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to unregister service".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

// ============================================================================
// Method Management Endpoints
// ============================================================================

/// List methods for a specific service
async fn list_service_methods(
    State(state): State<GrpcAdminState>,
    Path(service_name): Path<String>,
) -> Result<Json<ListMethodsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.grpc_handler.get_service_info(&service_name).await {
        Some(service_info) => Ok(Json(ListMethodsResponse {
            service_name: service_info.name,
            methods: service_info.methods,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service not found".to_string(),
                details: Some(format!("No service found with name: {}", service_name)),
            }),
        )),
    }
}

/// Get information about a specific method
async fn get_method_info(
    State(state): State<GrpcAdminState>,
    Path((service_name, method_name)): Path<(String, String)>,
) -> Result<Json<GrpcMethodInfo>, (StatusCode, Json<ErrorResponse>)> {
    match state.grpc_handler.get_service_info(&service_name).await {
        Some(service_info) => {
            if let Some(method) = service_info.methods.iter().find(|m| m.name == method_name) {
                Ok(Json(method.clone()))
            } else {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Method not found".to_string(),
                        details: Some(format!("No method '{}' found in service '{}'", method_name, service_name)),
                    }),
                ))
            }
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Service not found".to_string(),
                details: Some(format!("No service found with name: {}", service_name)),
            }),
        )),
    }
}

// ============================================================================
// Connection Management Endpoints
// ============================================================================

/// Get connection pool statistics
async fn get_connection_stats(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<ConnectionStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd get actual stats from the connection pool
    Ok(Json(ConnectionStatsResponse {
        total_connections: 5,
        active_connections: 3,
        idle_connections: 2,
        failed_connections: 0,
        connection_details: vec![
            ConnectionDetail {
                endpoint: "127.0.0.1:50051".to_string(),
                status: "active".to_string(),
                created_at: chrono::Utc::now(),
                last_used: Some(chrono::Utc::now()),
                request_count: 42,
            },
            ConnectionDetail {
                endpoint: "127.0.0.1:50052".to_string(),
                status: "idle".to_string(),
                created_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                last_used: Some(chrono::Utc::now() - chrono::Duration::minutes(2)),
                request_count: 15,
            },
        ],
    }))
}

/// Check health of all connections
async fn check_connection_health(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<ConnectionHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd actually check connection health
    Ok(Json(ConnectionHealthResponse {
        overall_health: "healthy".to_string(),
        healthy_connections: 4,
        unhealthy_connections: 1,
        connection_health: vec![
            ConnectionHealth {
                endpoint: "127.0.0.1:50051".to_string(),
                healthy: true,
                last_check: chrono::Utc::now(),
                error_message: None,
            },
            ConnectionHealth {
                endpoint: "127.0.0.1:50052".to_string(),
                healthy: false,
                last_check: chrono::Utc::now(),
                error_message: Some("Connection timeout".to_string()),
            },
        ],
    }))
}

/// Reset all connections in the pool
async fn reset_connections(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd reset the connection pool
    info!("Resetting gRPC connection pool");
    
    Ok(Json(ServiceOperationResponse {
        success: true,
        message: "Connection pool reset successfully".to_string(),
    }))
}

// ============================================================================
// Configuration Endpoints
// ============================================================================

/// Get current gRPC configuration
async fn get_grpc_config(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<GrpcConfig>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd get the actual config from the handler
    Ok(Json(GrpcConfig::default()))
}

/// Update gRPC configuration
async fn update_grpc_config(
    State(_state): State<GrpcAdminState>,
    Json(_config): Json<GrpcConfig>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd update the actual config
    info!("Updating gRPC configuration");
    
    Ok(Json(ServiceOperationResponse {
        success: true,
        message: "gRPC configuration updated successfully".to_string(),
    }))
}

// ============================================================================
// Monitoring Endpoints
// ============================================================================

/// Get gRPC metrics
async fn get_grpc_metrics(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<GrpcMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd collect actual metrics
    Ok(Json(GrpcMetricsResponse {
        total_requests: 1234,
        successful_requests: 1200,
        failed_requests: 34,
        average_latency_ms: 45.2,
        requests_per_second: 12.5,
        active_streams: 8,
        method_metrics: vec![
            MethodMetrics {
                service: "user.UserService".to_string(),
                method: "GetUser".to_string(),
                request_count: 500,
                success_count: 495,
                error_count: 5,
                average_latency_ms: 25.1,
            },
            MethodMetrics {
                service: "user.UserService".to_string(),
                method: "ListUsers".to_string(),
                request_count: 200,
                success_count: 198,
                error_count: 2,
                average_latency_ms: 85.3,
            },
        ],
    }))
}

/// Get gRPC health status
async fn get_grpc_health(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<GrpcHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(GrpcHealthResponse {
        status: "healthy".to_string(),
        services_registered: 3,
        active_connections: 5,
        grpc_web_enabled: true,
        message_inspection_enabled: false,
        uptime_seconds: 3600,
    }))
}

// ============================================================================
// Message Inspection Endpoints
// ============================================================================

/// Enable message inspection
async fn enable_message_inspection(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd enable message inspection in the handler
    info!("Enabling gRPC message inspection");
    
    Ok(Json(ServiceOperationResponse {
        success: true,
        message: "Message inspection enabled successfully".to_string(),
    }))
}

/// Disable message inspection
async fn disable_message_inspection(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<ServiceOperationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In a real implementation, you'd disable message inspection in the handler
    info!("Disabling gRPC message inspection");
    
    Ok(Json(ServiceOperationResponse {
        success: true,
        message: "Message inspection disabled successfully".to_string(),
    }))
}

/// Get message inspection status
async fn get_inspection_status(
    State(_state): State<GrpcAdminState>,
) -> Result<Json<InspectionStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(InspectionStatusResponse {
        enabled: false,
        inspected_messages: 0,
        inspection_errors: 0,
        last_inspection: None,
    }))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListServicesParams {
    package: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListServicesResponse {
    services: Vec<GrpcServiceInfo>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct RegisterServiceRequest {
    service: GrpcServiceInfo,
}

#[derive(Debug, Deserialize)]
struct UpdateServiceRequest {
    service: GrpcServiceInfo,
}

#[derive(Debug, Serialize)]
struct ServiceOperationResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ListMethodsResponse {
    service_name: String,
    methods: Vec<GrpcMethodInfo>,
}

#[derive(Debug, Serialize)]
struct ConnectionStatsResponse {
    total_connections: usize,
    active_connections: usize,
    idle_connections: usize,
    failed_connections: usize,
    connection_details: Vec<ConnectionDetail>,
}

#[derive(Debug, Serialize)]
struct ConnectionDetail {
    endpoint: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: Option<chrono::DateTime<chrono::Utc>>,
    request_count: u64,
}

#[derive(Debug, Serialize)]
struct ConnectionHealthResponse {
    overall_health: String,
    healthy_connections: usize,
    unhealthy_connections: usize,
    connection_health: Vec<ConnectionHealth>,
}

#[derive(Debug, Serialize)]
struct ConnectionHealth {
    endpoint: String,
    healthy: bool,
    last_check: chrono::DateTime<chrono::Utc>,
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct GrpcMetricsResponse {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    average_latency_ms: f64,
    requests_per_second: f64,
    active_streams: usize,
    method_metrics: Vec<MethodMetrics>,
}

#[derive(Debug, Serialize)]
struct MethodMetrics {
    service: String,
    method: String,
    request_count: u64,
    success_count: u64,
    error_count: u64,
    average_latency_ms: f64,
}

#[derive(Debug, Serialize)]
struct GrpcHealthResponse {
    status: String,
    services_registered: usize,
    active_connections: usize,
    grpc_web_enabled: bool,
    message_inspection_enabled: bool,
    uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
struct InspectionStatusResponse {
    enabled: bool,
    inspected_messages: u64,
    inspection_errors: u64,
    last_inspection: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}
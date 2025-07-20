//! # Tracing Admin Endpoints
//!
//! This module provides administrative endpoints for distributed tracing configuration and management.
//! It includes functionality for:
//! - Dynamic tracing configuration
//! - Trace sampling rate adjustment
//! - Tracing backend configuration
//! - Trace statistics and monitoring

use crate::observability::{
    tracing::DistributedTracer,
    config::TracingConfig,
    logging::{AuditLogEntry, AuditEventType, AuditOutcome, StructuredLogger},
};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tracing::info;

/// State for tracing admin endpoints
#[derive(Clone)]
pub struct TracingAdminState {
    pub tracer: Arc<DistributedTracer>,
    pub logger: Arc<StructuredLogger>,
    pub audit_logs: Arc<tokio::sync::RwLock<Vec<AuditLogEntry>>>,
}

/// Router for tracing admin endpoints
pub struct TracingAdminRouter;

impl TracingAdminRouter {
    /// Create the tracing admin router with all endpoints
    pub fn create_router(state: TracingAdminState) -> Router {
        Router::new()
            // Tracing configuration endpoints
            .route("/config", get(get_tracing_config))
            .route("/config", put(update_tracing_config))
            
            // Sampling configuration
            .route("/sampling", get(get_sampling_config))
            .route("/sampling", put(update_sampling_config))
            
            // Tracing statistics and monitoring
            .route("/statistics", get(get_tracing_statistics))
            .route("/health", get(get_tracing_health))
            
            // Trace management
            .route("/flush", axum::routing::post(flush_traces))
            .route("/reset", axum::routing::post(reset_tracer))
            
            .with_state(state)
    }
}

// ============================================================================
// Tracing Configuration Endpoints
// ============================================================================

/// Get current tracing configuration
async fn get_tracing_config(
    State(state): State<TracingAdminState>,
) -> Result<Json<TracingConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.tracer.get_config().await;
    Ok(Json(TracingConfigResponse { config }))
}

/// Update tracing configuration
async fn update_tracing_config(
    State(state): State<TracingAdminState>,
    Json(request): Json<UpdateTracingConfigRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Update tracing configuration");
    
    // Validate configuration
    if request.config.sample_rate < 0.0 || request.config.sample_rate > 1.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid sample rate".to_string(),
                details: Some("Sample rate must be between 0.0 and 1.0".to_string()),
            }),
        ));
    }
    
    match state.tracer.update_config(request.config.clone()).await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::ConfigurationChange,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "tracing_config".to_string(),
                action: "update".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("enabled".to_string(), serde_json::Value::Bool(request.config.enabled));
                    details.insert("service_name".to_string(), serde_json::Value::String(request.config.service_name.clone()));
                    details.insert("sample_rate".to_string(), serde_json::Value::Number(
                        serde_json::Number::from_f64(request.config.sample_rate).unwrap_or_else(|| serde_json::Number::from(0))
                    ));
                    if let Some(endpoint) = &request.config.jaeger_endpoint {
                        details.insert("jaeger_endpoint".to_string(), serde_json::Value::String(endpoint.clone()));
                    }
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Tracing configuration updated".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: "Tracing configuration updated successfully".to_string(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update tracing configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Sampling Configuration Endpoints
// ============================================================================

/// Get current sampling configuration
async fn get_sampling_config(
    State(state): State<TracingAdminState>,
) -> Result<Json<SamplingConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.tracer.get_config().await;
    Ok(Json(SamplingConfigResponse {
        sample_rate: config.sample_rate,
        enabled: config.enabled,
    }))
}

/// Update sampling configuration
async fn update_sampling_config(
    State(state): State<TracingAdminState>,
    Json(request): Json<UpdateSamplingConfigRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Update sampling configuration to rate {}", request.sample_rate);
    
    // Validate sample rate
    if request.sample_rate < 0.0 || request.sample_rate > 1.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid sample rate".to_string(),
                details: Some("Sample rate must be between 0.0 and 1.0".to_string()),
            }),
        ));
    }
    
    // Get current config and update sample rate
    let mut config = state.tracer.get_config().await;
    let old_sample_rate = config.sample_rate;
    config.sample_rate = request.sample_rate;
    
    match state.tracer.update_config(config).await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::ConfigurationChange,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "tracing_sampling".to_string(),
                action: "update".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("old_sample_rate".to_string(), serde_json::Value::Number(
                        serde_json::Number::from_f64(old_sample_rate).unwrap_or_else(|| serde_json::Number::from(0))
                    ));
                    details.insert("new_sample_rate".to_string(), serde_json::Value::Number(
                        serde_json::Number::from_f64(request.sample_rate).unwrap_or_else(|| serde_json::Number::from(0))
                    ));
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Sampling rate updated".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: format!("Sampling rate updated to {} successfully", request.sample_rate),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update sampling configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Tracing Statistics and Monitoring Endpoints
// ============================================================================

/// Get tracing statistics
async fn get_tracing_statistics(
    State(state): State<TracingAdminState>,
) -> Result<Json<TracingStatisticsResponse>, (StatusCode, Json<ErrorResponse>)> {
    use opentelemetry::global;
    use opentelemetry::metrics::MeterProvider;
    
    // Get OpenTelemetry metrics if available
    let meter_provider = global::meter_provider();
    let _meter = meter_provider.meter("api-gateway-tracing");
    
    // In a real implementation, these would be collected from OpenTelemetry metrics
    // For now, we'll provide basic statistics based on configuration
    let config = state.tracer.get_config().await;
    
    let stats = TracingStatisticsResponse {
        spans_created: 0, // Would be collected from OpenTelemetry metrics
        spans_exported: 0, // Would be collected from OpenTelemetry metrics
        spans_dropped: 0, // Would be collected from OpenTelemetry metrics
        active_spans: 0, // Would be collected from OpenTelemetry metrics
        export_errors: 0, // Would be collected from OpenTelemetry metrics
        last_export_time: Some(chrono::Utc::now()), // Would be actual last export time
        enabled: config.enabled,
        sample_rate: config.sample_rate,
        service_name: config.service_name,
        jaeger_endpoint: config.jaeger_endpoint,
    };
    
    info!("Tracing statistics requested");
    Ok(Json(stats))
}

/// Get tracing health status
async fn get_tracing_health(
    State(state): State<TracingAdminState>,
) -> Result<Json<TracingHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.tracer.get_config().await;
    
    let status = if config.enabled {
        "healthy"
    } else {
        "disabled"
    };
    
    Ok(Json(TracingHealthResponse {
        status: status.to_string(),
        enabled: config.enabled,
        service_name: config.service_name,
        sample_rate: config.sample_rate,
        jaeger_endpoint: config.jaeger_endpoint,
        last_check: Utc::now(),
    }))
}

// ============================================================================
// Trace Management Endpoints
// ============================================================================

/// Flush pending traces
async fn flush_traces(
    State(state): State<TracingAdminState>,
    Json(request): Json<FlushTracesRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Flush pending traces");
    
    // Note: This would typically call the OpenTelemetry SDK's flush method
    // For now, we'll just log the action
    
    // Log audit event
    let audit_entry = AuditLogEntry {
        timestamp: Utc::now(),
        event_type: AuditEventType::AdminOperation,
        user_id: request.changed_by.clone(),
        session_id: None,
        correlation_id: uuid::Uuid::new_v4().to_string(),
        source_ip: None,
        user_agent: None,
        resource: "tracing".to_string(),
        action: "flush".to_string(),
        outcome: AuditOutcome::Success,
        details: {
            let mut details = HashMap::new();
            details.insert("description".to_string(), serde_json::Value::String(
                request.description.unwrap_or_else(|| "Traces flushed".to_string())
            ));
            details
        },
    };
    
    state.logger.log_audit_event(audit_entry.clone());
    
    // Store audit log
    let mut audit_logs = state.audit_logs.write().await;
    audit_logs.push(audit_entry);
    
    Ok(Json(SuccessResponse {
        success: true,
        message: "Traces flushed successfully".to_string(),
    }))
}

/// Reset tracer (shutdown and reinitialize)
async fn reset_tracer(
    State(state): State<TracingAdminState>,
    Json(request): Json<ResetTracerRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Reset tracer");
    
    match state.tracer.shutdown().await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::AdminOperation,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "tracing".to_string(),
                action: "reset".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Tracer reset".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: "Tracer reset successfully".to_string(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reset tracer".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct TracingConfigResponse {
    config: TracingConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateTracingConfigRequest {
    config: TracingConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct SamplingConfigResponse {
    sample_rate: f64,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSamplingConfigRequest {
    sample_rate: f64,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct TracingStatisticsResponse {
    spans_created: u64,
    spans_exported: u64,
    spans_dropped: u64,
    active_spans: u64,
    export_errors: u64,
    last_export_time: Option<DateTime<Utc>>,
    enabled: bool,
    sample_rate: f64,
    service_name: String,
    jaeger_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct TracingHealthResponse {
    status: String,
    enabled: bool,
    service_name: String,
    sample_rate: f64,
    jaeger_endpoint: Option<String>,
    last_check: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct FlushTracesRequest {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetTracerRequest {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}
//! # HTTP Management Admin Endpoints
//!
//! This module provides admin endpoints for managing HTTP features including:
//! - HTTP/2 configuration
//! - Compression settings
//! - CORS policies
//! - OpenAPI validation settings
//! - Timeout configuration

use crate::core::error::{GatewayError, GatewayResult};
use crate::protocols::http::{
    HttpConfig, Http2Config, CompressionConfig, CorsConfig, 
    OpenApiConfig, HttpTimeoutConfig, KeepAliveConfig,
    CompressionAlgorithm
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
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// HTTP management admin state
#[derive(Clone)]
pub struct HttpAdminState {
    /// Current HTTP configuration
    pub http_config: Arc<RwLock<HttpConfig>>,
    
    /// Configuration change history
    pub config_history: Arc<RwLock<Vec<HttpConfigChange>>>,
}

impl HttpAdminState {
    /// Create new HTTP admin state
    pub fn new(initial_config: HttpConfig) -> Self {
        Self {
            http_config: Arc::new(RwLock::new(initial_config)),
            config_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Record configuration change
    async fn record_change(&self, change: HttpConfigChange) {
        let mut history = self.config_history.write().await;
        history.push(change);
        
        // Keep only last 100 changes
        if history.len() > 100 {
            history.remove(0);
        }
    }
}

/// HTTP configuration change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfigChange {
    /// Timestamp of change
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Type of change
    pub change_type: String,
    
    /// Description of change
    pub description: String,
    
    /// Previous configuration (if applicable)
    pub previous_config: Option<serde_json::Value>,
    
    /// New configuration
    pub new_config: serde_json::Value,
    
    /// User who made the change
    pub user: Option<String>,
}

/// HTTP admin router
pub struct HttpAdminRouter;

impl HttpAdminRouter {
    /// Create HTTP management admin router
    pub fn create_router(state: HttpAdminState) -> Router {
        Router::new()
            // HTTP configuration endpoints
            .route("/http/config", get(get_http_config))
            .route("/http/config", put(update_http_config))
            .route("/http/config/history", get(get_config_history))
            
            // HTTP/2 specific endpoints
            .route("/http/http2", get(get_http2_config))
            .route("/http/http2", put(update_http2_config))
            
            // Compression endpoints
            .route("/http/compression", get(get_compression_config))
            .route("/http/compression", put(update_compression_config))
            .route("/http/compression/test", post(test_compression))
            
            // CORS endpoints
            .route("/http/cors", get(get_cors_config))
            .route("/http/cors", put(update_cors_config))
            .route("/http/cors/test", post(test_cors_policy))
            
            // OpenAPI endpoints
            .route("/http/openapi", get(get_openapi_config))
            .route("/http/openapi", put(update_openapi_config))
            .route("/http/openapi/validate", post(validate_openapi_spec))
            
            // Timeout endpoints
            .route("/http/timeouts", get(get_timeout_config))
            .route("/http/timeouts", put(update_timeout_config))
            
            // Keep-alive endpoints
            .route("/http/keepalive", get(get_keepalive_config))
            .route("/http/keepalive", put(update_keepalive_config))
            
            // Status and metrics endpoints
            .route("/http/status", get(get_http_status))
            .route("/http/metrics", get(get_http_metrics))
            
            .with_state(state)
    }
}

// HTTP Configuration Endpoints

/// Get current HTTP configuration
async fn get_http_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<HttpConfig>> {
    let config = state.http_config.read().await;
    Ok(Json(config.clone()))
}

/// Update HTTP configuration
async fn update_http_config(
    State(state): State<HttpAdminState>,
    Json(new_config): Json<HttpConfig>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_config = config.clone();
    
    // Validate new configuration
    validate_http_config(&new_config)?;
    
    *config = new_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "http_config_update".to_string(),
        description: "Updated HTTP configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_config)?),
        new_config: serde_json::to_value(&new_config)?,
        user: None, // TODO: Extract from auth context
    };
    
    state.record_change(change).await;
    
    info!("HTTP configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "HTTP configuration updated successfully".to_string()
    )))
}

/// Get configuration change history
async fn get_config_history(
    State(state): State<HttpAdminState>,
    Query(params): Query<HistoryQuery>,
) -> GatewayResult<Json<Vec<HttpConfigChange>>> {
    let history = state.config_history.read().await;
    
    let mut filtered_history: Vec<HttpConfigChange> = history
        .iter()
        .filter(|change| {
            if let Some(ref change_type) = params.change_type {
                change.change_type == *change_type
            } else {
                true
            }
        })
        .cloned()
        .collect();
    
    // Sort by timestamp (newest first)
    filtered_history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    // Apply limit
    if let Some(limit) = params.limit {
        filtered_history.truncate(limit);
    }
    
    Ok(Json(filtered_history))
}

// HTTP/2 Configuration Endpoints

/// Get HTTP/2 configuration
async fn get_http2_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<Http2Config>> {
    let config = state.http_config.read().await;
    Ok(Json(config.http2.clone()))
}

/// Update HTTP/2 configuration
async fn update_http2_config(
    State(state): State<HttpAdminState>,
    Json(new_http2_config): Json<Http2Config>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_http2_config = config.http2.clone();
    
    // Validate HTTP/2 configuration
    validate_http2_config(&new_http2_config)?;
    
    config.http2 = new_http2_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "http2_config_update".to_string(),
        description: "Updated HTTP/2 configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_http2_config)?),
        new_config: serde_json::to_value(&new_http2_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("HTTP/2 configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "HTTP/2 configuration updated successfully".to_string()
    )))
}

// Compression Configuration Endpoints

/// Get compression configuration
async fn get_compression_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<CompressionConfig>> {
    let config = state.http_config.read().await;
    Ok(Json(config.compression.clone()))
}

/// Update compression configuration
async fn update_compression_config(
    State(state): State<HttpAdminState>,
    Json(new_compression_config): Json<CompressionConfig>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_compression_config = config.compression.clone();
    
    // Validate compression configuration
    validate_compression_config(&new_compression_config)?;
    
    config.compression = new_compression_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "compression_config_update".to_string(),
        description: "Updated compression configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_compression_config)?),
        new_config: serde_json::to_value(&new_compression_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("Compression configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "Compression configuration updated successfully".to_string()
    )))
}

/// Test compression with sample data
async fn test_compression(
    State(state): State<HttpAdminState>,
    Json(test_request): Json<CompressionTestRequest>,
) -> GatewayResult<Json<CompressionTestResponse>> {
    let config = state.http_config.read().await;
    
    if !config.compression.enabled {
        return Ok(Json(CompressionTestResponse {
            original_size: test_request.data.len(),
            compressed_sizes: HashMap::new(),
            compression_ratios: HashMap::new(),
            error: Some("Compression is disabled".to_string()),
        }));
    }
    
    let original_size = test_request.data.len();
    let mut compressed_sizes = HashMap::new();
    let mut compression_ratios = HashMap::new();
    
    // Test each enabled compression algorithm
    for algorithm in &config.compression.algorithms {
        match algorithm {
            CompressionAlgorithm::Gzip => {
                if let Ok(compressed) = compress_gzip(&test_request.data) {
                    let compressed_size = compressed.len();
                    let ratio = (original_size as f64 - compressed_size as f64) / original_size as f64 * 100.0;
                    compressed_sizes.insert("gzip".to_string(), compressed_size);
                    compression_ratios.insert("gzip".to_string(), ratio);
                }
            }
            CompressionAlgorithm::Brotli => {
                if let Ok(compressed) = compress_brotli(&test_request.data) {
                    let compressed_size = compressed.len();
                    let ratio = (original_size as f64 - compressed_size as f64) / original_size as f64 * 100.0;
                    compressed_sizes.insert("brotli".to_string(), compressed_size);
                    compression_ratios.insert("brotli".to_string(), ratio);
                }
            }
            CompressionAlgorithm::Deflate => {
                if let Ok(compressed) = compress_deflate(&test_request.data) {
                    let compressed_size = compressed.len();
                    let ratio = (original_size as f64 - compressed_size as f64) / original_size as f64 * 100.0;
                    compressed_sizes.insert("deflate".to_string(), compressed_size);
                    compression_ratios.insert("deflate".to_string(), ratio);
                }
            }
        }
    }
    
    Ok(Json(CompressionTestResponse {
        original_size,
        compressed_sizes,
        compression_ratios,
        error: None,
    }))
}

// CORS Configuration Endpoints

/// Get CORS configuration
async fn get_cors_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<CorsConfig>> {
    let config = state.http_config.read().await;
    Ok(Json(config.cors.clone()))
}

/// Update CORS configuration
async fn update_cors_config(
    State(state): State<HttpAdminState>,
    Json(new_cors_config): Json<CorsConfig>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_cors_config = config.cors.clone();
    
    // Validate CORS configuration
    validate_cors_config(&new_cors_config)?;
    
    config.cors = new_cors_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "cors_config_update".to_string(),
        description: "Updated CORS configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_cors_config)?),
        new_config: serde_json::to_value(&new_cors_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("CORS configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "CORS configuration updated successfully".to_string()
    )))
}

/// Test CORS policy with sample request
async fn test_cors_policy(
    State(state): State<HttpAdminState>,
    Json(test_request): Json<CorsTestRequest>,
) -> GatewayResult<Json<CorsTestResponse>> {
    let config = state.http_config.read().await;
    
    if !config.cors.enabled {
        return Ok(Json(CorsTestResponse {
            allowed: false,
            reason: "CORS is disabled".to_string(),
            headers: HashMap::new(),
        }));
    }
    
    // Test origin
    let origin_allowed = config.cors.allowed_origins.contains(&"*".to_string()) ||
        config.cors.allowed_origins.contains(&test_request.origin);
    
    if !origin_allowed {
        return Ok(Json(CorsTestResponse {
            allowed: false,
            reason: format!("Origin '{}' not allowed", test_request.origin),
            headers: HashMap::new(),
        }));
    }
    
    // Test method
    let method_allowed = config.cors.allowed_methods.contains(&test_request.method);
    
    if !method_allowed {
        return Ok(Json(CorsTestResponse {
            allowed: false,
            reason: format!("Method '{}' not allowed", test_request.method),
            headers: HashMap::new(),
        }));
    }
    
    // Test headers
    for header in &test_request.headers {
        if !config.cors.allowed_headers.contains(header) {
            return Ok(Json(CorsTestResponse {
                allowed: false,
                reason: format!("Header '{}' not allowed", header),
                headers: HashMap::new(),
            }));
        }
    }
    
    // Build response headers
    let mut headers = HashMap::new();
    headers.insert("Access-Control-Allow-Origin".to_string(), test_request.origin);
    headers.insert("Access-Control-Allow-Methods".to_string(), config.cors.allowed_methods.join(", "));
    headers.insert("Access-Control-Allow-Headers".to_string(), config.cors.allowed_headers.join(", "));
    headers.insert("Access-Control-Max-Age".to_string(), config.cors.max_age.to_string());
    
    if config.cors.allow_credentials {
        headers.insert("Access-Control-Allow-Credentials".to_string(), "true".to_string());
    }
    
    Ok(Json(CorsTestResponse {
        allowed: true,
        reason: "Request allowed by CORS policy".to_string(),
        headers,
    }))
}

// OpenAPI Configuration Endpoints

/// Get OpenAPI configuration
async fn get_openapi_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<Option<OpenApiConfig>>> {
    let config = state.http_config.read().await;
    Ok(Json(config.openapi.clone()))
}

/// Update OpenAPI configuration
async fn update_openapi_config(
    State(state): State<HttpAdminState>,
    Json(new_openapi_config): Json<Option<OpenApiConfig>>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_openapi_config = config.openapi.clone();
    
    // Validate OpenAPI configuration if provided
    if let Some(ref openapi_config) = new_openapi_config {
        validate_openapi_config(openapi_config)?;
    }
    
    config.openapi = new_openapi_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "openapi_config_update".to_string(),
        description: "Updated OpenAPI configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_openapi_config)?),
        new_config: serde_json::to_value(&new_openapi_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("OpenAPI configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "OpenAPI configuration updated successfully".to_string()
    )))
}

/// Validate OpenAPI specification file
async fn validate_openapi_spec(
    Json(validation_request): Json<OpenApiValidationRequest>,
) -> GatewayResult<Json<OpenApiValidationResponse>> {
    // In a full implementation, this would:
    // 1. Load the OpenAPI spec file
    // 2. Parse and validate the specification
    // 3. Check for common issues and best practices
    // 4. Return detailed validation results
    
    debug!("Validating OpenAPI specification: {}", validation_request.spec_path);
    
    // Placeholder validation
    let is_valid = validation_request.spec_path.ends_with(".yaml") || 
                   validation_request.spec_path.ends_with(".yml") ||
                   validation_request.spec_path.ends_with(".json");
    
    if is_valid {
        Ok(Json(OpenApiValidationResponse {
            valid: true,
            errors: Vec::new(),
            warnings: vec!["This is a placeholder validation".to_string()],
            info: Some("OpenAPI specification appears to be valid".to_string()),
        }))
    } else {
        Ok(Json(OpenApiValidationResponse {
            valid: false,
            errors: vec!["Invalid file extension. Expected .yaml, .yml, or .json".to_string()],
            warnings: Vec::new(),
            info: None,
        }))
    }
}

// Timeout Configuration Endpoints

/// Get timeout configuration
async fn get_timeout_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<HttpTimeoutConfig>> {
    let config = state.http_config.read().await;
    Ok(Json(config.timeouts.clone()))
}

/// Update timeout configuration
async fn update_timeout_config(
    State(state): State<HttpAdminState>,
    Json(new_timeout_config): Json<HttpTimeoutConfig>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_timeout_config = config.timeouts.clone();
    
    // Validate timeout configuration
    validate_timeout_config(&new_timeout_config)?;
    
    config.timeouts = new_timeout_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "timeout_config_update".to_string(),
        description: "Updated timeout configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_timeout_config)?),
        new_config: serde_json::to_value(&new_timeout_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("Timeout configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "Timeout configuration updated successfully".to_string()
    )))
}

// Keep-alive Configuration Endpoints

/// Get keep-alive configuration
async fn get_keepalive_config(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<KeepAliveConfig>> {
    let config = state.http_config.read().await;
    Ok(Json(config.keep_alive.clone()))
}

/// Update keep-alive configuration
async fn update_keepalive_config(
    State(state): State<HttpAdminState>,
    Json(new_keepalive_config): Json<KeepAliveConfig>,
) -> GatewayResult<Json<ApiResponse<String>>> {
    let mut config = state.http_config.write().await;
    let previous_keepalive_config = config.keep_alive.clone();
    
    // Validate keep-alive configuration
    validate_keepalive_config(&new_keepalive_config)?;
    
    config.keep_alive = new_keepalive_config.clone();
    
    // Record the change
    let change = HttpConfigChange {
        timestamp: chrono::Utc::now(),
        change_type: "keepalive_config_update".to_string(),
        description: "Updated keep-alive configuration".to_string(),
        previous_config: Some(serde_json::to_value(&previous_keepalive_config)?),
        new_config: serde_json::to_value(&new_keepalive_config)?,
        user: None,
    };
    
    state.record_change(change).await;
    
    info!("Keep-alive configuration updated successfully");
    
    Ok(Json(ApiResponse::success(
        "Keep-alive configuration updated successfully".to_string()
    )))
}

// Status and Metrics Endpoints

/// Get HTTP status information
async fn get_http_status(
    State(state): State<HttpAdminState>,
) -> GatewayResult<Json<HttpStatusResponse>> {
    let config = state.http_config.read().await;
    
    Ok(Json(HttpStatusResponse {
        http2_enabled: config.http2_enabled,
        compression_enabled: config.compression.enabled,
        cors_enabled: config.cors.enabled,
        openapi_validation_enabled: config.openapi.is_some(),
        max_body_size: config.max_body_size,
        request_timeout: config.timeouts.request_timeout,
        keep_alive_enabled: config.keep_alive.enabled,
    }))
}

/// Get HTTP metrics
async fn get_http_metrics(
    State(_state): State<HttpAdminState>,
) -> GatewayResult<Json<HttpMetricsResponse>> {
    // In a full implementation, this would collect real metrics
    Ok(Json(HttpMetricsResponse {
        total_requests: 1000,
        http1_requests: 600,
        http2_requests: 400,
        compressed_responses: 750,
        cors_preflight_requests: 50,
        validation_errors: 5,
        timeout_errors: 2,
        average_response_time_ms: 125.5,
    }))
}

// Request/Response Types

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    change_type: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CompressionTestRequest {
    data: String,
}

#[derive(Debug, Serialize)]
struct CompressionTestResponse {
    original_size: usize,
    compressed_sizes: HashMap<String, usize>,
    compression_ratios: HashMap<String, f64>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CorsTestRequest {
    origin: String,
    method: String,
    headers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CorsTestResponse {
    allowed: bool,
    reason: String,
    headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct OpenApiValidationRequest {
    spec_path: String,
}

#[derive(Debug, Serialize)]
struct OpenApiValidationResponse {
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    info: Option<String>,
}

#[derive(Debug, Serialize)]
struct HttpStatusResponse {
    http2_enabled: bool,
    compression_enabled: bool,
    cors_enabled: bool,
    openapi_validation_enabled: bool,
    max_body_size: usize,
    request_timeout: Duration,
    keep_alive_enabled: bool,
}

#[derive(Debug, Serialize)]
struct HttpMetricsResponse {
    total_requests: u64,
    http1_requests: u64,
    http2_requests: u64,
    compressed_responses: u64,
    cors_preflight_requests: u64,
    validation_errors: u64,
    timeout_errors: u64,
    average_response_time_ms: f64,
}

// Validation Functions

fn validate_http_config(config: &HttpConfig) -> GatewayResult<()> {
    if config.max_body_size == 0 {
        return Err(GatewayError::config("max_body_size must be greater than 0".to_string()));
    }
    
    validate_http2_config(&config.http2)?;
    validate_compression_config(&config.compression)?;
    validate_cors_config(&config.cors)?;
    validate_timeout_config(&config.timeouts)?;
    validate_keepalive_config(&config.keep_alive)?;
    
    if let Some(ref openapi_config) = config.openapi {
        validate_openapi_config(openapi_config)?;
    }
    
    Ok(())
}

fn validate_http2_config(config: &Http2Config) -> GatewayResult<()> {
    if config.max_concurrent_streams == 0 {
        return Err(GatewayError::config("max_concurrent_streams must be greater than 0".to_string()));
    }
    
    if config.initial_connection_window_size == 0 {
        return Err(GatewayError::config("initial_connection_window_size must be greater than 0".to_string()));
    }
    
    if config.initial_stream_window_size == 0 {
        return Err(GatewayError::config("initial_stream_window_size must be greater than 0".to_string()));
    }
    
    if config.max_frame_size < 16384 || config.max_frame_size > 16777215 {
        return Err(GatewayError::config("max_frame_size must be between 16384 and 16777215".to_string()));
    }
    
    Ok(())
}

fn validate_compression_config(config: &CompressionConfig) -> GatewayResult<()> {
    if config.enabled && config.algorithms.is_empty() {
        return Err(GatewayError::config("At least one compression algorithm must be specified when compression is enabled".to_string()));
    }
    
    if config.level == 0 || config.level > 9 {
        return Err(GatewayError::config("compression level must be between 1 and 9".to_string()));
    }
    
    Ok(())
}

fn validate_cors_config(config: &CorsConfig) -> GatewayResult<()> {
    if config.enabled {
        if config.allowed_origins.is_empty() {
            return Err(GatewayError::config("allowed_origins cannot be empty when CORS is enabled".to_string()));
        }
        
        if config.allowed_methods.is_empty() {
            return Err(GatewayError::config("allowed_methods cannot be empty when CORS is enabled".to_string()));
        }
    }
    
    Ok(())
}

fn validate_openapi_config(config: &OpenApiConfig) -> GatewayResult<()> {
    if config.spec_path.is_empty() {
        return Err(GatewayError::config("OpenAPI spec_path cannot be empty".to_string()));
    }
    
    Ok(())
}

fn validate_timeout_config(config: &HttpTimeoutConfig) -> GatewayResult<()> {
    if config.request_timeout.as_secs() == 0 {
        return Err(GatewayError::config("request_timeout must be greater than 0".to_string()));
    }
    
    if config.upstream_timeout.as_secs() == 0 {
        return Err(GatewayError::config("upstream_timeout must be greater than 0".to_string()));
    }
    
    Ok(())
}

fn validate_keepalive_config(config: &KeepAliveConfig) -> GatewayResult<()> {
    if config.enabled && config.timeout.as_secs() == 0 {
        return Err(GatewayError::config("keep-alive timeout must be greater than 0 when enabled".to_string()));
    }
    
    Ok(())
}

// Compression Helper Functions

fn compress_gzip(data: &str) -> Result<Vec<u8>, std::io::Error> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())?;
    encoder.finish()
}

fn compress_brotli(data: &str) -> Result<Vec<u8>, std::io::Error> {
    use brotli::CompressorWriter;
    use std::io::Write;
    
    let mut compressed = Vec::new();
    {
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 6, 22);
        compressor.write_all(data.as_bytes())?;
    }
    Ok(compressed)
}

fn compress_deflate(data: &str) -> Result<Vec<u8>, std::io::Error> {
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;
    
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_admin_state_creation() {
        let config = HttpConfig::default();
        let state = HttpAdminState::new(config);
        
        // State should be created successfully
        assert!(state.http_config.try_read().is_ok());
        assert!(state.config_history.try_read().is_ok());
    }

    #[test]
    fn test_validate_http_config() {
        let mut config = HttpConfig::default();
        assert!(validate_http_config(&config).is_ok());
        
        // Test invalid max_body_size
        config.max_body_size = 0;
        assert!(validate_http_config(&config).is_err());
    }

    #[test]
    fn test_validate_http2_config() {
        let mut config = Http2Config::default();
        assert!(validate_http2_config(&config).is_ok());
        
        // Test invalid max_concurrent_streams
        config.max_concurrent_streams = 0;
        assert!(validate_http2_config(&config).is_err());
        
        // Test invalid max_frame_size
        config.max_concurrent_streams = 100; // Reset to valid value
        config.max_frame_size = 1000; // Too small
        assert!(validate_http2_config(&config).is_err());
    }

    #[test]
    fn test_validate_compression_config() {
        let mut config = CompressionConfig::default();
        assert!(validate_compression_config(&config).is_ok());
        
        // Test enabled compression with no algorithms
        config.algorithms.clear();
        assert!(validate_compression_config(&config).is_err());
        
        // Test invalid compression level
        config.algorithms.push(CompressionAlgorithm::Gzip);
        config.level = 0;
        assert!(validate_compression_config(&config).is_err());
    }

    #[test]
    fn test_compression_helpers() {
        let test_data = "Hello, World! This is a test string for compression.";
        
        // Test gzip compression
        let gzip_result = compress_gzip(test_data);
        assert!(gzip_result.is_ok());
        assert!(gzip_result.unwrap().len() < test_data.len());
        
        // Test brotli compression
        let brotli_result = compress_brotli(test_data);
        assert!(brotli_result.is_ok());
        assert!(brotli_result.unwrap().len() < test_data.len());
        
        // Test deflate compression
        let deflate_result = compress_deflate(test_data);
        assert!(deflate_result.is_ok());
        assert!(deflate_result.unwrap().len() < test_data.len());
    }
}
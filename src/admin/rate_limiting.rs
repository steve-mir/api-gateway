//! # Rate Limiting Admin Module
//!
//! This module provides administrative endpoints for rate limiting configuration
//! and quota management. It allows administrators to:
//! - View current rate limiting configuration
//! - Update rate limiting rules and quotas
//! - Monitor rate limiting metrics and statistics
//! - Reset rate limits for specific keys
//! - Manage exemptions and custom rules
//!
//! ## Security Considerations
//! These endpoints can significantly impact system performance and availability.
//! They should be protected with appropriate authentication and authorization.
//!
//! ## Usage Example
//! ```rust
//! use crate::admin::rate_limiting::{RateLimitAdminRouter, RateLimitAdminState};
//! use crate::middleware::rate_limiting::RateLimitMiddleware;
//! use std::sync::Arc;
//!
//! let rate_limiter = Arc::new(RateLimitMiddleware::new(config).await?);
//! let admin_state = RateLimitAdminState { rate_limiter };
//! let admin_router = RateLimitAdminRouter::create_router(admin_state);
//! ```

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::middleware::rate_limiting::{
    EndpointRateLimit, RateLimitConfig, RateLimitGranularity,
    RateLimitMiddleware, RateLimitAlgorithmType,
};

/// State for rate limiting admin endpoints
#[derive(Clone)]
pub struct RateLimitAdminState {
    pub rate_limiter: Arc<RateLimitMiddleware>,
}

/// Request to update rate limiting configuration
#[derive(Debug, Deserialize)]
pub struct UpdateRateLimitConfigRequest {
    pub algorithm: Option<RateLimitAlgorithmType>,
    pub requests_per_window: Option<u32>,
    #[serde(with = "humantime_serde")]
    pub window_duration: Option<Duration>,
    pub burst_size: Option<u32>,
    pub granularity: Option<RateLimitGranularity>,
    pub distributed: Option<bool>,
    pub redis_url: Option<String>,
    pub key_prefix: Option<String>,
    pub admin_exemptions: Option<Vec<String>>,
}

/// Request to add or update endpoint-specific rate limit
#[derive(Debug, Deserialize)]
pub struct EndpointRateLimitRequest {
    pub requests_per_window: u32,
    #[serde(with = "humantime_serde")]
    pub window_duration: Duration,
    pub burst_size: Option<u32>,
    pub granularity: RateLimitGranularity,
}

/// Request to reset rate limit for a specific key
#[derive(Debug, Deserialize)]
pub struct ResetRateLimitRequest {
    pub key: String,
}

/// Query parameters for rate limit metrics
#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub detailed: Option<bool>,
}

/// Response containing current rate limiting configuration
#[derive(Debug, Serialize)]
pub struct RateLimitConfigResponse {
    pub algorithm: RateLimitAlgorithmType,
    pub requests_per_window: u32,
    pub window_duration_secs: u64,
    pub burst_size: Option<u32>,
    pub granularity: RateLimitGranularity,
    pub distributed: bool,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    pub admin_exemptions: Vec<String>,
    pub endpoint_rules: HashMap<String, EndpointRateLimit>,
}

/// Response containing rate limiting metrics
#[derive(Debug, Serialize)]
pub struct RateLimitMetricsResponse {
    pub requests_allowed: u64,
    pub requests_denied: u64,
    pub total_requests: u64,
    pub denial_rate: f64,
}

/// Response for successful operations
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub message: String,
}

/// Error response for admin operations
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

/// Router for rate limiting admin endpoints
pub struct RateLimitAdminRouter;

impl RateLimitAdminRouter {
    /// Create the admin router with all rate limiting endpoints
    pub fn create_router(state: RateLimitAdminState) -> Router {
        Router::new()
            .route("/config", get(get_rate_limit_config))
            .route("/config", put(update_rate_limit_config))
            .route("/metrics", get(get_rate_limit_metrics))
            .route("/endpoints/:endpoint", put(set_endpoint_rate_limit))
            .route("/endpoints/:endpoint", delete(remove_endpoint_rate_limit))
            .route("/reset", post(reset_rate_limit))
            .route("/exemptions", get(get_admin_exemptions))
            .route("/exemptions", post(add_admin_exemption))
            .route("/exemptions/:pattern", delete(remove_admin_exemption))
            .with_state(state)
    }
}

/// Get current rate limiting configuration
async fn get_rate_limit_config(
    State(state): State<RateLimitAdminState>,
) -> Result<Json<RateLimitConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Get rate limiting configuration");

    let config = state.rate_limiter.get_config().await;

    let response = RateLimitConfigResponse {
        algorithm: config.algorithm.clone(),
        requests_per_window: config.requests_per_window,
        window_duration_secs: config.window_duration.as_secs(),
        burst_size: config.burst_size,
        granularity: config.granularity.clone(),
        distributed: config.distributed,
        redis_url: config.redis_url.clone(),
        key_prefix: config.key_prefix.clone(),
        admin_exemptions: config.admin_exemptions.clone(),
        endpoint_rules: config.endpoint_rules.clone(),
    };

    Ok(Json(response))
}

/// Update rate limiting configuration
async fn update_rate_limit_config(
    State(state): State<RateLimitAdminState>,
    Json(request): Json<UpdateRateLimitConfigRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Update rate limiting configuration");

    // Get current configuration
    let current_config = state.rate_limiter.get_config().await;

    // Create new configuration with updates
    let new_config = RateLimitConfig {
        algorithm: request.algorithm.unwrap_or(current_config.algorithm),
        requests_per_window: request.requests_per_window.unwrap_or(current_config.requests_per_window),
        window_duration: request.window_duration.unwrap_or(current_config.window_duration),
        burst_size: request.burst_size.or(current_config.burst_size),
        granularity: request.granularity.unwrap_or(current_config.granularity),
        distributed: request.distributed.unwrap_or(current_config.distributed),
        redis_url: request.redis_url.or(current_config.redis_url),
        key_prefix: request.key_prefix.unwrap_or(current_config.key_prefix),
        admin_exemptions: request.admin_exemptions.unwrap_or(current_config.admin_exemptions),
        endpoint_rules: current_config.endpoint_rules,
    };

    // Update configuration
    match state.rate_limiter.update_config(new_config).await {
        Ok(()) => {
            info!("Rate limiting configuration updated successfully");
            Ok(Json(SuccessResponse {
                message: "Rate limiting configuration updated successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to update rate limiting configuration: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to update configuration".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// Get rate limiting metrics
async fn get_rate_limit_metrics(
    State(state): State<RateLimitAdminState>,
    Query(_query): Query<MetricsQuery>,
) -> Result<Json<RateLimitMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Get rate limiting metrics");

    let metrics = state.rate_limiter.get_metrics().await;
    let total_requests = metrics.requests_allowed + metrics.requests_denied;
    let denial_rate = if total_requests > 0 {
        (metrics.requests_denied as f64) / (total_requests as f64) * 100.0
    } else {
        0.0
    };

    let response = RateLimitMetricsResponse {
        requests_allowed: metrics.requests_allowed,
        requests_denied: metrics.requests_denied,
        total_requests,
        denial_rate,
    };

    Ok(Json(response))
}

/// Set endpoint-specific rate limit
async fn set_endpoint_rate_limit(
    State(state): State<RateLimitAdminState>,
    Path(endpoint): Path<String>,
    Json(request): Json<EndpointRateLimitRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Set rate limit for endpoint: {}", endpoint);

    // Get current configuration
    let mut current_config = state.rate_limiter.get_config().await;

    // Add or update endpoint rule
    let endpoint_rule = EndpointRateLimit {
        requests_per_window: request.requests_per_window,
        window_duration: request.window_duration,
        burst_size: request.burst_size,
        granularity: request.granularity,
    };

    current_config.endpoint_rules.insert(endpoint.clone(), endpoint_rule);

    // Update configuration
    match state.rate_limiter.update_config(current_config).await {
        Ok(()) => {
            info!("Endpoint rate limit set successfully for: {}", endpoint);
            Ok(Json(SuccessResponse {
                message: format!("Rate limit set for endpoint: {}", endpoint),
            }))
        }
        Err(e) => {
            error!("Failed to set endpoint rate limit for {}: {}", endpoint, e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to set endpoint rate limit".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// Remove endpoint-specific rate limit
async fn remove_endpoint_rate_limit(
    State(state): State<RateLimitAdminState>,
    Path(endpoint): Path<String>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Remove rate limit for endpoint: {}", endpoint);

    // Get current configuration
    let mut current_config = state.rate_limiter.get_config().await;

    // Remove endpoint rule
    if current_config.endpoint_rules.remove(&endpoint).is_some() {
        // Update configuration
        match state.rate_limiter.update_config(current_config).await {
            Ok(()) => {
                info!("Endpoint rate limit removed successfully for: {}", endpoint);
                Ok(Json(SuccessResponse {
                    message: format!("Rate limit removed for endpoint: {}", endpoint),
                }))
            }
            Err(e) => {
                error!("Failed to remove endpoint rate limit for {}: {}", endpoint, e);
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Failed to remove endpoint rate limit".to_string(),
                        details: Some(e.to_string()),
                    }),
                ))
            }
        }
    } else {
        warn!("Attempted to remove non-existent endpoint rate limit: {}", endpoint);
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Endpoint rate limit not found".to_string(),
                details: Some(format!("No rate limit configured for endpoint: {}", endpoint)),
            }),
        ))
    }
}

/// Reset rate limit for a specific key
async fn reset_rate_limit(
    State(state): State<RateLimitAdminState>,
    Json(request): Json<ResetRateLimitRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Reset rate limit for key: {}", request.key);

    match state.rate_limiter.reset_limit(&request.key).await {
        Ok(()) => {
            info!("Rate limit reset successfully for key: {}", request.key);
            Ok(Json(SuccessResponse {
                message: format!("Rate limit reset for key: {}", request.key),
            }))
        }
        Err(e) => {
            error!("Failed to reset rate limit for key {}: {}", request.key, e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to reset rate limit".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

/// Get admin exemption patterns
async fn get_admin_exemptions(
    State(state): State<RateLimitAdminState>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Get admin exemption patterns");

    let config = state.rate_limiter.get_config().await;
    
    Ok(Json(config.admin_exemptions.clone()))
}

/// Add admin exemption pattern
#[derive(Debug, Deserialize)]
pub struct AddExemptionRequest {
    pub pattern: String,
}

async fn add_admin_exemption(
    State(state): State<RateLimitAdminState>,
    Json(request): Json<AddExemptionRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Add exemption pattern: {}", request.pattern);

    // Get current configuration
    let mut current_config = state.rate_limiter.get_config().await;

    // Add exemption pattern if not already present
    if !current_config.admin_exemptions.contains(&request.pattern) {
        current_config.admin_exemptions.push(request.pattern.clone());

        // Update configuration
        match state.rate_limiter.update_config(current_config).await {
            Ok(()) => {
                info!("Admin exemption pattern added successfully: {}", request.pattern);
                Ok(Json(SuccessResponse {
                    message: format!("Exemption pattern added: {}", request.pattern),
                }))
            }
            Err(e) => {
                error!("Failed to add exemption pattern {}: {}", request.pattern, e);
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Failed to add exemption pattern".to_string(),
                        details: Some(e.to_string()),
                    }),
                ))
            }
        }
    } else {
        warn!("Exemption pattern already exists: {}", request.pattern);
        Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Exemption pattern already exists".to_string(),
                details: Some(format!("Pattern already configured: {}", request.pattern)),
            }),
        ))
    }
}

/// Remove admin exemption pattern
async fn remove_admin_exemption(
    State(state): State<RateLimitAdminState>,
    Path(pattern): Path<String>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Remove exemption pattern: {}", pattern);

    // Get current configuration
    let mut current_config = state.rate_limiter.get_config().await;

    // Remove exemption pattern
    if let Some(pos) = current_config.admin_exemptions.iter().position(|x| x == &pattern) {
        current_config.admin_exemptions.remove(pos);

        // Update configuration
        match state.rate_limiter.update_config(current_config).await {
            Ok(()) => {
                info!("Admin exemption pattern removed successfully: {}", pattern);
                Ok(Json(SuccessResponse {
                    message: format!("Exemption pattern removed: {}", pattern),
                }))
            }
            Err(e) => {
                error!("Failed to remove exemption pattern {}: {}", pattern, e);
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Failed to remove exemption pattern".to_string(),
                        details: Some(e.to_string()),
                    }),
                ))
            }
        }
    } else {
        warn!("Attempted to remove non-existent exemption pattern: {}", pattern);
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Exemption pattern not found".to_string(),
                details: Some(format!("Pattern not configured: {}", pattern)),
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::rate_limiting::RateLimitConfig;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::time::Duration;

    async fn create_test_server() -> TestServer {
        let config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimitMiddleware::new(config).await.unwrap());
        let state = RateLimitAdminState { rate_limiter };
        let app = RateLimitAdminRouter::create_router(state);
        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn test_get_rate_limit_config() {
        let server = create_test_server().await;
        let response = server.get("/config").await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let config: RateLimitConfigResponse = response.json();
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.window_duration_secs, 60);
    }

    #[tokio::test]
    async fn test_update_rate_limit_config() {
        let server = create_test_server().await;
        
        let update_request = UpdateRateLimitConfigRequest {
            requests_per_window: Some(200),
            window_duration: Some(Duration::from_secs(120)),
            algorithm: None,
            burst_size: None,
            granularity: None,
            distributed: None,
            redis_url: None,
            key_prefix: None,
            admin_exemptions: None,
        };
        
        let response = server.put("/config").json(&update_request).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        // Verify the configuration was updated
        let get_response = server.get("/config").await;
        let config: RateLimitConfigResponse = get_response.json();
        assert_eq!(config.requests_per_window, 200);
        assert_eq!(config.window_duration_secs, 120);
    }

    #[tokio::test]
    async fn test_get_rate_limit_metrics() {
        let server = create_test_server().await;
        let response = server.get("/metrics").await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let metrics: RateLimitMetricsResponse = response.json();
        assert_eq!(metrics.requests_allowed, 0);
        assert_eq!(metrics.requests_denied, 0);
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.denial_rate, 0.0);
    }

    #[tokio::test]
    async fn test_set_endpoint_rate_limit() {
        let server = create_test_server().await;
        
        let endpoint_request = EndpointRateLimitRequest {
            requests_per_window: 50,
            window_duration: Duration::from_secs(30),
            burst_size: Some(10),
            granularity: RateLimitGranularity::PerUser,
        };
        
        let response = server
            .put("/endpoints/api/users")
            .json(&endpoint_request)
            .await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        
        // Verify the endpoint rule was added
        let get_response = server.get("/config").await;
        let config: RateLimitConfigResponse = get_response.json();
        assert!(config.endpoint_rules.contains_key("api/users"));
    }

    #[tokio::test]
    async fn test_remove_endpoint_rate_limit() {
        let server = create_test_server().await;
        
        // First add an endpoint rule
        let endpoint_request = EndpointRateLimitRequest {
            requests_per_window: 50,
            window_duration: Duration::from_secs(30),
            burst_size: Some(10),
            granularity: RateLimitGranularity::PerUser,
        };
        
        server
            .put("/endpoints/api/users")
            .json(&endpoint_request)
            .await;
        
        // Then remove it
        let response = server.delete("/endpoints/api/users").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        // Verify the endpoint rule was removed
        let get_response = server.get("/config").await;
        let config: RateLimitConfigResponse = get_response.json();
        assert!(!config.endpoint_rules.contains_key("api/users"));
    }

    #[tokio::test]
    async fn test_add_admin_exemption() {
        let server = create_test_server().await;
        
        let exemption_request = AddExemptionRequest {
            pattern: "/health/*".to_string(),
        };
        
        let response = server.post("/exemptions").json(&exemption_request).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        // Verify the exemption was added
        let get_response = server.get("/exemptions").await;
        let exemptions: Vec<String> = get_response.json();
        assert!(exemptions.contains(&"/health/*".to_string()));
    }

    #[tokio::test]
    async fn test_remove_admin_exemption() {
        let server = create_test_server().await;
        
        // First add an exemption
        let exemption_request = AddExemptionRequest {
            pattern: "/health/*".to_string(),
        };
        
        server.post("/exemptions").json(&exemption_request).await;
        
        // Then remove it
        let response = server.delete("/exemptions/health/*").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        // Verify the exemption was removed
        let get_response = server.get("/exemptions").await;
        let exemptions: Vec<String> = get_response.json();
        assert!(!exemptions.contains(&"/health/*".to_string()));
    }
}
//! # Cache Admin Interface
//!
//! This module provides admin endpoints for cache management and monitoring.

use super::{CacheManager, InvalidationManager, CacheStats, InvalidationEvent};
use crate::core::error::GatewayError;
use axum::{
    extract::{Path, Query, State},
    // http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Cache admin state
#[derive(Clone)]
pub struct CacheAdminState {
    /// Cache manager
    pub cache_manager: Arc<CacheManager>,
    
    /// Invalidation manager
    pub invalidation_manager: Arc<InvalidationManager>,
}

/// Cache admin router
pub struct CacheAdminRouter;

impl CacheAdminRouter {
    /// Create cache admin router
    pub fn create_router(state: CacheAdminState) -> Router {
        Router::new()
            .route("/cache/stats", get(get_cache_stats))
            .route("/cache/health", get(get_cache_health))
            .route("/cache/config", get(get_cache_config))
            .route("/cache/clear", post(clear_cache))
            .route("/cache/keys/:key", get(get_cache_key))
            .route("/cache/keys/:key", delete(delete_cache_key))
            .route("/cache/keys", post(set_cache_key))
            .route("/cache/invalidate", post(invalidate_cache))
            .route("/cache/invalidate/pattern", post(invalidate_cache_pattern))
            .route("/cache/invalidate/prefix", post(invalidate_cache_prefix))
            .route("/cache/invalidate/user/:user_id", post(invalidate_user_cache))
            .route("/cache/invalidate/service/:service", post(invalidate_service_cache))
            .route("/cache/invalidate/tags", post(invalidate_cache_by_tags))
            .with_state(state)
    }
}

/// Cache statistics response
#[derive(Debug, Serialize)]
pub struct CacheStatsResponse {
    pub stats: CacheStats,
    pub health: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Cache health response
#[derive(Debug, Serialize)]
pub struct CacheHealthResponse {
    pub healthy: bool,
    pub details: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Cache configuration response
#[derive(Debug, Serialize)]
pub struct CacheConfigResponse {
    pub config: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Cache key request
#[derive(Debug, Deserialize)]
pub struct CacheKeyRequest {
    pub key: String,
    pub value: String,
    pub ttl_seconds: Option<u64>,
}

/// Cache key response
#[derive(Debug, Serialize)]
pub struct CacheKeyResponse {
    pub key: String,
    pub value: Option<String>,
    pub exists: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Cache invalidation request
#[derive(Debug, Deserialize)]
pub struct CacheInvalidationRequest {
    pub keys: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub prefix: Option<String>,
    pub user_id: Option<String>,
    pub service: Option<String>,
    pub tags: Option<Vec<String>>,
    pub all: Option<bool>,
}

/// Cache invalidation response
#[derive(Debug, Serialize)]
pub struct CacheInvalidationResponse {
    pub success: bool,
    pub message: String,
    pub invalidated_count: Option<usize>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for cache operations
#[derive(Debug, Deserialize)]
pub struct CacheQueryParams {
    pub format: Option<String>,
    pub include_metadata: Option<bool>,
}

/// Get cache statistics
pub async fn get_cache_stats(
    State(state): State<CacheAdminState>,
    Query(_params): Query<CacheQueryParams>,
) -> Result<Json<CacheStatsResponse>, GatewayError> {
    let stats = state.cache_manager.stats().await;
    let health = state.cache_manager.health_check().await
        .unwrap_or(false);

    let response = CacheStatsResponse {
        stats,
        health,
        timestamp: chrono::Utc::now(),
    };

    info!("Cache stats requested - entries: {}, hit_ratio: {:.2}%", 
          response.stats.memory_stats.entries, 
          response.stats.hit_ratio * 100.0);

    Ok(Json(response))
}

/// Get cache health status
pub async fn get_cache_health(
    State(state): State<CacheAdminState>,
) -> Result<Json<CacheHealthResponse>, GatewayError> {
    let healthy = state.cache_manager.health_check().await
        .unwrap_or(false);

    let mut details = HashMap::new();
    
    // Add detailed health information
    let stats = state.cache_manager.stats().await;
    details.insert("memory_cache_entries".to_string(), 
                   serde_json::Value::Number(stats.memory_stats.entries.into()));
    details.insert("memory_usage_bytes".to_string(), 
                   serde_json::Value::Number(stats.memory_stats.memory_usage.into()));
    details.insert("hit_ratio".to_string(), 
                   serde_json::Value::Number(serde_json::Number::from_f64(stats.hit_ratio).unwrap_or_else(|| serde_json::Number::from(0))));
    details.insert("total_operations".to_string(), 
                   serde_json::Value::Number(stats.operations.into()));

    let response = CacheHealthResponse {
        healthy,
        details,
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(response))
}

/// Get cache configuration
pub async fn get_cache_config(
    State(state): State<CacheAdminState>,
) -> Result<Json<CacheConfigResponse>, GatewayError> {
    let config = state.cache_manager.config();
    let config_json = serde_json::to_value(config)
        .map_err(|e| GatewayError::internal(format!("Config serialization error: {}", e)))?;

    let response = CacheConfigResponse {
        config: config_json,
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(response))
}

/// Clear all cache entries
pub async fn clear_cache(
    State(state): State<CacheAdminState>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    match state.cache_manager.clear().await {
        Ok(()) => {
            info!("Cache cleared via admin API");
            Ok(Json(CacheInvalidationResponse {
                success: true,
                message: "Cache cleared successfully".to_string(),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
        Err(e) => {
            warn!("Failed to clear cache via admin API: {}", e);
            Ok(Json(CacheInvalidationResponse {
                success: false,
                message: format!("Failed to clear cache: {}", e),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
    }
}

/// Get cache key value
pub async fn get_cache_key(
    State(state): State<CacheAdminState>,
    Path(key): Path<String>,
    Query(_params): Query<CacheQueryParams>,
) -> Result<Json<CacheKeyResponse>, GatewayError> {
    let exists = state.cache_manager.exists(&key).await
        .unwrap_or(false);

    let value = if exists {
        match state.cache_manager.get(&key).await {
            Ok(Some(data)) => {
                // Convert bytes to string if possible
                match String::from_utf8(data.clone()) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        // If not valid UTF-8, return base64 encoded
                        Some({
                            use base64::Engine;
                            base64::engine::general_purpose::STANDARD.encode(data)
                        })
                    }
                }
            }
            _ => None,
        }
    } else {
        None
    };

    let response = CacheKeyResponse {
        key: key.clone(),
        value,
        exists,
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(response))
}

/// Delete cache key
pub async fn delete_cache_key(
    State(state): State<CacheAdminState>,
    Path(key): Path<String>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    match state.cache_manager.delete(&key).await {
        Ok(was_deleted) => {
            if was_deleted {
                info!("Cache key '{}' deleted via admin API", key);
                Ok(Json(CacheInvalidationResponse {
                    success: true,
                    message: format!("Key '{}' deleted successfully", key),
                    invalidated_count: Some(1),
                    timestamp: chrono::Utc::now(),
                }))
            } else {
                Ok(Json(CacheInvalidationResponse {
                    success: true,
                    message: format!("Key '{}' not found", key),
                    invalidated_count: Some(0),
                    timestamp: chrono::Utc::now(),
                }))
            }
        }
        Err(e) => {
            warn!("Failed to delete cache key '{}' via admin API: {}", key, e);
            Ok(Json(CacheInvalidationResponse {
                success: false,
                message: format!("Failed to delete key '{}': {}", key, e),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
    }
}

/// Set cache key value
pub async fn set_cache_key(
    State(state): State<CacheAdminState>,
    Json(request): Json<CacheKeyRequest>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    let ttl = std::time::Duration::from_secs(request.ttl_seconds.unwrap_or(300));
    
    match state.cache_manager.set(&request.key, request.value.as_bytes(), ttl).await {
        Ok(()) => {
            info!("Cache key '{}' set via admin API with TTL {:?}", request.key, ttl);
            Ok(Json(CacheInvalidationResponse {
                success: true,
                message: format!("Key '{}' set successfully", request.key),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
        Err(e) => {
            warn!("Failed to set cache key '{}' via admin API: {}", request.key, e);
            Ok(Json(CacheInvalidationResponse {
                success: false,
                message: format!("Failed to set key '{}': {}", request.key, e),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
    }
}

/// Invalidate cache entries
pub async fn invalidate_cache(
    State(state): State<CacheAdminState>,
    Json(request): Json<CacheInvalidationRequest>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    if let Some(true) = request.all {
        return clear_cache(State(state)).await;
    }

    let mut invalidated_count = 0;
    let mut errors = Vec::new();

    // Invalidate specific keys
    if let Some(keys) = request.keys {
        for key in keys {
            match state.invalidation_manager.invalidate(InvalidationEvent::InvalidateKey { key: key.clone() }).await {
                Ok(()) => {
                    invalidated_count += 1;
                    info!("Invalidated cache key: {}", key);
                }
                Err(e) => {
                    errors.push(format!("Failed to invalidate key '{}': {}", key, e));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(Json(CacheInvalidationResponse {
            success: true,
            message: format!("Successfully invalidated {} cache entries", invalidated_count),
            invalidated_count: Some(invalidated_count),
            timestamp: chrono::Utc::now(),
        }))
    } else {
        Ok(Json(CacheInvalidationResponse {
            success: false,
            message: format!("Partial success: {} invalidated, errors: {}", invalidated_count, errors.join("; ")),
            invalidated_count: Some(invalidated_count),
            timestamp: chrono::Utc::now(),
        }))
    }
}

/// Invalidate cache by pattern
pub async fn invalidate_cache_pattern(
    State(state): State<CacheAdminState>,
    Json(request): Json<CacheInvalidationRequest>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    if let Some(pattern) = request.pattern {
        match state.invalidation_manager.invalidate(InvalidationEvent::InvalidatePattern { pattern: pattern.clone() }).await {
            Ok(()) => {
                info!("Invalidated cache entries matching pattern: {}", pattern);
                Ok(Json(CacheInvalidationResponse {
                    success: true,
                    message: format!("Successfully invalidated cache entries matching pattern '{}'", pattern),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
            Err(e) => {
                warn!("Failed to invalidate cache pattern '{}': {}", pattern, e);
                Ok(Json(CacheInvalidationResponse {
                    success: false,
                    message: format!("Failed to invalidate pattern '{}': {}", pattern, e),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
        }
    } else {
        Ok(Json(CacheInvalidationResponse {
            success: false,
            message: "Pattern is required".to_string(),
            invalidated_count: None,
            timestamp: chrono::Utc::now(),
        }))
    }
}

/// Invalidate cache by prefix
pub async fn invalidate_cache_prefix(
    State(state): State<CacheAdminState>,
    Json(request): Json<CacheInvalidationRequest>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    if let Some(prefix) = request.prefix {
        match state.invalidation_manager.invalidate(InvalidationEvent::InvalidatePrefix { prefix: prefix.clone() }).await {
            Ok(()) => {
                info!("Invalidated cache entries with prefix: {}", prefix);
                Ok(Json(CacheInvalidationResponse {
                    success: true,
                    message: format!("Successfully invalidated cache entries with prefix '{}'", prefix),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
            Err(e) => {
                warn!("Failed to invalidate cache prefix '{}': {}", prefix, e);
                Ok(Json(CacheInvalidationResponse {
                    success: false,
                    message: format!("Failed to invalidate prefix '{}': {}", prefix, e),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
        }
    } else {
        Ok(Json(CacheInvalidationResponse {
            success: false,
            message: "Prefix is required".to_string(),
            invalidated_count: None,
            timestamp: chrono::Utc::now(),
        }))
    }
}

/// Invalidate user cache
pub async fn invalidate_user_cache(
    State(state): State<CacheAdminState>,
    Path(user_id): Path<String>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    match state.invalidation_manager.invalidate(InvalidationEvent::InvalidateUser { user_id: user_id.clone() }).await {
        Ok(()) => {
            info!("Invalidated cache for user: {}", user_id);
            Ok(Json(CacheInvalidationResponse {
                success: true,
                message: format!("Successfully invalidated cache for user '{}'", user_id),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
        Err(e) => {
            warn!("Failed to invalidate cache for user '{}': {}", user_id, e);
            Ok(Json(CacheInvalidationResponse {
                success: false,
                message: format!("Failed to invalidate cache for user '{}': {}", user_id, e),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
    }
}

/// Invalidate service cache
pub async fn invalidate_service_cache(
    State(state): State<CacheAdminState>,
    Path(service): Path<String>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    match state.invalidation_manager.invalidate(InvalidationEvent::InvalidateService { service: service.clone() }).await {
        Ok(()) => {
            info!("Invalidated cache for service: {}", service);
            Ok(Json(CacheInvalidationResponse {
                success: true,
                message: format!("Successfully invalidated cache for service '{}'", service),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
        Err(e) => {
            warn!("Failed to invalidate cache for service '{}': {}", service, e);
            Ok(Json(CacheInvalidationResponse {
                success: false,
                message: format!("Failed to invalidate cache for service '{}': {}", service, e),
                invalidated_count: None,
                timestamp: chrono::Utc::now(),
            }))
        }
    }
}

/// Invalidate cache by tags
pub async fn invalidate_cache_by_tags(
    State(state): State<CacheAdminState>,
    Json(request): Json<CacheInvalidationRequest>,
) -> Result<Json<CacheInvalidationResponse>, GatewayError> {
    if let Some(tags) = request.tags {
        match state.invalidation_manager.invalidate(InvalidationEvent::InvalidateByTags { tags: tags.clone() }).await {
            Ok(()) => {
                info!("Invalidated cache entries with tags: {:?}", tags);
                Ok(Json(CacheInvalidationResponse {
                    success: true,
                    message: format!("Successfully invalidated cache entries with tags: {:?}", tags),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
            Err(e) => {
                warn!("Failed to invalidate cache by tags {:?}: {}", tags, e);
                Ok(Json(CacheInvalidationResponse {
                    success: false,
                    message: format!("Failed to invalidate cache by tags {:?}: {}", tags, e),
                    invalidated_count: None,
                    timestamp: chrono::Utc::now(),
                }))
            }
        }
    } else {
        Ok(Json(CacheInvalidationResponse {
            success: false,
            message: "Tags are required".to_string(),
            invalidated_count: None,
            timestamp: chrono::Utc::now(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::{CacheConfig, CacheManager, InvalidationStrategy};
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::time::Duration;

    async fn create_test_state() -> CacheAdminState {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            ..Default::default()
        };
        let cache_manager = Arc::new(CacheManager::new(config).await.unwrap());
        let invalidation_manager = Arc::new(InvalidationManager::new(
            cache_manager.clone(),
            InvalidationStrategy::Immediate,
        ));

        CacheAdminState {
            cache_manager,
            invalidation_manager,
        }
    }

    #[tokio::test]
    async fn test_cache_stats_endpoint() {
        let state = create_test_state().await;
        let app = CacheAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/cache/stats").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let stats: CacheStatsResponse = response.json();
        assert!(stats.stats.operations >= 0);
    }

    #[tokio::test]
    async fn test_cache_health_endpoint() {
        let state = create_test_state().await;
        let app = CacheAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/cache/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let health: CacheHealthResponse = response.json();
        assert!(health.healthy);
    }

    #[tokio::test]
    async fn test_cache_key_operations() {
        let state = create_test_state().await;
        let app = CacheAdminRouter::create_router(state.clone());
        let server = TestServer::new(app).unwrap();

        // Set a cache key
        let set_request = CacheKeyRequest {
            key: "test_key".to_string(),
            value: "test_value".to_string(),
            ttl_seconds: Some(60),
        };

        let response = server.post("/cache/keys").json(&set_request).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        // Get the cache key
        let response = server.get("/cache/keys/test_key").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let key_response: CacheKeyResponse = response.json();
        assert!(key_response.exists);
        assert_eq!(key_response.value, Some("test_value".to_string()));

        // Delete the cache key
        let response = server.delete("/cache/keys/test_key").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        // Verify key is deleted
        let response = server.get("/cache/keys/test_key").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let key_response: CacheKeyResponse = response.json();
        assert!(!key_response.exists);
    }

    #[tokio::test]
    async fn test_cache_clear_endpoint() {
        let state = create_test_state().await;
        let app = CacheAdminRouter::create_router(state.clone());
        let server = TestServer::new(app).unwrap();

        // Add some data to cache
        state.cache_manager.set("key1", b"value1", Duration::from_secs(60)).await.unwrap();
        state.cache_manager.set("key2", b"value2", Duration::from_secs(60)).await.unwrap();

        // Clear cache
        let response = server.post("/cache/clear").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let clear_response: CacheInvalidationResponse = response.json();
        assert!(clear_response.success);

        // Verify cache is empty
        assert!(!state.cache_manager.exists("key1").await.unwrap());
        assert!(!state.cache_manager.exists("key2").await.unwrap());
    }
}
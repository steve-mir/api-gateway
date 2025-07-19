//! # Cache Middleware
//!
//! This module provides middleware for automatic request/response caching
//! integrated with the gateway's middleware pipeline.

use super::{
    CacheManager, KeyGenerator, DefaultKeyGenerator,
    KeyGenerationStrategy, CacheResult, CacheError,
};
use super::deduplication::{DeduplicationManager, IdempotencyManager, DeduplicationConfig, IdempotencyConfig};
use crate::core::types::{IncomingRequest, RequestContext, GatewayResponse};
use crate::core::error::GatewayError;
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Cache policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePolicy {
    /// Enable caching for this policy
    pub enabled: bool,
    
    /// Cache TTL
    pub ttl: Duration,
    
    /// HTTP methods to cache
    pub cacheable_methods: Vec<String>,
    
    /// HTTP status codes to cache
    pub cacheable_status_codes: Vec<u16>,
    
    /// Headers to include in cache key
    pub vary_headers: Vec<String>,
    
    /// Whether to cache responses with authentication
    pub cache_authenticated: bool,
    
    /// Maximum response size to cache (in bytes)
    pub max_response_size: usize,
    
    /// Key generation strategy
    pub key_strategy: KeyGenerationStrategy,
    
    /// Enable request deduplication
    pub enable_deduplication: bool,
    
    /// Enable idempotency
    pub enable_idempotency: bool,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: Duration::from_secs(300), // 5 minutes
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
            cacheable_status_codes: vec![200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501],
            vary_headers: vec!["Accept".to_string(), "Accept-Encoding".to_string()],
            cache_authenticated: false,
            max_response_size: 1024 * 1024, // 1MB
            key_strategy: KeyGenerationStrategy::WithQuery,
            enable_deduplication: true,
            enable_idempotency: false,
        }
    }
}

/// Cache middleware
pub struct CacheMiddleware {
    /// Cache manager
    cache_manager: Arc<CacheManager>,
    
    /// Key generator
    key_generator: Box<dyn KeyGenerator>,
    
    /// Cache policy
    policy: CachePolicy,
    
    /// Deduplication manager
    deduplication_manager: Option<DeduplicationManager>,
    
    /// Idempotency manager
    idempotency_manager: Option<IdempotencyManager>,
}

impl CacheMiddleware {
    /// Create a new cache middleware
    pub fn new(cache_manager: Arc<CacheManager>, policy: CachePolicy) -> Self {
        let key_generator = Box::new(DefaultKeyGenerator::new(policy.key_strategy.clone()));
        
        let deduplication_manager = if policy.enable_deduplication {
            Some(DeduplicationManager::new(
                cache_manager.clone(),
                DeduplicationConfig::default(),
            ))
        } else {
            None
        };
        
        let idempotency_manager = if policy.enable_idempotency {
            Some(IdempotencyManager::new(
                cache_manager.clone(),
                IdempotencyConfig::default(),
            ))
        } else {
            None
        };

        Self {
            cache_manager,
            key_generator,
            policy,
            deduplication_manager,
            idempotency_manager,
        }
    }

    /// Create with custom key generator
    pub fn with_key_generator(
        cache_manager: Arc<CacheManager>,
        policy: CachePolicy,
        key_generator: Box<dyn KeyGenerator>,
    ) -> Self {
        let deduplication_manager = if policy.enable_deduplication {
            Some(DeduplicationManager::new(
                cache_manager.clone(),
                DeduplicationConfig::default(),
            ))
        } else {
            None
        };
        
        let idempotency_manager = if policy.enable_idempotency {
            Some(IdempotencyManager::new(
                cache_manager.clone(),
                IdempotencyConfig::default(),
            ))
        } else {
            None
        };

        Self {
            cache_manager,
            key_generator,
            policy,
            deduplication_manager,
            idempotency_manager,
        }
    }

    /// Process incoming request (before upstream)
    pub async fn process_request(
        &self,
        request: &IncomingRequest,
        context: &RequestContext,
    ) -> Result<Option<GatewayResponse>, GatewayError> {
        if !self.policy.enabled {
            return Ok(None);
        }

        // Check if request is cacheable
        if !self.is_request_cacheable(request, context) {
            return Ok(None);
        }

        // Handle deduplication
        if let Some(dedup_manager) = &self.deduplication_manager {
            let dedup_result = dedup_manager.check_duplicate(request, Some(context))
                .await
                .map_err(|e| GatewayError::internal(format!("Deduplication error: {}", e)))?;
            
            if !dedup_result.should_process {
                if let Some(cached_response) = dedup_result.cached_response {
                    debug!("Returning deduplicated response for key: {}", dedup_result.key);
                    return Ok(Some(self.deserialize_response(&cached_response)?));
                }
            }
        }

        // Handle idempotency
        if let Some(idempotency_manager) = &self.idempotency_manager {
            let idempotency_result = idempotency_manager.check_idempotency(request, Some(context))
                .await
                .map_err(|e| GatewayError::internal(format!("Idempotency error: {}", e)))?;
            
            if !idempotency_result.should_process {
                if let Some(cached_response) = idempotency_result.cached_response {
                    debug!("Returning idempotent response for key: {}", idempotency_result.key);
                    return Ok(Some(self.deserialize_response(&cached_response)?));
                }
            }
        }

        // Check regular cache
        let cache_key = self.key_generator.generate_key(request, Some(context));
        
        if let Some(cached_data) = self.cache_manager.get(&cache_key)
            .await
            .map_err(|e| GatewayError::internal(format!("Cache get error: {}", e)))? 
        {
            debug!("Cache hit for key: {}", cache_key);
            let response = self.deserialize_response(&cached_data)?;
            
            // Add cache headers
            let mut response_with_headers = response;
            self.add_cache_headers(&mut response_with_headers.headers, true);
            
            return Ok(Some(response_with_headers));
        }

        debug!("Cache miss for key: {}", cache_key);
        Ok(None)
    }

    /// Process outgoing response (after upstream)
    pub async fn process_response(
        &self,
        request: &IncomingRequest,
        context: &RequestContext,
        response: &mut GatewayResponse,
    ) -> Result<(), GatewayError> {
        if !self.policy.enabled {
            return Ok(());
        }

        // Check if response is cacheable
        if !self.is_response_cacheable(request, context, response) {
            return Ok(());
        }

        let cache_key = self.key_generator.generate_key(request, Some(context));
        let serialized_response = self.serialize_response(response)?;

        // Store in cache
        self.cache_manager.set(&cache_key, &serialized_response, self.policy.ttl)
            .await
            .map_err(|e| GatewayError::internal(format!("Cache set error: {}", e)))?;

        // Store for deduplication
        if let Some(dedup_manager) = &self.deduplication_manager {
            let dedup_key = format!("dedup:{}", cache_key);
            dedup_manager.store_response(&dedup_key, &serialized_response)
                .await
                .map_err(|e| GatewayError::internal(format!("Deduplication store error: {}", e)))?;
        }

        // Store for idempotency
        if let Some(idempotency_manager) = &self.idempotency_manager {
            if let Some(idempotency_key) = request.header("Idempotency-Key") {
                idempotency_manager.store_response(idempotency_key, &serialized_response)
                    .await
                    .map_err(|e| GatewayError::internal(format!("Idempotency store error: {}", e)))?;
            }
        }

        // Add cache headers to response
        self.add_cache_headers(&mut response.headers, false);

        debug!("Cached response for key: {}", cache_key);
        Ok(())
    }

    /// Check if request is cacheable
    fn is_request_cacheable(&self, request: &IncomingRequest, context: &RequestContext) -> bool {
        // Check method
        if !self.policy.cacheable_methods.contains(&request.method.to_string()) {
            return false;
        }

        // Check authentication
        if !self.policy.cache_authenticated && context.auth_context.is_some() {
            return false;
        }

        // Check for cache-control headers that prevent caching
        if let Some(cache_control) = request.header("cache-control") {
            if cache_control.contains("no-cache") || cache_control.contains("no-store") {
                return false;
            }
        }

        true
    }

    /// Check if response is cacheable
    fn is_response_cacheable(
        &self,
        _request: &IncomingRequest,
        _context: &RequestContext,
        response: &GatewayResponse,
    ) -> bool {
        // Check status code
        if !self.policy.cacheable_status_codes.contains(&response.status.as_u16()) {
            return false;
        }

        // Check response size
        if response.body.len() > self.policy.max_response_size {
            return false;
        }

        // Check for cache-control headers that prevent caching
        if let Some(cache_control) = response.headers.get("cache-control") {
            if let Ok(cache_control_str) = cache_control.to_str() {
                if cache_control_str.contains("no-cache") 
                    || cache_control_str.contains("no-store") 
                    || cache_control_str.contains("private") {
                    return false;
                }
            }
        }

        true
    }

    /// Serialize response for caching
    fn serialize_response(&self, response: &GatewayResponse) -> Result<Vec<u8>, GatewayError> {
        let cache_entry = CachedResponse {
            status: response.status.as_u16(),
            headers: response.headers.iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
                .collect(),
            body: response.body.as_ref().clone(),
            cached_at: chrono::Utc::now(),
        };

        serde_json::to_vec(&cache_entry)
            .map_err(|e| GatewayError::internal(format!("Response serialization error: {}", e)))
    }

    /// Deserialize response from cache
    fn deserialize_response(&self, data: &[u8]) -> Result<GatewayResponse, GatewayError> {
        let cache_entry: CachedResponse = serde_json::from_slice(data)
            .map_err(|e| GatewayError::internal(format!("Response deserialization error: {}", e)))?;

        let mut headers = HeaderMap::new();
        for (name, value) in cache_entry.headers {
            if let (Ok(header_name), Ok(header_value)) = (name.parse::<axum::http::HeaderName>(), value.parse::<axum::http::HeaderValue>()) {
                headers.insert(header_name, header_value);
            }
        }

        let status = StatusCode::from_u16(cache_entry.status)
            .map_err(|e| GatewayError::internal(format!("Invalid status code: {}", e)))?;

        Ok(GatewayResponse::new(status, headers, cache_entry.body))
    }

    /// Add cache-related headers to response
    fn add_cache_headers(&self, headers: &mut HeaderMap, is_cached: bool) {
        if is_cached {
            headers.insert("X-Cache", "HIT".parse().unwrap());
        } else {
            headers.insert("X-Cache", "MISS".parse().unwrap());
        }

        // Add cache-control header if not present
        if !headers.contains_key("cache-control") {
            let max_age = self.policy.ttl.as_secs();
            headers.insert(
                "cache-control",
                format!("public, max-age={}", max_age).parse().unwrap(),
            );
        }
    }
}

/// Cached response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
    cached_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::{CacheConfig, CacheManager};
    use crate::core::types::{Protocol, AuthContext};
    use axum::http::{Method, Version};
    use std::collections::HashMap;

    async fn create_test_cache_manager() -> Arc<CacheManager> {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            ..Default::default()
        };
        Arc::new(CacheManager::new(config).await.unwrap())
    }

    fn create_test_request() -> IncomingRequest {
        IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/api/users/123".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    fn create_test_response() -> GatewayResponse {
        GatewayResponse::text(StatusCode::OK, "test response".to_string())
    }

    #[tokio::test]
    async fn test_cache_middleware_miss_and_hit() {
        let cache_manager = create_test_cache_manager().await;
        let policy = CachePolicy::default();
        let middleware = CacheMiddleware::new(cache_manager, policy);

        let request = create_test_request();
        let context = RequestContext::new(Arc::new(request.clone()));

        // First request should be a cache miss
        let cached_response = middleware.process_request(&request, &context).await.unwrap();
        assert!(cached_response.is_none());

        // Process and cache a response
        let mut response = create_test_response();
        middleware.process_response(&request, &context, &mut response).await.unwrap();

        // Second request should be a cache hit
        let cached_response = middleware.process_request(&request, &context).await.unwrap();
        assert!(cached_response.is_some());
        
        let cached = cached_response.unwrap();
        assert_eq!(cached.status, StatusCode::OK);
        assert_eq!(cached.headers.get("X-Cache").unwrap(), "HIT");
    }

    #[tokio::test]
    async fn test_non_cacheable_method() {
        let cache_manager = create_test_cache_manager().await;
        let policy = CachePolicy::default();
        let middleware = CacheMiddleware::new(cache_manager, policy);

        let mut request = create_test_request();
        request.method = Method::POST;
        let context = RequestContext::new(Arc::new(request.clone()));

        // POST request should not be cached
        let cached_response = middleware.process_request(&request, &context).await.unwrap();
        assert!(cached_response.is_none());
    }

    #[tokio::test]
    async fn test_authenticated_request_caching() {
        let cache_manager = create_test_cache_manager().await;
        let mut policy = CachePolicy::default();
        policy.cache_authenticated = false;
        let middleware = CacheMiddleware::new(cache_manager, policy);

        let request = create_test_request();
        let mut context = RequestContext::new(Arc::new(request.clone()));
        
        // Add authentication context
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: None,
        };
        context.set_auth_context(auth_context);

        // Authenticated request should not be cached when cache_authenticated is false
        let cached_response = middleware.process_request(&request, &context).await.unwrap();
        assert!(cached_response.is_none());
    }

    #[tokio::test]
    async fn test_cache_headers() {
        let cache_manager = create_test_cache_manager().await;
        let policy = CachePolicy::default();
        let middleware = CacheMiddleware::new(cache_manager, policy);

        let request = create_test_request();
        let context = RequestContext::new(Arc::new(request.clone()));

        // Process and cache a response
        let mut response = create_test_response();
        middleware.process_response(&request, &context, &mut response).await.unwrap();

        // Response should have cache headers
        assert_eq!(response.headers.get("X-Cache").unwrap(), "MISS");
        assert!(response.headers.contains_key("cache-control"));
    }
}
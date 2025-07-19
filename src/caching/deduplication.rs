//! # Request Deduplication and Idempotency Module
//!
//! This module provides request deduplication and idempotency mechanisms
//! to prevent duplicate processing of identical requests.

use super::{CacheManager, CacheError, CacheResult};
use crate::core::types::{IncomingRequest, RequestContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};
// use uuid::Uuid;

/// Deduplication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    /// Enable request deduplication
    pub enabled: bool,
    
    /// TTL for deduplication entries
    pub ttl: Duration,
    
    /// Include request body in deduplication key
    pub include_body: bool,
    
    /// Include specific headers in deduplication key
    pub include_headers: Vec<String>,
    
    /// Include user context in deduplication key
    pub include_user: bool,
    
    /// Maximum concurrent in-flight requests per key
    pub max_concurrent: usize,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: Duration::from_secs(300), // 5 minutes
            include_body: true,
            include_headers: vec!["authorization".to_string()],
            include_user: true,
            max_concurrent: 10,
        }
    }
}

/// Idempotency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyConfig {
    /// Enable idempotency
    pub enabled: bool,
    
    /// TTL for idempotency keys
    pub ttl: Duration,
    
    /// Header name for idempotency key
    pub header_name: String,
    
    /// Automatically generate idempotency keys if not provided
    pub auto_generate: bool,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: Duration::from_secs(3600), // 1 hour
            header_name: "Idempotency-Key".to_string(),
            auto_generate: false,
        }
    }
}

/// Request deduplication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationResult {
    /// Whether this is a duplicate request
    pub is_duplicate: bool,
    
    /// Deduplication key used
    pub key: String,
    
    /// Number of concurrent requests for this key
    pub concurrent_count: usize,
    
    /// Whether the request should be processed
    pub should_process: bool,
    
    /// Cached response if available
    pub cached_response: Option<Vec<u8>>,
}

/// Idempotency result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyResult {
    /// Whether this request has been processed before
    pub is_repeat: bool,
    
    /// Idempotency key used
    pub key: String,
    
    /// Cached response if available
    pub cached_response: Option<Vec<u8>>,
    
    /// Whether the request should be processed
    pub should_process: bool,
}

/// In-flight request tracking
#[derive(Debug, Clone)]
struct InFlightRequest {
    request_id: String,
    started_at: u64,
    response_ready: Arc<tokio::sync::Notify>,
    response_data: Arc<RwLock<Option<Vec<u8>>>>,
}

/// Request deduplication manager
pub struct DeduplicationManager {
    /// Cache manager for storing deduplication data
    cache_manager: Arc<CacheManager>,
    
    /// Configuration
    config: DeduplicationConfig,
    
    /// In-flight requests tracking
    in_flight: Arc<RwLock<std::collections::HashMap<String, Vec<InFlightRequest>>>>,
}

impl DeduplicationManager {
    /// Create a new deduplication manager
    pub fn new(cache_manager: Arc<CacheManager>, config: DeduplicationConfig) -> Self {
        Self {
            cache_manager,
            config,
            in_flight: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Check if a request is a duplicate and handle accordingly
    pub async fn check_duplicate(
        &self,
        request: &IncomingRequest,
        context: Option<&RequestContext>,
    ) -> CacheResult<DeduplicationResult> {
        if !self.config.enabled {
            return Ok(DeduplicationResult {
                is_duplicate: false,
                key: String::new(),
                concurrent_count: 0,
                should_process: true,
                cached_response: None,
            });
        }

        let dedup_key = self.generate_deduplication_key(request, context);
        
        // Check for cached response first
        let cached_response = self.cache_manager.get(&dedup_key).await?;
        if cached_response.is_some() {
            debug!("Found cached response for deduplication key: {}", dedup_key);
            return Ok(DeduplicationResult {
                is_duplicate: true,
                key: dedup_key,
                concurrent_count: 0,
                should_process: false,
                cached_response,
            });
        }

        // Check in-flight requests
        let mut in_flight = self.in_flight.write().await;
        let in_flight_requests = in_flight.entry(dedup_key.clone()).or_insert_with(Vec::new);
        
        let concurrent_count = in_flight_requests.len();
        
        if concurrent_count >= self.config.max_concurrent {
            warn!("Too many concurrent requests for key: {}", dedup_key);
            return Ok(DeduplicationResult {
                is_duplicate: true,
                key: dedup_key,
                concurrent_count,
                should_process: false,
                cached_response: None,
            });
        }

        // If there are in-flight requests, wait for the first one to complete
        if !in_flight_requests.is_empty() {
            let first_request = in_flight_requests[0].clone();
            drop(in_flight); // Release the lock
            
            debug!("Waiting for in-flight request to complete: {}", dedup_key);
            first_request.response_ready.notified().await;
            
            // Check if response is available
            let response_data = first_request.response_data.read().await;
            if let Some(response) = response_data.as_ref() {
                return Ok(DeduplicationResult {
                    is_duplicate: true,
                    key: dedup_key,
                    concurrent_count: concurrent_count + 1,
                    should_process: false,
                    cached_response: Some(response.clone()),
                });
            }
        } else {
            // This is the first request for this key
            let in_flight_request = InFlightRequest {
                request_id: request.id.clone(),
                started_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                response_ready: Arc::new(tokio::sync::Notify::new()),
                response_data: Arc::new(RwLock::new(None)),
            };
            
            in_flight_requests.push(in_flight_request);
        }

        Ok(DeduplicationResult {
            is_duplicate: false,
            key: dedup_key,
            concurrent_count,
            should_process: true,
            cached_response: None,
        })
    }

    /// Store response for deduplication
    pub async fn store_response(
        &self,
        dedup_key: &str,
        response_data: &[u8],
    ) -> CacheResult<()> {
        // Store in cache
        self.cache_manager.set(dedup_key, response_data, self.config.ttl).await?;
        
        // Notify waiting requests
        let mut in_flight = self.in_flight.write().await;
        if let Some(requests) = in_flight.get_mut(dedup_key) {
            for request in requests {
                let mut response = request.response_data.write().await;
                *response = Some(response_data.to_vec());
                request.response_ready.notify_waiters();
            }
            
            // Clean up in-flight requests
            in_flight.remove(dedup_key);
        }

        debug!("Stored response for deduplication key: {}", dedup_key);
        Ok(())
    }

    /// Generate deduplication key from request
    fn generate_deduplication_key(
        &self,
        request: &IncomingRequest,
        context: Option<&RequestContext>,
    ) -> String {
        let mut hasher = Sha256::new();
        
        // Always include method and path
        hasher.update(request.method.as_str());
        hasher.update(request.path());
        
        // Include query parameters
        if let Some(query) = request.query() {
            hasher.update(query);
        }
        
        // Include specified headers
        for header_name in &self.config.include_headers {
            if let Some(header_value) = request.header(header_name) {
                hasher.update(header_name);
                hasher.update(header_value);
            }
        }
        
        // Include body if configured
        if self.config.include_body && !request.body.is_empty() {
            hasher.update(&*request.body);
        }
        
        // Include user context if configured
        if self.config.include_user {
            if let Some(ctx) = context {
                if let Some(auth_ctx) = &ctx.auth_context {
                    hasher.update(&auth_ctx.user_id);
                }
            }
        }
        
        let hash = hasher.finalize();
        format!("dedup:{:x}", hash)
    }

    /// Clean up expired in-flight requests
    pub async fn cleanup_expired(&self) -> CacheResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut in_flight = self.in_flight.write().await;
        let mut keys_to_remove = Vec::new();
        
        for (key, requests) in in_flight.iter_mut() {
            requests.retain(|request| {
                let age = now.saturating_sub(request.started_at);
                age < self.config.ttl.as_secs()
            });
            
            if requests.is_empty() {
                keys_to_remove.push(key.clone());
            }
        }
        
        for key in keys_to_remove {
            in_flight.remove(&key);
        }

        Ok(())
    }
}

/// Idempotency manager
pub struct IdempotencyManager {
    /// Cache manager for storing idempotency data
    cache_manager: Arc<CacheManager>,
    
    /// Configuration
    config: IdempotencyConfig,
}

impl IdempotencyManager {
    /// Create a new idempotency manager
    pub fn new(cache_manager: Arc<CacheManager>, config: IdempotencyConfig) -> Self {
        Self {
            cache_manager,
            config,
        }
    }

    /// Check idempotency for a request
    pub async fn check_idempotency(
        &self,
        request: &IncomingRequest,
        context: Option<&RequestContext>,
    ) -> CacheResult<IdempotencyResult> {
        if !self.config.enabled {
            return Ok(IdempotencyResult {
                is_repeat: false,
                key: String::new(),
                cached_response: None,
                should_process: true,
            });
        }

        let idempotency_key = self.get_or_generate_idempotency_key(request, context)?;
        let cache_key = format!("idempotency:{}", idempotency_key);
        
        // Check for existing response
        let cached_response = self.cache_manager.get(&cache_key).await?;
        
        if cached_response.is_some() {
            debug!("Found cached response for idempotency key: {}", idempotency_key);
            return Ok(IdempotencyResult {
                is_repeat: true,
                key: idempotency_key,
                cached_response,
                should_process: false,
            });
        }

        Ok(IdempotencyResult {
            is_repeat: false,
            key: idempotency_key,
            cached_response: None,
            should_process: true,
        })
    }

    /// Store response for idempotency
    pub async fn store_response(
        &self,
        idempotency_key: &str,
        response_data: &[u8],
    ) -> CacheResult<()> {
        let cache_key = format!("idempotency:{}", idempotency_key);
        self.cache_manager.set(&cache_key, response_data, self.config.ttl).await?;
        
        debug!("Stored response for idempotency key: {}", idempotency_key);
        Ok(())
    }

    /// Get or generate idempotency key
    fn get_or_generate_idempotency_key(
        &self,
        request: &IncomingRequest,
        _context: Option<&RequestContext>,
    ) -> CacheResult<String> {
        // Check for idempotency key in headers
        if let Some(key) = request.header(&self.config.header_name) {
            return Ok(key.to_string());
        }

        // Auto-generate if configured
        if self.config.auto_generate {
            let mut hasher = Sha256::new();
            hasher.update(request.method.as_str());
            hasher.update(request.path());
            
            if let Some(query) = request.query() {
                hasher.update(query);
            }
            
            if !request.body.is_empty() {
                hasher.update(&*request.body);
            }
            
            let hash = hasher.finalize();
            return Ok(format!("{:x}", hash));
        }

        Err(CacheError::KeyGeneration {
            message: format!("No {} header found and auto-generation is disabled", self.config.header_name),
        })
    }
}

/// Combined request deduplicator
pub struct RequestDeduplicator {
    deduplication_manager: DeduplicationManager,
    idempotency_manager: IdempotencyManager,
}

impl RequestDeduplicator {
    /// Create a new request deduplicator
    pub fn new(
        cache_manager: Arc<CacheManager>,
        dedup_config: DeduplicationConfig,
        idempotency_config: IdempotencyConfig,
    ) -> Self {
        Self {
            deduplication_manager: DeduplicationManager::new(cache_manager.clone(), dedup_config),
            idempotency_manager: IdempotencyManager::new(cache_manager, idempotency_config),
        }
    }

    /// Check both deduplication and idempotency
    pub async fn check_request(
        &self,
        request: &IncomingRequest,
        context: Option<&RequestContext>,
    ) -> CacheResult<(DeduplicationResult, IdempotencyResult)> {
        let dedup_result = self.deduplication_manager.check_duplicate(request, context).await?;
        let idempotency_result = self.idempotency_manager.check_idempotency(request, context).await?;
        
        Ok((dedup_result, idempotency_result))
    }

    /// Store response for both deduplication and idempotency
    pub async fn store_response(
        &self,
        dedup_key: &str,
        idempotency_key: &str,
        response_data: &[u8],
    ) -> CacheResult<()> {
        if !dedup_key.is_empty() {
            self.deduplication_manager.store_response(dedup_key, response_data).await?;
        }
        
        if !idempotency_key.is_empty() {
            self.idempotency_manager.store_response(idempotency_key, response_data).await?;
        }
        
        Ok(())
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) -> CacheResult<()> {
        self.deduplication_manager.cleanup_expired().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::{CacheConfig, CacheManager};
    use crate::core::types::{AuthContext, Protocol};
    use axum::http::{HeaderMap, Method, Version};
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
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token123".parse().unwrap());

        IncomingRequest::new(
            Protocol::Http,
            Method::POST,
            "/api/users".parse().unwrap(),
            Version::HTTP_11,
            headers,
            b"test body".to_vec(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn test_deduplication() {
        let cache_manager = create_test_cache_manager().await;
        let config = DeduplicationConfig::default();
        let dedup_manager = DeduplicationManager::new(cache_manager, config);

        let request = create_test_request();
        
        // First request should not be duplicate
        let result1 = dedup_manager.check_duplicate(&request, None).await.unwrap();
        assert!(!result1.is_duplicate);
        assert!(result1.should_process);

        // Store response
        let response_data = b"response data";
        dedup_manager.store_response(&result1.key, response_data).await.unwrap();

        // Second identical request should be duplicate
        let result2 = dedup_manager.check_duplicate(&request, None).await.unwrap();
        assert!(result2.is_duplicate);
        assert!(!result2.should_process);
        assert_eq!(result2.cached_response, Some(response_data.to_vec()));
    }

    #[tokio::test]
    async fn test_idempotency() {
        let cache_manager = create_test_cache_manager().await;
        let config = IdempotencyConfig::default();
        let idempotency_manager = IdempotencyManager::new(cache_manager, config);

        let mut request = create_test_request();
        request.headers.insert("Idempotency-Key", "test-key-123".parse().unwrap());
        
        // First request should not be repeat
        let result1 = idempotency_manager.check_idempotency(&request, None).await.unwrap();
        assert!(!result1.is_repeat);
        assert!(result1.should_process);
        assert_eq!(result1.key, "test-key-123");

        // Store response
        let response_data = b"idempotent response";
        idempotency_manager.store_response(&result1.key, response_data).await.unwrap();

        // Second request with same key should be repeat
        let result2 = idempotency_manager.check_idempotency(&request, None).await.unwrap();
        assert!(result2.is_repeat);
        assert!(!result2.should_process);
        assert_eq!(result2.cached_response, Some(response_data.to_vec()));
    }

    #[tokio::test]
    async fn test_auto_generated_idempotency() {
        let cache_manager = create_test_cache_manager().await;
        let config = IdempotencyConfig {
            auto_generate: true,
            ..Default::default()
        };
        let idempotency_manager = IdempotencyManager::new(cache_manager, config);

        let request = create_test_request();
        
        // Should auto-generate idempotency key
        let result = idempotency_manager.check_idempotency(&request, None).await.unwrap();
        assert!(!result.is_repeat);
        assert!(result.should_process);
        assert!(!result.key.is_empty());
    }

    #[tokio::test]
    async fn test_request_deduplicator() {
        let cache_manager = create_test_cache_manager().await;
        let dedup_config = DeduplicationConfig::default();
        let idempotency_config = IdempotencyConfig {
            auto_generate: true,
            ..Default::default()
        };
        
        let deduplicator = RequestDeduplicator::new(
            cache_manager,
            dedup_config,
            idempotency_config,
        );

        let request = create_test_request();
        
        // Check both deduplication and idempotency
        let (dedup_result, idempotency_result) = deduplicator.check_request(&request, None).await.unwrap();
        
        assert!(!dedup_result.is_duplicate);
        assert!(!idempotency_result.is_repeat);
        assert!(dedup_result.should_process);
        assert!(idempotency_result.should_process);

        // Store response for both
        let response_data = b"combined response";
        deduplicator.store_response(
            &dedup_result.key,
            &idempotency_result.key,
            response_data,
        ).await.unwrap();

        // Second check should find cached responses
        let (dedup_result2, idempotency_result2) = deduplicator.check_request(&request, None).await.unwrap();
        
        assert!(dedup_result2.is_duplicate);
        assert!(idempotency_result2.is_repeat);
        assert!(!dedup_result2.should_process);
        assert!(!idempotency_result2.should_process);
    }
}
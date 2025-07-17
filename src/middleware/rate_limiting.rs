//! # Rate Limiting System
//!
//! This module provides a comprehensive rate limiting system with pluggable algorithms
//! and storage backends. It supports:
//! - Token bucket algorithm for burst handling
//! - Sliding window algorithm for precise control
//! - Distributed rate limiting using Redis
//! - Per-user, per-service, and per-endpoint granularity
//! - Admin exemption system
//!
//! ## Architecture
//! The rate limiting system is built around several key traits:
//! - `RateLimitAlgorithm`: Defines rate limiting algorithms
//! - `RateLimitStorage`: Abstracts storage backends (in-memory, Redis)
//! - `RateLimitKey`: Generates keys for different granularity levels
//!
//! ## Usage Example
//! ```rust
//! use crate::middleware::rate_limiting::{RateLimiter, RateLimitConfig, TokenBucketAlgorithm};
//! use std::time::Duration;
//!
//! let config = RateLimitConfig {
//!     algorithm: "token_bucket".to_string(),
//!     requests_per_window: 100,
//!     window_duration: Duration::from_secs(60),
//!     burst_size: Some(20),
//!     ..Default::default()
//! };
//!
//! let rate_limiter = RateLimiter::new(config).await?;
//! let is_allowed = rate_limiter.is_allowed("user:123", &request).await?;
//! ```

use async_trait::async_trait;
use dashmap::DashMap;
use redis::{Client as RedisClient, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error};

/// Errors that can occur during rate limiting operations
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Algorithm error: {0}")]
    Algorithm(String),
    #[error("Redis connection error: {0}")]
    Redis(#[from] redis::RedisError),
}

/// Rate limiting algorithm types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitAlgorithmType {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
}

/// Rate limiting granularity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitGranularity {
    Global,
    PerUser,
    PerService,
    PerEndpoint,
    PerUserPerService,
    PerUserPerEndpoint,
}

/// Configuration for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Algorithm to use for rate limiting
    pub algorithm: RateLimitAlgorithmType,
    /// Maximum requests allowed per window
    pub requests_per_window: u32,
    /// Duration of the rate limiting window
    #[serde(with = "humantime_serde")]
    pub window_duration: Duration,
    /// Burst size for token bucket algorithm
    pub burst_size: Option<u32>,
    /// Granularity level for rate limiting
    pub granularity: RateLimitGranularity,
    /// Whether to use distributed storage (Redis)
    pub distributed: bool,
    /// Redis connection string (if distributed)
    pub redis_url: Option<String>,
    /// Key prefix for Redis storage
    pub key_prefix: String,
    /// Admin exemption patterns
    pub admin_exemptions: Vec<String>,
    /// Custom rate limit rules per endpoint
    pub endpoint_rules: HashMap<String, EndpointRateLimit>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            algorithm: RateLimitAlgorithmType::TokenBucket,
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: Some(20),
            granularity: RateLimitGranularity::PerUser,
            distributed: false,
            redis_url: None,
            key_prefix: "rate_limit".to_string(),
            admin_exemptions: vec!["/admin/*".to_string()],
            endpoint_rules: HashMap::new(),
        }
    }
}

/// Endpoint-specific rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    pub requests_per_window: u32,
    #[serde(with = "humantime_serde")]
    pub window_duration: Duration,
    pub burst_size: Option<u32>,
    pub granularity: RateLimitGranularity,
}

/// Rate limit decision result
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub reset_time: SystemTime,
    pub retry_after: Option<Duration>,
}

/// Trait for rate limiting algorithms
#[async_trait]
pub trait RateLimitAlgorithm: Send + Sync {
    async fn is_allowed(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
        burst_size: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError>;

    async fn reset(&self, key: &str) -> Result<(), RateLimitError>;
}

/// Trait for rate limiting storage backends
#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, RateLimitError>;
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), RateLimitError>;
    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, RateLimitError>;
    async fn delete(&self, key: &str) -> Result<(), RateLimitError>;
}

/// Token bucket algorithm implementation
pub struct TokenBucketAlgorithm {
    storage: Arc<dyn RateLimitStorage>,
}

impl TokenBucketAlgorithm {
    pub fn new(storage: Arc<dyn RateLimitStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl RateLimitAlgorithm for TokenBucketAlgorithm {
    async fn is_allowed(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
        burst_size: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let bucket_key = format!("bucket:{}", key);
        let last_refill_key = format!("refill:{}", key);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Get current bucket state
        let bucket_data = self.storage.get(&bucket_key).await?;
        let last_refill_data = self.storage.get(&last_refill_key).await?;
        
        let (mut tokens, last_refill) = match (bucket_data, last_refill_data) {
            (Some(tokens_str), Some(refill_str)) => {
                let tokens: f64 = tokens_str.parse().unwrap_or(limit as f64);
                let last_refill: u64 = refill_str.parse().unwrap_or(now);
                (tokens, last_refill)
            }
            _ => (limit as f64, now),
        };
        
        // Calculate tokens to add based on time elapsed
        let time_elapsed = now.saturating_sub(last_refill);
        let tokens_to_add = (time_elapsed as f64) * (limit as f64) / (window.as_secs() as f64);
        tokens = (tokens + tokens_to_add).min(burst_size.unwrap_or(limit) as f64);
        
        let allowed = tokens >= 1.0;
        let remaining = if allowed {
            tokens -= 1.0;
            tokens as u32
        } else {
            0
        };
        
        // Update storage
        self.storage.set(&bucket_key, &tokens.to_string(), window).await?;
        self.storage.set(&last_refill_key, &now.to_string(), window).await?;
        
        let reset_time = UNIX_EPOCH + Duration::from_secs(now + window.as_secs());
        let retry_after = if !allowed {
            Some(Duration::from_secs_f64(1.0 / (limit as f64 / window.as_secs() as f64)))
        } else {
            None
        };
        
        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_time,
            retry_after,
        })
    }

    async fn reset(&self, key: &str) -> Result<(), RateLimitError> {
        let bucket_key = format!("bucket:{}", key);
        let last_refill_key = format!("refill:{}", key);
        
        self.storage.delete(&bucket_key).await?;
        self.storage.delete(&last_refill_key).await?;
        
        Ok(())
    }
}

/// Sliding window algorithm implementation
pub struct SlidingWindowAlgorithm {
    storage: Arc<dyn RateLimitStorage>,
}

impl SlidingWindowAlgorithm {
    pub fn new(storage: Arc<dyn RateLimitStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl RateLimitAlgorithm for SlidingWindowAlgorithm {
    async fn is_allowed(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
        _burst_size: Option<u32>,
    ) -> Result<RateLimitResult, RateLimitError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let window_start = now - window.as_millis() as u64;
        let window_key = format!("window:{}:{}", key, now / 1000); // 1-second precision
        
        // Get current count in the sliding window
        let current_count = self.storage.increment(&window_key, window).await?;
        
        let allowed = current_count <= limit as u64;
        let remaining = if allowed {
            limit.saturating_sub(current_count as u32)
        } else {
            0
        };
        
        let reset_time = UNIX_EPOCH + Duration::from_millis(window_start + window.as_millis() as u64);
        let retry_after = if !allowed {
            Some(Duration::from_millis(window.as_millis() as u64 / limit as u64))
        } else {
            None
        };
        
        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_time,
            retry_after,
        })
    }

    async fn reset(&self, key: &str) -> Result<(), RateLimitError> {
        // For sliding window, we need to clear all window segments
        // This is a simplified implementation - in practice, you'd want to
        // track and clean up all relevant window keys
        self.storage.delete(&format!("window:{}", key)).await?;
        Ok(())
    }
}

/// In-memory storage implementation
pub struct InMemoryStorage {
    data: Arc<DashMap<String, (String, Instant)>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            data: Arc::new(DashMap::new()),
        }
    }
    
    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        self.data.retain(|_, (_, expiry)| *expiry > now);
    }
}

#[async_trait]
impl RateLimitStorage for InMemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, RateLimitError> {
        if let Some(entry) = self.data.get(key) {
            let (value, expiry) = entry.value();
            if *expiry > Instant::now() {
                Ok(Some(value.clone()))
            } else {
                self.data.remove(key);
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), RateLimitError> {
        let expiry = Instant::now() + ttl;
        self.data.insert(key.to_string(), (value.to_string(), expiry));
        Ok(())
    }

    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, RateLimitError> {
        let expiry = Instant::now() + ttl;
        let new_value = self.data
            .entry(key.to_string())
            .and_modify(|(value, exp)| {
                if *exp > Instant::now() {
                    let current: u64 = value.parse().unwrap_or(0);
                    *value = (current + 1).to_string();
                } else {
                    *value = "1".to_string();
                    *exp = expiry;
                }
            })
            .or_insert_with(|| ("1".to_string(), expiry));
        
        let count: u64 = new_value.0.parse().unwrap_or(1);
        Ok(count)
    }

    async fn delete(&self, key: &str) -> Result<(), RateLimitError> {
        self.data.remove(key);
        Ok(())
    }
}

/// Redis storage implementation
pub struct RedisStorage {
    client: RedisClient,
}

impl RedisStorage {
    pub async fn new(redis_url: &str) -> Result<Self, RateLimitError> {
        let client = RedisClient::open(redis_url)
            .map_err(|e| RateLimitError::Redis(e))?;
        
        Ok(Self { client })
    }
}

#[async_trait]
impl RateLimitStorage for RedisStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, RateLimitError> {
        let mut conn = self.client.get_async_connection().await?;
        let result: Option<String> = conn.get(key).await?;
        Ok(result)
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), RateLimitError> {
        let mut conn = self.client.get_async_connection().await?;
        conn.set_ex::<_, _, ()>(key, value, ttl.as_secs()).await?;
        Ok(())
    }

    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, RateLimitError> {
        let mut conn = self.client.get_async_connection().await?;
        let count: u64 = conn.incr(key, 1).await?;
        if count == 1 {
            conn.expire::<_, ()>(key, ttl.as_secs() as i64).await?;
        }
        Ok(count)
    }

    async fn delete(&self, key: &str) -> Result<(), RateLimitError> {
        let mut conn = self.client.get_async_connection().await?;
        conn.del::<_, ()>(key).await?;
        Ok(())
    }
}

/// Rate limiting key generator
pub struct RateLimitKeyGenerator;

impl RateLimitKeyGenerator {
    pub fn generate_key(
        granularity: &RateLimitGranularity,
        user_id: Option<&str>,
        service: Option<&str>,
        endpoint: Option<&str>,
        prefix: &str,
    ) -> String {
        match granularity {
            RateLimitGranularity::Global => format!("{}:global", prefix),
            RateLimitGranularity::PerUser => {
                format!("{}:user:{}", prefix, user_id.unwrap_or("anonymous"))
            }
            RateLimitGranularity::PerService => {
                format!("{}:service:{}", prefix, service.unwrap_or("unknown"))
            }
            RateLimitGranularity::PerEndpoint => {
                format!("{}:endpoint:{}", prefix, endpoint.unwrap_or("unknown"))
            }
            RateLimitGranularity::PerUserPerService => {
                format!(
                    "{}:user:{}:service:{}",
                    prefix,
                    user_id.unwrap_or("anonymous"),
                    service.unwrap_or("unknown")
                )
            }
            RateLimitGranularity::PerUserPerEndpoint => {
                format!(
                    "{}:user:{}:endpoint:{}",
                    prefix,
                    user_id.unwrap_or("anonymous"),
                    endpoint.unwrap_or("unknown")
                )
            }
        }
    }
}

/// Main rate limiter implementation
pub struct RateLimiter {
    config: RateLimitConfig,
    algorithm: Arc<dyn RateLimitAlgorithm>,
    storage: Arc<dyn RateLimitStorage>,
    metrics: RateLimitMetrics,
}

impl RateLimiter {
    pub async fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        let storage: Arc<dyn RateLimitStorage> = if config.distributed {
            if let Some(redis_url) = &config.redis_url {
                Arc::new(RedisStorage::new(redis_url).await?)
            } else {
                return Err(RateLimitError::Configuration(
                    "Redis URL required for distributed rate limiting".to_string(),
                ));
            }
        } else {
            Arc::new(InMemoryStorage::new())
        };

        let algorithm: Arc<dyn RateLimitAlgorithm> = match config.algorithm {
            RateLimitAlgorithmType::TokenBucket => {
                Arc::new(TokenBucketAlgorithm::new(storage.clone()))
            }
            RateLimitAlgorithmType::SlidingWindow => {
                Arc::new(SlidingWindowAlgorithm::new(storage.clone()))
            }
            RateLimitAlgorithmType::FixedWindow => {
                // For now, use sliding window as fixed window implementation
                Arc::new(SlidingWindowAlgorithm::new(storage.clone()))
            }
        };

        Ok(Self {
            config,
            algorithm,
            storage,
            metrics: RateLimitMetrics::new(),
        })
    }

    pub async fn is_allowed(
        &self,
        user_id: Option<&str>,
        service: Option<&str>,
        endpoint: Option<&str>,
        request_path: &str,
    ) -> Result<RateLimitResult, RateLimitError> {
        // Check admin exemptions
        if self.is_admin_exempt(request_path) {
            debug!("Request {} is admin exempt from rate limiting", request_path);
            return Ok(RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_time: SystemTime::now() + Duration::from_secs(3600),
                retry_after: None,
            });
        }

        // Get rate limit configuration for this endpoint
        let (limit, window, burst_size, granularity) = 
            self.get_endpoint_config(endpoint.unwrap_or(request_path));

        // Generate rate limiting key
        let key = RateLimitKeyGenerator::generate_key(
            &granularity,
            user_id,
            service,
            endpoint,
            &self.config.key_prefix,
        );

        debug!(
            "Checking rate limit for key: {}, limit: {}, window: {:?}",
            key, limit, window
        );

        // Check rate limit
        let result = self.algorithm.is_allowed(&key, limit, window, burst_size).await?;

        // Update metrics
        if result.allowed {
            self.metrics.requests_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
        }

        Ok(result)
    }

    pub async fn reset_limit(&self, key: &str) -> Result<(), RateLimitError> {
        self.algorithm.reset(key).await
    }

    fn is_admin_exempt(&self, path: &str) -> bool {
        self.config.admin_exemptions.iter().any(|pattern| {
            if pattern.ends_with("*") {
                path.starts_with(&pattern[..pattern.len() - 1])
            } else {
                path == pattern
            }
        })
    }

    fn get_endpoint_config(&self, endpoint: &str) -> (u32, Duration, Option<u32>, RateLimitGranularity) {
        if let Some(endpoint_config) = self.config.endpoint_rules.get(endpoint) {
            (
                endpoint_config.requests_per_window,
                endpoint_config.window_duration,
                endpoint_config.burst_size,
                endpoint_config.granularity.clone(),
            )
        } else {
            (
                self.config.requests_per_window,
                self.config.window_duration,
                self.config.burst_size,
                self.config.granularity.clone(),
            )
        }
    }

    pub fn get_metrics(&self) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            requests_allowed: self.metrics.requests_allowed.load(Ordering::Relaxed),
            requests_denied: self.metrics.requests_denied.load(Ordering::Relaxed),
        }
    }

    pub fn get_config(&self) -> &RateLimitConfig {
        &self.config
    }

    pub async fn update_config(&mut self, new_config: RateLimitConfig) -> Result<(), RateLimitError> {
        // Validate new configuration
        if new_config.distributed && new_config.redis_url.is_none() {
            return Err(RateLimitError::Configuration(
                "Redis URL required for distributed rate limiting".to_string(),
            ));
        }

        // Create new storage and algorithm if needed
        if new_config.distributed != self.config.distributed 
            || new_config.algorithm != self.config.algorithm 
            || new_config.redis_url != self.config.redis_url {
            
            let storage: Arc<dyn RateLimitStorage> = if new_config.distributed {
                if let Some(redis_url) = &new_config.redis_url {
                    Arc::new(RedisStorage::new(redis_url).await?)
                } else {
                    return Err(RateLimitError::Configuration(
                        "Redis URL required for distributed rate limiting".to_string(),
                    ));
                }
            } else {
                Arc::new(InMemoryStorage::new())
            };

            let algorithm: Arc<dyn RateLimitAlgorithm> = match new_config.algorithm {
                RateLimitAlgorithmType::TokenBucket => {
                    Arc::new(TokenBucketAlgorithm::new(storage.clone()))
                }
                RateLimitAlgorithmType::SlidingWindow => {
                    Arc::new(SlidingWindowAlgorithm::new(storage.clone()))
                }
                RateLimitAlgorithmType::FixedWindow => {
                    Arc::new(SlidingWindowAlgorithm::new(storage.clone()))
                }
            };

            self.storage = storage;
            self.algorithm = algorithm;
        }

        self.config = new_config;
        Ok(())
    }
}

/// Rate limiting metrics
#[derive(Debug)]
pub struct RateLimitMetrics {
    pub requests_allowed: AtomicU64,
    pub requests_denied: AtomicU64,
}

impl RateLimitMetrics {
    pub fn new() -> Self {
        Self {
            requests_allowed: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
        }
    }
}

/// Snapshot of rate limiting metrics
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitMetricsSnapshot {
    pub requests_allowed: u64,
    pub requests_denied: u64,
}

/// Rate limiting middleware for HTTP requests
pub struct RateLimitMiddleware {
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl RateLimitMiddleware {
    pub async fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        let rate_limiter = RateLimiter::new(config).await?;
        Ok(Self {
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
        })
    }

    pub async fn check_rate_limit(
        &self,
        user_id: Option<&str>,
        service: Option<&str>,
        endpoint: Option<&str>,
        request_path: &str,
    ) -> Result<RateLimitResult, RateLimitError> {
        let limiter = self.rate_limiter.read().await;
        limiter.is_allowed(user_id, service, endpoint, request_path).await
    }

    pub async fn get_metrics(&self) -> RateLimitMetricsSnapshot {
        let limiter = self.rate_limiter.read().await;
        limiter.get_metrics()
    }

    pub async fn get_config(&self) -> RateLimitConfig {
        let limiter = self.rate_limiter.read().await;
        limiter.get_config().clone()
    }

    pub async fn update_config(&self, new_config: RateLimitConfig) -> Result<(), RateLimitError> {
        let mut limiter = self.rate_limiter.write().await;
        limiter.update_config(new_config).await
    }

    pub async fn reset_limit(&self, key: &str) -> Result<(), RateLimitError> {
        let limiter = self.rate_limiter.read().await;
        limiter.reset_limit(key).await
    }

    /// Get read access to the internal rate limiter
    pub async fn get_rate_limiter_read(&self) -> tokio::sync::RwLockReadGuard<'_, RateLimiter> {
        self.rate_limiter.read().await
    }

    /// Get write access to the internal rate limiter
    pub async fn get_rate_limiter_write(&self) -> tokio::sync::RwLockWriteGuard<'_, RateLimiter> {
        self.rate_limiter.write().await
    }
}
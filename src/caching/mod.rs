//! # Caching System Module
//!
//! This module provides a comprehensive multi-level caching system for the API Gateway.
//! It supports both in-memory and Redis-based distributed caching with configurable
//! TTL, cache key generation strategies, and invalidation mechanisms.
//!
//! ## Features
//! - Multi-level caching (in-memory + Redis)
//! - Request/response caching with TTL support
//! - Configurable cache key generation strategies
//! - Cache invalidation mechanisms
//! - Request deduplication and idempotency
//! - Admin endpoints for cache management
//! - Performance and correctness testing
//!
//! ## Architecture
//! The caching system follows a layered approach:
//! 1. **Cache Manager**: Coordinates between different cache levels
//! 2. **Cache Stores**: In-memory and Redis implementations
//! 3. **Key Generators**: Pluggable strategies for cache key generation
//! 4. **Invalidation**: Mechanisms for cache invalidation
//! 5. **Admin Interface**: Management endpoints for cache operations
//!
//! ## Usage Example
//! ```rust
//! use std::sync::Arc;
//! use crate::caching::{CacheManager, CacheConfig, InMemoryCache, RedisCache};
//!
//! // Create cache configuration
//! let config = CacheConfig::default();
//!
//! // Create cache manager with both in-memory and Redis
//! let cache_manager = CacheManager::new(config).await?;
//!
//! // Cache a response
//! let key = "user:123:profile";
//! let response_data = b"user profile data";
//! cache_manager.set(key, response_data, Duration::from_secs(300)).await?;
//!
//! // Retrieve cached response
//! if let Some(cached_data) = cache_manager.get(key).await? {
//!     // Use cached data
//! }
//! ```

pub mod cache_manager;
pub mod stores;
pub mod key_generator;
pub mod invalidation;
pub mod deduplication;
pub mod admin;
pub mod middleware;

pub use cache_manager::{CacheManager, CacheConfig, CacheLevel, CacheStats};
pub use stores::{CacheStore, InMemoryCache, RedisCache, CacheEntry};
pub use key_generator::{KeyGenerator, DefaultKeyGenerator, CustomKeyGenerator, KeyGenerationStrategy};
pub use invalidation::{InvalidationManager, InvalidationStrategy, InvalidationEvent};
pub use deduplication::{DeduplicationManager, IdempotencyManager, RequestDeduplicator};
pub use admin::{CacheAdminRouter, CacheAdminState};
pub use middleware::{CacheMiddleware, CachePolicy};

use crate::core::error::GatewayError;
// use std::time::Duration;

/// Cache operation result
pub type CacheResult<T> = Result<T, CacheError>;

/// Cache-specific error types
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Cache store error: {message}")]
    Store { message: String },
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("Key generation error: {message}")]
    KeyGeneration { message: String },
    
    #[error("Cache configuration error: {message}")]
    Configuration { message: String },
    
    #[error("Cache operation timeout")]
    Timeout,
    
    #[error("Cache not available")]
    Unavailable,
}

impl From<CacheError> for GatewayError {
    fn from(err: CacheError) -> Self {
        GatewayError::internal(format!("Cache error: {}", err))
    }
}
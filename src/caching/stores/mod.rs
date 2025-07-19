//! # Cache Stores Module
//!
//! This module provides different cache store implementations including
//! in-memory and Redis-based caching.

pub mod memory;
pub mod redis_store;

pub use memory::{InMemoryCache, InMemoryCacheConfig};
pub use redis_store::{RedisCache, RedisCacheConfig};

use super::{CacheError, CacheResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cached value
    pub value: Vec<u8>,
    
    /// When the entry was created
    pub created_at: u64,
    
    /// When the entry expires (Unix timestamp)
    pub expires_at: u64,
    
    /// Number of times this entry has been accessed
    pub access_count: u64,
    
    /// Last access timestamp
    pub last_accessed: u64,
    
    /// Size of the entry in bytes
    pub size: usize,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(value: Vec<u8>, ttl: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let size = value.len() + std::mem::size_of::<Self>();
        
        Self {
            value,
            created_at: now,
            expires_at: now + ttl.as_secs(),
            access_count: 0,
            last_accessed: now,
            size,
        }
    }

    /// Check if the entry is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now > self.expires_at
    }

    /// Mark the entry as accessed
    pub fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Get the age of the entry in seconds
    pub fn age(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now.saturating_sub(self.created_at)
    }

    /// Get time until expiration in seconds
    pub fn ttl(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.expires_at.saturating_sub(now)
    }
}

/// Trait for cache store implementations
#[async_trait]
pub trait CacheStore: Send + Sync {
    /// Get a value from the cache
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>>;
    
    /// Set a value in the cache with TTL
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()>;
    
    /// Delete a value from the cache
    async fn delete(&self, key: &str) -> CacheResult<bool>;
    
    /// Check if a key exists in the cache
    async fn exists(&self, key: &str) -> CacheResult<bool>;
    
    /// Clear all entries from the cache
    async fn clear(&self) -> CacheResult<()>;
    
    /// Get cache statistics
    async fn stats(&self) -> CacheResult<CacheStoreStats>;
    
    /// Perform health check
    async fn health_check(&self) -> CacheResult<bool>;
}

/// Cache store statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStoreStats {
    /// Number of entries
    pub entries: usize,
    
    /// Total memory usage in bytes
    pub memory_usage: usize,
    
    /// Number of hits
    pub hits: u64,
    
    /// Number of misses
    pub misses: u64,
    
    /// Number of evictions
    pub evictions: u64,
    
    /// Number of expired entries cleaned up
    pub expired_cleanups: u64,
}

impl Default for CacheStoreStats {
    fn default() -> Self {
        Self {
            entries: 0,
            memory_usage: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
            expired_cleanups: 0,
        }
    }
}
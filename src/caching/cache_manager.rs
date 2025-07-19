//! # Cache Manager
//!
//! The cache manager coordinates between different cache levels (in-memory and Redis)
//! and provides a unified interface for caching operations.

use super::{CacheError, CacheResult, CacheStore, InMemoryCache, RedisCache};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable in-memory caching
    pub in_memory_enabled: bool,
    
    /// In-memory cache configuration
    pub in_memory: InMemoryCacheConfig,
    
    /// Enable Redis caching
    pub redis_enabled: bool,
    
    /// Redis cache configuration
    pub redis: RedisCacheConfig,
    
    /// Default TTL for cached items
    pub default_ttl: Duration,
    
    /// Maximum cache key length
    pub max_key_length: usize,
    
    /// Cache operation timeout
    pub operation_timeout: Duration,
    
    /// Enable cache statistics
    pub enable_stats: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryCacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCacheConfig {
    /// Redis connection URL
    pub url: String,
    
    /// Connection pool size
    pub pool_size: u32,
    
    /// Connection timeout
    pub connection_timeout: Duration,
    
    /// Key prefix for all cache entries
    pub key_prefix: String,
    
    /// Enable Redis cluster mode
    pub cluster_mode: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            in_memory_enabled: true,
            in_memory: InMemoryCacheConfig {
                max_entries: 10000,
                max_memory_bytes: 100 * 1024 * 1024, // 100MB
                cleanup_interval: Duration::from_secs(60),
            },
            redis_enabled: false,
            redis: RedisCacheConfig {
                url: "redis://localhost:6379".to_string(),
                pool_size: 10,
                connection_timeout: Duration::from_secs(5),
                key_prefix: "gateway:cache:".to_string(),
                cluster_mode: false,
            },
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_key_length: 250,
            operation_timeout: Duration::from_secs(1),
            enable_stats: true,
        }
    }
}

/// Cache level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLevel {
    /// In-memory cache (L1)
    Memory,
    /// Redis cache (L2)
    Redis,
    /// Both levels
    Both,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache hits
    pub hits: u64,
    
    /// Total cache misses
    pub misses: u64,
    
    /// Cache hit ratio
    pub hit_ratio: f64,
    
    /// Total cache operations
    pub operations: u64,
    
    /// Memory cache statistics
    pub memory_stats: MemoryCacheStats,
    
    /// Redis cache statistics
    pub redis_stats: RedisCacheStats,
    
    /// Statistics collection start time
    pub start_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCacheStats {
    /// Number of entries in memory cache
    pub entries: usize,
    
    /// Estimated memory usage in bytes
    pub memory_usage: usize,
    
    /// Memory cache hits
    pub hits: u64,
    
    /// Memory cache misses
    pub misses: u64,
    
    /// Number of evictions
    pub evictions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCacheStats {
    /// Redis cache hits
    pub hits: u64,
    
    /// Redis cache misses
    pub misses: u64,
    
    /// Redis connection errors
    pub connection_errors: u64,
    
    /// Redis operation timeouts
    pub timeouts: u64,
}

impl Default for CacheStats {
    fn default() -> Self {
        Self {
            hits: 0,
            misses: 0,
            hit_ratio: 0.0,
            operations: 0,
            memory_stats: MemoryCacheStats {
                entries: 0,
                memory_usage: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
            },
            redis_stats: RedisCacheStats {
                hits: 0,
                misses: 0,
                connection_errors: 0,
                timeouts: 0,
            },
            start_time: chrono::Utc::now(),
        }
    }
}

/// Multi-level cache manager
pub struct CacheManager {
    /// Configuration
    config: CacheConfig,
    
    /// In-memory cache (L1)
    memory_cache: Option<Arc<InMemoryCache>>,
    
    /// Redis cache (L2)
    redis_cache: Option<Arc<RedisCache>>,
    
    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
}

impl CacheManager {
    /// Create a new cache manager
    pub async fn new(config: CacheConfig) -> CacheResult<Self> {
        let mut memory_cache = None;
        let mut redis_cache = None;

        // Initialize in-memory cache if enabled
        if config.in_memory_enabled {
            let memory_config = super::stores::memory::InMemoryCacheConfig {
                max_entries: config.in_memory.max_entries,
                max_memory_bytes: config.in_memory.max_memory_bytes,
                cleanup_interval: config.in_memory.cleanup_interval,
                enable_lru: true,
            };
            memory_cache = Some(Arc::new(InMemoryCache::new(memory_config)?));
            info!("In-memory cache initialized with max {} entries", config.in_memory.max_entries);
        }

        // Initialize Redis cache if enabled
        if config.redis_enabled {
            let redis_config = super::stores::redis_store::RedisCacheConfig {
                url: config.redis.url.clone(),
                pool_size: config.redis.pool_size,
                connection_timeout: config.redis.connection_timeout,
                key_prefix: config.redis.key_prefix.clone(),
                cluster_mode: config.redis.cluster_mode,
                max_retries: 3,
                retry_delay: std::time::Duration::from_millis(100),
            };
            redis_cache = Some(Arc::new(RedisCache::new(redis_config).await?));
            info!("Redis cache initialized at {}", config.redis.url);
        }

        if memory_cache.is_none() && redis_cache.is_none() {
            return Err(CacheError::Configuration {
                message: "At least one cache level must be enabled".to_string(),
            });
        }

        Ok(Self {
            config,
            memory_cache,
            redis_cache,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        })
    }

    /// Get a value from cache
    pub async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.validate_key(key)?;
        
        let start = Instant::now();
        let result = self.get_internal(key).await;
        
        // Update statistics
        if self.config.enable_stats {
            self.update_stats(result.is_ok() && result.as_ref().unwrap().is_some(), start.elapsed()).await;
        }
        
        result
    }

    /// Set a value in cache
    pub async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        self.validate_key(key)?;
        
        let start = Instant::now();
        let result = self.set_internal(key, value, ttl).await;
        
        // Update statistics
        if self.config.enable_stats {
            self.update_operation_stats(start.elapsed()).await;
        }
        
        result
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &str) -> CacheResult<bool> {
        self.validate_key(key)?;
        
        let start = Instant::now();
        let result = self.delete_internal(key).await;
        
        // Update statistics
        if self.config.enable_stats {
            self.update_operation_stats(start.elapsed()).await;
        }
        
        result
    }

    /// Check if a key exists in cache
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        self.validate_key(key)?;
        
        // Check memory cache first
        if let Some(memory_cache) = &self.memory_cache {
            if memory_cache.exists(key).await? {
                return Ok(true);
            }
        }

        // Check Redis cache
        if let Some(redis_cache) = &self.redis_cache {
            return redis_cache.exists(key).await;
        }

        Ok(false)
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> CacheResult<()> {
        let mut errors = Vec::new();

        // Clear memory cache
        if let Some(memory_cache) = &self.memory_cache {
            if let Err(e) = memory_cache.clear().await {
                errors.push(format!("Memory cache clear error: {}", e));
            }
        }

        // Clear Redis cache
        if let Some(redis_cache) = &self.redis_cache {
            if let Err(e) = redis_cache.clear().await {
                errors.push(format!("Redis cache clear error: {}", e));
            }
        }

        if !errors.is_empty() {
            return Err(CacheError::Store {
                message: errors.join("; "),
            });
        }

        info!("All cache levels cleared");
        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let mut stats = self.stats.read().await.clone();
        
        // Update memory cache stats
        if let Some(memory_cache) = &self.memory_cache {
            if let Ok(memory_store_stats) = memory_cache.stats().await {
                stats.memory_stats = MemoryCacheStats {
                    entries: memory_store_stats.entries,
                    memory_usage: memory_store_stats.memory_usage,
                    hits: memory_store_stats.hits,
                    misses: memory_store_stats.misses,
                    evictions: memory_store_stats.evictions,
                };
            }
        }

        // Calculate hit ratio
        if stats.operations > 0 {
            stats.hit_ratio = stats.hits as f64 / stats.operations as f64;
        }

        stats
    }

    /// Reset cache statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = CacheStats::default();
        info!("Cache statistics reset");
    }

    /// Get cache configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Check if cache is healthy
    pub async fn health_check(&self) -> CacheResult<bool> {
        let mut healthy = true;

        // Check memory cache health
        if let Some(memory_cache) = &self.memory_cache {
            if !memory_cache.health_check().await? {
                healthy = false;
                warn!("Memory cache health check failed");
            }
        }

        // Check Redis cache health
        if let Some(redis_cache) = &self.redis_cache {
            if !redis_cache.health_check().await? {
                healthy = false;
                warn!("Redis cache health check failed");
            }
        }

        Ok(healthy)
    }

    /// Internal get implementation with cache level coordination
    async fn get_internal(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        // Try memory cache first (L1)
        if let Some(memory_cache) = &self.memory_cache {
            match memory_cache.get(key).await {
                Ok(Some(value)) => {
                    debug!("Cache hit in memory cache for key: {}", key);
                    return Ok(Some(value));
                }
                Ok(None) => {
                    debug!("Cache miss in memory cache for key: {}", key);
                }
                Err(e) => {
                    warn!("Memory cache error for key {}: {}", key, e);
                }
            }
        }

        // Try Redis cache (L2)
        if let Some(redis_cache) = &self.redis_cache {
            match redis_cache.get(key).await {
                Ok(Some(value)) => {
                    debug!("Cache hit in Redis cache for key: {}", key);
                    
                    // Populate memory cache with the value from Redis
                    if let Some(memory_cache) = &self.memory_cache {
                        if let Err(e) = memory_cache.set(key, &value, self.config.default_ttl).await {
                            warn!("Failed to populate memory cache from Redis for key {}: {}", key, e);
                        }
                    }
                    
                    return Ok(Some(value));
                }
                Ok(None) => {
                    debug!("Cache miss in Redis cache for key: {}", key);
                }
                Err(e) => {
                    warn!("Redis cache error for key {}: {}", key, e);
                }
            }
        }

        Ok(None)
    }

    /// Internal set implementation with cache level coordination
    async fn set_internal(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        let mut errors = Vec::new();

        // Set in memory cache (L1)
        if let Some(memory_cache) = &self.memory_cache {
            if let Err(e) = memory_cache.set(key, value, ttl).await {
                errors.push(format!("Memory cache set error: {}", e));
            }
        }

        // Set in Redis cache (L2)
        if let Some(redis_cache) = &self.redis_cache {
            if let Err(e) = redis_cache.set(key, value, ttl).await {
                errors.push(format!("Redis cache set error: {}", e));
            }
        }

        if !errors.is_empty() {
            error!("Cache set errors for key {}: {}", key, errors.join("; "));
            return Err(CacheError::Store {
                message: errors.join("; "),
            });
        }

        debug!("Successfully cached key: {} with TTL: {:?}", key, ttl);
        Ok(())
    }

    /// Internal delete implementation with cache level coordination
    async fn delete_internal(&self, key: &str) -> CacheResult<bool> {
        let mut deleted = false;

        // Delete from memory cache
        if let Some(memory_cache) = &self.memory_cache {
            match memory_cache.delete(key).await {
                Ok(was_deleted) => {
                    if was_deleted {
                        deleted = true;
                    }
                }
                Err(e) => {
                    warn!("Memory cache delete error for key {}: {}", key, e);
                }
            }
        }

        // Delete from Redis cache
        if let Some(redis_cache) = &self.redis_cache {
            match redis_cache.delete(key).await {
                Ok(was_deleted) => {
                    if was_deleted {
                        deleted = true;
                    }
                }
                Err(e) => {
                    warn!("Redis cache delete error for key {}: {}", key, e);
                }
            }
        }

        if deleted {
            debug!("Successfully deleted key from cache: {}", key);
        }

        Ok(deleted)
    }

    /// Validate cache key
    fn validate_key(&self, key: &str) -> CacheResult<()> {
        if key.is_empty() {
            return Err(CacheError::KeyGeneration {
                message: "Cache key cannot be empty".to_string(),
            });
        }

        if key.len() > self.config.max_key_length {
            return Err(CacheError::KeyGeneration {
                message: format!(
                    "Cache key length {} exceeds maximum {}",
                    key.len(),
                    self.config.max_key_length
                ),
            });
        }

        Ok(())
    }

    /// Update cache statistics for get operations
    async fn update_stats(&self, hit: bool, _duration: Duration) {
        let mut stats = self.stats.write().await;
        stats.operations += 1;
        
        if hit {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
    }

    /// Update cache statistics for other operations
    async fn update_operation_stats(&self, _duration: Duration) {
        let mut stats = self.stats.write().await;
        stats.operations += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_cache_manager_creation() {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            ..Default::default()
        };

        let cache_manager = CacheManager::new(config).await.unwrap();
        assert!(cache_manager.memory_cache.is_some());
        assert!(cache_manager.redis_cache.is_none());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            ..Default::default()
        };

        let cache_manager = CacheManager::new(config).await.unwrap();
        
        let key = "test_key";
        let value = b"test_value";
        let ttl = Duration::from_secs(60);

        // Test set
        cache_manager.set(key, value, ttl).await.unwrap();

        // Test get
        let cached_value = cache_manager.get(key).await.unwrap();
        assert_eq!(cached_value, Some(value.to_vec()));

        // Test exists
        assert!(cache_manager.exists(key).await.unwrap());

        // Test delete
        assert!(cache_manager.delete(key).await.unwrap());
        assert!(!cache_manager.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_key_validation() {
        let config = CacheConfig {
            max_key_length: 10,
            ..Default::default()
        };

        let cache_manager = CacheManager::new(config).await.unwrap();

        // Test empty key
        let result = cache_manager.get("").await;
        assert!(result.is_err());

        // Test key too long
        let long_key = "a".repeat(20);
        let result = cache_manager.get(&long_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            enable_stats: true,
            ..Default::default()
        };

        let cache_manager = CacheManager::new(config).await.unwrap();
        
        // Perform some operations
        cache_manager.set("key1", b"value1", Duration::from_secs(60)).await.unwrap();
        cache_manager.get("key1").await.unwrap(); // Hit
        cache_manager.get("key2").await.unwrap(); // Miss

        let stats = cache_manager.stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.operations, 3); // 1 set + 2 gets
    }
}
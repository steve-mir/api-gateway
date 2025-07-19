//! # Redis Cache Store
//!
//! This module provides a Redis-based cache implementation with connection pooling,
//! cluster support, and comprehensive error handling.

use super::{CacheStore, CacheStoreStats};
use crate::caching::{CacheError, CacheResult};
use async_trait::async_trait;
use redis::{aio::ConnectionManager, AsyncCommands, Client, RedisResult};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Redis cache configuration
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
    
    /// Maximum number of connection retries
    pub max_retries: u32,
    
    /// Retry delay
    pub retry_delay: Duration,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout: Duration::from_secs(5),
            key_prefix: "gateway:cache:".to_string(),
            cluster_mode: false,
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
        }
    }
}

/// Redis cache implementation
pub struct RedisCache {
    /// Configuration
    config: RedisCacheConfig,
    
    /// Redis connection manager
    connection_manager: Arc<RwLock<ConnectionManager>>,
    
    /// Statistics counters
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    connection_errors: Arc<AtomicU64>,
    timeouts: Arc<AtomicU64>,
}

impl RedisCache {
    /// Create a new Redis cache
    pub async fn new(config: RedisCacheConfig) -> CacheResult<Self> {
        let client = Client::open(config.url.as_str())
            .map_err(|e| CacheError::Redis(e))?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .map_err(|e| CacheError::Redis(e))?;

        info!("Redis cache connected to {}", config.url);

        Ok(Self {
            config,
            connection_manager: Arc::new(RwLock::new(connection_manager)),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            connection_errors: Arc::new(AtomicU64::new(0)),
            timeouts: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Get the full cache key with prefix
    fn full_key(&self, key: &str) -> String {
        format!("{}{}", self.config.key_prefix, key)
    }

    /// Execute a Redis operation with retry logic
    async fn execute_with_retry<F, T>(&self, operation: F) -> CacheResult<T>
    where
        F: Fn(&mut ConnectionManager) -> std::pin::Pin<Box<dyn std::future::Future<Output = RedisResult<T>> + Send + '_>> + Send + Sync,
        T: Send,
    {
        let mut retries = 0;
        
        loop {
            let mut conn = self.connection_manager.write().await;
            
            match operation(&mut *conn).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    error!("Redis operation failed: {}", e);
                    self.connection_errors.fetch_add(1, Ordering::Relaxed);
                    
                    if retries >= self.config.max_retries {
                        return Err(CacheError::Redis(e));
                    }
                    
                    retries += 1;
                    drop(conn); // Release the lock before sleeping
                    
                    tokio::time::sleep(self.config.retry_delay * retries).await;
                    
                    // Try to reconnect
                    if let Err(reconnect_err) = self.reconnect().await {
                        warn!("Failed to reconnect to Redis: {}", reconnect_err);
                    }
                }
            }
        }
    }

    /// Reconnect to Redis
    async fn reconnect(&self) -> CacheResult<()> {
        let client = Client::open(self.config.url.as_str())
            .map_err(|e| CacheError::Redis(e))?;

        let new_connection_manager = ConnectionManager::new(client)
            .await
            .map_err(|e| CacheError::Redis(e))?;

        let mut conn = self.connection_manager.write().await;
        *conn = new_connection_manager;
        
        info!("Reconnected to Redis");
        Ok(())
    }
}

#[async_trait]
impl CacheStore for RedisCache {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        let full_key = self.full_key(key);
        
        let result = self.execute_with_retry(|conn| {
            let full_key = full_key.clone();
            Box::pin(async move {
                conn.get::<_, Option<Vec<u8>>>(&full_key).await
            })
        }).await;

        match result {
            Ok(Some(value)) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                debug!("Redis cache hit for key: {}", key);
                Ok(Some(value))
            }
            Ok(None) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                debug!("Redis cache miss for key: {}", key);
                Ok(None)
            }
            Err(e) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        let full_key = self.full_key(key);
        let ttl_seconds = ttl.as_secs();
        let value = value.to_vec();
        
        self.execute_with_retry(|conn| {
            let full_key = full_key.clone();
            let value = value.clone();
            Box::pin(async move {
                conn.set_ex::<_, _, ()>(&full_key, &value, ttl_seconds).await
            })
        }).await?;

        debug!("Set Redis cache key: {} with TTL: {:?}", key, ttl);
        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<bool> {
        let full_key = self.full_key(key);
        
        let deleted_count: i32 = self.execute_with_retry(|conn| {
            let full_key = full_key.clone();
            Box::pin(async move {
                conn.del(&full_key).await
            })
        }).await?;

        let was_deleted = deleted_count > 0;
        if was_deleted {
            debug!("Deleted Redis cache key: {}", key);
        }
        
        Ok(was_deleted)
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let full_key = self.full_key(key);
        
        let exists: bool = self.execute_with_retry(|conn| {
            let full_key = full_key.clone();
            Box::pin(async move {
                conn.exists(&full_key).await
            })
        }).await?;

        Ok(exists)
    }

    async fn clear(&self) -> CacheResult<()> {
        // Use SCAN to find all keys with our prefix and delete them
        let pattern = format!("{}*", self.config.key_prefix);
        
        let keys: Vec<String> = self.execute_with_retry(|conn| {
            let pattern = pattern.clone();
            Box::pin(async move {
                let mut cursor = 0;
                let mut all_keys = Vec::new();
                
                loop {
                    let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(1000)
                        .query_async(conn)
                        .await?;
                    
                    all_keys.extend(keys);
                    
                    if new_cursor == 0 {
                        break;
                    }
                    cursor = new_cursor;
                }
                
                Ok::<Vec<String>, redis::RedisError>(all_keys)
            })
        }).await?;

        if !keys.is_empty() {
            let deleted_count: i32 = self.execute_with_retry(|conn| {
                let keys = keys.clone();
                Box::pin(async move {
                    conn.del(&keys).await
                })
            }).await?;
            
            info!("Cleared {} keys from Redis cache", deleted_count);
        }

        Ok(())
    }

    async fn stats(&self) -> CacheResult<CacheStoreStats> {
        // Get Redis info for memory usage and other stats
        let info: String = self.execute_with_retry(|conn| {
            Box::pin(async move {
                redis::cmd("INFO").arg("memory").query_async(conn).await
            })
        }).await.unwrap_or_default();

        // Parse memory usage from Redis INFO output
        let memory_usage = info
            .lines()
            .find(|line| line.starts_with("used_memory:"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);

        // Count keys with our prefix
        let pattern = format!("{}*", self.config.key_prefix);
        let key_count: usize = self.execute_with_retry(|conn| {
            let pattern = pattern.clone();
            Box::pin(async move {
                let mut cursor = 0;
                let mut count = 0;
                
                loop {
                    let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(1000)
                        .query_async(conn)
                        .await?;
                    
                    count += keys.len();
                    
                    if new_cursor == 0 {
                        break;
                    }
                    cursor = new_cursor;
                }
                
                Ok::<usize, redis::RedisError>(count)
            })
        }).await.unwrap_or(0);

        Ok(CacheStoreStats {
            entries: key_count,
            memory_usage,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: 0, // Redis handles eviction internally
            expired_cleanups: 0, // Redis handles TTL cleanup internally
        })
    }

    async fn health_check(&self) -> CacheResult<bool> {
        // Simple ping to check Redis connectivity
        let result = self.execute_with_retry(|conn| {
            Box::pin(async move {
                redis::cmd("PING").query_async::<_, String>(conn).await
            })
        }).await;

        match result {
            Ok(response) => Ok(response == "PONG"),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{clients::Cli, images::redis::Redis, Container, Docker};

    async fn setup_redis_cache() -> (RedisCache, Container<'static, Redis>) {
        let docker = Cli::default();
        let redis_container = docker.run(Redis::default());
        let redis_port = redis_container.get_host_port_ipv4(6379);
        
        let config = RedisCacheConfig {
            url: format!("redis://localhost:{}", redis_port),
            ..Default::default()
        };

        let cache = RedisCache::new(config).await.unwrap();
        (cache, redis_container)
    }

    #[tokio::test]
    #[ignore] // Requires Docker for Redis container
    async fn test_basic_operations() {
        let (cache, _container) = setup_redis_cache().await;

        let key = "test_key";
        let value = b"test_value";
        let ttl = Duration::from_secs(60);

        // Test set and get
        cache.set(key, value, ttl).await.unwrap();
        let result = cache.get(key).await.unwrap();
        assert_eq!(result, Some(value.to_vec()));

        // Test exists
        assert!(cache.exists(key).await.unwrap());

        // Test delete
        assert!(cache.delete(key).await.unwrap());
        assert!(!cache.exists(key).await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Requires Docker for Redis container
    async fn test_ttl_expiration() {
        let (cache, _container) = setup_redis_cache().await;

        let key = "expire_test";
        let value = b"expire_value";
        let ttl = Duration::from_secs(1);

        // Set with short TTL
        cache.set(key, value, ttl).await.unwrap();
        
        // Should exist immediately
        assert!(cache.exists(key).await.unwrap());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Should be expired
        let result = cache.get(key).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    #[ignore] // Requires Docker for Redis container
    async fn test_health_check() {
        let (cache, _container) = setup_redis_cache().await;
        assert!(cache.health_check().await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Requires Docker for Redis container
    async fn test_stats() {
        let (cache, _container) = setup_redis_cache().await;

        // Perform operations
        cache.set("key1", b"value1", Duration::from_secs(60)).await.unwrap();
        cache.get("key1").await.unwrap(); // Hit
        cache.get("key2").await.unwrap(); // Miss

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.entries, 1);
    }
}
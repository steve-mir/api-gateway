//! # In-Memory Cache Store
//!
//! This module provides a high-performance in-memory cache implementation
//! with LRU eviction, TTL support, and automatic cleanup of expired entries.

use super::{CacheEntry, CacheStore, CacheStoreStats};
use crate::caching::{CacheError, CacheResult};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info};

/// In-memory cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryCacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
    
    /// Enable LRU eviction
    pub enable_lru: bool,
}

impl Default for InMemoryCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            cleanup_interval: Duration::from_secs(60),
            enable_lru: true,
        }
    }
}

/// LRU tracking for cache entries
#[derive(Debug)]
struct LruEntry {
    key: String,
    access_time: u64,
}

/// In-memory cache implementation
pub struct InMemoryCache {
    /// Configuration
    config: InMemoryCacheConfig,
    
    /// Cache entries storage
    entries: Arc<DashMap<String, CacheEntry>>,
    
    /// LRU tracking (key -> access_time)
    lru_tracker: Arc<RwLock<Vec<LruEntry>>>,
    
    /// Statistics
    stats: Arc<CacheStoreStats>,
    
    /// Atomic counters for statistics
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    evictions: Arc<AtomicU64>,
    expired_cleanups: Arc<AtomicU64>,
    
    /// Current memory usage estimate
    memory_usage: Arc<AtomicUsize>,
    
    /// Cleanup task handle
    _cleanup_task: tokio::task::JoinHandle<()>,
}

impl InMemoryCache {
    /// Create a new in-memory cache
    pub fn new(config: InMemoryCacheConfig) -> CacheResult<Self> {
        let entries = Arc::new(DashMap::new());
        let lru_tracker = Arc::new(RwLock::new(Vec::new()));
        let hits = Arc::new(AtomicU64::new(0));
        let misses = Arc::new(AtomicU64::new(0));
        let evictions = Arc::new(AtomicU64::new(0));
        let expired_cleanups = Arc::new(AtomicU64::new(0));
        let memory_usage = Arc::new(AtomicUsize::new(0));

        // Start cleanup task
        let cleanup_task = {
            let entries = entries.clone();
            let expired_cleanups = expired_cleanups.clone();
            let memory_usage = memory_usage.clone();
            let cleanup_interval = config.cleanup_interval;
            
            tokio::spawn(async move {
                let mut interval = interval(cleanup_interval);
                loop {
                    interval.tick().await;
                    Self::cleanup_expired_entries(&entries, &expired_cleanups, &memory_usage).await;
                }
            })
        };

        Ok(Self {
            config,
            entries,
            lru_tracker,
            stats: Arc::new(CacheStoreStats::default()),
            hits,
            misses,
            evictions,
            expired_cleanups,
            memory_usage,
            _cleanup_task: cleanup_task,
        })
    }

    /// Cleanup expired entries
    async fn cleanup_expired_entries(
        entries: &DashMap<String, CacheEntry>,
        expired_cleanups: &AtomicU64,
        memory_usage: &AtomicUsize,
    ) {
        let mut expired_keys = Vec::new();
        
        // Find expired entries
        for entry in entries.iter() {
            if entry.value().is_expired() {
                expired_keys.push(entry.key().clone());
            }
        }

        // Remove expired entries
        let mut cleaned_count = 0;
        let mut freed_memory = 0;
        
        for key in expired_keys {
            if let Some((_, entry)) = entries.remove(&key) {
                freed_memory += entry.size;
                cleaned_count += 1;
            }
        }

        if cleaned_count > 0 {
            memory_usage.fetch_sub(freed_memory, Ordering::Relaxed);
            expired_cleanups.fetch_add(cleaned_count, Ordering::Relaxed);
            debug!("Cleaned up {} expired cache entries, freed {} bytes", cleaned_count, freed_memory);
        }
    }

    /// Evict entries to make space
    async fn evict_if_needed(&self) -> CacheResult<()> {
        let current_entries = self.entries.len();
        let current_memory = self.memory_usage.load(Ordering::Relaxed);

        // Check if eviction is needed
        let needs_eviction = current_entries >= self.config.max_entries
            || current_memory >= self.config.max_memory_bytes;

        if !needs_eviction {
            return Ok(());
        }

        if !self.config.enable_lru {
            return Err(CacheError::Store {
                message: "Cache is full and LRU eviction is disabled".to_string(),
            });
        }

        // Perform LRU eviction
        let evict_count = std::cmp::max(
            current_entries.saturating_sub(self.config.max_entries * 9 / 10), // Keep 90% of max entries
            1,
        );

        self.evict_lru_entries(evict_count).await?;
        
        Ok(())
    }

    /// Evict LRU entries
    async fn evict_lru_entries(&self, count: usize) -> CacheResult<()> {
        let mut lru_tracker = self.lru_tracker.write().await;
        
        // Sort by access time (oldest first)
        lru_tracker.sort_by_key(|entry| entry.access_time);
        
        let mut evicted_count = 0;
        let mut freed_memory = 0;
        
        // Remove oldest entries
        let keys_to_remove: Vec<String> = lru_tracker
            .iter()
            .take(count)
            .map(|entry| entry.key.clone())
            .collect();
        
        for key in keys_to_remove {
            if let Some((_, entry)) = self.entries.remove(&key) {
                freed_memory += entry.size;
                evicted_count += 1;
            }
        }
        
        // Update LRU tracker
        lru_tracker.drain(0..evicted_count);
        
        // Update statistics
        self.memory_usage.fetch_sub(freed_memory, Ordering::Relaxed);
        self.evictions.fetch_add(evicted_count as u64, Ordering::Relaxed);
        
        info!("Evicted {} LRU cache entries, freed {} bytes", evicted_count, freed_memory);
        
        Ok(())
    }

    /// Update LRU tracking for a key
    async fn update_lru(&self, key: &str) {
        if !self.config.enable_lru {
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut lru_tracker = self.lru_tracker.write().await;
        
        // Find existing entry and update access time
        if let Some(entry) = lru_tracker.iter_mut().find(|e| e.key == key) {
            entry.access_time = now;
        } else {
            // Add new entry
            lru_tracker.push(LruEntry {
                key: key.to_string(),
                access_time: now,
            });
        }
    }
}

#[async_trait]
impl CacheStore for InMemoryCache {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        if let Some(mut entry) = self.entries.get_mut(key) {
            // Check if expired
            if entry.is_expired() {
                // Remove expired entry
                drop(entry);
                if let Some((_, expired_entry)) = self.entries.remove(key) {
                    self.memory_usage.fetch_sub(expired_entry.size, Ordering::Relaxed);
                    self.expired_cleanups.fetch_add(1, Ordering::Relaxed);
                }
                self.misses.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }

            // Update access statistics
            entry.mark_accessed();
            let value = entry.value.clone();
            
            // Update LRU tracking
            self.update_lru(key).await;
            
            self.hits.fetch_add(1, Ordering::Relaxed);
            Ok(Some(value))
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        // Check if eviction is needed before adding new entry
        self.evict_if_needed().await?;

        let entry = CacheEntry::new(value.to_vec(), ttl);
        let entry_size = entry.size;

        // Insert the entry
        if let Some(old_entry) = self.entries.insert(key.to_string(), entry) {
            // Replace existing entry - adjust memory usage
            let size_diff = entry_size as isize - old_entry.size as isize;
            if size_diff > 0 {
                self.memory_usage.fetch_add(size_diff as usize, Ordering::Relaxed);
            } else {
                self.memory_usage.fetch_sub((-size_diff) as usize, Ordering::Relaxed);
            }
        } else {
            // New entry
            self.memory_usage.fetch_add(entry_size, Ordering::Relaxed);
        }

        // Update LRU tracking
        self.update_lru(key).await;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<bool> {
        if let Some((_, entry)) = self.entries.remove(key) {
            self.memory_usage.fetch_sub(entry.size, Ordering::Relaxed);
            
            // Remove from LRU tracker
            if self.config.enable_lru {
                let mut lru_tracker = self.lru_tracker.write().await;
                lru_tracker.retain(|e| e.key != key);
            }
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        if let Some(entry) = self.entries.get(key) {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn clear(&self) -> CacheResult<()> {
        let entry_count = self.entries.len();
        self.entries.clear();
        self.memory_usage.store(0, Ordering::Relaxed);
        
        if self.config.enable_lru {
            let mut lru_tracker = self.lru_tracker.write().await;
            lru_tracker.clear();
        }
        
        info!("Cleared {} entries from in-memory cache", entry_count);
        Ok(())
    }

    async fn stats(&self) -> CacheResult<CacheStoreStats> {
        Ok(CacheStoreStats {
            entries: self.entries.len(),
            memory_usage: self.memory_usage.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            expired_cleanups: self.expired_cleanups.load(Ordering::Relaxed),
        })
    }

    async fn health_check(&self) -> CacheResult<bool> {
        // Simple health check - verify we can perform basic operations
        let test_key = "__health_check__";
        let test_value = b"health_check_value";
        
        // Try to set and get a test value
        self.set(test_key, test_value, Duration::from_secs(1)).await?;
        let retrieved = self.get(test_key).await?;
        self.delete(test_key).await?;
        
        Ok(retrieved == Some(test_value.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_basic_operations() {
        let config = InMemoryCacheConfig::default();
        let cache = InMemoryCache::new(config).unwrap();

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
    async fn test_ttl_expiration() {
        let config = InMemoryCacheConfig::default();
        let cache = InMemoryCache::new(config).unwrap();

        let key = "expire_test";
        let value = b"expire_value";
        let ttl = Duration::from_millis(100);

        // Set with short TTL
        cache.set(key, value, ttl).await.unwrap();
        
        // Should exist immediately
        assert!(cache.exists(key).await.unwrap());
        
        // Wait for expiration
        sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        let result = cache.get(key).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_eviction() {
        let config = InMemoryCacheConfig {
            max_entries: 3,
            enable_lru: true,
            ..Default::default()
        };
        let cache = InMemoryCache::new(config).unwrap();

        // Fill cache to capacity
        for i in 0..3 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            cache.set(&key, value.as_bytes(), Duration::from_secs(60)).await.unwrap();
        }

        // Access first key to make it recently used
        cache.get("key_0").await.unwrap();

        // Add one more entry to trigger eviction
        cache.set("key_3", b"value_3", Duration::from_secs(60)).await.unwrap();

        // key_1 should be evicted (least recently used)
        assert!(!cache.exists("key_1").await.unwrap());
        assert!(cache.exists("key_0").await.unwrap()); // Recently accessed
        assert!(cache.exists("key_2").await.unwrap());
        assert!(cache.exists("key_3").await.unwrap()); // Just added
    }

    #[tokio::test]
    async fn test_stats() {
        let config = InMemoryCacheConfig::default();
        let cache = InMemoryCache::new(config).unwrap();

        // Perform operations
        cache.set("key1", b"value1", Duration::from_secs(60)).await.unwrap();
        cache.get("key1").await.unwrap(); // Hit
        cache.get("key2").await.unwrap(); // Miss

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.entries, 1);
        assert!(stats.memory_usage > 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = InMemoryCacheConfig::default();
        let cache = InMemoryCache::new(config).unwrap();

        assert!(cache.health_check().await.unwrap());
    }
}
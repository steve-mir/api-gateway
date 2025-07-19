//! # Cache Invalidation Module
//!
//! This module provides mechanisms for cache invalidation including
//! pattern-based invalidation, event-driven invalidation, and manual invalidation.

use super::{CacheManager, CacheError, CacheResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Invalidation event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvalidationEvent {
    /// Invalidate a specific key
    InvalidateKey { key: String },
    
    /// Invalidate keys matching a pattern
    InvalidatePattern { pattern: String },
    
    /// Invalidate keys with a specific prefix
    InvalidatePrefix { prefix: String },
    
    /// Invalidate keys associated with a user
    InvalidateUser { user_id: String },
    
    /// Invalidate keys associated with a service
    InvalidateService { service: String },
    
    /// Invalidate all cache entries
    InvalidateAll,
    
    /// Custom invalidation with tags
    InvalidateByTags { tags: Vec<String> },
}

/// Invalidation strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvalidationStrategy {
    /// Immediate invalidation
    Immediate,
    
    /// Batch invalidation with delay
    Batched { batch_size: usize, delay_ms: u64 },
    
    /// Time-based invalidation
    Scheduled { interval_seconds: u64 },
    
    /// Event-driven invalidation
    EventDriven,
}

impl Default for InvalidationStrategy {
    fn default() -> Self {
        Self::Immediate
    }
}

/// Cache invalidation manager
pub struct InvalidationManager {
    /// Cache manager reference
    cache_manager: Arc<CacheManager>,
    
    /// Invalidation strategy
    strategy: InvalidationStrategy,
    
    /// Event broadcaster
    event_sender: broadcast::Sender<InvalidationEvent>,
    
    /// Key-to-tags mapping for tag-based invalidation
    key_tags: Arc<RwLock<HashMap<String, Vec<String>>>>,
    
    /// Pending invalidations for batched strategy
    pending_invalidations: Arc<RwLock<Vec<InvalidationEvent>>>,
}

impl InvalidationManager {
    /// Create a new invalidation manager
    pub fn new(cache_manager: Arc<CacheManager>, strategy: InvalidationStrategy) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        let manager = Self {
            cache_manager,
            strategy,
            event_sender,
            key_tags: Arc::new(RwLock::new(HashMap::new())),
            pending_invalidations: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Start background tasks based on strategy
        manager.start_background_tasks();
        
        manager
    }

    /// Subscribe to invalidation events
    pub fn subscribe(&self) -> broadcast::Receiver<InvalidationEvent> {
        self.event_sender.subscribe()
    }

    /// Invalidate cache entries based on event
    pub async fn invalidate(&self, event: InvalidationEvent) -> CacheResult<()> {
        match &self.strategy {
            InvalidationStrategy::Immediate => {
                self.process_invalidation(&event).await?;
            }
            
            InvalidationStrategy::Batched { .. } => {
                let mut pending = self.pending_invalidations.write().await;
                pending.push(event.clone());
            }
            
            InvalidationStrategy::Scheduled { .. } => {
                let mut pending = self.pending_invalidations.write().await;
                pending.push(event.clone());
            }
            
            InvalidationStrategy::EventDriven => {
                // Just broadcast the event, subscribers will handle it
            }
        }

        // Broadcast the event
        if let Err(e) = self.event_sender.send(event) {
            warn!("Failed to broadcast invalidation event: {}", e);
        }

        Ok(())
    }

    /// Associate tags with a cache key
    pub async fn tag_key(&self, key: &str, tags: Vec<String>) -> CacheResult<()> {
        let mut key_tags = self.key_tags.write().await;
        key_tags.insert(key.to_string(), tags);
        Ok(())
    }

    /// Remove tags for a cache key
    pub async fn untag_key(&self, key: &str) -> CacheResult<()> {
        let mut key_tags = self.key_tags.write().await;
        key_tags.remove(key);
        Ok(())
    }

    /// Get tags for a cache key
    pub async fn get_key_tags(&self, key: &str) -> Vec<String> {
        let key_tags = self.key_tags.read().await;
        key_tags.get(key).cloned().unwrap_or_default()
    }

    /// Process a single invalidation event
    async fn process_invalidation(&self, event: &InvalidationEvent) -> CacheResult<()> {
        match event {
            InvalidationEvent::InvalidateKey { key } => {
                self.cache_manager.delete(key).await?;
                self.untag_key(key).await?;
                debug!("Invalidated cache key: {}", key);
            }
            
            InvalidationEvent::InvalidatePattern { pattern } => {
                self.invalidate_by_pattern(pattern).await?;
            }
            
            InvalidationEvent::InvalidatePrefix { prefix } => {
                self.invalidate_by_prefix(prefix).await?;
            }
            
            InvalidationEvent::InvalidateUser { user_id } => {
                self.invalidate_by_user(user_id).await?;
            }
            
            InvalidationEvent::InvalidateService { service } => {
                self.invalidate_by_service(service).await?;
            }
            
            InvalidationEvent::InvalidateAll => {
                self.cache_manager.clear().await?;
                let mut key_tags = self.key_tags.write().await;
                key_tags.clear();
                info!("Invalidated all cache entries");
            }
            
            InvalidationEvent::InvalidateByTags { tags } => {
                self.invalidate_by_tags(tags).await?;
            }
        }

        Ok(())
    }

    /// Invalidate keys matching a pattern (simplified glob-style matching)
    async fn invalidate_by_pattern(&self, pattern: &str) -> CacheResult<()> {
        // This is a simplified implementation
        // In a real implementation, you'd need to scan all keys and match against the pattern
        // For now, we'll treat it as a prefix match
        if pattern.ends_with('*') {
            let prefix = pattern.trim_end_matches('*');
            self.invalidate_by_prefix(prefix).await?;
        } else {
            // Exact match
            self.cache_manager.delete(pattern).await?;
        }
        
        debug!("Invalidated cache keys matching pattern: {}", pattern);
        Ok(())
    }

    /// Invalidate keys with a specific prefix
    async fn invalidate_by_prefix(&self, prefix: &str) -> CacheResult<()> {
        // Note: This is a simplified implementation
        // In a production system, you'd need to maintain an index of keys
        // or use Redis SCAN with pattern matching
        
        // For now, we'll clear all keys with the prefix from our tag mapping
        let mut key_tags = self.key_tags.write().await;
        let keys_to_remove: Vec<String> = key_tags
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        
        for key in &keys_to_remove {
            self.cache_manager.delete(key).await?;
            key_tags.remove(key);
        }
        
        debug!("Invalidated {} cache keys with prefix: {}", keys_to_remove.len(), prefix);
        Ok(())
    }

    /// Invalidate keys associated with a user
    async fn invalidate_by_user(&self, user_id: &str) -> CacheResult<()> {
        let user_tag = format!("user:{}", user_id);
        self.invalidate_by_tags(&[user_tag]).await
    }

    /// Invalidate keys associated with a service
    async fn invalidate_by_service(&self, service: &str) -> CacheResult<()> {
        let service_tag = format!("service:{}", service);
        self.invalidate_by_tags(&[service_tag]).await
    }

    /// Invalidate keys by tags
    async fn invalidate_by_tags(&self, tags: &[String]) -> CacheResult<()> {
        let key_tags = self.key_tags.read().await;
        let mut keys_to_invalidate = Vec::new();
        
        // Find keys that have any of the specified tags
        for (key, key_tag_list) in key_tags.iter() {
            if tags.iter().any(|tag| key_tag_list.contains(tag)) {
                keys_to_invalidate.push(key.clone());
            }
        }
        
        drop(key_tags); // Release read lock
        
        // Invalidate the keys
        for key in &keys_to_invalidate {
            self.cache_manager.delete(key).await?;
            self.untag_key(key).await?;
        }
        
        debug!("Invalidated {} cache keys with tags: {:?}", keys_to_invalidate.len(), tags);
        Ok(())
    }

    /// Start background tasks based on strategy
    fn start_background_tasks(&self) {
        match &self.strategy {
            InvalidationStrategy::Batched { batch_size, delay_ms } => {
                let pending = self.pending_invalidations.clone();
                let cache_manager = self.cache_manager.clone();
                let batch_size = *batch_size;
                let delay = std::time::Duration::from_millis(*delay_ms);
                
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(delay);
                    
                    loop {
                        interval.tick().await;
                        
                        let events = {
                            let mut pending_guard = pending.write().await;
                            if pending_guard.is_empty() {
                                continue;
                            }
                            
                            let batch_end = std::cmp::min(batch_size, pending_guard.len());
                            pending_guard.drain(0..batch_end).collect::<Vec<_>>()
                        };
                        
                        for event in events {
                            if let Err(e) = Self::process_invalidation_static(&cache_manager, &event).await {
                                warn!("Failed to process batched invalidation: {}", e);
                            }
                        }
                    }
                });
            }
            
            InvalidationStrategy::Scheduled { interval_seconds } => {
                let pending = self.pending_invalidations.clone();
                let cache_manager = self.cache_manager.clone();
                let interval_duration = std::time::Duration::from_secs(*interval_seconds);
                
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(interval_duration);
                    
                    loop {
                        interval.tick().await;
                        
                        let events = {
                            let mut pending_guard = pending.write().await;
                            std::mem::take(&mut *pending_guard)
                        };
                        
                        for event in events {
                            if let Err(e) = Self::process_invalidation_static(&cache_manager, &event).await {
                                warn!("Failed to process scheduled invalidation: {}", e);
                            }
                        }
                    }
                });
            }
            
            _ => {
                // No background tasks needed for immediate or event-driven strategies
            }
        }
    }

    /// Static version of process_invalidation for use in background tasks
    async fn process_invalidation_static(
        cache_manager: &CacheManager,
        event: &InvalidationEvent,
    ) -> CacheResult<()> {
        match event {
            InvalidationEvent::InvalidateKey { key } => {
                cache_manager.delete(key).await?;
                debug!("Invalidated cache key: {}", key);
            }
            
            InvalidationEvent::InvalidateAll => {
                cache_manager.clear().await?;
                info!("Invalidated all cache entries");
            }
            
            // For other events, we'd need more complex logic
            // This is a simplified implementation
            _ => {
                warn!("Complex invalidation events not fully supported in background tasks");
            }
        }

        Ok(())
    }
}

/// Convenience functions for common invalidation patterns
impl InvalidationManager {
    /// Invalidate cache for a specific user
    pub async fn invalidate_user_cache(&self, user_id: &str) -> CacheResult<()> {
        self.invalidate(InvalidationEvent::InvalidateUser {
            user_id: user_id.to_string(),
        }).await
    }

    /// Invalidate cache for a specific service
    pub async fn invalidate_service_cache(&self, service: &str) -> CacheResult<()> {
        self.invalidate(InvalidationEvent::InvalidateService {
            service: service.to_string(),
        }).await
    }

    /// Invalidate cache entries with specific prefix
    pub async fn invalidate_prefix_cache(&self, prefix: &str) -> CacheResult<()> {
        self.invalidate(InvalidationEvent::InvalidatePrefix {
            prefix: prefix.to_string(),
        }).await
    }

    /// Invalidate all cache entries
    pub async fn invalidate_all_cache(&self) -> CacheResult<()> {
        self.invalidate(InvalidationEvent::InvalidateAll).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::{CacheConfig, CacheManager};
    use std::time::Duration;

    async fn create_test_cache_manager() -> Arc<CacheManager> {
        let config = CacheConfig {
            in_memory_enabled: true,
            redis_enabled: false,
            ..Default::default()
        };
        Arc::new(CacheManager::new(config).await.unwrap())
    }

    #[tokio::test]
    async fn test_immediate_invalidation() {
        let cache_manager = create_test_cache_manager().await;
        let invalidation_manager = InvalidationManager::new(
            cache_manager.clone(),
            InvalidationStrategy::Immediate,
        );

        // Set a cache entry
        cache_manager.set("test_key", b"test_value", Duration::from_secs(60)).await.unwrap();
        assert!(cache_manager.exists("test_key").await.unwrap());

        // Invalidate the key
        invalidation_manager.invalidate(InvalidationEvent::InvalidateKey {
            key: "test_key".to_string(),
        }).await.unwrap();

        // Key should be gone
        assert!(!cache_manager.exists("test_key").await.unwrap());
    }

    #[tokio::test]
    async fn test_tag_based_invalidation() {
        let cache_manager = create_test_cache_manager().await;
        let invalidation_manager = InvalidationManager::new(
            cache_manager.clone(),
            InvalidationStrategy::Immediate,
        );

        // Set cache entries with tags
        cache_manager.set("user:123:profile", b"profile_data", Duration::from_secs(60)).await.unwrap();
        cache_manager.set("user:123:settings", b"settings_data", Duration::from_secs(60)).await.unwrap();
        cache_manager.set("user:456:profile", b"other_profile", Duration::from_secs(60)).await.unwrap();

        // Tag the keys
        invalidation_manager.tag_key("user:123:profile", vec!["user:123".to_string()]).await.unwrap();
        invalidation_manager.tag_key("user:123:settings", vec!["user:123".to_string()]).await.unwrap();
        invalidation_manager.tag_key("user:456:profile", vec!["user:456".to_string()]).await.unwrap();

        // Invalidate by user tag
        invalidation_manager.invalidate_user_cache("123").await.unwrap();

        // User 123's cache should be gone, but user 456's should remain
        assert!(!cache_manager.exists("user:123:profile").await.unwrap());
        assert!(!cache_manager.exists("user:123:settings").await.unwrap());
        assert!(cache_manager.exists("user:456:profile").await.unwrap());
    }

    #[tokio::test]
    async fn test_prefix_invalidation() {
        let cache_manager = create_test_cache_manager().await;
        let invalidation_manager = InvalidationManager::new(
            cache_manager.clone(),
            InvalidationStrategy::Immediate,
        );

        // Set cache entries with common prefix
        cache_manager.set("api:v1:users", b"users_data", Duration::from_secs(60)).await.unwrap();
        cache_manager.set("api:v1:posts", b"posts_data", Duration::from_secs(60)).await.unwrap();
        cache_manager.set("api:v2:users", b"v2_users_data", Duration::from_secs(60)).await.unwrap();

        // Tag keys for tracking
        invalidation_manager.tag_key("api:v1:users", vec!["api:v1".to_string()]).await.unwrap();
        invalidation_manager.tag_key("api:v1:posts", vec!["api:v1".to_string()]).await.unwrap();
        invalidation_manager.tag_key("api:v2:users", vec!["api:v2".to_string()]).await.unwrap();

        // Invalidate by prefix
        invalidation_manager.invalidate_prefix_cache("api:v1").await.unwrap();

        // v1 entries should be gone, v2 should remain
        assert!(!cache_manager.exists("api:v1:users").await.unwrap());
        assert!(!cache_manager.exists("api:v1:posts").await.unwrap());
        assert!(cache_manager.exists("api:v2:users").await.unwrap());
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let cache_manager = create_test_cache_manager().await;
        let invalidation_manager = InvalidationManager::new(
            cache_manager.clone(),
            InvalidationStrategy::EventDriven,
        );

        let mut receiver = invalidation_manager.subscribe();

        // Send an invalidation event
        let event = InvalidationEvent::InvalidateKey {
            key: "test_key".to_string(),
        };
        invalidation_manager.invalidate(event.clone()).await.unwrap();

        // Receive the event
        let received_event = receiver.recv().await.unwrap();
        match received_event {
            InvalidationEvent::InvalidateKey { key } => {
                assert_eq!(key, "test_key");
            }
            _ => panic!("Unexpected event type"),
        }
    }
}
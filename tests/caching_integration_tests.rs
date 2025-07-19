//! # Caching System Integration Tests
//!
//! Comprehensive tests for the caching system including performance and correctness tests.

use api_gateway::caching::{
    CacheManager, CacheConfig, InvalidationManager, InvalidationStrategy, InvalidationEvent,
    DeduplicationManager, IdempotencyManager, DeduplicationConfig, IdempotencyConfig,
    CacheMiddleware, CachePolicy, KeyGenerationStrategy,
};
use api_gateway::core::types::{IncomingRequest, RequestContext, Protocol, AuthContext};
use axum::http::{HeaderMap, Method, StatusCode, Version};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Create a test cache manager with in-memory cache only
async fn create_test_cache_manager() -> Arc<CacheManager> {
    let config = CacheConfig {
        in_memory_enabled: true,
        redis_enabled: false,
        default_ttl: Duration::from_secs(300),
        enable_stats: true,
        ..Default::default()
    };
    Arc::new(CacheManager:
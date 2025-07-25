//! # Memory Optimization Module
//!
//! This module provides memory optimization utilities for the API Gateway including:
//! - Smart Arc/Rc usage patterns for shared data
//! - Memory pool management for frequent allocations
//! - Zero-copy optimizations where possible
//! - Memory usage monitoring and reporting
//!
//! ## Rust Memory Management Concepts
//!
//! - `Arc<T>` (Atomically Reference Counted) for thread-safe shared ownership
//! - `Rc<T>` (Reference Counted) for single-threaded shared ownership  
//! - `Box<T>` for heap allocation with unique ownership
//! - `Cow<T>` (Clone on Write) for efficient copy-on-write semantics
//! - Memory pools to reduce allocation overhead

use std::sync::{Arc, Weak};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use smallvec::SmallVec;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};
use metrics::{gauge, counter, histogram};

use crate::core::error::{GatewayError, GatewayResult};

/// Memory optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Enable memory pooling
    pub enable_pooling: bool,
    /// Pool size for different object types
    pub pool_sizes: PoolSizes,
    /// Memory monitoring interval
    pub monitoring_interval: Duration,
    /// Maximum memory usage threshold (bytes)
    pub max_memory_threshold: usize,
    /// Enable zero-copy optimizations
    pub enable_zero_copy: bool,
    /// Buffer reuse settings
    pub buffer_reuse: BufferReuseConfig,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enable_pooling: true,
            pool_sizes: PoolSizes::default(),
            monitoring_interval: Duration::from_secs(30),
            max_memory_threshold: 1024 * 1024 * 1024, // 1GB
            enable_zero_copy: true,
            buffer_reuse: BufferReuseConfig::default(),
        }
    }
}

/// Pool sizes for different object types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSizes {
    /// Buffer pool size
    pub buffer_pool_size: usize,
    /// Request context pool size
    pub request_context_pool_size: usize,
    /// Response pool size
    pub response_pool_size: usize,
    /// Header map pool size
    pub header_map_pool_size: usize,
}

impl Default for PoolSizes {
    fn default() -> Self {
        Self {
            buffer_pool_size: 1000,
            request_context_pool_size: 500,
            response_pool_size: 500,
            header_map_pool_size: 200,
        }
    }
}

/// Buffer reuse configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferReuseConfig {
    /// Maximum buffer size to reuse
    pub max_reuse_size: usize,
    /// Minimum buffer size to reuse
    pub min_reuse_size: usize,
    /// Buffer cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for BufferReuseConfig {
    fn default() -> Self {
        Self {
            max_reuse_size: 64 * 1024, // 64KB
            min_reuse_size: 1024,      // 1KB
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Smart pointer wrapper for optimized memory usage
#[derive(Debug, Clone)]
pub struct OptimizedArc<T> {
    inner: Arc<T>,
    /// Weak reference for memory pressure detection
    weak_ref: Weak<T>,
    /// Creation timestamp for age tracking
    created_at: Instant,
}

impl<T> OptimizedArc<T> {
    /// Create a new optimized Arc
    pub fn new(value: T) -> Self {
        let arc = Arc::new(value);
        let weak_ref = Arc::downgrade(&arc);
        
        Self {
            inner: arc,
            weak_ref,
            created_at: Instant::now(),
        }
    }

    /// Get the inner Arc
    pub fn inner(&self) -> &Arc<T> {
        &self.inner
    }

    /// Get reference count
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Get weak reference count
    pub fn weak_count(&self) -> usize {
        Arc::weak_count(&self.inner)
    }

    /// Check if this is the only reference
    pub fn is_unique(&self) -> bool {
        Arc::strong_count(&self.inner) == 1
    }

    /// Get age of this Arc
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Try to get mutable reference if unique
    pub fn get_mut(&mut self) -> Option<&mut T> {
        Arc::get_mut(&mut self.inner)
    }

    /// Clone the inner value if cheap to clone, otherwise return Arc
    pub fn clone_or_arc(&self) -> OptimizedArc<T>
    where
        T: Clone,
    {
        if self.is_unique() {
            // If we're the only reference, we can safely clone the inner value
            OptimizedArc::new((*self.inner).clone())
        } else {
            // Otherwise, just clone the Arc
            self.clone()
        }
    }
}

impl<T> std::ops::Deref for OptimizedArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Memory pool for reusable objects
pub struct MemoryPool<T> {
    /// Pool of available objects
    pool: Arc<RwLock<Vec<T>>>,
    /// Factory function for creating new objects
    factory: Box<dyn Fn() -> T + Send + Sync>,
    /// Maximum pool size
    max_size: usize,
    /// Pool statistics
    stats: PoolStats,
}

impl<T> MemoryPool<T>
where
    T: Send + Sync + 'static,
{
    /// Create a new memory pool
    pub fn new<F>(factory: F, max_size: usize) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            pool: Arc::new(RwLock::new(Vec::with_capacity(max_size))),
            factory: Box::new(factory),
            max_size,
            stats: PoolStats::default(),
        }
    }

    /// Get an object from the pool or create a new one
    pub fn get(&self) -> PooledObject<T> {
        let mut pool = self.pool.write();
        
        if let Some(object) = pool.pop() {
            self.stats.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            counter!("memory_pool_hits").increment(1);
            
            debug!("Retrieved object from memory pool");
            
            PooledObject::new(object, self.pool.clone())
        } else {
            self.stats.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            counter!("memory_pool_misses").increment(1);
            
            let object = (self.factory)();
            debug!("Created new object for memory pool");
            
            PooledObject::new(object, self.pool.clone())
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.pool.read().len()
    }

    /// Clear the pool
    pub fn clear(&self) {
        let mut pool = self.pool.write();
        pool.clear();
        
        info!("Cleared memory pool");
    }

    /// Preallocate objects in the pool
    pub fn preallocate(&self, count: usize) {
        let mut pool = self.pool.write();
        let current_size = pool.len();
        let target_size = std::cmp::min(current_size + count, self.max_size);
        
        for _ in current_size..target_size {
            pool.push((self.factory)());
        }
        
        info!(
            preallocated = target_size - current_size,
            total_size = target_size,
            "Preallocated objects in memory pool"
        );
    }
}

/// Pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    pub hits: std::sync::atomic::AtomicU64,
    pub misses: std::sync::atomic::AtomicU64,
}

impl PoolStats {
    /// Get hit rate as percentage
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}

/// Pooled object wrapper that returns to pool when dropped
pub struct PooledObject<T> {
    object: Option<T>,
    pool: Arc<RwLock<Vec<T>>>,
}

impl<T> PooledObject<T> {
    fn new(object: T, pool: Arc<RwLock<Vec<T>>>) -> Self {
        Self {
            object: Some(object),
            pool,
        }
    }

    /// Take ownership of the object (prevents return to pool)
    pub fn take(mut self) -> T {
        self.object.take().expect("Object already taken")
    }
}

impl<T> std::ops::Deref for PooledObject<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.object.as_ref().expect("Object already taken")
    }
}

impl<T> std::ops::DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.object.as_mut().expect("Object already taken")
    }
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(object) = self.object.take() {
            let mut pool = self.pool.write();
            if pool.len() < pool.capacity() {
                pool.push(object);
                debug!("Returned object to memory pool");
            } else {
                debug!("Memory pool full, dropping object");
            }
        }
    }
}

/// Zero-copy buffer for efficient data handling
#[derive(Debug, Clone)]
pub struct ZeroCopyBuffer {
    /// Underlying bytes
    bytes: Bytes,
    /// Offset into the bytes
    offset: usize,
    /// Length of the valid data
    length: usize,
}

impl ZeroCopyBuffer {
    /// Create a new zero-copy buffer
    pub fn new(bytes: Bytes) -> Self {
        let length = bytes.len();
        Self {
            bytes,
            offset: 0,
            length,
        }
    }

    /// Create from a slice (will copy data)
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
    }

    /// Create from static data (zero-copy)
    pub fn from_static(data: &'static [u8]) -> Self {
        Self::new(Bytes::from_static(data))
    }

    /// Get a slice of the buffer without copying
    pub fn slice(&self, start: usize, end: usize) -> GatewayResult<ZeroCopyBuffer> {
        if start > end || end > self.length {
            return Err(GatewayError::internal("Invalid slice bounds"));
        }

        Ok(Self {
            bytes: self.bytes.clone(),
            offset: self.offset + start,
            length: end - start,
        })
    }

    /// Get the data as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[self.offset..self.offset + self.length]
    }

    /// Get the length of valid data
    pub fn len(&self) -> usize {
        self.length
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Convert to Bytes (zero-copy if possible)
    pub fn into_bytes(self) -> Bytes {
        if self.offset == 0 && self.length == self.bytes.len() {
            self.bytes
        } else {
            self.bytes.slice(self.offset..self.offset + self.length)
        }
    }

    /// Extend buffer with more data
    pub fn extend(&mut self, other: &ZeroCopyBuffer) -> GatewayResult<()> {
        // For simplicity, we'll create a new buffer
        // In a more sophisticated implementation, you might use a rope-like structure
        let mut new_data = BytesMut::with_capacity(self.length + other.length);
        new_data.put_slice(self.as_slice());
        new_data.put_slice(other.as_slice());
        
        self.bytes = new_data.freeze();
        self.offset = 0;
        self.length = self.bytes.len();
        
        Ok(())
    }
}

/// Buffer manager for efficient buffer reuse
pub struct BufferManager {
    /// Pools of buffers by size class
    buffer_pools: DashMap<usize, MemoryPool<BytesMut>>,
    /// Configuration
    config: BufferReuseConfig,
    /// Statistics
    stats: BufferManagerStats,
}

impl BufferManager {
    /// Create a new buffer manager
    pub fn new(config: BufferReuseConfig) -> Self {
        Self {
            buffer_pools: DashMap::new(),
            config,
            stats: BufferManagerStats::default(),
        }
    }

    /// Get a buffer of the specified size
    pub fn get_buffer(&self, size: usize) -> BytesMut {
        if size < self.config.min_reuse_size || size > self.config.max_reuse_size {
            // Don't pool buffers outside the reuse range
            self.stats.direct_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return BytesMut::with_capacity(size);
        }

        // Round up to next power of 2 for size class
        let size_class = size.next_power_of_two();
        
        let pool = self.buffer_pools.entry(size_class).or_insert_with(|| {
            MemoryPool::new(
                move || BytesMut::with_capacity(size_class),
                100, // Max 100 buffers per size class
            )
        });

        let mut buffer = pool.get().take();
        buffer.clear();
        buffer.reserve(size);
        
        self.stats.pooled_allocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        buffer
    }

    /// Return a buffer to the pool
    pub fn return_buffer(&self, mut buffer: BytesMut) {
        let capacity = buffer.capacity();
        
        if capacity < self.config.min_reuse_size || capacity > self.config.max_reuse_size {
            // Don't pool buffers outside the reuse range
            return;
        }

        // Clear the buffer for reuse
        buffer.clear();
        
        let size_class = capacity.next_power_of_two();
        
        if let Some(pool) = self.buffer_pools.get(&size_class) {
            // Try to return to pool (will be dropped if pool is full)
            let _pooled_buffer = PooledObject::new(buffer, pool.pool.clone());
        }
    }

    /// Get buffer manager statistics
    pub fn stats(&self) -> &BufferManagerStats {
        &self.stats
    }

    /// Start cleanup task for buffer pools
    pub fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = self.config.cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let start_time = Instant::now();
                let mut total_cleared = 0;
                
                // Clear pools that haven't been used recently
                for entry in self.buffer_pools.iter() {
                    let pool_size = entry.value().size();
                    if pool_size > 10 {
                        // Keep some buffers but clear excess
                        entry.value().clear();
                        total_cleared += pool_size;
                    }
                }
                
                let cleanup_duration = start_time.elapsed();
                
                if total_cleared > 0 {
                    info!(
                        cleared_buffers = total_cleared,
                        cleanup_duration_ms = cleanup_duration.as_millis(),
                        "Buffer pool cleanup completed"
                    );
                }
                
                histogram!("buffer_manager_cleanup_duration").record(cleanup_duration.as_secs_f64());
            }
        });
    }
}

/// Buffer manager statistics
#[derive(Debug, Default)]
pub struct BufferManagerStats {
    pub pooled_allocations: std::sync::atomic::AtomicU64,
    pub direct_allocations: std::sync::atomic::AtomicU64,
}

impl BufferManagerStats {
    /// Get pool utilization rate
    pub fn pool_utilization(&self) -> f64 {
        let pooled = self.pooled_allocations.load(std::sync::atomic::Ordering::Relaxed);
        let direct = self.direct_allocations.load(std::sync::atomic::Ordering::Relaxed);
        let total = pooled + direct;
        
        if total == 0 {
            0.0
        } else {
            (pooled as f64 / total as f64) * 100.0
        }
    }
}

/// Memory usage monitor
pub struct MemoryMonitor {
    /// Configuration
    config: MemoryConfig,
    /// Current memory usage
    current_usage: std::sync::atomic::AtomicUsize,
    /// Peak memory usage
    peak_usage: std::sync::atomic::AtomicUsize,
    /// Memory usage history
    usage_history: Arc<RwLock<SmallVec<[MemoryUsageSnapshot; 100]>>>,
}

impl MemoryMonitor {
    /// Create a new memory monitor
    pub fn new(config: MemoryConfig) -> Self {
        Self {
            config,
            current_usage: std::sync::atomic::AtomicUsize::new(0),
            peak_usage: std::sync::atomic::AtomicUsize::new(0),
            usage_history: Arc::new(RwLock::new(SmallVec::new())),
        }
    }

    /// Record memory allocation
    pub fn record_allocation(&self, size: usize) {
        let new_usage = self.current_usage.fetch_add(size, std::sync::atomic::Ordering::Relaxed) + size;
        
        // Update peak usage
        let mut peak = self.peak_usage.load(std::sync::atomic::Ordering::Relaxed);
        while new_usage > peak {
            match self.peak_usage.compare_exchange_weak(
                peak,
                new_usage,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => peak = current,
            }
        }
        
        gauge!("memory_usage_bytes").set(new_usage as f64);
        
        // Check threshold
        if new_usage > self.config.max_memory_threshold {
            warn!(
                current_usage = new_usage,
                threshold = self.config.max_memory_threshold,
                "Memory usage exceeded threshold"
            );
        }
    }

    /// Record memory deallocation
    pub fn record_deallocation(&self, size: usize) {
        let new_usage = self.current_usage.fetch_sub(size, std::sync::atomic::Ordering::Relaxed) - size;
        gauge!("memory_usage_bytes").set(new_usage as f64);
    }

    /// Get current memory usage
    pub fn current_usage(&self) -> usize {
        self.current_usage.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get peak memory usage
    pub fn peak_usage(&self) -> usize {
        self.peak_usage.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Take a memory usage snapshot
    pub fn take_snapshot(&self) -> MemoryUsageSnapshot {
        let snapshot = MemoryUsageSnapshot {
            timestamp: Instant::now(),
            current_usage: self.current_usage(),
            peak_usage: self.peak_usage(),
        };

        // Add to history
        let mut history = self.usage_history.write();
        history.push(snapshot.clone());
        
        // Keep only last 100 snapshots
        if history.len() > 100 {
            history.remove(0);
        }
        
        snapshot
    }

    /// Get memory usage history
    pub fn get_history(&self) -> Vec<MemoryUsageSnapshot> {
        self.usage_history.read().to_vec()
    }

    /// Start monitoring task
    pub fn start_monitoring_task(self: Arc<Self>) {
        let monitoring_interval = self.config.monitoring_interval;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitoring_interval);
            
            loop {
                interval.tick().await;
                
                let snapshot = self.take_snapshot();
                
                debug!(
                    current_usage = snapshot.current_usage,
                    peak_usage = snapshot.peak_usage,
                    "Memory usage snapshot taken"
                );
                
                gauge!("memory_peak_usage_bytes").set(snapshot.peak_usage as f64);
            }
        });
    }
}

/// Memory usage snapshot
#[derive(Debug, Clone, Serialize)]
pub struct MemoryUsageSnapshot {
    #[serde(skip)]
    pub timestamp: Instant,
    pub current_usage: usize,
    pub peak_usage: usize,
}

/// Global memory optimization manager
pub struct MemoryOptimizer {
    /// Buffer manager
    pub buffer_manager: Arc<BufferManager>,
    /// Memory monitor
    pub memory_monitor: Arc<MemoryMonitor>,
    /// Configuration
    config: MemoryConfig,
}

impl MemoryOptimizer {
    /// Create a new memory optimizer
    pub fn new(config: MemoryConfig) -> Self {
        let buffer_manager = Arc::new(BufferManager::new(config.buffer_reuse.clone()));
        let memory_monitor = Arc::new(MemoryMonitor::new(config.clone()));
        
        Self {
            buffer_manager,
            memory_monitor,
            config,
        }
    }

    /// Initialize and start background tasks
    pub fn initialize(self: Arc<Self>) {
        // Start buffer cleanup task
        self.buffer_manager.clone().start_cleanup_task();
        
        // Start memory monitoring task
        self.memory_monitor.clone().start_monitoring_task();
        
        info!("Memory optimizer initialized with background tasks");
    }

    /// Get optimization statistics
    pub fn get_stats(&self) -> MemoryOptimizationStats {
        MemoryOptimizationStats {
            buffer_manager_stats: BufferManagerStatsSnapshot {
                pooled_allocations: self.buffer_manager.stats().pooled_allocations.load(std::sync::atomic::Ordering::Relaxed),
                direct_allocations: self.buffer_manager.stats().direct_allocations.load(std::sync::atomic::Ordering::Relaxed),
                pool_utilization: self.buffer_manager.stats().pool_utilization(),
            },
            memory_usage: self.memory_monitor.take_snapshot(),
            config: self.config.clone(),
        }
    }
}

/// Memory optimization statistics
#[derive(Debug, Clone, Serialize)]
pub struct MemoryOptimizationStats {
    pub buffer_manager_stats: BufferManagerStatsSnapshot,
    pub memory_usage: MemoryUsageSnapshot,
    pub config: MemoryConfig,
}

/// Buffer manager statistics snapshot
#[derive(Debug, Clone, Serialize)]
pub struct BufferManagerStatsSnapshot {
    pub pooled_allocations: u64,
    pub direct_allocations: u64,
    pub pool_utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_arc_creation() {
        let arc = OptimizedArc::new(42);
        assert_eq!(*arc, 42);
        assert_eq!(arc.ref_count(), 1);
        assert!(arc.is_unique());
    }

    #[test]
    fn test_optimized_arc_cloning() {
        let arc1 = OptimizedArc::new(String::from("test"));
        let arc2 = arc1.clone();
        
        assert_eq!(arc1.ref_count(), 2);
        assert_eq!(arc2.ref_count(), 2);
        assert!(!arc1.is_unique());
        assert!(!arc2.is_unique());
    }

    #[tokio::test]
    async fn test_memory_pool() {
        let pool = MemoryPool::new(|| Vec::<u8>::new(), 10);
        
        let obj1 = pool.get();
        let obj2 = pool.get();
        
        assert_eq!(pool.stats().misses.load(std::sync::atomic::Ordering::Relaxed), 2);
        
        drop(obj1);
        drop(obj2);
        
        // Get another object, should be from pool now
        let _obj3 = pool.get();
        assert_eq!(pool.stats().hits.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn test_zero_copy_buffer() {
        let data = b"Hello, World!";
        let buffer = ZeroCopyBuffer::from_slice(data);
        
        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.as_slice(), data);
        
        let slice = buffer.slice(0, 5).unwrap();
        assert_eq!(slice.as_slice(), b"Hello");
    }

    #[test]
    fn test_buffer_manager() {
        let config = BufferReuseConfig::default();
        let manager = BufferManager::new(config);
        
        let buffer1 = manager.get_buffer(1024);
        assert_eq!(buffer1.capacity(), 1024);
        
        manager.return_buffer(buffer1);
        
        let buffer2 = manager.get_buffer(1024);
        // Should reuse the buffer
        assert!(manager.stats().pooled_allocations.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_memory_monitor() {
        let config = MemoryConfig::default();
        let monitor = MemoryMonitor::new(config);
        
        monitor.record_allocation(1024);
        assert_eq!(monitor.current_usage(), 1024);
        assert_eq!(monitor.peak_usage(), 1024);
        
        monitor.record_allocation(512);
        assert_eq!(monitor.current_usage(), 1536);
        assert_eq!(monitor.peak_usage(), 1536);
        
        monitor.record_deallocation(512);
        assert_eq!(monitor.current_usage(), 1024);
        assert_eq!(monitor.peak_usage(), 1536); // Peak should remain
    }
}
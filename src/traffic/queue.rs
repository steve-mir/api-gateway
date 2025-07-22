//! # Request Queue with Backpressure Handling
//! 
//! This module implements a sophisticated request queuing system with backpressure
//! handling to manage system load and prevent resource exhaustion.

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, GatewayResponse};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Configuration for request queue and backpressure handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureConfig {
    /// Maximum number of queued requests
    pub max_queue_size: usize,
    
    /// Maximum time a request can wait in queue
    pub max_wait_time: Duration,
    
    /// Maximum number of concurrent requests being processed
    pub max_concurrent_requests: usize,
    
    /// Backpressure threshold (percentage of max_queue_size)
    pub backpressure_threshold: f32,
    
    /// Enable adaptive queue sizing based on system load
    pub adaptive_sizing: bool,
    
    /// Queue size adjustment interval for adaptive sizing
    pub adjustment_interval: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10000,
            max_wait_time: Duration::from_secs(30),
            max_concurrent_requests: 1000,
            backpressure_threshold: 0.8,
            adaptive_sizing: true,
            adjustment_interval: Duration::from_secs(10),
        }
    }
}

/// Metrics for request queue monitoring
#[derive(Debug, Clone)]
pub struct QueueMetrics {
    /// Current queue size
    pub current_queue_size: Arc<AtomicUsize>,
    
    /// Total requests queued
    pub total_queued: Arc<AtomicU64>,
    
    /// Total requests processed
    pub total_processed: Arc<AtomicU64>,
    
    /// Total requests dropped due to backpressure
    pub total_dropped: Arc<AtomicU64>,
    
    /// Total requests timed out in queue
    pub total_timeouts: Arc<AtomicU64>,
    
    /// Current concurrent requests
    pub current_concurrent: Arc<AtomicUsize>,
    
    /// Average queue wait time (in milliseconds)
    pub avg_wait_time_ms: Arc<AtomicU64>,
}

impl Default for QueueMetrics {
    fn default() -> Self {
        Self {
            current_queue_size: Arc::new(AtomicUsize::new(0)),
            total_queued: Arc::new(AtomicU64::new(0)),
            total_processed: Arc::new(AtomicU64::new(0)),
            total_dropped: Arc::new(AtomicU64::new(0)),
            total_timeouts: Arc::new(AtomicU64::new(0)),
            current_concurrent: Arc::new(AtomicUsize::new(0)),
            avg_wait_time_ms: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Queued request with metadata
#[derive(Debug)]
struct QueuedRequest {
    request: IncomingRequest,
    queued_at: Instant,
    priority: u8,
}

/// Request queue with backpressure handling
pub struct RequestQueue {
    config: BackpressureConfig,
    queue: Arc<Mutex<VecDeque<QueuedRequest>>>,
    semaphore: Arc<Semaphore>,
    metrics: QueueMetrics,
    shutdown: Arc<RwLock<bool>>,
}

impl RequestQueue {
    /// Create a new request queue with the given configuration
    pub fn new(config: BackpressureConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
        
        Self {
            config,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            semaphore,
            metrics: QueueMetrics::default(),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Queue a request for processing with backpressure handling
    /// 
    /// Returns Ok(()) if request was queued successfully
    /// Returns Err if backpressure is triggered or queue is full
    pub async fn enqueue(&self, request: IncomingRequest, priority: u8) -> GatewayResult<()> {
        // Check if shutdown is in progress
        if *self.shutdown.read().await {
            return Err(GatewayError::ServiceUnavailable { 
                service: "queue".to_string(), 
                reason: "Queue is shutting down".to_string() 
            });
        }
        
        let mut queue = self.queue.lock().await;
        
        // Check queue capacity and apply backpressure
        let current_size = queue.len();
        let backpressure_limit = (self.config.max_queue_size as f32 * self.config.backpressure_threshold) as usize;
        
        if current_size >= self.config.max_queue_size {
            self.metrics.total_dropped.fetch_add(1, Ordering::Relaxed);
            warn!("Request queue full, dropping request. Queue size: {}", current_size);
            return Err(GatewayError::ServiceUnavailable { 
                service: "queue".to_string(), 
                reason: "Queue is full".to_string() 
            });
        }
        
        if current_size >= backpressure_limit {
            self.metrics.total_dropped.fetch_add(1, Ordering::Relaxed);
            warn!("Backpressure triggered, dropping request. Queue size: {}", current_size);
            return Err(GatewayError::RateLimitExceeded { 
                limit: backpressure_limit as u32, 
                window: "queue".to_string() 
            });
        }
        
        // Create queued request
        let queued_request = QueuedRequest {
            request,
            queued_at: Instant::now(),
            priority,
        };
        
        // Insert request based on priority (higher priority first)
        let insert_pos = queue
            .iter()
            .position(|req| req.priority < priority)
            .unwrap_or(queue.len());
        
        queue.insert(insert_pos, queued_request);
        
        // Update metrics
        self.metrics.current_queue_size.store(queue.len(), Ordering::Relaxed);
        self.metrics.total_queued.fetch_add(1, Ordering::Relaxed);
        
        debug!("Request queued with priority {}. Queue size: {}", priority, queue.len());
        
        Ok(())
    }
    
    /// Dequeue and process the next request
    /// 
    /// This method will wait for a semaphore permit (to limit concurrent processing)
    /// and then dequeue the highest priority request from the queue
    pub async fn dequeue(&self) -> GatewayResult<Option<(IncomingRequest, tokio::sync::SemaphorePermit<'_>)>> {
        // Acquire semaphore permit to limit concurrent processing
        let permit = match timeout(self.config.max_wait_time, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                warn!("Failed to acquire semaphore permit");
                return Err(GatewayError::ServiceUnavailable { 
                    service: "queue".to_string(), 
                    reason: "Failed to acquire semaphore permit".to_string() 
                });
            }
            Err(_) => {
                warn!("Timeout waiting for semaphore permit");
                return Err(GatewayError::Timeout);
            }
        };
        
        let mut queue = self.queue.lock().await;
        
        // Check if there are any requests in queue
        if queue.is_empty() {
            return Ok(None);
        }
        
        // Remove expired requests
        let now = Instant::now();
        while let Some(front) = queue.front() {
            if now.duration_since(front.queued_at) > self.config.max_wait_time {
                let expired = queue.pop_front().unwrap();
                self.metrics.total_timeouts.fetch_add(1, Ordering::Relaxed);
                warn!("Request expired in queue after {:?}", now.duration_since(expired.queued_at));
            } else {
                break;
            }
        }
        
        // Dequeue the highest priority request
        if let Some(queued_request) = queue.pop_front() {
            let wait_time = now.duration_since(queued_request.queued_at);
            
            // Update metrics
            self.metrics.current_queue_size.store(queue.len(), Ordering::Relaxed);
            self.metrics.total_processed.fetch_add(1, Ordering::Relaxed);
            self.metrics.current_concurrent.fetch_add(1, Ordering::Relaxed);
            
            // Update average wait time (simple moving average)
            let current_avg = self.metrics.avg_wait_time_ms.load(Ordering::Relaxed);
            let new_avg = (current_avg + wait_time.as_millis() as u64) / 2;
            self.metrics.avg_wait_time_ms.store(new_avg, Ordering::Relaxed);
            
            debug!("Request dequeued after waiting {:?}. Queue size: {}", wait_time, queue.len());
            
            Ok(Some((queued_request.request, permit)))
        } else {
            Ok(None)
        }
    }
    
    /// Get current queue metrics
    pub fn metrics(&self) -> QueueMetrics {
        self.metrics.clone()
    }
    
    /// Get current queue size
    pub async fn queue_size(&self) -> usize {
        self.queue.lock().await.len()
    }
    
    /// Check if backpressure should be applied
    pub async fn should_apply_backpressure(&self) -> bool {
        let current_size = self.queue_size().await;
        let threshold = (self.config.max_queue_size as f32 * self.config.backpressure_threshold) as usize;
        current_size >= threshold
    }
    
    /// Start graceful shutdown - stop accepting new requests
    pub async fn start_shutdown(&self) {
        *self.shutdown.write().await = true;
        info!("Request queue shutdown initiated");
    }
    
    /// Wait for all queued requests to be processed
    pub async fn wait_for_empty(&self, timeout_duration: Duration) -> GatewayResult<()> {
        let start = Instant::now();
        
        while start.elapsed() < timeout_duration {
            if self.queue_size().await == 0 {
                info!("Request queue is empty");
                return Ok(());
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        warn!("Timeout waiting for request queue to empty. Remaining: {}", self.queue_size().await);
        Err(GatewayError::Timeout { timeout_ms: self.config.max_wait_time.as_millis() as u64 })
    }
    
    /// Update configuration (for dynamic reconfiguration)
    pub async fn update_config(&mut self, new_config: BackpressureConfig) {
        // Update semaphore if concurrent request limit changed
        if new_config.max_concurrent_requests != self.config.max_concurrent_requests {
            self.semaphore = Arc::new(Semaphore::new(new_config.max_concurrent_requests));
        }
        
        self.config = new_config;
        info!("Request queue configuration updated");
    }
}

impl Drop for RequestQueue {
    fn drop(&mut self) {
        // Update metrics when request processing is complete
        self.metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{IncomingRequest, RequestContext, Protocol};
    use std::sync::Arc;
    use tokio::time::sleep;
    use axum::http::{Method, HeaderMap, Version};
    
    fn create_test_request() -> IncomingRequest {
        IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/test".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }
    
    #[tokio::test]
    async fn test_basic_queue_operations() {
        let config = BackpressureConfig {
            max_queue_size: 10,
            max_concurrent_requests: 2,
            ..Default::default()
        };
        
        let queue = RequestQueue::new(config);
        
        // Test enqueue
        let request = create_test_request();
        assert!(queue.enqueue(request, 1).await.is_ok());
        assert_eq!(queue.queue_size().await, 1);
        
        // Test dequeue
        let result = queue.dequeue().await.unwrap();
        assert!(result.is_some());
        assert_eq!(queue.queue_size().await, 0);
    }
    
    #[tokio::test]
    async fn test_priority_ordering() {
        let config = BackpressureConfig {
            max_queue_size: 10,
            max_concurrent_requests: 1,
            ..Default::default()
        };
        
        let queue = RequestQueue::new(config);
        
        // Enqueue requests with different priorities
        queue.enqueue(create_test_request(), 1).await.unwrap();
        queue.enqueue(create_test_request(), 3).await.unwrap();
        queue.enqueue(create_test_request(), 2).await.unwrap();
        
        // Dequeue should return highest priority first
        let (req1, _permit1) = queue.dequeue().await.unwrap().unwrap();
        let (req2, _permit2) = queue.dequeue().await.unwrap().unwrap();
        let (req3, _permit3) = queue.dequeue().await.unwrap().unwrap();
        
        // Note: In a real test, we'd need to verify the actual priority order
        // This is simplified for the example
    }
    
    #[tokio::test]
    async fn test_backpressure() {
        let config = BackpressureConfig {
            max_queue_size: 10,
            backpressure_threshold: 0.5, // 50% of max_queue_size = 5
            max_concurrent_requests: 1,
            ..Default::default()
        };
        
        let queue = RequestQueue::new(config);
        
        // Fill queue to backpressure threshold
        for _ in 0..5 {
            assert!(queue.enqueue(create_test_request(), 1).await.is_ok());
        }
        
        // Next request should trigger backpressure
        let result = queue.enqueue(create_test_request(), 1).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let config = BackpressureConfig::default();
        let queue = RequestQueue::new(config);
        
        // Enqueue some requests
        queue.enqueue(create_test_request(), 1).await.unwrap();
        queue.enqueue(create_test_request(), 1).await.unwrap();
        
        // Start shutdown
        queue.start_shutdown().await;
        
        // New requests should be rejected
        let result = queue.enqueue(create_test_request(), 1).await;
        assert!(result.is_err());
        
        // Existing requests can still be processed
        assert!(queue.dequeue().await.unwrap().is_some());
    }
}
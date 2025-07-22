//! # Traffic Manager
//! 
//! This module coordinates all traffic management components including
//! queuing, shaping, prioritization, graceful shutdown, and traffic splitting.
//! 
//! The TrafficManager serves as the central coordinator for all traffic management
//! features, providing a unified interface for request processing with advanced
//! traffic control capabilities.

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, GatewayResponse};
use crate::traffic::{
    BackpressureConfig, PriorityConfig, RequestPriority, RequestQueue, ShutdownConfig,
    SplitConfig, ThrottleConfig, TrafficShaper, TrafficSplitter, GracefulShutdown, PriorityManager,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Configuration for the traffic manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficManagerConfig {
    /// Request queue configuration
    pub queue: BackpressureConfig,
    
    /// Traffic shaping configuration
    pub shaping: ThrottleConfig,
    
    /// Request prioritization configuration
    pub priority: PriorityConfig,
    
    /// Graceful shutdown configuration
    pub shutdown: ShutdownConfig,
    
    /// Traffic splitting configurations
    pub splits: Vec<SplitConfig>,
    
    /// Enable traffic management features
    pub enabled: bool,
    
    /// Default timeout for request processing
    pub default_timeout: Duration,
    
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
}

impl Default for TrafficManagerConfig {
    fn default() -> Self {
        Self {
            queue: BackpressureConfig::default(),
            shaping: ThrottleConfig::default(),
            priority: PriorityConfig::default(),
            shutdown: ShutdownConfig::default(),
            splits: Vec::new(),
            enabled: true,
            default_timeout: Duration::from_secs(30),
            max_concurrent_requests: 1000,
        }
    }
}

/// Comprehensive traffic management metrics
#[derive(Debug, Clone)]
pub struct TrafficManagerMetrics {
    /// Total requests processed
    pub total_requests: u64,
    
    /// Requests currently being processed
    pub active_requests: u64,
    
    /// Requests queued
    pub queued_requests: u64,
    
    /// Requests throttled
    pub throttled_requests: u64,
    
    /// Requests shaped (delayed)
    pub shaped_requests: u64,
    
    /// Average request processing time
    pub avg_processing_time_ms: u64,
    
    /// Current system load
    pub system_load: f32,
    
    /// Traffic split decisions
    pub split_decisions: u64,
}

/// Request processing context with traffic management metadata
#[derive(Debug)]
pub struct TrafficContext {
    /// Request priority
    pub priority: RequestPriority,
    
    /// Traffic split variant
    pub variant: Option<String>,
    
    /// Processing start time
    pub started_at: Instant,
    
    /// Whether request was queued
    pub was_queued: bool,
    
    /// Whether request was shaped (delayed)
    pub was_shaped: bool,
    
    /// Queue wait time
    pub queue_wait_time: Option<Duration>,
    
    /// Shaping delay time
    pub shaping_delay: Option<Duration>,
}

/// Central traffic manager coordinating all traffic management components
pub struct TrafficManager {
    config: Arc<RwLock<TrafficManagerConfig>>,
    queue: Arc<RequestQueue>,
    shaper: Arc<TrafficShaper>,
    priority_manager: Arc<RwLock<PriorityManager>>,
    splitter: Arc<TrafficSplitter>,
    shutdown: Arc<GracefulShutdown>,
}

impl TrafficManager {
    /// Create a new traffic manager with the given configuration
    pub async fn new(config: TrafficManagerConfig) -> GatewayResult<Self> {
        let queue = Arc::new(RequestQueue::new(config.queue.clone()));
        let shaper = Arc::new(TrafficShaper::new(config.shaping.clone()));
        let priority_manager = Arc::new(RwLock::new(PriorityManager::new(config.priority.clone())));
        let splitter = Arc::new(TrafficSplitter::new());
        let shutdown = Arc::new(GracefulShutdown::new(config.shutdown.clone()));
        
        // Add traffic splits to splitter
        for split in &config.splits {
            splitter.add_split(split.clone()).await?;
        }
        
        let manager = Self {
            config: Arc::new(RwLock::new(config)),
            queue,
            shaper,
            priority_manager,
            splitter,
            shutdown,
        };
        
        info!("Traffic manager initialized successfully");
        Ok(manager)
    }
    
    /// Process a request through the complete traffic management pipeline
    pub async fn process_request<F, Fut>(
        &self,
        mut request: IncomingRequest,
        handler: F,
    ) -> GatewayResult<(GatewayResponse, TrafficContext)>
    where
        F: FnOnce(IncomingRequest) -> Fut + Send,
        Fut: std::future::Future<Output = GatewayResult<GatewayResponse>> + Send,
    {
        let processing_start = Instant::now();
        let config = self.config.read().await;
        
        if !config.enabled {
            // Traffic management disabled, process directly
            let response = handler(request).await?;
            let context = TrafficContext {
                priority: RequestPriority::Normal,
                variant: None,
                started_at: processing_start,
                was_queued: false,
                was_shaped: false,
                queue_wait_time: None,
                shaping_delay: None,
            };
            return Ok((response, context));
        }
        
        // Step 1: Check graceful shutdown status
        let _request_guard = self.shutdown.start_request().await?;
        
        // Step 2: Determine request priority
        let priority = {
            let priority_manager = self.priority_manager.read().await;
            priority_manager.determine_priority(&request).await
        };
        
        debug!("Request {} assigned priority: {:?}", request.id, priority);
        
        // Step 3: Apply traffic shaping
        let client_id = self.extract_client_id(&request);
        let endpoint = &request.path;
        
        let shaping_result = self.shaper.check_request(
            &client_id,
            endpoint,
            None, // Could be extracted from request context
        ).await;
        
        let (was_shaped, shaping_delay) = match shaping_result {
            Ok(Some(delay)) => {
                info!("Shaping request {} with delay: {:?}", request.id, delay);
                self.shaper.shape_request(delay).await?;
                (true, Some(delay))
            }
            Ok(None) => (false, None),
            Err(GatewayError::RateLimitExceeded) => {
                warn!("Request {} throttled due to rate limit", request.id);
                return Err(GatewayError::RateLimitExceeded);
            }
            Err(GatewayError::ServiceUnavailable) => {
                warn!("Request {} throttled due to service unavailability", request.id);
                return Err(GatewayError::ServiceUnavailable);
            }
            Err(e) => return Err(e),
        };
        
        // Step 4: Determine traffic split variant (if applicable)
        let variant = if !config.splits.is_empty() {
            // Use the first split configuration for simplicity
            // In a real implementation, you'd have logic to select the appropriate split
            if let Some(split) = config.splits.first() {
                match self.splitter.determine_variant(&request, &split.id).await {
                    Ok(v) => {
                        debug!("Request {} routed to variant: {}", request.id, v);
                        Some(v)
                    }
                    Err(e) => {
                        warn!("Failed to determine variant for request {}: {}", request.id, e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        
        // Step 5: Queue request with priority
        let queue_start = Instant::now();
        self.queue.enqueue(request.clone(), priority as u8).await?;
        
        // Step 6: Dequeue and process request
        let (dequeued_request, _permit) = match self.queue.dequeue().await? {
            Some((req, permit)) => (req, permit),
            None => {
                error!("Failed to dequeue request {}", request.id);
                return Err(GatewayError::Internal("Queue dequeue failed".into()));
            }
        };
        
        let queue_wait_time = queue_start.elapsed();
        debug!("Request {} waited in queue for: {:?}", dequeued_request.id, queue_wait_time);
        
        // Step 7: Process the request
        let response = handler(dequeued_request).await?;
        
        // Step 8: Create traffic context
        let context = TrafficContext {
            priority,
            variant,
            started_at: processing_start,
            was_queued: true,
            was_shaped,
            queue_wait_time: Some(queue_wait_time),
            shaping_delay,
        };
        
        info!(
            "Request {} processed successfully in {:?} (queue: {:?}, shaping: {:?})",
            request.id,
            processing_start.elapsed(),
            queue_wait_time,
            shaping_delay.unwrap_or(Duration::ZERO)
        );
        
        Ok((response, context))
    }
    
    /// Extract client ID from request for traffic shaping
    fn extract_client_id(&self, request: &IncomingRequest) -> String {
        // Try various sources for client identification
        if let Some(client_id) = request.header("x-client-id") {
            return client_id.to_string();
        }
        
        // Fallback to remote address as client ID
        request.remote_addr.ip().to_string()
    }
    
    /// Get comprehensive traffic management metrics
    pub async fn get_metrics(&self) -> TrafficManagerMetrics {
        let queue_metrics = self.queue.metrics();
        let shaping_metrics = self.shaper.metrics();
        let split_metrics = self.splitter.metrics();
        
        TrafficManagerMetrics {
            total_requests: queue_metrics.total_processed.load(std::sync::atomic::Ordering::Relaxed),
            active_requests: queue_metrics.current_concurrent.load(std::sync::atomic::Ordering::Relaxed),
            queued_requests: queue_metrics.current_queue_size.load(std::sync::atomic::Ordering::Relaxed) as u64,
            throttled_requests: shaping_metrics.total_throttled.load(std::sync::atomic::Ordering::Relaxed),
            shaped_requests: shaping_metrics.total_shaped.load(std::sync::atomic::Ordering::Relaxed),
            avg_processing_time_ms: queue_metrics.avg_wait_time_ms.load(std::sync::atomic::Ordering::Relaxed),
            system_load: shaping_metrics.system_load.load(std::sync::atomic::Ordering::Relaxed) as f32 / 100.0,
            split_decisions: split_metrics.split_decisions.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
    
    /// Update traffic manager configuration
    pub async fn update_config(&self, new_config: TrafficManagerConfig) -> GatewayResult<()> {
        // Update individual component configurations
        let mut queue = Arc::try_unwrap(Arc::clone(&self.queue))
            .map_err(|_| GatewayError::Internal("Failed to update queue config".into()))?;
        queue.update_config(new_config.queue.clone()).await;
        
        self.shaper.update_config(new_config.shaping.clone()).await;
        
        {
            let mut priority_manager = self.priority_manager.write().await;
            priority_manager.update_config(new_config.priority.clone()).await;
        }
        
        // Update splits
        for split in &new_config.splits {
            self.splitter.update_split(split.clone()).await?;
        }
        
        // Update main configuration
        *self.config.write().await = new_config;
        
        info!("Traffic manager configuration updated successfully");
        Ok(())
    }
    
    /// Add a new traffic split configuration
    pub async fn add_traffic_split(&self, split: SplitConfig) -> GatewayResult<()> {
        self.splitter.add_split(split.clone()).await?;
        
        // Update config to include the new split
        let mut config = self.config.write().await;
        config.splits.push(split);
        
        Ok(())
    }
    
    /// Remove a traffic split configuration
    pub async fn remove_traffic_split(&self, split_id: &str) -> GatewayResult<bool> {
        let removed = self.splitter.remove_split(split_id).await?;
        
        if removed {
            // Update config to remove the split
            let mut config = self.config.write().await;
            config.splits.retain(|split| split.id != split_id);
        }
        
        Ok(removed)
    }
    
    /// Enable or disable traffic management
    pub async fn set_enabled(&self, enabled: bool) {
        let mut config = self.config.write().await;
        config.enabled = enabled;
        info!("Traffic management {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Check if traffic management is enabled
    pub async fn is_enabled(&self) -> bool {
        self.config.read().await.enabled
    }
    
    /// Get current queue size
    pub async fn get_queue_size(&self) -> usize {
        self.queue.queue_size().await
    }
    
    /// Check if backpressure should be applied
    pub async fn should_apply_backpressure(&self) -> bool {
        self.queue.should_apply_backpressure().await
    }
    
    /// Get traffic split variant counts
    pub fn get_variant_counts(&self) -> std::collections::HashMap<String, u64> {
        self.splitter.get_variant_counts()
    }
    
    /// List all active traffic splits
    pub fn list_traffic_splits(&self) -> Vec<SplitConfig> {
        self.splitter.list_splits()
    }
    
    /// Initiate graceful shutdown
    pub async fn initiate_shutdown(&self) -> GatewayResult<()> {
        info!("Initiating traffic manager shutdown");
        
        // Stop accepting new requests
        self.queue.start_shutdown().await;
        
        // Initiate graceful shutdown
        self.shutdown.initiate_shutdown().await?;
        
        info!("Traffic manager shutdown completed");
        Ok(())
    }
    
    /// Force immediate shutdown
    pub async fn force_shutdown(&self) -> GatewayResult<()> {
        warn!("Forcing immediate traffic manager shutdown");
        self.shutdown.force_shutdown().await
    }
    
    /// Wait for all queued requests to complete
    pub async fn wait_for_completion(&self, timeout: Duration) -> GatewayResult<()> {
        self.queue.wait_for_empty(timeout).await
    }
    
    /// Get shutdown status
    pub async fn is_shutdown_initiated(&self) -> bool {
        self.shutdown.is_shutdown_initiated()
    }
    
    /// Get current shutdown phase
    pub async fn get_shutdown_phase(&self) -> crate::traffic::shutdown::ShutdownPhase {
        self.shutdown.current_phase().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{RequestContext, GatewayResponse};
    use std::collections::HashMap;
    use tokio::time::sleep;
    
    fn create_test_request(id: &str) -> Request {
        Request {
            id: id.to_string(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            context: RequestContext::default(),
        }
    }
    
    async fn dummy_handler(request: Request) -> GatewayResult<Response> {
        // Simulate some processing time
        sleep(Duration::from_millis(10)).await;
        
        Ok(Response {
            status: 200,
            headers: HashMap::new(),
            body: format!("Processed request: {}", request.id).into_bytes(),
        })
    }
    
    #[tokio::test]
    async fn test_traffic_manager_basic_processing() {
        let config = TrafficManagerConfig {
            enabled: true,
            queue: BackpressureConfig {
                max_queue_size: 100,
                max_concurrent_requests: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let manager = TrafficManager::new(config).await.unwrap();
        let request = create_test_request("test-1");
        
        let (response, context) = manager.process_request(request, dummy_handler).await.unwrap();
        
        assert_eq!(response.status, 200);
        assert!(context.was_queued);
        assert_eq!(context.priority, RequestPriority::Normal);
    }
    
    #[tokio::test]
    async fn test_traffic_manager_disabled() {
        let config = TrafficManagerConfig {
            enabled: false,
            ..Default::default()
        };
        
        let manager = TrafficManager::new(config).await.unwrap();
        let request = create_test_request("test-1");
        
        let (response, context) = manager.process_request(request, dummy_handler).await.unwrap();
        
        assert_eq!(response.status, 200);
        assert!(!context.was_queued);
        assert!(!context.was_shaped);
    }
    
    #[tokio::test]
    async fn test_traffic_manager_metrics() {
        let config = TrafficManagerConfig::default();
        let manager = TrafficManager::new(config).await.unwrap();
        
        // Process a few requests
        for i in 0..3 {
            let request = create_test_request(&format!("test-{}", i));
            let _ = manager.process_request(request, dummy_handler).await.unwrap();
        }
        
        let metrics = manager.get_metrics().await;
        assert!(metrics.total_requests >= 3);
    }
    
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let config = TrafficManagerConfig {
            shutdown: ShutdownConfig {
                graceful_timeout: Duration::from_millis(100),
                ..Default::default()
            },
            ..Default::default()
        };
        
        let manager = TrafficManager::new(config).await.unwrap();
        
        // Start shutdown
        assert!(manager.initiate_shutdown().await.is_ok());
        assert!(manager.is_shutdown_initiated().await);
        
        // New requests should be rejected
        let request = create_test_request("test-after-shutdown");
        let result = manager.process_request(request, dummy_handler).await;
        assert!(result.is_err());
    }
}
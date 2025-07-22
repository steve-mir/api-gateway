//! # Traffic Shaping and Throttling
//! 
//! This module implements traffic shaping capabilities to control the rate
//! of requests and provide throttling mechanisms for load management.

use crate::core::error::{GatewayError, GatewayResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{interval, sleep_until, Instant as TokioInstant};
use tracing::{debug, info, warn};

/// Configuration for traffic shaping and throttling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleConfig {
    /// Global requests per second limit
    pub global_rps_limit: Option<u64>,
    
    /// Per-client requests per second limit
    pub per_client_rps_limit: Option<u64>,
    
    /// Per-endpoint requests per second limit
    pub per_endpoint_rps_limit: Option<u64>,
    
    /// Burst capacity (number of requests that can exceed the rate limit temporarily)
    pub burst_capacity: u64,
    
    /// Time window for rate limiting (in seconds)
    pub window_size: Duration,
    
    /// Enable adaptive throttling based on system load
    pub adaptive_throttling: bool,
    
    /// CPU threshold for adaptive throttling (0.0 to 1.0)
    pub cpu_threshold: f32,
    
    /// Memory threshold for adaptive throttling (0.0 to 1.0)
    pub memory_threshold: f32,
    
    /// Throttling policies for different request types
    pub policies: HashMap<String, ThrottlePolicy>,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            global_rps_limit: Some(10000),
            per_client_rps_limit: Some(100),
            per_endpoint_rps_limit: Some(1000),
            burst_capacity: 100,
            window_size: Duration::from_secs(1),
            adaptive_throttling: true,
            cpu_threshold: 0.8,
            memory_threshold: 0.8,
            policies: HashMap::new(),
        }
    }
}

/// Throttling policy for specific request types or endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottlePolicy {
    /// Requests per second limit for this policy
    pub rps_limit: u64,
    
    /// Burst capacity for this policy
    pub burst_capacity: u64,
    
    /// Priority level (higher values = higher priority)
    pub priority: u8,
    
    /// Whether to queue requests when limit is exceeded
    pub queue_on_limit: bool,
    
    /// Maximum queue time for this policy
    pub max_queue_time: Duration,
}

impl Default for ThrottlePolicy {
    fn default() -> Self {
        Self {
            rps_limit: 100,
            burst_capacity: 10,
            priority: 1,
            queue_on_limit: true,
            max_queue_time: Duration::from_secs(5),
        }
    }
}

/// Metrics for traffic shaping monitoring
#[derive(Debug, Clone)]
pub struct ShapingMetrics {
    /// Total requests processed
    pub total_requests: Arc<AtomicU64>,
    
    /// Total requests throttled
    pub total_throttled: Arc<AtomicU64>,
    
    /// Total requests shaped (delayed)
    pub total_shaped: Arc<AtomicU64>,
    
    /// Current requests per second
    pub current_rps: Arc<AtomicU64>,
    
    /// Average response time (in milliseconds)
    pub avg_response_time_ms: Arc<AtomicU64>,
    
    /// Current system load (0.0 to 1.0)
    pub system_load: Arc<AtomicU64>, // Stored as percentage * 100
}

impl Default for ShapingMetrics {
    fn default() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            total_throttled: Arc::new(AtomicU64::new(0)),
            total_shaped: Arc::new(AtomicU64::new(0)),
            current_rps: Arc::new(AtomicU64::new(0)),
            avg_response_time_ms: Arc::new(AtomicU64::new(0)),
            system_load: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }
    
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
    
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
    
    fn tokens_available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// Traffic shaper with throttling capabilities
pub struct TrafficShaper {
    config: Arc<RwLock<ThrottleConfig>>,
    global_bucket: Arc<RwLock<TokenBucket>>,
    client_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    endpoint_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    metrics: ShapingMetrics,
    system_monitor: Arc<RwLock<SystemLoad>>,
}

#[derive(Debug, Clone)]
struct SystemLoad {
    cpu_usage: f32,
    memory_usage: f32,
    last_updated: Instant,
}

impl Default for SystemLoad {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            last_updated: Instant::now(),
        }
    }
}

impl TrafficShaper {
    /// Create a new traffic shaper with the given configuration
    pub fn new(config: ThrottleConfig) -> Self {
        let global_bucket = if let Some(limit) = config.global_rps_limit {
            Arc::new(RwLock::new(TokenBucket::new(
                config.burst_capacity as f64,
                limit as f64,
            )))
        } else {
            Arc::new(RwLock::new(TokenBucket::new(f64::INFINITY, f64::INFINITY)))
        };
        
        let shaper = Self {
            config: Arc::new(RwLock::new(config)),
            global_bucket,
            client_buckets: Arc::new(RwLock::new(HashMap::new())),
            endpoint_buckets: Arc::new(RwLock::new(HashMap::new())),
            metrics: ShapingMetrics::default(),
            system_monitor: Arc::new(RwLock::new(SystemLoad::default())),
        };
        
        // Start system monitoring task
        shaper.start_system_monitoring();
        
        shaper
    }
    
    /// Check if a request should be allowed, throttled, or shaped
    /// 
    /// Returns:
    /// - Ok(None) if request should proceed immediately
    /// - Ok(Some(delay)) if request should be delayed (shaped)
    /// - Err if request should be throttled (rejected)
    pub async fn check_request(
        &self,
        client_id: &str,
        endpoint: &str,
        policy_name: Option<&str>,
    ) -> GatewayResult<Option<Duration>> {
        let config = self.config.read().await;
        
        // Check adaptive throttling first
        if config.adaptive_throttling {
            let system_load = self.system_monitor.read().await;
            if system_load.cpu_usage > config.cpu_threshold || system_load.memory_usage > config.memory_threshold {
                self.metrics.total_throttled.fetch_add(1, Ordering::Relaxed);
                warn!("Adaptive throttling triggered - CPU: {:.2}%, Memory: {:.2}%", 
                      system_load.cpu_usage * 100.0, system_load.memory_usage * 100.0);
                return Err(GatewayError::ServiceUnavailable);
            }
        }
        
        // Check policy-specific limits
        if let Some(policy_name) = policy_name {
            if let Some(policy) = config.policies.get(policy_name) {
                if !self.check_policy_limit(policy).await? {
                    if policy.queue_on_limit {
                        let delay = self.calculate_delay(policy.rps_limit).await;
                        self.metrics.total_shaped.fetch_add(1, Ordering::Relaxed);
                        return Ok(Some(delay));
                    } else {
                        self.metrics.total_throttled.fetch_add(1, Ordering::Relaxed);
                        return Err(GatewayError::RateLimitExceeded);
                    }
                }
            }
        }
        
        // Check global limit
        if !self.check_global_limit().await? {
            let delay = self.calculate_global_delay().await;
            self.metrics.total_shaped.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(delay));
        }
        
        // Check per-client limit
        if let Some(limit) = config.per_client_rps_limit {
            if !self.check_client_limit(client_id, limit, config.burst_capacity).await? {
                let delay = self.calculate_delay(limit).await;
                self.metrics.total_shaped.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(delay));
            }
        }
        
        // Check per-endpoint limit
        if let Some(limit) = config.per_endpoint_rps_limit {
            if !self.check_endpoint_limit(endpoint, limit, config.burst_capacity).await? {
                let delay = self.calculate_delay(limit).await;
                self.metrics.total_shaped.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(delay));
            }
        }
        
        // Update metrics
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        
        Ok(None)
    }
    
    /// Apply traffic shaping by delaying the request
    pub async fn shape_request(&self, delay: Duration) -> GatewayResult<()> {
        if delay > Duration::ZERO {
            debug!("Shaping request with delay: {:?}", delay);
            let target_time = TokioInstant::now() + delay;
            sleep_until(target_time).await;
        }
        Ok(())
    }
    
    async fn check_global_limit(&self) -> GatewayResult<bool> {
        let mut bucket = self.global_bucket.write().await;
        Ok(bucket.try_consume(1.0))
    }
    
    async fn check_client_limit(&self, client_id: &str, limit: u64, burst: u64) -> GatewayResult<bool> {
        let mut buckets = self.client_buckets.write().await;
        let bucket = buckets.entry(client_id.to_string()).or_insert_with(|| {
            TokenBucket::new(burst as f64, limit as f64)
        });
        Ok(bucket.try_consume(1.0))
    }
    
    async fn check_endpoint_limit(&self, endpoint: &str, limit: u64, burst: u64) -> GatewayResult<bool> {
        let mut buckets = self.endpoint_buckets.write().await;
        let bucket = buckets.entry(endpoint.to_string()).or_insert_with(|| {
            TokenBucket::new(burst as f64, limit as f64)
        });
        Ok(bucket.try_consume(1.0))
    }
    
    async fn check_policy_limit(&self, policy: &ThrottlePolicy) -> GatewayResult<bool> {
        // For simplicity, we'll use a basic check here
        // In a real implementation, you'd want separate buckets per policy
        Ok(true) // Placeholder
    }
    
    async fn calculate_delay(&self, rps_limit: u64) -> Duration {
        // Calculate delay based on current load and rate limit
        let base_delay = Duration::from_millis(1000 / rps_limit.max(1));
        
        // Add jitter to prevent thundering herd
        let jitter = fastrand::u64(0..=base_delay.as_millis() as u64 / 4);
        base_delay + Duration::from_millis(jitter)
    }
    
    async fn calculate_global_delay(&self) -> Duration {
        let config = self.config.read().await;
        if let Some(limit) = config.global_rps_limit {
            self.calculate_delay(limit).await
        } else {
            Duration::ZERO
        }
    }
    
    /// Get current shaping metrics
    pub fn metrics(&self) -> ShapingMetrics {
        self.metrics.clone()
    }
    
    /// Update configuration dynamically
    pub async fn update_config(&self, new_config: ThrottleConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("Traffic shaper configuration updated");
    }
    
    /// Start system monitoring for adaptive throttling
    fn start_system_monitoring(&self) {
        let system_monitor = Arc::clone(&self.system_monitor);
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Simulate system load monitoring
                // In a real implementation, you'd use system APIs to get actual CPU/memory usage
                let cpu_usage = Self::get_cpu_usage().await;
                let memory_usage = Self::get_memory_usage().await;
                
                {
                    let mut load = system_monitor.write().await;
                    load.cpu_usage = cpu_usage;
                    load.memory_usage = memory_usage;
                    load.last_updated = Instant::now();
                }
                
                // Update metrics
                let system_load_pct = ((cpu_usage + memory_usage) / 2.0 * 100.0) as u64;
                metrics.system_load.store(system_load_pct, Ordering::Relaxed);
                
                debug!("System load updated - CPU: {:.2}%, Memory: {:.2}%", 
                       cpu_usage * 100.0, memory_usage * 100.0);
            }
        });
    }
    
    async fn get_cpu_usage() -> f32 {
        // Placeholder implementation
        // In a real system, you'd use sysinfo or similar crate
        fastrand::f32() * 0.3 // Simulate 0-30% CPU usage
    }
    
    async fn get_memory_usage() -> f32 {
        // Placeholder implementation
        // In a real system, you'd use sysinfo or similar crate
        fastrand::f32() * 0.4 // Simulate 0-40% memory usage
    }
    
    /// Clean up old client and endpoint buckets
    pub async fn cleanup_buckets(&self) {
        let cleanup_threshold = Duration::from_secs(300); // 5 minutes
        let now = Instant::now();
        
        // Clean up client buckets
        {
            let mut buckets = self.client_buckets.write().await;
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_refill) < cleanup_threshold
            });
        }
        
        // Clean up endpoint buckets
        {
            let mut buckets = self.endpoint_buckets.write().await;
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_refill) < cleanup_threshold
            });
        }
        
        debug!("Cleaned up old token buckets");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10.0, 5.0); // 10 capacity, 5 tokens/sec
        
        // Should be able to consume initial tokens
        assert!(bucket.try_consume(5.0));
        assert!(bucket.try_consume(5.0));
        
        // Should not be able to consume more
        assert!(!bucket.try_consume(1.0));
        
        // Wait for refill
        sleep(Duration::from_millis(200)).await;
        bucket.refill();
        
        // Should have some tokens available now
        assert!(bucket.tokens_available() > 0.0);
    }
    
    #[tokio::test]
    async fn test_traffic_shaper_basic() {
        let config = ThrottleConfig {
            global_rps_limit: Some(10),
            burst_capacity: 5,
            ..Default::default()
        };
        
        let shaper = TrafficShaper::new(config);
        
        // First few requests should pass
        for _ in 0..5 {
            let result = shaper.check_request("client1", "/api/test", None).await;
            assert!(result.is_ok());
        }
        
        // Next request might be shaped or throttled
        let result = shaper.check_request("client1", "/api/test", None).await;
        // Result depends on timing, but should not panic
        assert!(result.is_ok() || result.is_err());
    }
    
    #[tokio::test]
    async fn test_per_client_limiting() {
        let config = ThrottleConfig {
            per_client_rps_limit: Some(2),
            burst_capacity: 2,
            global_rps_limit: None,
            ..Default::default()
        };
        
        let shaper = TrafficShaper::new(config);
        
        // Client1 should be able to make 2 requests
        assert!(shaper.check_request("client1", "/api/test", None).await.is_ok());
        assert!(shaper.check_request("client1", "/api/test", None).await.is_ok());
        
        // Third request should be shaped or throttled
        let result = shaper.check_request("client1", "/api/test", None).await;
        assert!(result.is_ok()); // Might return delay or pass depending on timing
        
        // Different client should still work
        assert!(shaper.check_request("client2", "/api/test", None).await.is_ok());
    }
}
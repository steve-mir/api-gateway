//! # Error Recovery Module
//!
//! This module provides error recovery mechanisms for the API Gateway.
//! It implements various strategies to handle failures gracefully and
//! maintain service availability even when upstream services fail.
//!
//! ## Recovery Strategies
//! - Retry with exponential backoff
//! - Fallback to alternative services
//! - Cached response fallback
//! - Default/static response fallback
//! - Graceful degradation

use crate::core::error::{GatewayError, GatewayResult};
use axum::http::{StatusCode, HeaderMap};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn, error};

/// Recovery strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable error recovery mechanisms
    pub enabled: bool,
    
    /// Maximum number of recovery attempts
    pub max_attempts: u32,
    
    /// Recovery strategies by error type
    pub strategies: HashMap<String, Vec<RecoveryStrategy>>,
    
    /// Default recovery strategy for unmatched errors
    pub default_strategy: Vec<RecoveryStrategy>,
    
    /// Recovery timeout (maximum time to spend on recovery)
    pub recovery_timeout: Duration,
    
    /// Enable recovery metrics collection
    pub collect_metrics: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        let mut strategies = HashMap::new();
        
        // Service unavailable errors - try retry, then fallback
        strategies.insert("service_unavailable".to_string(), vec![
            RecoveryStrategy::RetryWithBackoff {
                max_retries: 3,
                initial_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(5),
                backoff_multiplier: 2.0,
            },
            RecoveryStrategy::FallbackService {
                fallback_service: "fallback-api".to_string(),
            },
            RecoveryStrategy::UseCachedResponse,
        ]);
        
        // Timeout errors - retry with shorter timeout, then fallback
        strategies.insert("timeout".to_string(), vec![
            RecoveryStrategy::RetryWithBackoff {
                max_retries: 2,
                initial_delay: Duration::from_millis(50),
                max_delay: Duration::from_secs(2),
                backoff_multiplier: 1.5,
            },
            RecoveryStrategy::UseCachedResponse,
            RecoveryStrategy::DefaultResponse {
                status_code: 503,
                body: "Service temporarily unavailable".to_string(),
                headers: HashMap::new(),
            },
        ]);
        
        // Circuit breaker open - use cache or default response
        strategies.insert("circuit_breaker_open".to_string(), vec![
            RecoveryStrategy::UseCachedResponse,
            RecoveryStrategy::GracefulDegradation {
                degraded_response: "Limited functionality available".to_string(),
                status_code: 206,
            },
        ]);
        
        // Default strategy for other errors
        let default_strategy = vec![
            RecoveryStrategy::UseCachedResponse,
            RecoveryStrategy::DefaultResponse {
                status_code: 500,
                body: "An error occurred while processing your request".to_string(),
                headers: HashMap::new(),
            },
        ];
        
        Self {
            enabled: true,
            max_attempts: 3,
            strategies,
            default_strategy,
            recovery_timeout: Duration::from_secs(10),
            collect_metrics: true,
        }
    }
}

/// Recovery strategy types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Retry the request with exponential backoff
    RetryWithBackoff {
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_multiplier: f64,
    },
    
    /// Fallback to an alternative service
    FallbackService {
        fallback_service: String,
    },
    
    /// Return cached response if available
    UseCachedResponse,
    
    /// Return a default/static response
    DefaultResponse {
        status_code: u16,
        body: String,
        headers: HashMap<String, String>,
    },
    
    /// Graceful degradation with reduced functionality
    GracefulDegradation {
        degraded_response: String,
        status_code: u16,
    },
}

/// Recovery attempt result
#[derive(Debug)]
pub enum RecoveryResult {
    /// Recovery was successful
    Success(Response),
    
    /// Recovery failed, try next strategy
    Failed(GatewayError),
    
    /// Recovery not applicable for this error
    NotApplicable,
    
    /// Recovery timed out
    TimedOut,
}

/// Recovery context containing request information
#[derive(Debug, Clone)]
pub struct RecoveryContext {
    /// Original request path
    pub request_path: String,
    
    /// Original request method
    pub request_method: String,
    
    /// Original request headers
    pub request_headers: HeaderMap,
    
    /// Original request body (if available)
    pub request_body: Option<Vec<u8>>,
    
    /// Request ID for correlation
    pub request_id: String,
    
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
    
    /// Target service that failed
    pub target_service: Option<String>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Recovery metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    /// Total recovery attempts
    pub total_attempts: u64,
    
    /// Successful recoveries
    pub successful_recoveries: u64,
    
    /// Failed recoveries
    pub failed_recoveries: u64,
    
    /// Recovery attempts by strategy
    pub attempts_by_strategy: HashMap<String, u64>,
    
    /// Success rate by strategy
    pub success_rate_by_strategy: HashMap<String, f64>,
    
    /// Average recovery time
    pub average_recovery_time: Duration,
}

/// Error recovery manager
pub struct ErrorRecoveryManager {
    /// Recovery configuration
    config: RecoveryConfig,
    
    /// Recovery metrics
    metrics: Arc<std::sync::RwLock<RecoveryMetrics>>,
    
    /// Cache manager for cached response fallback
    cache_manager: Option<Arc<dyn CacheProvider>>,
    
    /// Service discovery for fallback services
    service_discovery: Option<Arc<dyn ServiceProvider>>,
}

/// Trait for cache providers used in recovery
#[async_trait::async_trait]
pub trait CacheProvider: Send + Sync {
    async fn get_cached_response(&self, key: &str) -> Option<Response>;
}

/// Trait for service providers used in recovery
#[async_trait::async_trait]
pub trait ServiceProvider: Send + Sync {
    async fn call_service(&self, service: &str, context: &RecoveryContext) -> GatewayResult<Response>;
}

impl ErrorRecoveryManager {
    /// Create a new error recovery manager
    pub fn new(config: RecoveryConfig) -> Self {
        let metrics = Arc::new(std::sync::RwLock::new(RecoveryMetrics {
            total_attempts: 0,
            successful_recoveries: 0,
            failed_recoveries: 0,
            attempts_by_strategy: HashMap::new(),
            success_rate_by_strategy: HashMap::new(),
            average_recovery_time: Duration::from_millis(0),
        }));
        
        Self {
            config,
            metrics,
            cache_manager: None,
            service_discovery: None,
        }
    }
    
    /// Set cache provider for cached response fallback
    pub fn with_cache_provider(mut self, cache_provider: Arc<dyn CacheProvider>) -> Self {
        self.cache_manager = Some(cache_provider);
        self
    }
    
    /// Set service provider for fallback services
    pub fn with_service_provider(mut self, service_provider: Arc<dyn ServiceProvider>) -> Self {
        self.service_discovery = Some(service_provider);
        self
    }
    
    /// Attempt to recover from an error
    pub async fn recover_from_error(
        &self,
        error: &GatewayError,
        context: RecoveryContext,
    ) -> RecoveryResult {
        if !self.config.enabled {
            debug!("Error recovery is disabled");
            return RecoveryResult::NotApplicable;
        }
        
        let start_time = Instant::now();
        let error_type = error.error_type();
        
        info!(
            "Attempting error recovery for {} error: {}",
            error_type, error
        );
        
        // Get recovery strategies for this error type
        let strategies = self.config.strategies
            .get(error_type)
            .cloned()
            .unwrap_or_else(|| self.config.default_strategy.clone());
        
        if strategies.is_empty() {
            debug!("No recovery strategies configured for error type: {}", error_type);
            return RecoveryResult::NotApplicable;
        }
        
        // Try each recovery strategy in order
        for (attempt, strategy) in strategies.iter().enumerate() {
            if start_time.elapsed() > self.config.recovery_timeout {
                warn!("Recovery timeout exceeded");
                self.update_metrics("timeout", false, start_time.elapsed());
                return RecoveryResult::TimedOut;
            }
            
            if attempt >= self.config.max_attempts as usize {
                warn!("Maximum recovery attempts exceeded");
                break;
            }
            
            debug!("Trying recovery strategy: {:?}", strategy);
            
            match self.execute_recovery_strategy(strategy, &context).await {
                RecoveryResult::Success(response) => {
                    info!("Recovery successful using strategy: {:?}", strategy);
                    self.update_metrics(&strategy_name(strategy), true, start_time.elapsed());
                    return RecoveryResult::Success(response);
                }
                RecoveryResult::Failed(recovery_error) => {
                    warn!("Recovery strategy failed: {:?} - {}", strategy, recovery_error);
                    self.update_metrics(&strategy_name(strategy), false, start_time.elapsed());
                    continue;
                }
                RecoveryResult::NotApplicable => {
                    debug!("Recovery strategy not applicable: {:?}", strategy);
                    continue;
                }
                RecoveryResult::TimedOut => {
                    warn!("Recovery strategy timed out: {:?}", strategy);
                    self.update_metrics(&strategy_name(strategy), false, start_time.elapsed());
                    continue;
                }
            }
        }
        
        error!("All recovery strategies failed for error: {}", error);
        self.update_metrics("all_failed", false, start_time.elapsed());
        RecoveryResult::Failed(GatewayError::internal("All retry attempts failed"))
    }
    
    /// Execute a specific recovery strategy
    async fn execute_recovery_strategy(
        &self,
        strategy: &RecoveryStrategy,
        context: &RecoveryContext,
    ) -> RecoveryResult {
        match strategy {
            RecoveryStrategy::RetryWithBackoff {
                max_retries,
                initial_delay,
                max_delay,
                backoff_multiplier,
            } => {
                self.execute_retry_strategy(
                    *max_retries,
                    *initial_delay,
                    *max_delay,
                    *backoff_multiplier,
                    context,
                ).await
            }
            
            RecoveryStrategy::FallbackService { fallback_service } => {
                self.execute_fallback_service_strategy(fallback_service, context).await
            }
            
            RecoveryStrategy::UseCachedResponse => {
                self.execute_cached_response_strategy(context).await
            }
            
            RecoveryStrategy::DefaultResponse { status_code, body, headers } => {
                self.execute_default_response_strategy(*status_code, body, headers).await
            }
            
            RecoveryStrategy::GracefulDegradation { degraded_response, status_code } => {
                self.execute_graceful_degradation_strategy(degraded_response, *status_code).await
            }
        }
    }
    
    /// Execute retry with backoff strategy
    async fn execute_retry_strategy(
        &self,
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_multiplier: f64,
        context: &RecoveryContext,
    ) -> RecoveryResult {
        let delay = initial_delay;
        
        for attempt in 0..max_retries {
            if attempt > 0 {
                debug!("Retrying request after {}ms delay", delay.as_millis());
                sleep(delay).await;
                
                // Calculate next delay with exponential backoff
                let _delay = std::cmp::min(
                    Duration::from_millis((delay.as_millis() as f64 * backoff_multiplier) as u64),
                    max_delay,
                );
            }
            
            // In a real implementation, this would retry the original request
            // For now, we'll simulate a retry attempt
            debug!("Retry attempt {} for request {}", attempt + 1, context.request_id);
            
            // Simulate retry logic - in practice, this would call the original service
            // For this implementation, we'll return NotApplicable to indicate
            // that retry logic needs to be integrated with the actual request handling
            return RecoveryResult::NotApplicable;
        }
        
        RecoveryResult::Failed(GatewayError::internal("All retry attempts failed"))
    }
    
    /// Execute fallback service strategy
    async fn execute_fallback_service_strategy(
        &self,
        fallback_service: &str,
        context: &RecoveryContext,
    ) -> RecoveryResult {
        if let Some(service_provider) = &self.service_discovery {
            debug!("Attempting fallback to service: {}", fallback_service);
            
            match service_provider.call_service(fallback_service, context).await {
                Ok(response) => {
                    info!("Fallback service call successful: {}", fallback_service);
                    RecoveryResult::Success(response)
                }
                Err(e) => {
                    warn!("Fallback service call failed: {} - {}", fallback_service, e);
                    RecoveryResult::Failed(e)
                }
            }
        } else {
            debug!("No service provider configured for fallback");
            RecoveryResult::NotApplicable
        }
    }
    
    /// Execute cached response strategy
    async fn execute_cached_response_strategy(&self, context: &RecoveryContext) -> RecoveryResult {
        if let Some(cache_manager) = &self.cache_manager {
            let cache_key = format!("{}:{}", context.request_method, context.request_path);
            debug!("Attempting to use cached response for key: {}", cache_key);
            
            if let Some(cached_response) = cache_manager.get_cached_response(&cache_key).await {
                info!("Using cached response for recovery");
                return RecoveryResult::Success(cached_response);
            } else {
                debug!("No cached response available");
            }
        } else {
            debug!("No cache manager configured");
        }
        
        RecoveryResult::NotApplicable
    }
    
    /// Execute default response strategy
    async fn execute_default_response_strategy(
        &self,
        status_code: u16,
        body: &str,
        headers: &HashMap<String, String>,
    ) -> RecoveryResult {
        debug!("Using default response strategy");
        
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = axum::response::Response::builder()
            .status(status)
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        
        // Add custom headers
        let response_headers = response.headers_mut();
        for (key, value) in headers {
            if let (Ok(header_name), Ok(header_value)) = (key.parse::<axum::http::HeaderName>(), value.parse::<axum::http::HeaderValue>()) {
                response_headers.insert(header_name, header_value);
            }
        }
        
        info!("Generated default response with status: {}", status_code);
        RecoveryResult::Success(response)
    }
    
    /// Execute graceful degradation strategy
    async fn execute_graceful_degradation_strategy(
        &self,
        degraded_response: &str,
        status_code: u16,
    ) -> RecoveryResult {
        debug!("Using graceful degradation strategy");
        
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let response = axum::response::Response::builder()
            .status(status)
            .header("X-Degraded-Service", "true")
            .body(axum::body::Body::from(degraded_response.to_string()))
            .unwrap();
        
        info!("Generated degraded response with status: {}", status_code);
        RecoveryResult::Success(response)
    }
    
    /// Update recovery metrics
    fn update_metrics(&self, strategy: &str, success: bool, duration: Duration) {
        if !self.config.collect_metrics {
            return;
        }
        
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.total_attempts += 1;
            
            if success {
                metrics.successful_recoveries += 1;
            } else {
                metrics.failed_recoveries += 1;
            }
            
            // Update strategy-specific metrics
            let attempts = metrics.attempts_by_strategy.entry(strategy.to_string()).or_insert(0);
            *attempts += 1;
            
            // Calculate success rate for this strategy
            let total_attempts = *attempts;
            let successful_attempts = if success { 1 } else { 0 };
            let current_success_rate = metrics.success_rate_by_strategy
                .get(strategy)
                .copied()
                .unwrap_or(0.0);
            
            let new_success_rate = (current_success_rate * (total_attempts - 1) as f64 + successful_attempts as f64) / total_attempts as f64;
            metrics.success_rate_by_strategy.insert(strategy.to_string(), new_success_rate);
            
            // Update average recovery time
            let current_avg = metrics.average_recovery_time;
            let total_attempts = metrics.total_attempts;
            metrics.average_recovery_time = Duration::from_millis(
                ((current_avg.as_millis() as u64 * (total_attempts - 1)) + duration.as_millis() as u64) / total_attempts
            );
        }
    }
    
    /// Get current recovery metrics
    pub fn get_metrics(&self) -> RecoveryMetrics {
        self.metrics.read().unwrap().clone()
    }
    
    /// Reset recovery metrics
    pub fn reset_metrics(&self) {
        if let Ok(mut metrics) = self.metrics.write() {
            *metrics = RecoveryMetrics {
                total_attempts: 0,
                successful_recoveries: 0,
                failed_recoveries: 0,
                attempts_by_strategy: HashMap::new(),
                success_rate_by_strategy: HashMap::new(),
                average_recovery_time: Duration::from_millis(0),
            };
        }
    }
    
    /// Update recovery configuration
    pub fn update_config(&mut self, config: RecoveryConfig) {
        self.config = config;
        info!("Recovery configuration updated");
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &RecoveryConfig {
        &self.config
    }
}

/// Get strategy name for metrics
fn strategy_name(strategy: &RecoveryStrategy) -> String {
    match strategy {
        RecoveryStrategy::RetryWithBackoff { .. } => "retry_with_backoff".to_string(),
        RecoveryStrategy::FallbackService { .. } => "fallback_service".to_string(),
        RecoveryStrategy::UseCachedResponse => "cached_response".to_string(),
        RecoveryStrategy::DefaultResponse { .. } => "default_response".to_string(),
        RecoveryStrategy::GracefulDegradation { .. } => "graceful_degradation".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct MockCacheProvider {
        has_cache: bool,
    }

    #[async_trait::async_trait]
    impl CacheProvider for MockCacheProvider {
        async fn get_cached_response(&self, _key: &str) -> Option<Response> {
            if self.has_cache {
                Some(axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .body(axum::body::Body::from("cached response"))
                    .unwrap())
            } else {
                None
            }
        }
    }

    struct MockServiceProvider {
        call_count: AtomicU32,
        should_succeed: bool,
    }

    #[async_trait::async_trait]
    impl ServiceProvider for MockServiceProvider {
        async fn call_service(&self, _service: &str, _context: &RecoveryContext) -> GatewayResult<Response> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            
            if self.should_succeed {
                Ok(axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .body(axum::body::Body::from("fallback response"))
                    .unwrap())
            } else {
                Err(GatewayError::internal("fallback service failed"))
            }
        }
    }

    #[tokio::test]
    async fn test_default_response_strategy() {
        let config = RecoveryConfig::default();
        let recovery_manager = ErrorRecoveryManager::new(config);
        
        let context = RecoveryContext {
            request_path: "/api/test".to_string(),
            request_method: "GET".to_string(),
            request_headers: HeaderMap::new(),
            request_body: None,
            request_id: "req-123".to_string(),
            trace_id: None,
            target_service: None,
            metadata: HashMap::new(),
        };
        
        let strategy = RecoveryStrategy::DefaultResponse {
            status_code: 503,
            body: "Service temporarily unavailable".to_string(),
            headers: HashMap::new(),
        };
        
        let result = recovery_manager.execute_recovery_strategy(&strategy, &context).await;
        
        match result {
            RecoveryResult::Success(response) => {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            }
            _ => panic!("Expected successful recovery"),
        }
    }
    
    #[tokio::test]
    async fn test_cached_response_strategy() {
        let config = RecoveryConfig::default();
        let cache_provider = Arc::new(MockCacheProvider { has_cache: true });
        let recovery_manager = ErrorRecoveryManager::new(config)
            .with_cache_provider(cache_provider);
        
        let context = RecoveryContext {
            request_path: "/api/test".to_string(),
            request_method: "GET".to_string(),
            request_headers: HeaderMap::new(),
            request_body: None,
            request_id: "req-123".to_string(),
            trace_id: None,
            target_service: None,
            metadata: HashMap::new(),
        };
        
        let result = recovery_manager.execute_cached_response_strategy(&context).await;
        
        match result {
            RecoveryResult::Success(response) => {
                assert_eq!(response.status(), StatusCode::OK);
            }
            _ => panic!("Expected successful recovery from cache"),
        }
    }
    
    #[tokio::test]
    async fn test_fallback_service_strategy() {
        let config = RecoveryConfig::default();
        let service_provider = Arc::new(MockServiceProvider {
            call_count: AtomicU32::new(0),
            should_succeed: true,
        });
        let recovery_manager = ErrorRecoveryManager::new(config)
            .with_service_provider(service_provider.clone());
        
        let context = RecoveryContext {
            request_path: "/api/test".to_string(),
            request_method: "GET".to_string(),
            request_headers: HeaderMap::new(),
            request_body: None,
            request_id: "req-123".to_string(),
            trace_id: None,
            target_service: None,
            metadata: HashMap::new(),
        };
        
        let result = recovery_manager.execute_fallback_service_strategy("fallback-api", &context).await;
        
        match result {
            RecoveryResult::Success(response) => {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(service_provider.call_count.load(Ordering::SeqCst), 1);
            }
            _ => panic!("Expected successful recovery from fallback service"),
        }
    }
    
    #[tokio::test]
    async fn test_recovery_metrics() {
        let config = RecoveryConfig::default();
        let recovery_manager = ErrorRecoveryManager::new(config);
        
        // Simulate some recovery attempts
        recovery_manager.update_metrics("retry_with_backoff", true, Duration::from_millis(100));
        recovery_manager.update_metrics("fallback_service", false, Duration::from_millis(200));
        recovery_manager.update_metrics("cached_response", true, Duration::from_millis(50));
        
        let metrics = recovery_manager.get_metrics();
        assert_eq!(metrics.total_attempts, 3);
        assert_eq!(metrics.successful_recoveries, 2);
        assert_eq!(metrics.failed_recoveries, 1);
        assert!(metrics.attempts_by_strategy.contains_key("retry_with_backoff"));
        assert!(metrics.success_rate_by_strategy.contains_key("retry_with_backoff"));
    }
}
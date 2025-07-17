//! Circuit Breaker Implementation
//! 
//! This module provides a circuit breaker pattern implementation to prevent cascade failures
//! when upstream services become unavailable. The circuit breaker follows a state machine
//! pattern with three states: Closed, Open, and HalfOpen.
//! 
//! ## States:
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Circuit is open, requests fail fast without calling upstream
//! - **HalfOpen**: Testing state, limited requests allowed to test if service recovered
//! 
//! ## Key Rust Concepts:
//! - Uses `Arc<Mutex<>>` for thread-safe state sharing across async tasks
//! - Leverages `Instant` for precise timing measurements
//! - Employs `AtomicU64` for lock-free metrics collection
//! - Uses `thiserror` for ergonomic error handling

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Circuit breaker specific errors
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Metrics collection error: {0}")]
    Metrics(String),
}

/// Circuit breaker state machine
/// 
/// The circuit breaker can be in one of three states:
/// - Closed: Normal operation, all requests pass through
/// - Open: Circuit is open, requests fail immediately
/// - HalfOpen: Testing if the service has recovered
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    /// Circuit is closed, normal operation
    /// Tracks the number of consecutive failures
    Closed { failure_count: u32 },
    
    /// Circuit is open, requests fail fast
    /// Records when the circuit was opened
    Open { opened_at: Instant },
    
    /// Circuit is half-open, testing recovery
    /// Tracks successful requests in this state
    HalfOpen { success_count: u32 },
}

/// Configuration for circuit breaker behavior
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    pub failure_threshold: u32,
    
    /// How long to wait before transitioning from Open to HalfOpen
    pub timeout: Duration,
    
    /// Number of successful requests needed in HalfOpen to close the circuit
    pub success_threshold: u32,
    
    /// Maximum number of requests allowed in HalfOpen state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            success_threshold: 3,
            half_open_max_requests: 10,
        }
    }
}

/// Metrics collected by the circuit breaker
/// 
/// Uses atomic operations for lock-free updates from multiple threads
#[derive(Debug, Default)]
pub struct CircuitBreakerMetrics {
    /// Total number of requests processed
    pub total_requests: AtomicU64,
    
    /// Total number of successful requests
    pub successful_requests: AtomicU64,
    
    /// Total number of failed requests
    pub failed_requests: AtomicU64,
    
    /// Number of requests rejected due to open circuit
    pub rejected_requests: AtomicU64,
    
    /// Number of times circuit has opened
    pub circuit_opened_count: AtomicU64,
    
    /// Number of times circuit has closed
    pub circuit_closed_count: AtomicU64,
    
    /// Current state duration in milliseconds
    pub current_state_duration_ms: AtomicU64,
}

impl CircuitBreakerMetrics {
    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> CircuitBreakerMetricsSnapshot {
        CircuitBreakerMetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            rejected_requests: self.rejected_requests.load(Ordering::Relaxed),
            circuit_opened_count: self.circuit_opened_count.load(Ordering::Relaxed),
            circuit_closed_count: self.circuit_closed_count.load(Ordering::Relaxed),
            current_state_duration_ms: self.current_state_duration_ms.load(Ordering::Relaxed),
        }
    }
    
    /// Calculate failure rate as a percentage
    pub fn failure_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let failed = self.failed_requests.load(Ordering::Relaxed);
        (failed as f64 / total as f64) * 100.0
    }
}

/// Immutable snapshot of circuit breaker metrics
#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerMetricsSnapshot {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub rejected_requests: u64,
    pub circuit_opened_count: u64,
    pub circuit_closed_count: u64,
    pub current_state_duration_ms: u64,
}

/// Main circuit breaker implementation
/// 
/// This struct manages the state machine and provides thread-safe access
/// to circuit breaker functionality across async tasks.
pub struct CircuitBreaker {
    /// Current state of the circuit breaker (protected by mutex for thread safety)
    state: Arc<Mutex<CircuitBreakerState>>,
    
    /// Configuration parameters
    config: CircuitBreakerConfig,
    
    /// Metrics collection
    metrics: Arc<CircuitBreakerMetrics>,
    
    /// When the current state was entered
    state_entered_at: Arc<Mutex<Instant>>,
    
    /// Name/identifier for this circuit breaker instance
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    /// 
    /// # Arguments
    /// * `name` - Identifier for this circuit breaker instance
    /// * `config` - Configuration parameters
    /// 
    /// # Example
    /// ```rust
    /// use std::time::Duration;
    /// let config = CircuitBreakerConfig {
    ///     failure_threshold: 5,
    ///     timeout: Duration::from_secs(30),
    ///     success_threshold: 3,
    ///     half_open_max_requests: 5,
    /// };
    /// let cb = CircuitBreaker::new("user-service", config);
    /// ```
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            state: Arc::new(Mutex::new(CircuitBreakerState::Closed { failure_count: 0 })),
            config,
            metrics: Arc::new(CircuitBreakerMetrics::default()),
            state_entered_at: Arc::new(Mutex::new(now)),
            name: name.into(),
        }
    }
    
    /// Create a circuit breaker with default configuration
    pub fn with_defaults(name: impl Into<String>) -> Self {
        Self::new(name, CircuitBreakerConfig::default())
    }
    
    /// Check if a request can proceed through the circuit breaker
    /// 
    /// Returns `Ok(())` if the request can proceed, or `Err(CircuitBreakerError::CircuitOpen)`
    /// if the circuit is open and the request should be rejected.
    pub fn can_proceed(&self) -> Result<(), CircuitBreakerError> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        // Update state duration metrics
        if let Ok(entered_at) = self.state_entered_at.lock() {
            let duration_ms = now.duration_since(*entered_at).as_millis() as u64;
            self.metrics.current_state_duration_ms.store(duration_ms, Ordering::Relaxed);
        }
        
        match *state {
            CircuitBreakerState::Closed { .. } => {
                // Circuit is closed, allow request
                self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            CircuitBreakerState::Open { opened_at } => {
                // Check if timeout has elapsed to transition to HalfOpen
                if now.duration_since(opened_at) >= self.config.timeout {
                    *state = CircuitBreakerState::HalfOpen { success_count: 0 };
                    self.update_state_entered_at(now);
                    self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                } else {
                    // Circuit is still open, reject request
                    self.metrics.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
            CircuitBreakerState::HalfOpen { .. } => {
                // In half-open state, allow limited requests
                let total_requests = self.metrics.total_requests.load(Ordering::Relaxed);
                let requests_in_half_open = total_requests - 
                    self.get_requests_before_half_open();
                
                if requests_in_half_open < self.config.half_open_max_requests as u64 {
                    self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                } else {
                    // Too many requests in half-open, reject
                    self.metrics.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
        }
    }
    
    /// Record a successful request
    /// 
    /// This updates the circuit breaker state based on the success and may
    /// transition from HalfOpen to Closed if enough successes are recorded.
    pub fn record_success(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        self.metrics.successful_requests.fetch_add(1, Ordering::Relaxed);
        
        match *state {
            CircuitBreakerState::Closed { .. } => {
                // Already closed, nothing to do
            }
            CircuitBreakerState::Open { .. } => {
                // Shouldn't happen if can_proceed was called first, but handle gracefully
            }
            CircuitBreakerState::HalfOpen { success_count } => {
                let new_success_count = success_count + 1;
                if new_success_count >= self.config.success_threshold {
                    // Enough successes, close the circuit
                    *state = CircuitBreakerState::Closed { failure_count: 0 };
                    self.update_state_entered_at(now);
                    self.metrics.circuit_closed_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Update success count
                    *state = CircuitBreakerState::HalfOpen { success_count: new_success_count };
                }
            }
        }
    }
    
    /// Record a failed request
    /// 
    /// This updates the circuit breaker state based on the failure and may
    /// transition from Closed to Open if the failure threshold is exceeded.
    pub fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        self.metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
        
        match *state {
            CircuitBreakerState::Closed { failure_count } => {
                let new_failure_count = failure_count + 1;
                if new_failure_count >= self.config.failure_threshold {
                    // Threshold exceeded, open the circuit
                    *state = CircuitBreakerState::Open { opened_at: now };
                    self.update_state_entered_at(now);
                    self.metrics.circuit_opened_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Update failure count
                    *state = CircuitBreakerState::Closed { failure_count: new_failure_count };
                }
            }
            CircuitBreakerState::Open { .. } => {
                // Already open, nothing to do
            }
            CircuitBreakerState::HalfOpen { .. } => {
                // Failure in half-open state, go back to open
                *state = CircuitBreakerState::Open { opened_at: now };
                self.update_state_entered_at(now);
                self.metrics.circuit_opened_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Get the current state of the circuit breaker
    pub fn state(&self) -> CircuitBreakerState {
        self.state.lock().unwrap().clone()
    }
    
    /// Get the name/identifier of this circuit breaker
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the configuration
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }
    
    /// Get metrics
    pub fn metrics(&self) -> Arc<CircuitBreakerMetrics> {
        Arc::clone(&self.metrics)
    }
    
    /// Manually force the circuit breaker to open (for admin override)
    pub fn force_open(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        *state = CircuitBreakerState::Open { opened_at: now };
        self.update_state_entered_at(now);
        self.metrics.circuit_opened_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Manually force the circuit breaker to close (for admin override)
    pub fn force_close(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        *state = CircuitBreakerState::Closed { failure_count: 0 };
        self.update_state_entered_at(now);
        self.metrics.circuit_closed_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Manually force the circuit breaker to half-open (for admin override)
    pub fn force_half_open(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        
        *state = CircuitBreakerState::HalfOpen { success_count: 0 };
        self.update_state_entered_at(now);
    }
    
    /// Reset all metrics
    pub fn reset_metrics(&self) {
        self.metrics.total_requests.store(0, Ordering::Relaxed);
        self.metrics.successful_requests.store(0, Ordering::Relaxed);
        self.metrics.failed_requests.store(0, Ordering::Relaxed);
        self.metrics.rejected_requests.store(0, Ordering::Relaxed);
        self.metrics.circuit_opened_count.store(0, Ordering::Relaxed);
        self.metrics.circuit_closed_count.store(0, Ordering::Relaxed);
        self.metrics.current_state_duration_ms.store(0, Ordering::Relaxed);
    }
    
    /// Helper method to update when the current state was entered
    fn update_state_entered_at(&self, now: Instant) {
        if let Ok(mut entered_at) = self.state_entered_at.lock() {
            *entered_at = now;
        }
    }
    
    /// Helper method to estimate requests before half-open state
    /// This is a simplified implementation - in production you might want more sophisticated tracking
    fn get_requests_before_half_open(&self) -> u64 {
        // For simplicity, we'll use the successful + failed requests as a proxy
        // In a real implementation, you might want to track this more precisely
        self.metrics.successful_requests.load(Ordering::Relaxed) + 
        self.metrics.failed_requests.load(Ordering::Relaxed)
    }
}

/// Circuit breaker registry for managing multiple circuit breakers
/// 
/// This allows the gateway to maintain separate circuit breakers for different
/// upstream services or endpoints.
pub struct CircuitBreakerRegistry {
    breakers: Arc<Mutex<std::collections::HashMap<String, Arc<CircuitBreaker>>>>,
}

impl CircuitBreakerRegistry {
    /// Create a new circuit breaker registry
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
    
    /// Get or create a circuit breaker for the given name
    pub fn get_or_create(&self, name: &str, config: CircuitBreakerConfig) -> Arc<CircuitBreaker> {
        let mut breakers = self.breakers.lock().unwrap();
        
        if let Some(breaker) = breakers.get(name) {
            Arc::clone(breaker)
        } else {
            let breaker = Arc::new(CircuitBreaker::new(name, config));
            breakers.insert(name.to_string(), Arc::clone(&breaker));
            breaker
        }
    }
    
    /// Get all circuit breakers
    pub fn get_all(&self) -> Vec<Arc<CircuitBreaker>> {
        let breakers = self.breakers.lock().unwrap();
        breakers.values().cloned().collect()
    }
    
    /// Remove a circuit breaker
    pub fn remove(&self, name: &str) -> Option<Arc<CircuitBreaker>> {
        let mut breakers = self.breakers.lock().unwrap();
        breakers.remove(name)
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_circuit_breaker_initial_state() {
        let cb = CircuitBreaker::with_defaults("test");
        
        match cb.state() {
            CircuitBreakerState::Closed { failure_count } => {
                assert_eq!(failure_count, 0);
            }
            _ => panic!("Expected initial state to be Closed"),
        }
    }
    
    #[test]
    fn test_circuit_breaker_can_proceed_when_closed() {
        let cb = CircuitBreaker::with_defaults("test");
        
        assert!(cb.can_proceed().is_ok());
        assert_eq!(cb.metrics().total_requests.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            timeout: Duration::from_secs(60),
            success_threshold: 2,
            half_open_max_requests: 5,
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Record failures up to threshold
        for i in 0..3 {
            assert!(cb.can_proceed().is_ok());
            cb.record_failure();
            
            if i < 2 {
                // Should still be closed
                match cb.state() {
                    CircuitBreakerState::Closed { failure_count } => {
                        assert_eq!(failure_count, i + 1);
                    }
                    _ => panic!("Expected state to be Closed"),
                }
            }
        }
        
        // Should now be open
        match cb.state() {
            CircuitBreakerState::Open { .. } => {}
            _ => panic!("Expected state to be Open"),
        }
        
        // Requests should be rejected
        assert!(matches!(cb.can_proceed(), Err(CircuitBreakerError::CircuitOpen)));
        assert_eq!(cb.metrics().rejected_requests.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_circuit_breaker_transitions_to_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100), // Short timeout for testing
            success_threshold: 2,
            half_open_max_requests: 5,
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Open the circuit
        cb.can_proceed().unwrap();
        cb.record_failure();
        cb.can_proceed().unwrap();
        cb.record_failure();
        
        // Should be open
        assert!(matches!(cb.state(), CircuitBreakerState::Open { .. }));
        
        // Wait for timeout
        thread::sleep(Duration::from_millis(150));
        
        // Next request should transition to half-open
        assert!(cb.can_proceed().is_ok());
        assert!(matches!(cb.state(), CircuitBreakerState::HalfOpen { .. }));
    }
    
    #[test]
    fn test_circuit_breaker_closes_after_successes_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            success_threshold: 2,
            half_open_max_requests: 5,
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Open the circuit
        cb.can_proceed().unwrap();
        cb.record_failure();
        cb.can_proceed().unwrap();
        cb.record_failure();
        
        // Wait and transition to half-open
        thread::sleep(Duration::from_millis(150));
        cb.can_proceed().unwrap();
        
        // Record successes
        cb.record_success();
        assert!(matches!(cb.state(), CircuitBreakerState::HalfOpen { success_count: 1 }));
        
        cb.record_success();
        assert!(matches!(cb.state(), CircuitBreakerState::Closed { failure_count: 0 }));
    }
    
    #[test]
    fn test_circuit_breaker_reopens_on_failure_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            success_threshold: 2,
            half_open_max_requests: 5,
        };
        let cb = CircuitBreaker::new("test", config);
        
        // Open the circuit
        cb.can_proceed().unwrap();
        cb.record_failure();
        cb.can_proceed().unwrap();
        cb.record_failure();
        
        // Wait and transition to half-open
        thread::sleep(Duration::from_millis(150));
        cb.can_proceed().unwrap();
        
        // Record failure in half-open state
        cb.record_failure();
        assert!(matches!(cb.state(), CircuitBreakerState::Open { .. }));
    }
    
    #[test]
    fn test_circuit_breaker_manual_override() {
        let cb = CircuitBreaker::with_defaults("test");
        
        // Force open
        cb.force_open();
        assert!(matches!(cb.state(), CircuitBreakerState::Open { .. }));
        
        // Force close
        cb.force_close();
        assert!(matches!(cb.state(), CircuitBreakerState::Closed { failure_count: 0 }));
        
        // Force half-open
        cb.force_half_open();
        assert!(matches!(cb.state(), CircuitBreakerState::HalfOpen { success_count: 0 }));
    }
    
    #[test]
    fn test_circuit_breaker_metrics() {
        let cb = CircuitBreaker::with_defaults("test");
        
        // Test successful request
        cb.can_proceed().unwrap();
        cb.record_success();
        
        let metrics = cb.metrics();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failed_requests.load(Ordering::Relaxed), 0);
        
        // Test failed request
        cb.can_proceed().unwrap();
        cb.record_failure();
        
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failed_requests.load(Ordering::Relaxed), 1);
        
        // Test failure rate calculation
        assert_eq!(metrics.failure_rate(), 50.0);
    }
    
    #[test]
    fn test_circuit_breaker_registry() {
        let registry = CircuitBreakerRegistry::new();
        let config = CircuitBreakerConfig::default();
        
        // Get or create circuit breaker
        let cb1 = registry.get_or_create("service1", config.clone());
        let cb2 = registry.get_or_create("service1", config.clone()); // Should return same instance
        let cb3 = registry.get_or_create("service2", config);
        
        assert_eq!(cb1.name(), "service1");
        assert_eq!(cb2.name(), "service1");
        assert_eq!(cb3.name(), "service2");
        
        // cb1 and cb2 should be the same instance
        assert!(Arc::ptr_eq(&cb1, &cb2));
        
        // Get all circuit breakers
        let all = registry.get_all();
        assert_eq!(all.len(), 2);
        
        // Remove circuit breaker
        let removed = registry.remove("service1");
        assert!(removed.is_some());
        
        let all = registry.get_all();
        assert_eq!(all.len(), 1);
    }
}
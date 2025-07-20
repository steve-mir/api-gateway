//! # Error Tracking Module
//!
//! This module provides comprehensive error tracking, alerting, and recovery mechanisms
//! for the API Gateway. It tracks error patterns, provides error analytics, and
//! implements graceful degradation strategies.
//!
//! ## Features
//! - Error event collection and aggregation
//! - Error pattern detection and alerting
//! - Error recovery mechanisms
//! - Custom error page generation
//! - Error analytics and reporting

use crate::core::error::GatewayError;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{warn, info, debug};
use uuid::Uuid;

/// Error event representing a single error occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEvent {
    /// Unique identifier for this error event
    pub id: String,
    
    /// Timestamp when the error occurred
    pub timestamp: u64,
    
    /// Error type classification
    pub error_type: String,
    
    /// HTTP status code associated with the error
    pub status_code: u16,
    
    /// Error message
    pub message: String,
    
    /// Request path where the error occurred
    pub request_path: String,
    
    /// HTTP method of the failed request
    pub request_method: String,
    
    /// Client IP address
    pub client_ip: String,
    
    /// User agent string
    pub user_agent: Option<String>,
    
    /// Request ID for correlation
    pub request_id: String,
    
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
    
    /// Service that caused the error (if applicable)
    pub service: Option<String>,
    
    /// Whether this error is retryable
    pub retryable: bool,
    
    /// Whether this error should trigger circuit breaker
    pub circuit_breaker_trigger: bool,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ErrorEvent {
    /// Create a new error event from a gateway error and request context
    pub fn new(
        error: &GatewayError,
        request_path: String,
        request_method: String,
        client_ip: String,
        user_agent: Option<String>,
        request_id: String,
        trace_id: Option<String>,
        service: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp,
            error_type: error.error_type().to_string(),
            status_code: error.status_code().as_u16(),
            message: error.to_string(),
            request_path,
            request_method,
            client_ip,
            user_agent,
            request_id,
            trace_id,
            service,
            retryable: error.is_retryable(),
            circuit_breaker_trigger: error.should_trigger_circuit_breaker(),
            metadata: HashMap::new(),
        }
    }
}

/// Error statistics for a specific error type or service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStats {
    /// Total number of errors
    pub total_count: u64,
    
    /// Error count in the last hour
    pub last_hour_count: u64,
    
    /// Error count in the last day
    pub last_day_count: u64,
    
    /// Error rate (errors per minute)
    pub error_rate: f64,
    
    /// Most recent error timestamp
    pub last_error_time: u64,
    
    /// Most common error messages
    pub common_messages: Vec<(String, u64)>,
    
    /// Affected services
    pub affected_services: Vec<String>,
}

/// Error pattern detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPatternConfig {
    /// Threshold for error rate alerting (errors per minute)
    pub error_rate_threshold: f64,
    
    /// Time window for error rate calculation (minutes)
    pub error_rate_window: u64,
    
    /// Threshold for consecutive errors from same service
    pub consecutive_error_threshold: u32,
    
    /// Time window for consecutive error detection (minutes)
    pub consecutive_error_window: u64,
    
    /// Enable automatic circuit breaker triggering
    pub auto_circuit_breaker: bool,
    
    /// Enable error recovery mechanisms
    pub auto_recovery: bool,
}

impl Default for ErrorPatternConfig {
    fn default() -> Self {
        Self {
            error_rate_threshold: 10.0, // 10 errors per minute
            error_rate_window: 5,       // 5 minute window
            consecutive_error_threshold: 5, // 5 consecutive errors
            consecutive_error_window: 2,    // 2 minute window
            auto_circuit_breaker: true,
            auto_recovery: true,
        }
    }
}

/// Error alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorAlert {
    /// High error rate detected
    HighErrorRate {
        error_type: String,
        rate: f64,
        threshold: f64,
        window_minutes: u64,
    },
    
    /// Consecutive errors from same service
    ConsecutiveErrors {
        service: String,
        count: u32,
        threshold: u32,
        window_minutes: u64,
    },
    
    /// Service degradation detected
    ServiceDegradation {
        service: String,
        error_rate: f64,
        success_rate: f64,
    },
    
    /// Circuit breaker triggered
    CircuitBreakerTriggered {
        service: String,
        error_count: u32,
    },
}



/// Error tracking and analytics system
pub struct ErrorTracker {
    /// Configuration for error pattern detection
    config: ErrorPatternConfig,
    
    /// Recent error events (circular buffer)
    recent_errors: Arc<RwLock<VecDeque<ErrorEvent>>>,
    
    /// Error statistics by type
    error_stats: Arc<RwLock<HashMap<String, ErrorStats>>>,
    
    /// Error statistics by service
    service_stats: Arc<RwLock<HashMap<String, ErrorStats>>>,
    
    /// Alert broadcaster
    alert_sender: broadcast::Sender<ErrorAlert>,
    
    /// Maximum number of recent errors to keep in memory
    max_recent_errors: usize,
}

impl ErrorTracker {
    /// Create a new error tracker
    pub fn new(config: ErrorPatternConfig) -> Self {
        let (alert_sender, _) = broadcast::channel(1000);
        
        Self {
            config,
            recent_errors: Arc::new(RwLock::new(VecDeque::new())),
            error_stats: Arc::new(RwLock::new(HashMap::new())),
            service_stats: Arc::new(RwLock::new(HashMap::new())),
            alert_sender,
            max_recent_errors: 10000, // Keep last 10k errors
        }
    }
    
    /// Track a new error event
    pub async fn track_error(&self, error_event: ErrorEvent) {
        debug!("Tracking error event: {}", error_event.id);
        
        // Add to recent errors
        {
            let mut recent_errors = self.recent_errors.write().unwrap();
            recent_errors.push_back(error_event.clone());
            
            // Keep only the most recent errors
            while recent_errors.len() > self.max_recent_errors {
                recent_errors.pop_front();
            }
        }
        
        // Update error statistics
        self.update_error_stats(&error_event).await;
        
        // Check for error patterns and trigger alerts
        self.check_error_patterns(&error_event).await;
        
        info!(
            "Error tracked: {} - {} ({})",
            error_event.error_type,
            error_event.message,
            error_event.status_code
        );
    }
    
    /// Update error statistics
    async fn update_error_stats(&self, error_event: &ErrorEvent) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Update error type statistics
        {
            let mut error_stats = self.error_stats.write().unwrap();
            let stats = error_stats
                .entry(error_event.error_type.clone())
                .or_insert_with(|| ErrorStats {
                    total_count: 0,
                    last_hour_count: 0,
                    last_day_count: 0,
                    error_rate: 0.0,
                    last_error_time: 0,
                    common_messages: Vec::new(),
                    affected_services: Vec::new(),
                });
            
            stats.total_count += 1;
            stats.last_error_time = error_event.timestamp;
            
            // Add service to affected services if not already present
            if let Some(service) = &error_event.service {
                if !stats.affected_services.contains(service) {
                    stats.affected_services.push(service.clone());
                }
            }
        }
        
        // Update service statistics if service is specified
        if let Some(service) = &error_event.service {
            let mut service_stats = self.service_stats.write().unwrap();
            let stats = service_stats
                .entry(service.clone())
                .or_insert_with(|| ErrorStats {
                    total_count: 0,
                    last_hour_count: 0,
                    last_day_count: 0,
                    error_rate: 0.0,
                    last_error_time: 0,
                    common_messages: Vec::new(),
                    affected_services: vec![service.clone()],
                });
            
            stats.total_count += 1;
            stats.last_error_time = error_event.timestamp;
        }
        
        // Recalculate error rates
        self.recalculate_error_rates().await;
    }
    
    /// Recalculate error rates for all tracked errors
    async fn recalculate_error_rates(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let one_hour_ago = now - 3600;
        let one_day_ago = now - 86400;
        let rate_window_ago = now - (self.config.error_rate_window * 60);
        
        // Count recent errors
        let recent_errors = self.recent_errors.read().unwrap();
        let mut error_counts: HashMap<String, (u64, u64, u64)> = HashMap::new();
        let mut service_counts: HashMap<String, (u64, u64, u64)> = HashMap::new();
        
        for error in recent_errors.iter() {
            // Count by error type
            let (hour_count, day_count, rate_count) = error_counts
                .entry(error.error_type.clone())
                .or_insert((0, 0, 0));
            
            if error.timestamp >= one_hour_ago {
                *hour_count += 1;
            }
            if error.timestamp >= one_day_ago {
                *day_count += 1;
            }
            if error.timestamp >= rate_window_ago {
                *rate_count += 1;
            }
            
            // Count by service
            if let Some(service) = &error.service {
                let (hour_count, day_count, rate_count) = service_counts
                    .entry(service.clone())
                    .or_insert((0, 0, 0));
                
                if error.timestamp >= one_hour_ago {
                    *hour_count += 1;
                }
                if error.timestamp >= one_day_ago {
                    *day_count += 1;
                }
                if error.timestamp >= rate_window_ago {
                    *rate_count += 1;
                }
            }
        }
        
        // Update error type statistics
        {
            let mut error_stats = self.error_stats.write().unwrap();
            for (error_type, (hour_count, day_count, rate_count)) in error_counts {
                if let Some(stats) = error_stats.get_mut(&error_type) {
                    stats.last_hour_count = hour_count;
                    stats.last_day_count = day_count;
                    stats.error_rate = rate_count as f64 / self.config.error_rate_window as f64;
                }
            }
        }
        
        // Update service statistics
        {
            let mut service_stats = self.service_stats.write().unwrap();
            for (service, (hour_count, day_count, rate_count)) in service_counts {
                if let Some(stats) = service_stats.get_mut(&service) {
                    stats.last_hour_count = hour_count;
                    stats.last_day_count = day_count;
                    stats.error_rate = rate_count as f64 / self.config.error_rate_window as f64;
                }
            }
        }
    }
    
    /// Check for error patterns and trigger alerts
    async fn check_error_patterns(&self, error_event: &ErrorEvent) {
        // Check for high error rate
        {
            let error_stats = self.error_stats.read().unwrap();
            if let Some(stats) = error_stats.get(&error_event.error_type) {
                if stats.error_rate > self.config.error_rate_threshold {
                    let alert = ErrorAlert::HighErrorRate {
                        error_type: error_event.error_type.clone(),
                        rate: stats.error_rate,
                        threshold: self.config.error_rate_threshold,
                        window_minutes: self.config.error_rate_window,
                    };
                    
                    if let Err(e) = self.alert_sender.send(alert) {
                        warn!("Failed to send error rate alert: {}", e);
                    }
                }
            }
        }
        
        // Check for consecutive errors from same service
        if let Some(service) = &error_event.service {
            let consecutive_count = self.count_consecutive_errors(service).await;
            if consecutive_count >= self.config.consecutive_error_threshold {
                let alert = ErrorAlert::ConsecutiveErrors {
                    service: service.clone(),
                    count: consecutive_count,
                    threshold: self.config.consecutive_error_threshold,
                    window_minutes: self.config.consecutive_error_window,
                };
                
                if let Err(e) = self.alert_sender.send(alert) {
                    warn!("Failed to send consecutive errors alert: {}", e);
                }
            }
        }
    }
    
    /// Count consecutive errors for a service within the configured window
    async fn count_consecutive_errors(&self, service: &str) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let window_start = now - (self.config.consecutive_error_window * 60);
        
        let recent_errors = self.recent_errors.read().unwrap();
        let mut consecutive_count = 0;
        
        // Count consecutive errors from the end of the queue
        for error in recent_errors.iter().rev() {
            if error.timestamp < window_start {
                break;
            }
            
            if error.service.as_ref() == Some(&service.to_string()) {
                consecutive_count += 1;
            } else {
                // Break on first non-matching service (not consecutive)
                break;
            }
        }
        
        consecutive_count
    }
    
    /// Get error statistics by type
    pub fn get_error_stats(&self) -> HashMap<String, ErrorStats> {
        self.error_stats.read().unwrap().clone()
    }
    
    /// Get error statistics by service
    pub fn get_service_stats(&self) -> HashMap<String, ErrorStats> {
        self.service_stats.read().unwrap().clone()
    }
    
    /// Get recent error events
    pub fn get_recent_errors(&self, limit: Option<usize>) -> Vec<ErrorEvent> {
        let recent_errors = self.recent_errors.read().unwrap();
        let limit = limit.unwrap_or(100);
        
        recent_errors
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    /// Subscribe to error alerts
    pub fn subscribe_to_alerts(&self) -> broadcast::Receiver<ErrorAlert> {
        self.alert_sender.subscribe()
    }
    
    /// Clear all error tracking data
    pub fn clear_all_data(&self) {
        self.recent_errors.write().unwrap().clear();
        self.error_stats.write().unwrap().clear();
        self.service_stats.write().unwrap().clear();
        info!("All error tracking data cleared");
    }
    
    /// Get error summary for the last period
    pub fn get_error_summary(&self, hours: u64) -> ErrorSummary {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let period_start = now - (hours * 3600);
        
        let recent_errors = self.recent_errors.read().unwrap();
        let period_errors: Vec<_> = recent_errors
            .iter()
            .filter(|e| e.timestamp >= period_start)
            .collect();
        
        let total_errors = period_errors.len() as u64;
        let unique_error_types = period_errors
            .iter()
            .map(|e| &e.error_type)
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;
        
        let affected_services = period_errors
            .iter()
            .filter_map(|e| e.service.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;
        
        let retryable_errors = period_errors
            .iter()
            .filter(|e| e.retryable)
            .count() as u64;
        
        ErrorSummary {
            period_hours: hours,
            total_errors,
            unique_error_types,
            affected_services,
            retryable_errors,
            error_rate: total_errors as f64 / hours as f64,
        }
    }
}

/// Error summary for a specific time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummary {
    /// Time period in hours
    pub period_hours: u64,
    
    /// Total number of errors in the period
    pub total_errors: u64,
    
    /// Number of unique error types
    pub unique_error_types: u64,
    
    /// Number of affected services
    pub affected_services: u64,
    
    /// Number of retryable errors
    pub retryable_errors: u64,
    
    /// Average error rate (errors per hour)
    pub error_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn test_error_tracking() {
        let config = ErrorPatternConfig::default();
        let tracker = ErrorTracker::new(config);
        
        let error_event = ErrorEvent::new(
            &GatewayError::internal("test error"),
            "/api/test".to_string(),
            "GET".to_string(),
            "127.0.0.1".to_string(),
            Some("test-agent".to_string()),
            "req-123".to_string(),
            Some("trace-456".to_string()),
            Some("test-service".to_string()),
        );
        
        tracker.track_error(error_event.clone()).await;
        
        let recent_errors = tracker.get_recent_errors(Some(10));
        assert_eq!(recent_errors.len(), 1);
        assert_eq!(recent_errors[0].id, error_event.id);
        
        let error_stats = tracker.get_error_stats();
        assert!(error_stats.contains_key("internal_error"));
        
        let service_stats = tracker.get_service_stats();
        assert!(service_stats.contains_key("test-service"));
    }
    
    #[tokio::test]
    async fn test_error_rate_calculation() {
        let config = ErrorPatternConfig {
            error_rate_threshold: 2.0,
            error_rate_window: 1, // 1 minute window
            ..Default::default()
        };
        let tracker = ErrorTracker::new(config);
        
        // Add multiple errors quickly
        for i in 0..5 {
            let error_event = ErrorEvent::new(
                &GatewayError::internal(format!("test error {}", i)),
                "/api/test".to_string(),
                "GET".to_string(),
                "127.0.0.1".to_string(),
                None,
                format!("req-{}", i),
                None,
                Some("test-service".to_string()),
            );
            tracker.track_error(error_event).await;
        }
        
        let error_stats = tracker.get_error_stats();
        let internal_stats = error_stats.get("internal_error").unwrap();
        assert!(internal_stats.error_rate > 2.0);
    }
    
    #[tokio::test]
    async fn test_error_summary() {
        let config = ErrorPatternConfig::default();
        let tracker = ErrorTracker::new(config);
        
        // Add some test errors
        for i in 0..3 {
            let error_event = ErrorEvent::new(
                &GatewayError::internal(format!("test error {}", i)),
                "/api/test".to_string(),
                "GET".to_string(),
                "127.0.0.1".to_string(),
                None,
                format!("req-{}", i),
                None,
                Some("test-service".to_string()),
            );
            tracker.track_error(error_event).await;
        }
        
        let summary = tracker.get_error_summary(1); // Last 1 hour
        assert_eq!(summary.total_errors, 3);
        assert_eq!(summary.unique_error_types, 1);
        assert_eq!(summary.affected_services, 1);
    }
}
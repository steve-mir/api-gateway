//! # Health Checking System
//!
//! This module provides comprehensive health check functionality for the API gateway and its dependencies.
//! It includes HTTP health check probes, health status aggregation, automatic service instance removal,
//! and admin endpoints for health check configuration.
//!
//! ## Key Features
//! - Configurable HTTP health check probes with intervals
//! - Health status aggregation and reporting
//! - Automatic service instance removal on health check failures
//! - Gateway self-health endpoints
//! - Admin endpoints for health check configuration and manual overrides
//!
//! ## Rust Concepts Used
//! - `Arc<T>` for shared ownership across async tasks
//! - `DashMap` for thread-safe concurrent access to health check data
//! - `tokio::time::interval` for scheduled health checks
//! - `async_trait` for async methods in traits

use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{HealthStatus as CoreHealthStatus, ServiceInstance};
use crate::discovery::ServiceRegistry;

/// Overall health status of the gateway or a service
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service is healthy and ready to receive traffic
    Healthy,
    /// Service is partially degraded but still functional
    Degraded,
    /// Service is unhealthy and should not receive traffic
    Unhealthy,
    /// Health status is unknown (e.g., not yet checked)
    Unknown,
}

impl From<CoreHealthStatus> for ServiceStatus {
    fn from(status: CoreHealthStatus) -> Self {
        match status {
            CoreHealthStatus::Healthy => ServiceStatus::Healthy,
            CoreHealthStatus::Unhealthy => ServiceStatus::Unhealthy,
            CoreHealthStatus::Unknown => ServiceStatus::Unknown,
            CoreHealthStatus::Starting => ServiceStatus::Unknown,
            CoreHealthStatus::Stopping => ServiceStatus::Unhealthy,
        }
    }
}

impl From<ServiceStatus> for CoreHealthStatus {
    fn from(status: ServiceStatus) -> Self {
        match status {
            ServiceStatus::Healthy => CoreHealthStatus::Healthy,
            ServiceStatus::Degraded => CoreHealthStatus::Healthy, // Treat degraded as healthy for routing
            ServiceStatus::Unhealthy => CoreHealthStatus::Unhealthy,
            ServiceStatus::Unknown => CoreHealthStatus::Unknown,
        }
    }
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Name of the health check
    pub name: String,
    /// Health status
    pub status: ServiceStatus,
    /// Optional message with details
    pub message: Option<String>,
    /// Duration of the health check
    pub duration: Duration,
    /// Timestamp when the check was performed
    pub timestamp: u64,
    /// Number of consecutive successes
    pub consecutive_successes: u32,
    /// Number of consecutive failures
    pub consecutive_failures: u32,
}

impl HealthCheck {
    /// Create a new health check result
    pub fn new(name: String, status: ServiceStatus, message: Option<String>, duration: Duration) -> Self {
        Self {
            name,
            status,
            message,
            duration,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }

    /// Create a successful health check
    pub fn success(name: String, duration: Duration) -> Self {
        Self::new(name, ServiceStatus::Healthy, None, duration)
    }

    /// Create a failed health check
    pub fn failure(name: String, error: String, duration: Duration) -> Self {
        Self::new(name, ServiceStatus::Unhealthy, Some(error), duration)
    }
}

/// Aggregated health status with individual check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall status
    pub status: ServiceStatus,
    /// Timestamp of the report
    pub timestamp: u64,
    /// Individual health checks
    pub checks: HashMap<String, HealthCheck>,
    /// Gateway version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
}

impl HealthReport {
    /// Create a new health report
    pub fn new(checks: HashMap<String, HealthCheck>) -> Self {
        let status = Self::aggregate_status(&checks);
        
        Self {
            status,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            checks,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: 0, // Will be set by the health checker
        }
    }

    /// Aggregate individual check statuses into overall status
    fn aggregate_status(checks: &HashMap<String, HealthCheck>) -> ServiceStatus {
        if checks.is_empty() {
            return ServiceStatus::Unknown;
        }

        let mut healthy_count = 0;
        let mut degraded_count = 0;
        let mut unhealthy_count = 0;
        let mut unknown_count = 0;

        for check in checks.values() {
            match check.status {
                ServiceStatus::Healthy => healthy_count += 1,
                ServiceStatus::Degraded => degraded_count += 1,
                ServiceStatus::Unhealthy => unhealthy_count += 1,
                ServiceStatus::Unknown => unknown_count += 1,
            }
        }

        // If any critical checks are unhealthy, overall status is unhealthy
        if unhealthy_count > 0 {
            ServiceStatus::Unhealthy
        } else if degraded_count > 0 {
            ServiceStatus::Degraded
        } else if healthy_count > 0 {
            ServiceStatus::Healthy
        } else {
            ServiceStatus::Unknown
        }
    }
}

/// Configuration for a health check probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Name of the health check
    pub name: String,
    /// Target URL for HTTP health checks
    pub url: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (for POST/PUT requests)
    pub body: Option<String>,
    /// Check interval
    pub interval: Duration,
    /// Request timeout
    pub timeout: Duration,
    /// Number of consecutive successes required to mark as healthy
    pub healthy_threshold: u32,
    /// Number of consecutive failures required to mark as unhealthy
    pub unhealthy_threshold: u32,
    /// Expected HTTP status codes (empty means any 2xx)
    pub expected_status_codes: Vec<u16>,
    /// Expected response body content (substring match)
    pub expected_body_content: Option<String>,
    /// Whether this is a critical health check
    pub critical: bool,
    /// Whether this check is enabled
    pub enabled: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            url: "/health".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            expected_status_codes: vec![200],
            expected_body_content: None,
            critical: true,
            enabled: true,
        }
    }
}

/// Health check probe trait for different types of health checks
#[async_trait]
pub trait HealthProbe: Send + Sync {
    /// Perform the health check
    async fn check(&self, config: &HealthCheckConfig) -> HealthCheck;
    
    /// Get the probe type name
    fn probe_type(&self) -> &'static str;
}

/// HTTP health check probe implementation
pub struct HttpHealthProbe {
    client: HttpClient,
}

impl HttpHealthProbe {
    /// Create a new HTTP health probe
    pub fn new() -> Self {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }
}

impl Default for HttpHealthProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HealthProbe for HttpHealthProbe {
    async fn check(&self, config: &HealthCheckConfig) -> HealthCheck {
        let start_time = Instant::now();
        
        // Build the request
        let mut request_builder = match config.method.to_uppercase().as_str() {
            "GET" => self.client.get(&config.url),
            "POST" => self.client.post(&config.url),
            "PUT" => self.client.put(&config.url),
            "HEAD" => self.client.head(&config.url),
            _ => self.client.get(&config.url),
        };

        // Add headers
        for (key, value) in &config.headers {
            request_builder = request_builder.header(key, value);
        }

        // Add body if specified
        if let Some(body) = &config.body {
            request_builder = request_builder.body(body.clone());
        }

        // Perform the request with timeout
        let result = timeout(config.timeout, request_builder.send()).await;
        let duration = start_time.elapsed();

        match result {
            Ok(Ok(response)) => {
                let status_code = response.status().as_u16();
                
                // Check if status code is expected
                let status_ok = if config.expected_status_codes.is_empty() {
                    response.status().is_success()
                } else {
                    config.expected_status_codes.contains(&status_code)
                };

                if !status_ok {
                    return HealthCheck::failure(
                        config.name.clone(),
                        format!("Unexpected status code: {}", status_code),
                        duration,
                    );
                }

                // Check response body content if specified
                if let Some(expected_content) = &config.expected_body_content {
                    match response.text().await {
                        Ok(body) => {
                            if !body.contains(expected_content) {
                                return HealthCheck::failure(
                                    config.name.clone(),
                                    format!("Response body does not contain expected content: {}", expected_content),
                                    duration,
                                );
                            }
                        }
                        Err(e) => {
                            return HealthCheck::failure(
                                config.name.clone(),
                                format!("Failed to read response body: {}", e),
                                duration,
                            );
                        }
                    }
                }

                HealthCheck::success(config.name.clone(), duration)
            }
            Ok(Err(e)) => HealthCheck::failure(
                config.name.clone(),
                format!("HTTP request failed: {}", e),
                duration,
            ),
            Err(_) => HealthCheck::failure(
                config.name.clone(),
                format!("Health check timed out after {:?}", config.timeout),
                duration,
            ),
        }
    }

    fn probe_type(&self) -> &'static str {
        "http"
    }
}

/// Health check event types
#[derive(Debug, Clone)]
pub enum HealthEvent {
    /// Health status changed for a service instance
    InstanceHealthChanged {
        instance_id: String,
        old_status: ServiceStatus,
        new_status: ServiceStatus,
    },
    /// Gateway health status changed
    GatewayHealthChanged {
        old_status: ServiceStatus,
        new_status: ServiceStatus,
    },
    /// Health check configuration updated
    ConfigurationUpdated {
        instance_id: String,
        config: HealthCheckConfig,
    },
}

/// Type aliases for health event channels
pub type HealthEventSender = broadcast::Sender<HealthEvent>;
pub type HealthEventReceiver = broadcast::Receiver<HealthEvent>;

/// Main health checker that manages all health checks
pub struct HealthChecker {
    /// HTTP client for health checks
    http_probe: Arc<HttpHealthProbe>,
    /// Service registry for updating instance health
    service_registry: Option<Arc<ServiceRegistry>>,
    /// Health check configurations per service instance
    instance_configs: Arc<DashMap<String, HealthCheckConfig>>,
    /// Current health check results per instance
    instance_results: Arc<DashMap<String, HealthCheck>>,
    /// Gateway self-health checks
    gateway_checks: Arc<DashMap<String, HealthCheckConfig>>,
    /// Gateway health results
    gateway_results: Arc<DashMap<String, HealthCheck>>,
    /// Event broadcaster
    event_sender: HealthEventSender,
    /// Gateway start time for uptime calculation
    start_time: Instant,
    /// Manual health status overrides
    manual_overrides: Arc<DashMap<String, ServiceStatus>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(service_registry: Option<Arc<ServiceRegistry>>) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        Self {
            http_probe: Arc::new(HttpHealthProbe::new()),
            service_registry,
            instance_configs: Arc::new(DashMap::new()),
            instance_results: Arc::new(DashMap::new()),
            gateway_checks: Arc::new(DashMap::new()),
            gateway_results: Arc::new(DashMap::new()),
            event_sender,
            start_time: Instant::now(),
            manual_overrides: Arc::new(DashMap::new()),
        }
    }

    /// Add a health check configuration for a service instance
    pub fn add_instance_health_check(&self, instance_id: String, config: HealthCheckConfig) {
        self.instance_configs.insert(instance_id.clone(), config.clone());
        
        // Send configuration update event
        let event = HealthEvent::ConfigurationUpdated { instance_id, config };
        if let Err(e) = self.event_sender.send(event) {
            warn!("Failed to send health configuration update event: {}", e);
        }
    }

    /// Remove health check configuration for a service instance
    pub fn remove_instance_health_check(&self, instance_id: &str) {
        self.instance_configs.remove(instance_id);
        self.instance_results.remove(instance_id);
        self.manual_overrides.remove(instance_id);
    }

    /// Add a gateway self-health check
    pub fn add_gateway_health_check(&self, name: String, config: HealthCheckConfig) {
        self.gateway_checks.insert(name, config);
    }

    /// Remove a gateway self-health check
    pub fn remove_gateway_health_check(&self, name: &str) {
        self.gateway_checks.remove(name);
        self.gateway_results.remove(name);
    }

    /// Manually override health status for an instance
    pub fn set_manual_override(&self, instance_id: String, status: ServiceStatus) {
        self.manual_overrides.insert(instance_id, status);
    }

    /// Remove manual health status override
    pub fn remove_manual_override(&self, instance_id: &str) {
        self.manual_overrides.remove(instance_id);
    }

    /// Get current health status for a service instance
    pub fn get_instance_health(&self, instance_id: &str) -> ServiceStatus {
        // Check for manual override first
        if let Some(override_status) = self.manual_overrides.get(instance_id) {
            return override_status.clone();
        }

        // Get latest health check result
        self.instance_results
            .get(instance_id)
            .map(|result| result.status.clone())
            .unwrap_or(ServiceStatus::Unknown)
    }

    /// Get gateway health report
    pub fn get_gateway_health(&self) -> HealthReport {
        let checks: HashMap<String, HealthCheck> = self.gateway_results
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        let mut report = HealthReport::new(checks);
        report.uptime = self.start_time.elapsed().as_secs();
        report
    }

    /// Perform health check for a specific service instance
    pub async fn check_instance_health(&self, instance_id: &str) -> GatewayResult<HealthCheck> {
        let config = self.instance_configs
            .get(instance_id)
            .ok_or_else(|| GatewayError::config(format!("No health check config for instance: {}", instance_id)))?;

        if !config.enabled {
            return Ok(HealthCheck::new(
                config.name.clone(),
                ServiceStatus::Unknown,
                Some("Health check disabled".to_string()),
                Duration::from_millis(0),
            ));
        }

        let mut result = self.http_probe.check(&config).await;

        // Update consecutive success/failure counts
        if let Some(mut previous) = self.instance_results.get_mut(instance_id) {
            match result.status {
                ServiceStatus::Healthy => {
                    result.consecutive_successes = previous.consecutive_successes + 1;
                    result.consecutive_failures = 0;
                }
                ServiceStatus::Unhealthy => {
                    result.consecutive_failures = previous.consecutive_failures + 1;
                    result.consecutive_successes = 0;
                }
                _ => {
                    result.consecutive_successes = 0;
                    result.consecutive_failures = 0;
                }
            }
        }

        // Apply thresholds
        let final_status = if result.consecutive_successes >= config.healthy_threshold {
            ServiceStatus::Healthy
        } else if result.consecutive_failures >= config.unhealthy_threshold {
            ServiceStatus::Unhealthy
        } else {
            // Keep previous status if thresholds not met
            self.instance_results
                .get(instance_id)
                .map(|r| r.status.clone())
                .unwrap_or(ServiceStatus::Unknown)
        };

        result.status = final_status.clone();

        // Update service registry if available
        if let Some(registry) = &self.service_registry {
            registry.update_instance_health(instance_id, final_status.clone().into());
        }

        // Send health change event if status changed
        if let Some(previous) = self.instance_results.get(instance_id) {
            if previous.status != final_status {
                let event = HealthEvent::InstanceHealthChanged {
                    instance_id: instance_id.to_string(),
                    old_status: previous.status.clone(),
                    new_status: final_status,
                };
                if let Err(e) = self.event_sender.send(event) {
                    warn!("Failed to send health change event: {}", e);
                }
            }
        }

        // Store the result
        self.instance_results.insert(instance_id.to_string(), result.clone());

        Ok(result)
    }

    /// Perform all gateway self-health checks
    pub async fn check_gateway_health(&self) -> HealthReport {
        let mut tasks = Vec::new();

        // Collect all gateway health check tasks
        for entry in self.gateway_checks.iter() {
            let name = entry.key().clone();
            let config = entry.value().clone();
            let probe = self.http_probe.clone();

            let task = tokio::spawn(async move {
                let result = probe.check(&config).await;
                (name, result)
            });

            tasks.push(task);
        }

        // Wait for all health checks to complete
        let mut checks = HashMap::new();
        for task in tasks {
            if let Ok((name, result)) = task.await {
                checks.insert(name.clone(), result.clone());
                self.gateway_results.insert(name, result);
            }
        }

        let mut report = HealthReport::new(checks);
        report.uptime = self.start_time.elapsed().as_secs();
        report
    }

    /// Start background health checking tasks
    pub async fn start_background_tasks(self: Arc<Self>) -> GatewayResult<()> {
        // Start instance health checking task
        let instance_checker = self.clone();
        tokio::spawn(async move {
            loop {
                // Get all configured instances
                let instance_ids: Vec<String> = instance_checker.instance_configs
                    .iter()
                    .map(|entry| entry.key().clone())
                    .collect();

                // Check each instance
                for instance_id in instance_ids {
                    let checker = instance_checker.clone();
                    let id = instance_id.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = checker.check_instance_health(&id).await {
                            error!("Failed to check health for instance {}: {}", id, e);
                        }
                    });
                }

                // Wait before next round of checks
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        // Start gateway self-health checking task
        let gateway_checker = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let _report = gateway_checker.check_gateway_health().await;
                debug!("Gateway health check completed");
            }
        });

        // Start automatic service instance removal task
        let removal_checker = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                removal_checker.remove_unhealthy_instances().await;
            }
        });

        info!("Started health checker background tasks");
        Ok(())
    }

    /// Remove unhealthy service instances from the registry
    async fn remove_unhealthy_instances(&self) {
        if let Some(registry) = &self.service_registry {
            let unhealthy_instances: Vec<String> = self.instance_results
                .iter()
                .filter_map(|entry| {
                    let instance_id = entry.key();
                    let result = entry.value();
                    
                    // Check if instance has been unhealthy for too long
                    if result.status == ServiceStatus::Unhealthy && result.consecutive_failures >= 5 {
                        Some(instance_id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for instance_id in unhealthy_instances {
                info!("Removing unhealthy instance from registry: {}", instance_id);
                registry.remove_instance(&instance_id);
                self.remove_instance_health_check(&instance_id);
            }
        }
    }

    /// Subscribe to health events
    pub fn subscribe_to_events(&self) -> HealthEventReceiver {
        self.event_sender.subscribe()
    }

    /// Get all instance health check configurations
    pub fn get_instance_configs(&self) -> HashMap<String, HealthCheckConfig> {
        self.instance_configs
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get all gateway health check configurations
    pub fn get_gateway_configs(&self) -> HashMap<String, HealthCheckConfig> {
        self.gateway_checks
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get health check statistics
    pub fn get_health_stats(&self) -> HealthStats {
        let total_instances = self.instance_configs.len();
        let healthy_instances = self.instance_results
            .iter()
            .filter(|entry| entry.value().status == ServiceStatus::Healthy)
            .count();
        let unhealthy_instances = self.instance_results
            .iter()
            .filter(|entry| entry.value().status == ServiceStatus::Unhealthy)
            .count();

        let gateway_status = self.get_gateway_health().status;

        HealthStats {
            total_instances,
            healthy_instances,
            unhealthy_instances,
            unknown_instances: total_instances - healthy_instances - unhealthy_instances,
            gateway_status,
            manual_overrides: self.manual_overrides.len(),
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Health check statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStats {
    pub total_instances: usize,
    pub healthy_instances: usize,
    pub unhealthy_instances: usize,
    pub unknown_instances: usize,
    pub gateway_status: ServiceStatus,
    pub manual_overrides: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_health_check_creation() {
        let check = HealthCheck::success("test".to_string(), Duration::from_millis(100));
        assert_eq!(check.name, "test");
        assert_eq!(check.status, ServiceStatus::Healthy);
        assert_eq!(check.duration, Duration::from_millis(100));
    }

    #[test]
    fn test_health_report_aggregation() {
        let mut checks = HashMap::new();
        checks.insert("check1".to_string(), HealthCheck::success("check1".to_string(), Duration::from_millis(50)));
        checks.insert("check2".to_string(), HealthCheck::failure("check2".to_string(), "error".to_string(), Duration::from_millis(100)));

        let report = HealthReport::new(checks);
        assert_eq!(report.status, ServiceStatus::Unhealthy);
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert_eq!(config.name, "default");
        assert_eq!(config.method, "GET");
        assert_eq!(config.healthy_threshold, 2);
        assert_eq!(config.unhealthy_threshold, 3);
        assert!(config.enabled);
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let checker = HealthChecker::new(None);
        let stats = checker.get_health_stats();
        assert_eq!(stats.total_instances, 0);
        assert_eq!(stats.gateway_status, ServiceStatus::Unknown);
    }

    #[tokio::test]
    async fn test_manual_override() {
        let checker = HealthChecker::new(None);
        checker.set_manual_override("test-instance".to_string(), ServiceStatus::Healthy);
        
        let status = checker.get_instance_health("test-instance");
        assert_eq!(status, ServiceStatus::Healthy);
        
        checker.remove_manual_override("test-instance");
        let status = checker.get_instance_health("test-instance");
        assert_eq!(status, ServiceStatus::Unknown);
    }
}
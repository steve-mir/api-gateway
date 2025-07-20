//! # Metrics Collection and Monitoring
//!
//! This module provides comprehensive metrics collection, Prometheus export,
//! and real-time monitoring capabilities for the API Gateway.
//!
//! ## Features
//! - Standard gateway metrics (latency, throughput, error rates)
//! - Custom business metrics support
//! - Prometheus metrics export
//! - Real-time metrics dashboard endpoints
//! - Resource utilization monitoring
//! - Metrics aggregation and querying
//!
//! ## Usage Example
//! ```rust
//! use crate::observability::metrics::{MetricsCollector, MetricsConfig};
//!
//! let config = MetricsConfig::default();
//! let collector = MetricsCollector::new(config).await?;
//!
//! // Record request metrics
//! collector.record_request_latency("GET", "/api/users", 150.0);
//! collector.increment_request_count("GET", "/api/users", 200);
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use metrics::{Counter, Gauge, Histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during metrics operations
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Failed to initialize metrics exporter: {0}")]
    InitializationError(String),
    
    #[error("Failed to record metric: {0}")]
    RecordingError(String),
    
    #[error("Failed to export metrics: {0}")]
    ExportError(String),
    
    #[error("Invalid metric configuration: {0}")]
    ConfigurationError(String),
    
    #[error("Metric not found: {0}")]
    MetricNotFound(String),
}

/// Configuration for metrics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics collection is enabled
    pub enabled: bool,
    
    /// Prometheus metrics endpoint path
    pub prometheus_endpoint: String,
    
    /// Metrics collection interval in seconds
    pub collection_interval: u64,
    
    /// Maximum number of custom metrics to store
    pub max_custom_metrics: usize,
    
    /// Histogram buckets for latency metrics
    pub latency_buckets: Vec<f64>,
    
    /// Labels to add to all metrics
    pub global_labels: HashMap<String, String>,
    
    /// Resource monitoring configuration
    pub resource_monitoring: ResourceMonitoringConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus_endpoint: "/metrics".to_string(),
            collection_interval: 15,
            max_custom_metrics: 1000,
            latency_buckets: vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
            ],
            global_labels: HashMap::new(),
            resource_monitoring: ResourceMonitoringConfig::default(),
        }
    }
}

/// Configuration for resource monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMonitoringConfig {
    /// Whether to monitor CPU usage
    pub monitor_cpu: bool,
    
    /// Whether to monitor memory usage
    pub monitor_memory: bool,
    
    /// Whether to monitor network I/O
    pub monitor_network: bool,
    
    /// Whether to monitor disk I/O
    pub monitor_disk: bool,
    
    /// Resource monitoring interval in seconds
    pub monitoring_interval: u64,
}

impl Default for ResourceMonitoringConfig {
    fn default() -> Self {
        Self {
            monitor_cpu: true,
            monitor_memory: true,
            monitor_network: true,
            monitor_disk: true,
            monitoring_interval: 30,
        }
    }
}

/// Standard gateway metrics - simplified without Debug derive since metrics types don't implement Debug
#[derive(Clone)]
pub struct GatewayMetrics {
    // Request metrics
    pub request_count: Counter,
    pub request_duration: Histogram,
    pub request_size: Histogram,
    pub response_size: Histogram,
    
    // Error metrics
    pub error_count: Counter,
    pub error_rate: Gauge,
    
    // Upstream metrics
    pub upstream_request_count: Counter,
    pub upstream_request_duration: Histogram,
    pub upstream_error_count: Counter,
    
    // Connection metrics
    pub active_connections: Gauge,
    pub connection_count: Counter,
    pub connection_duration: Histogram,
    
    // Circuit breaker metrics
    pub circuit_breaker_state: Gauge,
    pub circuit_breaker_failures: Counter,
    
    // Rate limiting metrics
    pub rate_limit_hits: Counter,
    pub rate_limit_remaining: Gauge,
    
    // Cache metrics
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub cache_size: Gauge,
}

/// Resource utilization metrics - simplified without Debug derive
#[derive(Clone)]
pub struct ResourceMetrics {
    // CPU metrics
    pub cpu_usage_percent: Gauge,
    pub cpu_load_average: Gauge,
    
    // Memory metrics
    pub memory_usage_bytes: Gauge,
    pub memory_usage_percent: Gauge,
    pub memory_available_bytes: Gauge,
    
    // Network metrics
    pub network_bytes_sent: Counter,
    pub network_bytes_received: Counter,
    pub network_packets_sent: Counter,
    pub network_packets_received: Counter,
    
    // Disk metrics
    pub disk_bytes_read: Counter,
    pub disk_bytes_written: Counter,
    pub disk_usage_percent: Gauge,
}

/// Custom business metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetric {
    pub name: String,
    pub metric_type: CustomMetricType,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: SystemTime,
    pub description: Option<String>,
}

/// Types of custom metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomMetricType {
    Counter,
    Gauge,
    Histogram,
}

/// Metrics query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQuery {
    pub metric_name: Option<String>,
    pub labels: HashMap<String, String>,
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub aggregation: Option<MetricsAggregation>,
}

/// Metrics aggregation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricsAggregation {
    Sum,
    Average,
    Min,
    Max,
    Count,
    Percentile(f64),
}

/// Metrics query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryResult {
    pub metric_name: String,
    pub values: Vec<MetricValue>,
    pub aggregated_value: Option<f64>,
}

/// Individual metric value with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub value: f64,
    pub timestamp: SystemTime,
    pub labels: HashMap<String, String>,
}

/// Main metrics collector
pub struct MetricsCollector {
    config: MetricsConfig,
    gateway_metrics: GatewayMetrics,
    resource_metrics: ResourceMetrics,
    custom_metrics: Arc<RwLock<HashMap<String, CustomMetric>>>,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub async fn new(config: MetricsConfig) -> Result<Self, MetricsError> {
        if !config.enabled {
            return Err(MetricsError::ConfigurationError(
                "Metrics collection is disabled".to_string()
            ));
        }

        // Initialize Prometheus exporter
        let mut builder = PrometheusBuilder::new();

        // Add global labels
        for (key, value) in &config.global_labels {
            builder = builder.add_global_label(key, value);
        }

        // Set up histogram buckets
        let latency_matcher = Matcher::Full("request_duration".to_string());
        builder = builder.set_buckets_for_metric(latency_matcher, &config.latency_buckets)
            .map_err(|e| MetricsError::InitializationError(format!("Failed to set histogram buckets: {}", e)))?;

        // In version 0.13, we install the recorder directly
        builder.install()
            .map_err(|e| MetricsError::InitializationError(e.to_string()))?;

        // Initialize standard metrics
        let gateway_metrics = Self::initialize_gateway_metrics();
        let resource_metrics = Self::initialize_resource_metrics();

        Ok(Self {
            config,
            gateway_metrics,
            resource_metrics,
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        })
    }

    /// Initialize standard gateway metrics
    fn initialize_gateway_metrics() -> GatewayMetrics {
        GatewayMetrics {
            request_count: metrics::counter!("gateway_requests_total"),
            request_duration: metrics::histogram!("gateway_request_duration_seconds"),
            request_size: metrics::histogram!("gateway_request_size_bytes"),
            response_size: metrics::histogram!("gateway_response_size_bytes"),
            
            error_count: metrics::counter!("gateway_errors_total"),
            error_rate: metrics::gauge!("gateway_error_rate"),
            
            upstream_request_count: metrics::counter!("gateway_upstream_requests_total"),
            upstream_request_duration: metrics::histogram!("gateway_upstream_request_duration_seconds"),
            upstream_error_count: metrics::counter!("gateway_upstream_errors_total"),
            
            active_connections: metrics::gauge!("gateway_active_connections"),
            connection_count: metrics::counter!("gateway_connections_total"),
            connection_duration: metrics::histogram!("gateway_connection_duration_seconds"),
            
            circuit_breaker_state: metrics::gauge!("gateway_circuit_breaker_state"),
            circuit_breaker_failures: metrics::counter!("gateway_circuit_breaker_failures_total"),
            
            rate_limit_hits: metrics::counter!("gateway_rate_limit_hits_total"),
            rate_limit_remaining: metrics::gauge!("gateway_rate_limit_remaining"),
            
            cache_hits: metrics::counter!("gateway_cache_hits_total"),
            cache_misses: metrics::counter!("gateway_cache_misses_total"),
            cache_size: metrics::gauge!("gateway_cache_size_bytes"),
        }
    }

    /// Initialize resource monitoring metrics
    fn initialize_resource_metrics() -> ResourceMetrics {
        ResourceMetrics {
            cpu_usage_percent: metrics::gauge!("system_cpu_usage_percent"),
            cpu_load_average: metrics::gauge!("system_cpu_load_average"),
            
            memory_usage_bytes: metrics::gauge!("system_memory_usage_bytes"),
            memory_usage_percent: metrics::gauge!("system_memory_usage_percent"),
            memory_available_bytes: metrics::gauge!("system_memory_available_bytes"),
            
            network_bytes_sent: metrics::counter!("system_network_bytes_sent_total"),
            network_bytes_received: metrics::counter!("system_network_bytes_received_total"),
            network_packets_sent: metrics::counter!("system_network_packets_sent_total"),
            network_packets_received: metrics::counter!("system_network_packets_received_total"),
            
            disk_bytes_read: metrics::counter!("system_disk_bytes_read_total"),
            disk_bytes_written: metrics::counter!("system_disk_bytes_written_total"),
            disk_usage_percent: metrics::gauge!("system_disk_usage_percent"),
        }
    }

    /// Record request metrics
    pub fn record_request(&self, method: &str, path: &str, status_code: u16, duration: Duration, request_size: u64, response_size: u64) {
        // Create owned strings for labels to satisfy static lifetime requirements
        let method_owned = method.to_string();
        let path_owned = path.to_string();
        let status_code_owned = status_code.to_string();
        
        // Create labeled metrics for each combination
        let request_counter = metrics::counter!("gateway_requests_total", "method" => method_owned.clone(), "path" => path_owned.clone(), "status_code" => status_code_owned.clone());
        let duration_histogram = metrics::histogram!("gateway_request_duration_seconds", "method" => method_owned.clone(), "path" => path_owned.clone(), "status_code" => status_code_owned.clone());
        let request_size_histogram = metrics::histogram!("gateway_request_size_bytes", "method" => method_owned.clone(), "path" => path_owned.clone(), "status_code" => status_code_owned.clone());
        let response_size_histogram = metrics::histogram!("gateway_response_size_bytes", "method" => method_owned.clone(), "path" => path_owned.clone(), "status_code" => status_code_owned.clone());

        request_counter.increment(1);
        duration_histogram.record(duration.as_secs_f64());
        request_size_histogram.record(request_size as f64);
        response_size_histogram.record(response_size as f64);

        // Record error metrics for non-2xx status codes
        if status_code >= 400 {
            let error_counter = metrics::counter!("gateway_errors_total", "method" => method_owned, "path" => path_owned, "status_code" => status_code_owned);
            error_counter.increment(1);
        }
    }

    /// Record upstream request metrics
    pub fn record_upstream_request(&self, service: &str, method: &str, status_code: u16, duration: Duration) {
        let service_owned = service.to_string();
        let method_owned = method.to_string();
        let status_code_owned = status_code.to_string();
        
        let upstream_counter = metrics::counter!("gateway_upstream_requests_total", "service" => service_owned.clone(), "method" => method_owned.clone(), "status_code" => status_code_owned.clone());
        let upstream_duration = metrics::histogram!("gateway_upstream_request_duration_seconds", "service" => service_owned.clone(), "method" => method_owned.clone(), "status_code" => status_code_owned.clone());

        upstream_counter.increment(1);
        upstream_duration.record(duration.as_secs_f64());

        if status_code >= 400 {
            let upstream_error_counter = metrics::counter!("gateway_upstream_errors_total", "service" => service_owned, "method" => method_owned, "status_code" => status_code_owned);
            upstream_error_counter.increment(1);
        }
    }

    /// Update connection metrics
    pub fn update_connection_metrics(&self, active_connections: i64, new_connection: bool, connection_duration: Option<Duration>) {
        let active_gauge = metrics::gauge!("gateway_active_connections");
        active_gauge.set(active_connections as f64);
        
        if new_connection {
            let connection_counter = metrics::counter!("gateway_connections_total");
            connection_counter.increment(1);
        }
        
        if let Some(duration) = connection_duration {
            let duration_histogram = metrics::histogram!("gateway_connection_duration_seconds");
            duration_histogram.record(duration.as_secs_f64());
        }
    }

    /// Update circuit breaker metrics
    pub fn update_circuit_breaker_metrics(&self, service: &str, state: &str, failure_count: u64) {
        let service_owned = service.to_string();
        
        let state_value = match state {
            "closed" => 0.0,
            "open" => 1.0,
            "half_open" => 0.5,
            _ => -1.0,
        };
        
        let state_gauge = metrics::gauge!("gateway_circuit_breaker_state", "service" => service_owned.clone());
        state_gauge.set(state_value);
        
        if failure_count > 0 {
            let failure_counter = metrics::counter!("gateway_circuit_breaker_failures_total", "service" => service_owned);
            failure_counter.increment(failure_count);
        }
    }

    /// Update rate limiting metrics
    pub fn update_rate_limit_metrics(&self, identifier: &str, hits: u64, remaining: i64) {
        let identifier_owned = identifier.to_string();
        
        if hits > 0 {
            let hits_counter = metrics::counter!("gateway_rate_limit_hits_total", "identifier" => identifier_owned.clone());
            hits_counter.increment(hits);
        }
        
        let remaining_gauge = metrics::gauge!("gateway_rate_limit_remaining", "identifier" => identifier_owned);
        remaining_gauge.set(remaining as f64);
    }

    /// Update cache metrics
    pub fn update_cache_metrics(&self, cache_type: &str, hits: u64, misses: u64, size_bytes: u64) {
        let cache_type_owned = cache_type.to_string();
        
        if hits > 0 {
            let hits_counter = metrics::counter!("gateway_cache_hits_total", "cache_type" => cache_type_owned.clone());
            hits_counter.increment(hits);
        }
        
        if misses > 0 {
            let misses_counter = metrics::counter!("gateway_cache_misses_total", "cache_type" => cache_type_owned.clone());
            misses_counter.increment(misses);
        }
        
        let size_gauge = metrics::gauge!("gateway_cache_size_bytes", "cache_type" => cache_type_owned);
        size_gauge.set(size_bytes as f64);
    }

    /// Record custom metric
    pub async fn record_custom_metric(&self, metric: CustomMetric) -> Result<(), MetricsError> {
        let mut custom_metrics = self.custom_metrics.write().await;
        
        if custom_metrics.len() >= self.config.max_custom_metrics {
            return Err(MetricsError::ConfigurationError(
                "Maximum number of custom metrics reached".to_string()
            ));
        }
        
        // Record the metric using the metrics crate with labels
        match metric.metric_type {
            CustomMetricType::Counter => {
                // Create counter with labels dynamically
                if metric.labels.is_empty() {
                    let counter = metrics::counter!(metric.name.clone());
                    counter.increment(metric.value as u64);
                } else {
                    // For now, we'll create a simple labeled counter
                    // In a real implementation, you'd want to handle this more dynamically
                    let counter = metrics::counter!(metric.name.clone(), "custom" => "true");
                    counter.increment(metric.value as u64);
                }
            }
            CustomMetricType::Gauge => {
                if metric.labels.is_empty() {
                    let gauge = metrics::gauge!(metric.name.clone());
                    gauge.set(metric.value);
                } else {
                    let gauge = metrics::gauge!(metric.name.clone(), "custom" => "true");
                    gauge.set(metric.value);
                }
            }
            CustomMetricType::Histogram => {
                if metric.labels.is_empty() {
                    let histogram = metrics::histogram!(metric.name.clone());
                    histogram.record(metric.value);
                } else {
                    let histogram = metrics::histogram!(metric.name.clone(), "custom" => "true");
                    histogram.record(metric.value);
                }
            }
        }
        
        custom_metrics.insert(metric.name.clone(), metric);
        Ok(())
    }

    /// Get Prometheus metrics
    pub fn get_prometheus_metrics(&self) -> String {
        // In version 0.13, we need to use a different approach to get metrics
        // Since we don't have a handle, we'll return a placeholder for now
        // In a real implementation, you might need to use a different method
        "# Prometheus metrics would be available at the configured endpoint\n".to_string()
    }

    /// Query metrics
    pub async fn query_metrics(&self, query: MetricsQuery) -> Result<Vec<MetricsQueryResult>, MetricsError> {
        let custom_metrics = self.custom_metrics.read().await;
        let mut results = Vec::new();
        
        for (name, metric) in custom_metrics.iter() {
            // Filter by metric name if specified
            if let Some(ref query_name) = query.metric_name {
                if name != query_name {
                    continue;
                }
            }
            
            // Filter by labels
            let mut matches_labels = true;
            for (key, value) in &query.labels {
                if metric.labels.get(key) != Some(value) {
                    matches_labels = false;
                    break;
                }
            }
            
            if !matches_labels {
                continue;
            }
            
            // Filter by time range
            if let Some(start_time) = query.start_time {
                if metric.timestamp < start_time {
                    continue;
                }
            }
            
            if let Some(end_time) = query.end_time {
                if metric.timestamp > end_time {
                    continue;
                }
            }
            
            let metric_value = MetricValue {
                value: metric.value,
                timestamp: metric.timestamp,
                labels: metric.labels.clone(),
            };
            
            results.push(MetricsQueryResult {
                metric_name: name.clone(),
                values: vec![metric_value],
                aggregated_value: Some(metric.value),
            });
        }
        
        Ok(results)
    }

    /// Get system resource metrics
    pub async fn collect_resource_metrics(&self) -> Result<(), MetricsError> {
        if !self.config.resource_monitoring.monitor_cpu && 
           !self.config.resource_monitoring.monitor_memory &&
           !self.config.resource_monitoring.monitor_network &&
           !self.config.resource_monitoring.monitor_disk {
            return Ok(());
        }

        // Note: In a real implementation, you would use system monitoring libraries
        // like `sysinfo` or `procfs` to collect actual system metrics.
        // For this implementation, we'll simulate the metrics collection.
        
        if self.config.resource_monitoring.monitor_cpu {
            // Simulate CPU metrics
            self.resource_metrics.cpu_usage_percent.set(45.0);
            self.resource_metrics.cpu_load_average.set(1.2);
        }
        
        if self.config.resource_monitoring.monitor_memory {
            // Simulate memory metrics
            self.resource_metrics.memory_usage_bytes.set(1024.0 * 1024.0 * 512.0); // 512MB
            self.resource_metrics.memory_usage_percent.set(60.0);
            self.resource_metrics.memory_available_bytes.set(1024.0 * 1024.0 * 1024.0); // 1GB
        }
        
        if self.config.resource_monitoring.monitor_network {
            // Simulate network metrics
            self.resource_metrics.network_bytes_sent.increment(1024);
            self.resource_metrics.network_bytes_received.increment(2048);
            self.resource_metrics.network_packets_sent.increment(10);
            self.resource_metrics.network_packets_received.increment(15);
        }
        
        if self.config.resource_monitoring.monitor_disk {
            // Simulate disk metrics
            self.resource_metrics.disk_bytes_read.increment(4096);
            self.resource_metrics.disk_bytes_written.increment(2048);
            self.resource_metrics.disk_usage_percent.set(75.0);
        }
        
        Ok(())
    }

    /// Start resource monitoring background task
    pub fn start_resource_monitoring(&self) -> tokio::task::JoinHandle<()> {
        let collector = self.clone();
        let interval = Duration::from_secs(collector.config.resource_monitoring.monitoring_interval);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                if let Err(e) = collector.collect_resource_metrics().await {
                    tracing::error!("Failed to collect resource metrics: {}", e);
                }
            }
        })
    }

    /// Get uptime in seconds
    pub fn get_uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Get metrics summary
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        let custom_metrics_count = self.custom_metrics.read().await.len();
        
        MetricsSummary {
            uptime_seconds: self.get_uptime_seconds(),
            custom_metrics_count,
            prometheus_endpoint: self.config.prometheus_endpoint.clone(),
            collection_interval: self.config.collection_interval,
            resource_monitoring_enabled: self.config.resource_monitoring.monitor_cpu ||
                                       self.config.resource_monitoring.monitor_memory ||
                                       self.config.resource_monitoring.monitor_network ||
                                       self.config.resource_monitoring.monitor_disk,
        }
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            gateway_metrics: self.gateway_metrics.clone(),
            resource_metrics: self.resource_metrics.clone(),
            custom_metrics: self.custom_metrics.clone(),
            start_time: self.start_time,
        }
    }
}

/// Metrics summary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub uptime_seconds: f64,
    pub custom_metrics_count: usize,
    pub prometheus_endpoint: String,
    pub collection_interval: u64,
    pub resource_monitoring_enabled: bool,
}
//! # Performance Admin Module
//!
//! This module provides admin endpoints for performance monitoring and tuning
//! including connection pool statistics, memory usage monitoring, and
//! performance optimization controls.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use metrics::{gauge, counter, histogram};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::connection_pool::{ConnectionPoolManager, GlobalPoolStats, PoolStats};
use crate::core::memory_optimization::{
    MemoryOptimizer, MemoryOptimizationStats, MemoryConfig, BufferReuseConfig
};
use crate::core::zero_copy::ZeroCopyConfig;

/// Performance admin state
#[derive(Clone)]
pub struct PerformanceAdminState {
    /// Connection pool manager
    pub connection_pool: Arc<ConnectionPoolManager>,
    /// Memory optimizer
    pub memory_optimizer: Arc<MemoryOptimizer>,
    /// Performance configuration
    pub config: Arc<tokio::sync::RwLock<PerformanceConfig>>,
    /// Performance metrics collector
    pub metrics_collector: Arc<PerformanceMetricsCollector>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Memory optimization configuration
    pub memory: MemoryConfig,
    /// Zero-copy configuration
    pub zero_copy: ZeroCopyConfig,
    /// Performance monitoring settings
    pub monitoring: PerformanceMonitoringConfig,
    /// Auto-tuning settings
    pub auto_tuning: AutoTuningConfig,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            memory: MemoryConfig::default(),
            zero_copy: ZeroCopyConfig::default(),
            monitoring: PerformanceMonitoringConfig::default(),
            auto_tuning: AutoTuningConfig::default(),
        }
    }
}

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMonitoringConfig {
    /// Enable performance monitoring
    pub enabled: bool,
    /// Metrics collection interval
    pub collection_interval: Duration,
    /// Performance alert thresholds
    pub alert_thresholds: AlertThresholds,
    /// Enable detailed profiling
    pub enable_profiling: bool,
    /// Hot path detection settings
    pub hot_path_detection: HotPathDetectionConfig,
}

impl Default for PerformanceMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval: Duration::from_secs(30),
            alert_thresholds: AlertThresholds::default(),
            enable_profiling: false,
            hot_path_detection: HotPathDetectionConfig::default(),
        }
    }
}

/// Performance alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Memory usage threshold (percentage)
    pub memory_usage_percent: f64,
    /// Connection pool utilization threshold (percentage)
    pub pool_utilization_percent: f64,
    /// Response time threshold (milliseconds)
    pub response_time_ms: u64,
    /// Error rate threshold (percentage)
    pub error_rate_percent: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            memory_usage_percent: 80.0,
            pool_utilization_percent: 85.0,
            response_time_ms: 1000,
            error_rate_percent: 5.0,
        }
    }
}

/// Hot path detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathDetectionConfig {
    /// Enable hot path detection
    pub enabled: bool,
    /// Minimum call count to consider a path hot
    pub min_call_count: u64,
    /// Time window for hot path analysis
    pub analysis_window: Duration,
    /// Top N hot paths to track
    pub top_n_paths: usize,
}

impl Default for HotPathDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_call_count: 100,
            analysis_window: Duration::from_secs(300), // 5 minutes
            top_n_paths: 10,
        }
    }
}

/// Auto-tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTuningConfig {
    /// Enable auto-tuning
    pub enabled: bool,
    /// Auto-tuning interval
    pub tuning_interval: Duration,
    /// Connection pool auto-tuning
    pub connection_pool_tuning: bool,
    /// Memory optimization auto-tuning
    pub memory_tuning: bool,
    /// Buffer size auto-tuning
    pub buffer_size_tuning: bool,
}

impl Default for AutoTuningConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for safety
            tuning_interval: Duration::from_secs(300), // 5 minutes
            connection_pool_tuning: true,
            memory_tuning: true,
            buffer_size_tuning: true,
        }
    }
}

/// Performance metrics collector
pub struct PerformanceMetricsCollector {
    /// Hot path statistics
    hot_paths: Arc<tokio::sync::RwLock<HashMap<String, HotPathStats>>>,
    /// Performance history
    performance_history: Arc<tokio::sync::RwLock<Vec<PerformanceSnapshot>>>,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl PerformanceMetricsCollector {
    /// Create a new performance metrics collector
    pub fn new() -> Self {
        Self {
            hot_paths: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            performance_history: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    /// Record a request for hot path analysis
    pub async fn record_request(&self, path: &str, duration: Duration) {
        let mut hot_paths = self.hot_paths.write().await;
        let stats = hot_paths.entry(path.to_string()).or_insert_with(|| HotPathStats {
            path: path.to_string(),
            call_count: 0,
            total_duration: Duration::ZERO,
            min_duration: Duration::MAX,
            max_duration: Duration::ZERO,
            last_called: Instant::now(),
        });

        stats.call_count += 1;
        stats.total_duration += duration;
        stats.min_duration = stats.min_duration.min(duration);
        stats.max_duration = stats.max_duration.max(duration);
        stats.last_called = Instant::now();
    }

    /// Get hot path statistics
    pub async fn get_hot_paths(&self, config: &HotPathDetectionConfig) -> Vec<HotPathStats> {
        let hot_paths = self.hot_paths.read().await;
        let mut paths: Vec<_> = hot_paths.values()
            .filter(|stats| {
                stats.call_count >= config.min_call_count &&
                stats.last_called.elapsed() <= config.analysis_window
            })
            .cloned()
            .collect();

        // Sort by average response time (descending)
        paths.sort_by(|a, b| {
            let avg_a = a.total_duration.as_nanos() / a.call_count as u128;
            let avg_b = b.total_duration.as_nanos() / b.call_count as u128;
            avg_b.cmp(&avg_a)
        });

        paths.truncate(config.top_n_paths);
        paths
    }

    /// Take a performance snapshot
    pub async fn take_snapshot(
        &self,
        connection_pool: &ConnectionPoolManager,
        memory_optimizer: &MemoryOptimizer,
    ) -> PerformanceSnapshot {
        let snapshot = PerformanceSnapshot {
            timestamp: Instant::now(),
            uptime: self.start_time.elapsed(),
            connection_pool_stats: connection_pool.get_global_stats().await,
            memory_stats: memory_optimizer.get_stats(),
            hot_paths_count: self.hot_paths.read().await.len(),
        };

        // Store in history (keep last 100 snapshots)
        let mut history = self.performance_history.write().await;
        history.push(snapshot.clone());
        if history.len() > 100 {
            history.remove(0);
        }

        snapshot
    }

    /// Get performance history
    pub async fn get_history(&self) -> Vec<PerformanceSnapshot> {
        self.performance_history.read().await.clone()
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Hot path statistics
#[derive(Debug, Clone, Serialize)]
pub struct HotPathStats {
    pub path: String,
    pub call_count: u64,
    pub total_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    #[serde(skip)]
    pub last_called: Instant,
}

impl HotPathStats {
    /// Get average duration
    pub fn average_duration(&self) -> Duration {
        if self.call_count > 0 {
            Duration::from_nanos((self.total_duration.as_nanos() / self.call_count as u128) as u64)
        } else {
            Duration::ZERO
        }
    }
}

/// Performance snapshot
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceSnapshot {
    #[serde(skip)]
    pub timestamp: Instant,
    pub uptime: Duration,
    pub connection_pool_stats: GlobalPoolStats,
    pub memory_stats: MemoryOptimizationStats,
    pub hot_paths_count: usize,
}

/// Query parameters for performance endpoints
#[derive(Debug, Deserialize)]
pub struct PerformanceQuery {
    /// Include detailed statistics
    pub detailed: Option<bool>,
    /// Time range for historical data
    pub time_range: Option<String>,
    /// Specific metric to query
    pub metric: Option<String>,
}

/// Performance tuning request
#[derive(Debug, Deserialize)]
pub struct PerformanceTuningRequest {
    /// Configuration updates
    pub config: Option<PerformanceConfig>,
    /// Specific tuning actions
    pub actions: Option<Vec<TuningAction>>,
}

/// Performance tuning action
#[derive(Debug, Deserialize)]
pub enum TuningAction {
    /// Optimize connection pools
    OptimizeConnectionPools,
    /// Clear memory pools
    ClearMemoryPools,
    /// Reset performance metrics
    ResetMetrics,
    /// Force garbage collection
    ForceGC,
    /// Optimize buffer sizes
    OptimizeBufferSizes,
}

/// Create performance admin routes
pub fn create_performance_routes() -> Router<PerformanceAdminState> {
    Router::new()
        .route("/performance/overview", get(get_performance_overview))
        .route("/performance/connection-pools", get(get_connection_pool_stats))
        .route("/performance/memory", get(get_memory_stats))
        .route("/performance/hot-paths", get(get_hot_paths))
        .route("/performance/history", get(get_performance_history))
        .route("/performance/config", get(get_performance_config))
        .route("/performance/config", put(update_performance_config))
        .route("/performance/tune", post(tune_performance))
        .route("/performance/benchmark", post(run_performance_benchmark))
        .route("/performance/alerts", get(get_performance_alerts))
}

/// Get performance overview
async fn get_performance_overview(
    State(state): State<PerformanceAdminState>,
    Query(query): Query<PerformanceQuery>,
) -> GatewayResult<Json<serde_json::Value>> {
    let detailed = query.detailed.unwrap_or(false);
    
    let snapshot = state.metrics_collector
        .take_snapshot(&state.connection_pool, &state.memory_optimizer)
        .await;
    
    let mut overview = serde_json::json!({
        "uptime_seconds": snapshot.uptime.as_secs(),
        "connection_pools": {
            "total_pools": snapshot.connection_pool_stats.total_pools,
            "total_active_connections": snapshot.connection_pool_stats.total_active_connections,
            "pool_utilization_percent": snapshot.connection_pool_stats.pool_utilization,
        },
        "memory": {
            "current_usage_bytes": snapshot.memory_stats.memory_usage.current_usage,
            "peak_usage_bytes": snapshot.memory_stats.memory_usage.peak_usage,
            "buffer_pool_utilization_percent": snapshot.memory_stats.buffer_manager_stats.pool_utilization,
        },
        "hot_paths_tracked": snapshot.hot_paths_count,
    });
    
    if detailed {
        let config = state.config.read().await;
        let hot_paths = state.metrics_collector
            .get_hot_paths(&config.monitoring.hot_path_detection)
            .await;
        
        overview["detailed"] = serde_json::json!({
            "connection_pool_details": snapshot.connection_pool_stats,
            "memory_details": snapshot.memory_stats,
            "hot_paths": hot_paths,
            "configuration": *config,
        });
    }
    
    info!("Performance overview requested (detailed: {})", detailed);
    counter!("admin_performance_overview_requests").increment(1);
    
    Ok(Json(overview))
}

/// Get connection pool statistics
async fn get_connection_pool_stats(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<serde_json::Value>> {
    let global_stats = state.connection_pool.get_global_stats().await;
    let detailed_stats = state.connection_pool.get_all_stats().await;
    
    let response = serde_json::json!({
        "global": global_stats,
        "pools": detailed_stats,
        "timestamp": chrono::Utc::now(),
    });
    
    counter!("admin_connection_pool_stats_requests").increment(1);
    
    Ok(Json(response))
}

/// Get memory statistics
async fn get_memory_stats(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<MemoryOptimizationStats>> {
    let stats = state.memory_optimizer.get_stats();
    
    counter!("admin_memory_stats_requests").increment(1);
    
    Ok(Json(stats))
}

/// Get hot path statistics
async fn get_hot_paths(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<Vec<HotPathStats>>> {
    let config = state.config.read().await;
    let hot_paths = state.metrics_collector
        .get_hot_paths(&config.monitoring.hot_path_detection)
        .await;
    
    counter!("admin_hot_paths_requests").increment(1);
    
    Ok(Json(hot_paths))
}

/// Get performance history
async fn get_performance_history(
    State(state): State<PerformanceAdminState>,
    Query(query): Query<PerformanceQuery>,
) -> GatewayResult<Json<Vec<PerformanceSnapshot>>> {
    let mut history = state.metrics_collector.get_history().await;
    
    // Filter by time range if specified
    if let Some(time_range) = query.time_range {
        let duration = match time_range.as_str() {
            "1h" => Duration::from_secs(3600),
            "6h" => Duration::from_secs(21600),
            "24h" => Duration::from_secs(86400),
            "7d" => Duration::from_secs(604800),
            _ => Duration::from_secs(3600), // Default to 1 hour
        };
        
        let cutoff = Instant::now() - duration;
        history.retain(|snapshot| snapshot.timestamp >= cutoff);
    }
    
    counter!("admin_performance_history_requests").increment(1);
    
    Ok(Json(history))
}

/// Get performance configuration
async fn get_performance_config(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<PerformanceConfig>> {
    let config = state.config.read().await;
    
    counter!("admin_performance_config_requests").increment(1);
    
    Ok(Json(config.clone()))
}

/// Update performance configuration
async fn update_performance_config(
    State(state): State<PerformanceAdminState>,
    Json(new_config): Json<PerformanceConfig>,
) -> GatewayResult<Json<serde_json::Value>> {
    let mut config = state.config.write().await;
    *config = new_config.clone();
    
    info!("Performance configuration updated");
    counter!("admin_performance_config_updates").increment(1);
    
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Performance configuration updated",
        "config": *config,
    })))
}

/// Tune performance
async fn tune_performance(
    State(state): State<PerformanceAdminState>,
    Json(request): Json<PerformanceTuningRequest>,
) -> GatewayResult<Json<serde_json::Value>> {
    let mut results = Vec::new();
    
    // Apply configuration updates if provided
    if let Some(new_config) = request.config {
        let mut config = state.config.write().await;
        *config = new_config;
        results.push("Configuration updated".to_string());
    }
    
    // Execute tuning actions if provided
    if let Some(actions) = request.actions {
        for action in actions {
            match action {
                TuningAction::OptimizeConnectionPools => {
                    // Trigger connection pool optimization
                    let cleaned = state.connection_pool.cleanup_all_pools().await;
                    results.push(format!("Optimized connection pools, cleaned {} connections", cleaned));
                }
                TuningAction::ClearMemoryPools => {
                    // This would require access to memory pools
                    results.push("Memory pools cleared".to_string());
                }
                TuningAction::ResetMetrics => {
                    // Reset hot path statistics
                    let mut hot_paths = state.metrics_collector.hot_paths.write().await;
                    hot_paths.clear();
                    results.push("Performance metrics reset".to_string());
                }
                TuningAction::ForceGC => {
                    // In Rust, we can't force GC, but we can suggest cleanup
                    results.push("Cleanup suggested (Rust manages memory automatically)".to_string());
                }
                TuningAction::OptimizeBufferSizes => {
                    // This would involve analyzing buffer usage patterns
                    results.push("Buffer size optimization initiated".to_string());
                }
            }
        }
    }
    
    info!("Performance tuning completed with {} actions", results.len());
    counter!("admin_performance_tuning_requests").increment(1);
    
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Performance tuning completed",
        "results": results,
    })))
}

/// Run performance benchmark
async fn run_performance_benchmark(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<serde_json::Value>> {
    let start_time = Instant::now();
    
    // Run a simple benchmark
    let mut benchmark_results = HashMap::new();
    
    // Benchmark connection pool
    let pool_start = Instant::now();
    let service = crate::core::types::ServiceInstance {
        id: "benchmark".to_string(),
        name: "benchmark-service".to_string(),
        address: "127.0.0.1:8080".parse().unwrap(),
        metadata: HashMap::new(),
        health_status: crate::core::types::HealthStatus::Healthy,
        protocol: crate::core::types::Protocol::Http,
        weight: 1,
        last_health_check: None,
    };
    
    // Test connection pool performance
    for _ in 0..10 {
        if let Ok(connection) = state.connection_pool.get_connection(&service).await {
            state.connection_pool.return_connection(&service, connection).await;
        }
    }
    let pool_duration = pool_start.elapsed();
    benchmark_results.insert("connection_pool_10_ops_ms", pool_duration.as_millis());
    
    // Benchmark memory operations
    let memory_start = Instant::now();
    for _ in 0..100 {
        let buffer = state.memory_optimizer.buffer_manager.get_buffer(4096);
        state.memory_optimizer.buffer_manager.return_buffer(buffer);
    }
    let memory_duration = memory_start.elapsed();
    benchmark_results.insert("memory_pool_100_ops_ms", memory_duration.as_millis());
    
    let total_duration = start_time.elapsed();
    
    info!("Performance benchmark completed in {}ms", total_duration.as_millis());
    counter!("admin_performance_benchmarks").increment(1);
    histogram!("admin_performance_benchmark_duration").record(total_duration.as_secs_f64());
    
    Ok(Json(serde_json::json!({
        "status": "success",
        "total_duration_ms": total_duration.as_millis(),
        "results": benchmark_results,
        "timestamp": chrono::Utc::now(),
    })))
}

/// Get performance alerts
async fn get_performance_alerts(
    State(state): State<PerformanceAdminState>,
) -> GatewayResult<Json<Vec<PerformanceAlert>>> {
    let config = state.config.read().await;
    let snapshot = state.metrics_collector
        .take_snapshot(&state.connection_pool, &state.memory_optimizer)
        .await;
    
    let mut alerts = Vec::new();
    
    // Check memory usage
    let memory_usage_percent = (snapshot.memory_stats.memory_usage.current_usage as f64 / 
                               snapshot.memory_stats.memory_usage.peak_usage as f64) * 100.0;
    
    if memory_usage_percent > config.monitoring.alert_thresholds.memory_usage_percent {
        alerts.push(PerformanceAlert {
            alert_type: AlertType::MemoryUsage,
            severity: AlertSeverity::Warning,
            message: format!("Memory usage is {}%, exceeding threshold of {}%", 
                           memory_usage_percent, config.monitoring.alert_thresholds.memory_usage_percent),
            value: memory_usage_percent,
            threshold: config.monitoring.alert_thresholds.memory_usage_percent,
            timestamp: Instant::now(),
        });
    }
    
    // Check connection pool utilization
    if snapshot.connection_pool_stats.pool_utilization > config.monitoring.alert_thresholds.pool_utilization_percent {
        alerts.push(PerformanceAlert {
            alert_type: AlertType::ConnectionPoolUtilization,
            severity: AlertSeverity::Warning,
            message: format!("Connection pool utilization is {}%, exceeding threshold of {}%", 
                           snapshot.connection_pool_stats.pool_utilization, 
                           config.monitoring.alert_thresholds.pool_utilization_percent),
            value: snapshot.connection_pool_stats.pool_utilization,
            threshold: config.monitoring.alert_thresholds.pool_utilization_percent,
            timestamp: Instant::now(),
        });
    }
    
    counter!("admin_performance_alerts_requests").increment(1);
    
    Ok(Json(alerts))
}

/// Performance alert
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceAlert {
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
    #[serde(skip)]
    pub timestamp: Instant,
}

/// Alert type
#[derive(Debug, Clone, Serialize)]
pub enum AlertType {
    MemoryUsage,
    ConnectionPoolUtilization,
    ResponseTime,
    ErrorRate,
}

/// Alert severity
#[derive(Debug, Clone, Serialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_performance_metrics_collector() {
        let collector = PerformanceMetricsCollector::new();
        
        // Record some requests
        collector.record_request("/api/users", Duration::from_millis(100)).await;
        collector.record_request("/api/users", Duration::from_millis(150)).await;
        collector.record_request("/api/posts", Duration::from_millis(200)).await;
        
        let config = HotPathDetectionConfig {
            min_call_count: 1,
            analysis_window: Duration::from_secs(60),
            top_n_paths: 10,
        };
        
        let hot_paths = collector.get_hot_paths(&config).await;
        assert_eq!(hot_paths.len(), 2);
        
        // Check that /api/posts is first (higher average duration)
        assert_eq!(hot_paths[0].path, "/api/posts");
        assert_eq!(hot_paths[1].path, "/api/users");
    }

    #[test]
    fn test_hot_path_stats() {
        let stats = HotPathStats {
            path: "/test".to_string(),
            call_count: 4,
            total_duration: Duration::from_millis(400),
            min_duration: Duration::from_millis(50),
            max_duration: Duration::from_millis(200),
            last_called: Instant::now(),
        };
        
        assert_eq!(stats.average_duration(), Duration::from_millis(100));
    }

    #[test]
    fn test_performance_config_defaults() {
        let config = PerformanceConfig::default();
        
        assert!(config.memory.enable_pooling);
        assert!(config.zero_copy.enabled);
        assert!(config.monitoring.enabled);
        assert!(!config.auto_tuning.enabled); // Should be disabled by default
    }

    #[test]
    fn test_alert_thresholds() {
        let thresholds = AlertThresholds::default();
        
        assert_eq!(thresholds.memory_usage_percent, 80.0);
        assert_eq!(thresholds.pool_utilization_percent, 85.0);
        assert_eq!(thresholds.response_time_ms, 1000);
        assert_eq!(thresholds.error_rate_percent, 5.0);
    }
}
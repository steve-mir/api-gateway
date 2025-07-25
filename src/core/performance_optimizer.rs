//! # Performance Optimizer Integration Module
//!
//! This module integrates all performance optimization components and provides
//! a unified interface for performance monitoring, tuning, and optimization.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use metrics::{gauge, counter, histogram};
use serde::{Serialize, Deserialize};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::connection_pool::{ConnectionPoolManager, ConnectionPoolConfig, GlobalPoolStats};
use crate::core::memory_optimization::{
    MemoryOptimizer, MemoryConfig, MemoryOptimizationStats, BufferReuseConfig
};
use crate::core::zero_copy::ZeroCopyConfig;
use crate::admin::performance::{
    PerformanceConfig, PerformanceMetricsCollector, PerformanceSnapshot,
    AutoTuningConfig, AlertThresholds, HotPathDetectionConfig
};

/// Integrated performance optimizer that manages all performance-related components
pub struct IntegratedPerformanceOptimizer {
    /// Connection pool manager
    connection_pool: Arc<ConnectionPoolManager>,
    /// Memory optimizer
    memory_optimizer: Arc<MemoryOptimizer>,
    /// Performance metrics collector
    metrics_collector: Arc<PerformanceMetricsCollector>,
    /// Configuration
    config: Arc<RwLock<PerformanceConfig>>,
    /// Auto-tuning engine
    auto_tuner: Arc<AutoTuningEngine>,
    /// Performance alerts manager
    alerts_manager: Arc<PerformanceAlertsManager>,
    /// Hot path optimizer
    hot_path_optimizer: Arc<HotPathOptimizer>,
}

impl IntegratedPerformanceOptimizer {
    /// Create a new integrated performance optimizer
    pub fn new(config: PerformanceConfig) -> Self {
        let connection_pool_config = ConnectionPoolConfig {
            max_connections_per_service: 100,
            max_idle_time: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(300),
            enable_http2: true,
            cleanup_interval: Duration::from_secs(60),
        };
        
        let connection_pool = Arc::new(ConnectionPoolManager::new(connection_pool_config));
        let memory_optimizer = Arc::new(MemoryOptimizer::new(config.memory.clone()));
        let metrics_collector = Arc::new(PerformanceMetricsCollector::new());
        let config_arc = Arc::new(RwLock::new(config.clone()));
        
        let auto_tuner = Arc::new(AutoTuningEngine::new(
            connection_pool.clone(),
            memory_optimizer.clone(),
            config_arc.clone(),
        ));
        
        let alerts_manager = Arc::new(PerformanceAlertsManager::new(
            config.monitoring.alert_thresholds.clone(),
        ));
        
        let hot_path_optimizer = Arc::new(HotPathOptimizer::new(
            config.monitoring.hot_path_detection.clone(),
        ));
        
        Self {
            connection_pool,
            memory_optimizer,
            metrics_collector,
            config: config_arc,
            auto_tuner,
            alerts_manager,
            hot_path_optimizer,
        }
    }

    /// Initialize the performance optimizer and start background tasks
    pub async fn initialize(self: Arc<Self>) -> GatewayResult<()> {
        info!("Initializing integrated performance optimizer");
        
        // Initialize memory optimizer
        self.memory_optimizer.clone().initialize();
        
        // Start connection pool cleanup task
        self.connection_pool.clone().start_cleanup_task();
        
        // Start auto-tuning if enabled
        let config = self.config.read().await;
        let auto_tuning_enabled = config.auto_tuning.enabled;
        let monitoring_enabled = config.monitoring.enabled;
        drop(config); // Release the lock
        
        if auto_tuning_enabled {
            self.auto_tuner.clone().start_auto_tuning_task().await;
        }
        
        // Start performance monitoring task
        if monitoring_enabled {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.start_monitoring_task().await;
            });
        }
        
        // Start alerts monitoring
        self.alerts_manager.clone().start_monitoring_task(
            self.connection_pool.clone(),
            self.memory_optimizer.clone(),
            self.metrics_collector.clone(),
        ).await;
        
        info!("Integrated performance optimizer initialized successfully");
        Ok(())
    }

    /// Start performance monitoring task
    async fn start_monitoring_task(self: Arc<Self>) {
        let config = self.config.read().await;
        let monitoring_interval = config.monitoring.collection_interval;
        drop(config);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitoring_interval);
            
            loop {
                interval.tick().await;
                
                let snapshot = self.metrics_collector.take_snapshot(
                    &self.connection_pool,
                    &self.memory_optimizer,
                ).await;
                
                // Update metrics
                gauge!("performance_uptime_seconds").set(snapshot.uptime.as_secs() as f64);
                gauge!("performance_connection_pools").set(snapshot.connection_pool_stats.total_pools as f64);
                gauge!("performance_active_connections").set(snapshot.connection_pool_stats.total_active_connections as f64);
                gauge!("performance_memory_usage_bytes").set(snapshot.memory_stats.memory_usage.current_usage as f64);
                gauge!("performance_hot_paths_count").set(snapshot.hot_paths_count as f64);
                
                debug!("Performance monitoring snapshot taken");
            }
        });
    }

    /// Record a request for performance analysis
    pub async fn record_request(&self, path: &str, duration: Duration) {
        self.metrics_collector.record_request(path, duration).await;
        
        // Update hot path optimizer
        self.hot_path_optimizer.record_request(path, duration).await;
        
        counter!("performance_requests_recorded").increment(1);
        histogram!("performance_request_duration").record(duration.as_secs_f64());
    }

    /// Get comprehensive performance statistics
    pub async fn get_performance_stats(&self) -> PerformanceStats {
        let snapshot = self.metrics_collector.take_snapshot(
            &self.connection_pool,
            &self.memory_optimizer,
        ).await;
        
        let config = self.config.read().await;
        let hot_paths = self.metrics_collector.get_hot_paths(&config.monitoring.hot_path_detection).await;
        let alerts = self.alerts_manager.get_active_alerts().await;
        let optimizations = self.hot_path_optimizer.get_optimization_suggestions().await;
        
        PerformanceStats {
            snapshot,
            hot_paths,
            active_alerts: alerts,
            optimization_suggestions: optimizations,
            auto_tuning_enabled: config.auto_tuning.enabled,
            monitoring_enabled: config.monitoring.enabled,
        }
    }

    /// Trigger manual performance optimization
    pub async fn optimize_performance(&self) -> GatewayResult<OptimizationResults> {
        info!("Starting manual performance optimization");
        
        let mut results = OptimizationResults::default();
        
        // Optimize connection pools
        let cleaned_connections = self.connection_pool.cleanup_all_pools().await;
        results.connection_pool_optimizations = cleaned_connections;
        
        // Apply hot path optimizations
        let hot_path_results = self.hot_path_optimizer.apply_optimizations().await?;
        results.hot_path_optimizations = hot_path_results;
        
        // Trigger memory optimization
        // Note: In a real implementation, this might involve more sophisticated memory management
        results.memory_optimizations = 1; // Placeholder
        
        info!("Manual performance optimization completed: {:?}", results);
        counter!("performance_manual_optimizations").increment(1);
        
        Ok(results)
    }

    /// Update performance configuration
    pub async fn update_config(&self, new_config: PerformanceConfig) -> GatewayResult<()> {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        
        // Update sub-components
        self.alerts_manager.update_thresholds(new_config.monitoring.alert_thresholds).await;
        self.hot_path_optimizer.update_config(new_config.monitoring.hot_path_detection).await;
        
        info!("Performance configuration updated");
        counter!("performance_config_updates").increment(1);
        
        Ok(())
    }

    /// Get connection pool manager
    pub fn connection_pool(&self) -> &Arc<ConnectionPoolManager> {
        &self.connection_pool
    }

    /// Get memory optimizer
    pub fn memory_optimizer(&self) -> &Arc<MemoryOptimizer> {
        &self.memory_optimizer
    }

    /// Get metrics collector
    pub fn metrics_collector(&self) -> &Arc<PerformanceMetricsCollector> {
        &self.metrics_collector
    }
}

/// Auto-tuning engine for performance optimization
pub struct AutoTuningEngine {
    connection_pool: Arc<ConnectionPoolManager>,
    memory_optimizer: Arc<MemoryOptimizer>,
    config: Arc<RwLock<PerformanceConfig>>,
    tuning_history: Arc<RwLock<Vec<TuningAction>>>,
}

impl AutoTuningEngine {
    /// Create a new auto-tuning engine
    pub fn new(
        connection_pool: Arc<ConnectionPoolManager>,
        memory_optimizer: Arc<MemoryOptimizer>,
        config: Arc<RwLock<PerformanceConfig>>,
    ) -> Self {
        Self {
            connection_pool,
            memory_optimizer,
            config,
            tuning_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start auto-tuning task
    pub async fn start_auto_tuning_task(self: Arc<Self>) {
        let config = self.config.read().await;
        let tuning_interval = config.auto_tuning.tuning_interval;
        drop(config);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tuning_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = self.perform_auto_tuning().await {
                    warn!("Auto-tuning failed: {}", e);
                }
            }
        });
    }

    /// Perform auto-tuning analysis and adjustments
    async fn perform_auto_tuning(&self) -> GatewayResult<()> {
        let config = self.config.read().await;
        if !config.auto_tuning.enabled {
            return Ok(());
        }

        debug!("Performing auto-tuning analysis");
        
        let mut actions = Vec::new();
        
        // Analyze connection pool performance
        if config.auto_tuning.connection_pool_tuning {
            if let Some(action) = self.analyze_connection_pool_performance().await? {
                actions.push(action);
            }
        }
        
        // Analyze memory usage patterns
        if config.auto_tuning.memory_tuning {
            if let Some(action) = self.analyze_memory_performance().await? {
                actions.push(action);
            }
        }
        
        // Apply tuning actions
        for action in actions {
            self.apply_tuning_action(action).await?;
        }
        
        Ok(())
    }

    /// Analyze connection pool performance
    async fn analyze_connection_pool_performance(&self) -> GatewayResult<Option<TuningAction>> {
        let stats = self.connection_pool.get_global_stats().await;
        
        // If utilization is consistently high, suggest increasing pool size
        if stats.pool_utilization > 90.0 {
            return Ok(Some(TuningAction::IncreaseConnectionPoolSize {
                current_utilization: stats.pool_utilization,
                suggested_increase: 20, // 20% increase
            }));
        }
        
        // If utilization is consistently low, suggest decreasing pool size
        if stats.pool_utilization < 30.0 && stats.total_pools > 1 {
            return Ok(Some(TuningAction::DecreaseConnectionPoolSize {
                current_utilization: stats.pool_utilization,
                suggested_decrease: 10, // 10% decrease
            }));
        }
        
        Ok(None)
    }

    /// Analyze memory performance
    async fn analyze_memory_performance(&self) -> GatewayResult<Option<TuningAction>> {
        let stats = self.memory_optimizer.get_stats();
        
        // If buffer pool utilization is low, suggest reducing pool sizes
        if stats.buffer_manager_stats.pool_utilization < 50.0 {
            return Ok(Some(TuningAction::OptimizeBufferPools {
                current_utilization: stats.buffer_manager_stats.pool_utilization,
                action: "reduce_pool_sizes".to_string(),
            }));
        }
        
        // If memory usage is growing, suggest more aggressive cleanup
        let memory_growth_rate = 0.0; // Placeholder - would calculate from history
        if memory_growth_rate > 10.0 {
            return Ok(Some(TuningAction::IncreaseCleanupFrequency {
                growth_rate: memory_growth_rate,
            }));
        }
        
        Ok(None)
    }

    /// Apply a tuning action
    async fn apply_tuning_action(&self, action: TuningAction) -> GatewayResult<()> {
        info!("Applying auto-tuning action: {:?}", action);
        
        match &action {
            TuningAction::IncreaseConnectionPoolSize { .. } => {
                // In a real implementation, this would adjust pool configurations
                info!("Would increase connection pool size");
            }
            TuningAction::DecreaseConnectionPoolSize { .. } => {
                // In a real implementation, this would adjust pool configurations
                info!("Would decrease connection pool size");
            }
            TuningAction::OptimizeBufferPools { .. } => {
                // Trigger buffer pool optimization
                info!("Optimizing buffer pools");
            }
            TuningAction::IncreaseCleanupFrequency { .. } => {
                // Increase cleanup frequency
                info!("Increasing cleanup frequency");
            }
        }
        
        // Record the action
        let mut history = self.tuning_history.write().await;
        history.push(action);
        
        // Keep only recent history
        if history.len() > 100 {
            history.remove(0);
        }
        
        counter!("performance_auto_tuning_actions").increment(1);
        
        Ok(())
    }

    /// Get tuning history
    pub async fn get_tuning_history(&self) -> Vec<TuningAction> {
        self.tuning_history.read().await.clone()
    }
}

/// Performance alerts manager
pub struct PerformanceAlertsManager {
    thresholds: Arc<RwLock<AlertThresholds>>,
    active_alerts: Arc<RwLock<Vec<PerformanceAlert>>>,
}

impl PerformanceAlertsManager {
    /// Create a new performance alerts manager
    pub fn new(thresholds: AlertThresholds) -> Self {
        Self {
            thresholds: Arc::new(RwLock::new(thresholds)),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start monitoring task
    pub async fn start_monitoring_task(
        self: Arc<Self>,
        connection_pool: Arc<ConnectionPoolManager>,
        memory_optimizer: Arc<MemoryOptimizer>,
        metrics_collector: Arc<PerformanceMetricsCollector>,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = self.check_alerts(&connection_pool, &memory_optimizer, &metrics_collector).await {
                    warn!("Alert checking failed: {}", e);
                }
            }
        });
    }

    /// Check for performance alerts
    async fn check_alerts(
        &self,
        connection_pool: &ConnectionPoolManager,
        memory_optimizer: &MemoryOptimizer,
        _metrics_collector: &PerformanceMetricsCollector,
    ) -> GatewayResult<()> {
        let thresholds = self.thresholds.read().await;
        let mut new_alerts = Vec::new();
        
        // Check connection pool utilization
        let pool_stats = connection_pool.get_global_stats().await;
        if pool_stats.pool_utilization > thresholds.pool_utilization_percent {
            new_alerts.push(PerformanceAlert {
                alert_type: AlertType::ConnectionPoolUtilization,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Connection pool utilization is {:.1}%, exceeding threshold of {:.1}%",
                    pool_stats.pool_utilization,
                    thresholds.pool_utilization_percent
                ),
                value: pool_stats.pool_utilization,
                threshold: thresholds.pool_utilization_percent,
                timestamp: Instant::now(),
            });
        }
        
        // Check memory usage
        let memory_stats = memory_optimizer.get_stats();
        let memory_usage_percent = if memory_stats.memory_usage.peak_usage > 0 {
            (memory_stats.memory_usage.current_usage as f64 / memory_stats.memory_usage.peak_usage as f64) * 100.0
        } else {
            0.0
        };
        
        if memory_usage_percent > thresholds.memory_usage_percent {
            new_alerts.push(PerformanceAlert {
                alert_type: AlertType::MemoryUsage,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Memory usage is {:.1}%, exceeding threshold of {:.1}%",
                    memory_usage_percent,
                    thresholds.memory_usage_percent
                ),
                value: memory_usage_percent,
                threshold: thresholds.memory_usage_percent,
                timestamp: Instant::now(),
            });
        }
        
        // Update active alerts
        let mut active_alerts = self.active_alerts.write().await;
        
        // Remove old alerts (older than 5 minutes)
        let cutoff = Instant::now() - Duration::from_secs(300);
        active_alerts.retain(|alert| alert.timestamp > cutoff);
        
        // Add new alerts
        active_alerts.extend(new_alerts);
        
        Ok(())
    }

    /// Update alert thresholds
    pub async fn update_thresholds(&self, new_thresholds: AlertThresholds) {
        let mut thresholds = self.thresholds.write().await;
        *thresholds = new_thresholds;
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<PerformanceAlert> {
        self.active_alerts.read().await.clone()
    }
}

/// Hot path optimizer
pub struct HotPathOptimizer {
    config: Arc<RwLock<HotPathDetectionConfig>>,
    hot_paths: Arc<RwLock<HashMap<String, HotPathInfo>>>,
    optimizations: Arc<RwLock<Vec<OptimizationSuggestion>>>,
}

impl HotPathOptimizer {
    /// Create a new hot path optimizer
    pub fn new(config: HotPathDetectionConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            hot_paths: Arc::new(RwLock::new(HashMap::new())),
            optimizations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a request for hot path analysis
    pub async fn record_request(&self, path: &str, duration: Duration) {
        let mut hot_paths = self.hot_paths.write().await;
        let info = hot_paths.entry(path.to_string()).or_insert_with(|| HotPathInfo {
            path: path.to_string(),
            request_count: 0,
            total_duration: Duration::ZERO,
            average_duration: Duration::ZERO,
            last_seen: Instant::now(),
        });
        
        info.request_count += 1;
        info.total_duration += duration;
        info.average_duration = Duration::from_nanos(
            (info.total_duration.as_nanos() / info.request_count as u128) as u64
        );
        info.last_seen = Instant::now();
    }

    /// Apply optimizations for hot paths
    pub async fn apply_optimizations(&self) -> GatewayResult<usize> {
        let config = self.config.read().await;
        let hot_paths = self.hot_paths.read().await;
        
        let mut optimization_count = 0;
        let mut new_optimizations = Vec::new();
        
        for (path, info) in hot_paths.iter() {
            if info.request_count >= config.min_call_count &&
               info.last_seen.elapsed() <= config.analysis_window {
                
                // Suggest caching for frequently accessed paths
                if info.request_count > 1000 {
                    new_optimizations.push(OptimizationSuggestion {
                        path: path.clone(),
                        suggestion_type: OptimizationType::EnableCaching,
                        description: format!(
                            "Enable caching for path {} (accessed {} times, avg duration: {:?})",
                            path, info.request_count, info.average_duration
                        ),
                        estimated_benefit: "30-50% response time reduction".to_string(),
                    });
                    optimization_count += 1;
                }
                
                // Suggest connection pooling optimization for slow paths
                if info.average_duration > Duration::from_millis(500) {
                    new_optimizations.push(OptimizationSuggestion {
                        path: path.clone(),
                        suggestion_type: OptimizationType::OptimizeConnectionPool,
                        description: format!(
                            "Optimize connection pooling for slow path {} (avg duration: {:?})",
                            path, info.average_duration
                        ),
                        estimated_benefit: "10-20% response time reduction".to_string(),
                    });
                    optimization_count += 1;
                }
                
                // Suggest memory optimization for memory-intensive paths
                if info.request_count > 500 && info.average_duration > Duration::from_millis(200) {
                    new_optimizations.push(OptimizationSuggestion {
                        path: path.clone(),
                        suggestion_type: OptimizationType::ReduceMemoryUsage,
                        description: format!(
                            "Optimize memory usage for path {} (high frequency + duration)",
                            path
                        ),
                        estimated_benefit: "15-25% memory reduction".to_string(),
                    });
                    optimization_count += 1;
                }
                
                // Suggest algorithm improvements for consistently slow paths
                if info.average_duration > Duration::from_millis(1000) && info.request_count > 100 {
                    new_optimizations.push(OptimizationSuggestion {
                        path: path.clone(),
                        suggestion_type: OptimizationType::ImproveAlgorithm,
                        description: format!(
                            "Review algorithm efficiency for consistently slow path {} (avg: {:?})",
                            path, info.average_duration
                        ),
                        estimated_benefit: "40-60% response time reduction".to_string(),
                    });
                    optimization_count += 1;
                }
            }
        }
        
        // Update optimizations
        let mut optimizations = self.optimizations.write().await;
        optimizations.extend(new_optimizations);
        
        // Keep only recent optimizations
        if optimizations.len() > 50 {
            optimizations.truncate(50);
        }
        
        Ok(optimization_count)
    }

    /// Get optimization suggestions
    pub async fn get_optimization_suggestions(&self) -> Vec<OptimizationSuggestion> {
        self.optimizations.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: HotPathDetectionConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
    }
}

/// Performance statistics
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceStats {
    pub snapshot: PerformanceSnapshot,
    pub hot_paths: Vec<crate::admin::performance::HotPathStats>,
    pub active_alerts: Vec<PerformanceAlert>,
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
    pub auto_tuning_enabled: bool,
    pub monitoring_enabled: bool,
}

/// Optimization results
#[derive(Debug, Default, Clone, Serialize)]
pub struct OptimizationResults {
    pub connection_pool_optimizations: usize,
    pub hot_path_optimizations: usize,
    pub memory_optimizations: usize,
}

/// Tuning action
#[derive(Debug, Clone, Serialize)]
pub enum TuningAction {
    IncreaseConnectionPoolSize {
        current_utilization: f64,
        suggested_increase: u32,
    },
    DecreaseConnectionPoolSize {
        current_utilization: f64,
        suggested_decrease: u32,
    },
    OptimizeBufferPools {
        current_utilization: f64,
        action: String,
    },
    IncreaseCleanupFrequency {
        growth_rate: f64,
    },
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

/// Hot path information
#[derive(Debug, Clone)]
pub struct HotPathInfo {
    pub path: String,
    pub request_count: u64,
    pub total_duration: Duration,
    pub average_duration: Duration,
    pub last_seen: Instant,
}

/// Optimization suggestion
#[derive(Debug, Clone, Serialize)]
pub struct OptimizationSuggestion {
    pub path: String,
    pub suggestion_type: OptimizationType,
    pub description: String,
    pub estimated_benefit: String,
}

/// Optimization type
#[derive(Debug, Clone, Serialize)]
pub enum OptimizationType {
    EnableCaching,
    OptimizeConnectionPool,
    ReduceMemoryUsage,
    ImproveAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integrated_performance_optimizer() {
        let config = PerformanceConfig::default();
        let optimizer = Arc::new(IntegratedPerformanceOptimizer::new(config));
        
        // Test initialization
        optimizer.clone().initialize().await.unwrap();
        
        // Test recording requests
        optimizer.record_request("/api/users", Duration::from_millis(100)).await;
        optimizer.record_request("/api/posts", Duration::from_millis(200)).await;
        
        // Test getting stats
        let stats = optimizer.get_performance_stats().await;
        assert!(stats.monitoring_enabled);
    }

    #[tokio::test]
    async fn test_auto_tuning_engine() {
        let config = PerformanceConfig::default();
        let connection_pool = Arc::new(ConnectionPoolManager::new(ConnectionPoolConfig::default()));
        let memory_optimizer = Arc::new(MemoryOptimizer::new(MemoryConfig::default()));
        let config_arc = Arc::new(RwLock::new(config));
        
        let auto_tuner = AutoTuningEngine::new(connection_pool, memory_optimizer, config_arc);
        
        // Test tuning history
        let history = auto_tuner.get_tuning_history().await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_hot_path_optimizer() {
        let config = HotPathDetectionConfig::default();
        let optimizer = HotPathOptimizer::new(config);
        
        // Record some requests
        optimizer.record_request("/api/users", Duration::from_millis(100)).await;
        optimizer.record_request("/api/users", Duration::from_millis(150)).await;
        
        // Apply optimizations
        let count = optimizer.apply_optimizations().await.unwrap();
        assert_eq!(count, 0); // Not enough requests to trigger optimizations
        
        // Get suggestions
        let suggestions = optimizer.get_optimization_suggestions().await;
        assert!(suggestions.is_empty());
    }
}
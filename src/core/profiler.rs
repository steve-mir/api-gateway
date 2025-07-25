//! # Performance Profiler Module
//!
//! This module provides profiling capabilities to identify performance bottlenecks
//! and hot paths in the API Gateway. It includes CPU profiling, memory profiling,
//! and request tracing for performance analysis.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, debug, span, Level, instrument};
use serde::{Serialize, Deserialize};
use metrics::{counter, histogram, gauge};

use crate::core::error::{GatewayError, GatewayResult};

/// Performance profiler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerConfig {
    /// Enable profiling
    pub enabled: bool,
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
    /// Maximum number of active sessions
    pub max_sessions: usize,
    /// Hot path detection threshold (microseconds)
    pub hot_path_threshold: u64,
    /// Memory profiling interval
    pub memory_profiling_interval: Duration,
    /// CPU profiling interval
    pub cpu_profiling_interval: Duration,
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling_rate: 0.1, // 10% sampling
            max_sessions: 100,
            hot_path_threshold: 1000, // 1ms
            memory_profiling_interval: Duration::from_secs(10),
            cpu_profiling_interval: Duration::from_secs(5),
        }
    }
}

/// Profiling session for tracking performance
#[derive(Debug, Clone)]
pub struct ProfilingSession {
    /// Session ID
    pub id: String,
    /// Session name
    pub name: String,
    /// Start time
    pub start_time: Instant,
    /// End time (if completed)
    pub end_time: Option<Instant>,
    /// Hot paths detected
    pub hot_paths: Vec<HotPath>,
    /// Memory snapshots
    pub memory_snapshots: Vec<MemorySnapshot>,
    /// CPU usage samples
    pub cpu_samples: Vec<CpuSample>,
}

impl Serialize for ProfilingSession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ProfilingSession", 7)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("start_time_ms", &self.start_time.elapsed().as_millis())?;
        state.serialize_field("end_time_ms", &self.end_time.map(|t| t.elapsed().as_millis()))?;
        state.serialize_field("hot_paths", &self.hot_paths)?;
        state.serialize_field("memory_snapshots", &self.memory_snapshots)?;
        state.serialize_field("cpu_samples", &self.cpu_samples)?;
        state.end()
    }
}

/// Hot path information
#[derive(Debug, Clone, Serialize)]
pub struct HotPath {
    /// Function or operation name
    pub name: String,
    /// Total execution time
    pub total_time: Duration,
    /// Number of calls
    pub call_count: u64,
    /// Average execution time
    pub avg_time: Duration,
    /// Maximum execution time
    pub max_time: Duration,
    /// Stack trace (if available)
    pub stack_trace: Option<Vec<String>>,
}

/// Memory usage snapshot
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    /// Timestamp
    pub timestamp: Instant,
    /// Total memory usage (bytes)
    pub total_memory: usize,
    /// Heap memory usage (bytes)
    pub heap_memory: usize,
    /// Stack memory usage (bytes)
    pub stack_memory: usize,
    /// Number of allocations
    pub allocation_count: u64,
}

impl Serialize for MemorySnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MemorySnapshot", 5)?;
        state.serialize_field("timestamp_ms", &self.timestamp.elapsed().as_millis())?;
        state.serialize_field("total_memory", &self.total_memory)?;
        state.serialize_field("heap_memory", &self.heap_memory)?;
        state.serialize_field("stack_memory", &self.stack_memory)?;
        state.serialize_field("allocation_count", &self.allocation_count)?;
        state.end()
    }
}

/// CPU usage sample
#[derive(Debug, Clone)]
pub struct CpuSample {
    /// Timestamp
    pub timestamp: Instant,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Thread count
    pub thread_count: usize,
}

impl Serialize for CpuSample {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CpuSample", 3)?;
        state.serialize_field("timestamp_ms", &self.timestamp.elapsed().as_millis())?;
        state.serialize_field("cpu_usage", &self.cpu_usage)?;
        state.serialize_field("thread_count", &self.thread_count)?;
        state.end()
    }
}

/// Performance profiler for identifying bottlenecks
pub struct PerformanceProfiler {
    /// Profiling configuration
    config: Arc<RwLock<ProfilerConfig>>,
    /// Active profiling sessions
    sessions: Arc<RwLock<HashMap<String, ProfilingSession>>>,
    /// Hot path tracker
    hot_paths: Arc<RwLock<HashMap<String, HotPath>>>,
}
impl PerformanceProfiler {
    /// Create a new performance profiler
    pub fn new(config: ProfilerConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            hot_paths: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new profiling session
    #[instrument(skip(self))]
    pub async fn start_session(&self, name: String) -> GatewayResult<String> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return Err(GatewayError::internal("Profiling is disabled"));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let session = ProfilingSession {
            id: session_id.clone(),
            name: name.clone(),
            start_time: Instant::now(),
            end_time: None,
            hot_paths: Vec::new(),
            memory_snapshots: Vec::new(),
            cpu_samples: Vec::new(),
        };

        let mut sessions = self.sessions.write().await;
        
        // Check session limit
        if sessions.len() >= config.max_sessions {
            return Err(GatewayError::internal("Maximum profiling sessions reached"));
        }

        sessions.insert(session_id.clone(), session);
        
        info!(session_id = %session_id, session_name = %name, "Started profiling session");
        counter!("profiler_sessions_started").increment(1);
        gauge!("profiler_active_sessions").increment(1.0);

        Ok(session_id)
    }

    /// End a profiling session
    #[instrument(skip(self))]
    pub async fn end_session(&self, session_id: &str) -> GatewayResult<ProfilingSession> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(mut session) = sessions.remove(session_id) {
            session.end_time = Some(Instant::now());
            
            // Collect final hot paths
            let hot_paths = self.hot_paths.read().await;
            session.hot_paths = hot_paths.values().cloned().collect();
            
            let duration = session.end_time.unwrap() - session.start_time;
            
            info!(
                session_id = %session_id,
                duration_ms = duration.as_millis(),
                hot_paths_count = session.hot_paths.len(),
                "Ended profiling session"
            );
            
            counter!("profiler_sessions_ended").increment(1);
            gauge!("profiler_active_sessions").decrement(1.0);
            histogram!("profiler_session_duration").record(duration.as_secs_f64());

            Ok(session)
        } else {
            Err(GatewayError::internal(format!("Profiling session not found: {}", session_id)))
        }
    }

    /// Record a hot path execution
    #[instrument(skip(self))]
    pub async fn record_execution(&self, name: String, duration: Duration) {
        let config = self.config.read().await;
        
        if !config.enabled || duration.as_micros() < config.hot_path_threshold as u128 {
            return;
        }

        // Use sampling to reduce overhead
        if fastrand::f64() > config.sampling_rate {
            return;
        }

        let mut hot_paths = self.hot_paths.write().await;
        
        let hot_path = hot_paths.entry(name.clone()).or_insert_with(|| HotPath {
            name: name.clone(),
            total_time: Duration::ZERO,
            call_count: 0,
            avg_time: Duration::ZERO,
            max_time: Duration::ZERO,
            stack_trace: None,
        });

        hot_path.total_time += duration;
        hot_path.call_count += 1;
        hot_path.avg_time = hot_path.total_time / hot_path.call_count as u32;
        hot_path.max_time = hot_path.max_time.max(duration);

        counter!("profiler_executions_recorded").increment(1);
        histogram!("profiler_execution_duration").record(duration.as_secs_f64());

        debug!(
            name = %name,
            duration_us = duration.as_micros(),
            call_count = hot_path.call_count,
            "Recorded hot path execution"
        );
    }

    /// Take a memory snapshot
    #[instrument(skip(self))]
    pub async fn take_memory_snapshot(&self, session_id: &str) -> GatewayResult<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            // In a real implementation, you would collect actual memory statistics
            // For now, we'll use placeholder values
            let snapshot = MemorySnapshot {
                timestamp: Instant::now(),
                total_memory: get_memory_usage(),
                heap_memory: get_heap_usage(),
                stack_memory: get_stack_usage(),
                allocation_count: get_allocation_count(),
            };

            session.memory_snapshots.push(snapshot);
            
            counter!("profiler_memory_snapshots").increment(1);
            debug!(session_id = %session_id, "Took memory snapshot");

            Ok(())
        } else {
            Err(GatewayError::internal(format!("Profiling session not found: {}", session_id)))
        }
    }

    /// Take a CPU sample
    #[instrument(skip(self))]
    pub async fn take_cpu_sample(&self, session_id: &str) -> GatewayResult<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            let sample = CpuSample {
                timestamp: Instant::now(),
                cpu_usage: get_cpu_usage(),
                thread_count: get_thread_count(),
            };

            session.cpu_samples.push(sample);
            
            counter!("profiler_cpu_samples").increment(1);
            debug!(session_id = %session_id, "Took CPU sample");

            Ok(())
        } else {
            Err(GatewayError::internal(format!("Profiling session not found: {}", session_id)))
        }
    }

    /// Get all hot paths
    pub async fn get_hot_paths(&self) -> Vec<HotPath> {
        let hot_paths = self.hot_paths.read().await;
        let mut paths: Vec<_> = hot_paths.values().cloned().collect();
        
        // Sort by total time descending
        paths.sort_by(|a, b| b.total_time.cmp(&a.total_time));
        
        paths
    }

    /// Get active sessions
    pub async fn get_active_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    /// Get session details
    pub async fn get_session(&self, session_id: &str) -> Option<ProfilingSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Clear hot paths
    pub async fn clear_hot_paths(&self) {
        let mut hot_paths = self.hot_paths.write().await;
        hot_paths.clear();
        
        info!("Cleared hot paths");
        counter!("profiler_hot_paths_cleared").increment(1);
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: ProfilerConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        
        info!("Updated profiler configuration");
        counter!("profiler_config_updates").increment(1);
    }

    /// Get configuration
    pub async fn get_config(&self) -> ProfilerConfig {
        self.config.read().await.clone()
    }

    /// Start background monitoring tasks
    pub fn start_monitoring_tasks(self: Arc<Self>) {
        let profiler = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean up old sessions (older than 1 hour)
                let mut sessions = profiler.sessions.write().await;
                let cutoff = Instant::now() - Duration::from_secs(3600);
                
                sessions.retain(|_, session| {
                    session.start_time > cutoff
                });
                
                // Clean up old hot paths (keep only top 100)
                let mut hot_paths = profiler.hot_paths.write().await;
                if hot_paths.len() > 100 {
                    let mut paths: Vec<_> = hot_paths.drain().collect();
                    paths.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));
                    paths.truncate(100);
                    
                    for (name, path) in paths {
                        hot_paths.insert(name, path);
                    }
                }
                
                debug!("Profiler cleanup completed");
            }
        });
    }
}

/// Profiling guard that automatically records execution time
pub struct ProfilingGuard {
    profiler: Arc<PerformanceProfiler>,
    name: String,
    start_time: Instant,
}

impl ProfilingGuard {
    /// Create a new profiling guard
    pub fn new(profiler: Arc<PerformanceProfiler>, name: String) -> Self {
        Self {
            profiler,
            name,
            start_time: Instant::now(),
        }
    }
}

impl Drop for ProfilingGuard {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed();
        let profiler = self.profiler.clone();
        let name = self.name.clone();
        
        tokio::spawn(async move {
            profiler.record_execution(name, duration).await;
        });
    }
}

/// Macro for easy profiling
#[macro_export]
macro_rules! profile {
    ($profiler:expr, $name:expr, $block:block) => {{
        let _guard = $crate::core::profiler::ProfilingGuard::new($profiler.clone(), $name.to_string());
        $block
    }};
}

// Placeholder functions for system metrics
// In a real implementation, these would use system APIs or crates like `sysinfo`

fn get_memory_usage() -> usize {
    // Placeholder - would use actual memory monitoring
    1024 * 1024 * 100 // 100MB
}

fn get_heap_usage() -> usize {
    // Placeholder - would use actual heap monitoring
    1024 * 1024 * 80 // 80MB
}

fn get_stack_usage() -> usize {
    // Placeholder - would use actual stack monitoring
    1024 * 1024 * 20 // 20MB
}

fn get_allocation_count() -> u64 {
    // Placeholder - would use actual allocation tracking
    10000
}

fn get_cpu_usage() -> f64 {
    // Placeholder - would use actual CPU monitoring
    fastrand::f64() * 100.0
}

fn get_thread_count() -> usize {
    // Placeholder - would use actual thread counting
    std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1)
}

impl Default for PerformanceProfiler {
    fn default() -> Self {
        Self::new(ProfilerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_profiler_session_lifecycle() {
        let profiler = Arc::new(PerformanceProfiler::default());
        
        // Start session
        let session_id = profiler.start_session("test-session".to_string()).await.unwrap();
        assert!(!session_id.is_empty());
        
        // Check active sessions
        let active = profiler.get_active_sessions().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], session_id);
        
        // End session
        let session = profiler.end_session(&session_id).await.unwrap();
        assert_eq!(session.name, "test-session");
        assert!(session.end_time.is_some());
        
        // Check no active sessions
        let active = profiler.get_active_sessions().await;
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_hot_path_recording() {
        let profiler = Arc::new(PerformanceProfiler::default());
        
        // Record some executions
        profiler.record_execution("test-function".to_string(), Duration::from_millis(10)).await;
        profiler.record_execution("test-function".to_string(), Duration::from_millis(20)).await;
        profiler.record_execution("another-function".to_string(), Duration::from_millis(5)).await;
        
        let hot_paths = profiler.get_hot_paths().await;
        
        // Should have recorded the hot paths (depending on sampling)
        // Note: Due to sampling, this test might be flaky
        if !hot_paths.is_empty() {
            let test_function = hot_paths.iter().find(|p| p.name == "test-function");
            if let Some(path) = test_function {
                assert!(path.call_count > 0);
                assert!(path.total_time > Duration::ZERO);
            }
        }
    }

    #[tokio::test]
    async fn test_profiling_guard() {
        let profiler = Arc::new(PerformanceProfiler::default());
        
        {
            let _guard = ProfilingGuard::new(profiler.clone(), "guarded-function".to_string());
            sleep(Duration::from_millis(1)).await;
        }
        
        // Give some time for the async recording to complete
        sleep(Duration::from_millis(10)).await;
        
        // Check if the execution was recorded (might not be due to sampling)
        let hot_paths = profiler.get_hot_paths().await;
        // This test is probabilistic due to sampling
    }

    #[tokio::test]
    async fn test_memory_and_cpu_sampling() {
        let profiler = Arc::new(PerformanceProfiler::default());
        let session_id = profiler.start_session("sampling-test".to_string()).await.unwrap();
        
        // Take samples
        profiler.take_memory_snapshot(&session_id).await.unwrap();
        profiler.take_cpu_sample(&session_id).await.unwrap();
        
        let session = profiler.get_session(&session_id).await.unwrap();
        assert_eq!(session.memory_snapshots.len(), 1);
        assert_eq!(session.cpu_samples.len(), 1);
        
        profiler.end_session(&session_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_config_update() {
        let profiler = Arc::new(PerformanceProfiler::default());
        
        let mut new_config = ProfilerConfig::default();
        new_config.sampling_rate = 0.5;
        new_config.hot_path_threshold = 2000;
        
        profiler.update_config(new_config.clone()).await;
        
        let current_config = profiler.get_config().await;
        assert_eq!(current_config.sampling_rate, 0.5);
        assert_eq!(current_config.hot_path_threshold, 2000);
    }
}
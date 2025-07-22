//! # Graceful Shutdown System
//! 
//! This module implements graceful shutdown capabilities that ensure in-flight
//! requests are completed before the system shuts down.

use crate::core::error::{GatewayError, GatewayResult};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock, Semaphore};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// Configuration for graceful shutdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Maximum time to wait for in-flight requests to complete
    pub graceful_timeout: Duration,
    
    /// Time to wait before starting shutdown (allows load balancers to update)
    pub pre_shutdown_delay: Duration,
    
    /// Maximum number of shutdown phases
    pub max_shutdown_phases: u8,
    
    /// Time between shutdown phases
    pub phase_interval: Duration,
    
    /// Whether to reject new requests immediately on shutdown signal
    pub immediate_rejection: bool,
    
    /// Whether to send shutdown notifications to upstream services
    pub notify_upstream: bool,
    
    /// Custom shutdown hooks configuration
    pub hooks: Vec<ShutdownHookConfig>,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            graceful_timeout: Duration::from_secs(30),
            pre_shutdown_delay: Duration::from_secs(5),
            max_shutdown_phases: 3,
            phase_interval: Duration::from_secs(5),
            immediate_rejection: false,
            notify_upstream: true,
            hooks: Vec::new(),
        }
    }
}

/// Configuration for shutdown hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownHookConfig {
    /// Hook name for identification
    pub name: String,
    
    /// Phase when this hook should run (0 = pre-shutdown, 1+ = shutdown phases)
    pub phase: u8,
    
    /// Maximum time to wait for this hook to complete
    pub timeout: Duration,
    
    /// Whether failure of this hook should abort shutdown
    pub critical: bool,
}

/// Shutdown phase enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Normal operation
    Running,
    /// Pre-shutdown phase (preparing for shutdown)
    PreShutdown,
    /// Phase 1: Stop accepting new requests
    StopAccepting,
    /// Phase 2: Drain existing connections
    Draining,
    /// Phase 3: Force close remaining connections
    ForceClose,
    /// Shutdown complete
    Complete,
}

/// Shutdown hook trait for custom shutdown logic
#[async_trait::async_trait]
pub trait ShutdownHook: Send + Sync {
    /// Execute the shutdown hook
    async fn execute(&self, phase: ShutdownPhase) -> GatewayResult<()>;
    
    /// Get the name of this hook
    fn name(&self) -> &str;
    
    /// Get the phase this hook should run in
    fn phase(&self) -> u8;
    
    /// Whether this hook is critical (failure aborts shutdown)
    fn is_critical(&self) -> bool;
}

/// Metrics for shutdown monitoring
#[derive(Debug, Clone)]
pub struct ShutdownMetrics {
    /// Current shutdown phase
    pub current_phase: Arc<RwLock<ShutdownPhase>>,
    
    /// Number of in-flight requests
    pub in_flight_requests: Arc<AtomicU64>,
    
    /// Number of active connections
    pub active_connections: Arc<AtomicU64>,
    
    /// Shutdown start time
    pub shutdown_started_at: Arc<RwLock<Option<Instant>>>,
    
    /// Time spent in each phase
    pub phase_durations: Arc<RwLock<Vec<Duration>>>,
    
    /// Whether shutdown was forced
    pub forced_shutdown: Arc<AtomicBool>,
}

impl Default for ShutdownMetrics {
    fn default() -> Self {
        Self {
            current_phase: Arc::new(RwLock::new(ShutdownPhase::Running)),
            in_flight_requests: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            shutdown_started_at: Arc::new(RwLock::new(None)),
            phase_durations: Arc::new(RwLock::new(Vec::new())),
            forced_shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Graceful shutdown manager
pub struct GracefulShutdown {
    config: Arc<ShutdownConfig>,
    metrics: ShutdownMetrics,
    shutdown_sender: broadcast::Sender<ShutdownPhase>,
    shutdown_receiver: broadcast::Receiver<ShutdownPhase>,
    request_semaphore: Arc<Semaphore>,
    hooks: Vec<Box<dyn ShutdownHook>>,
    shutdown_initiated: Arc<AtomicBool>,
}

impl GracefulShutdown {
    /// Create a new graceful shutdown manager
    pub fn new(config: ShutdownConfig) -> Self {
        let (shutdown_sender, shutdown_receiver) = broadcast::channel(16);
        let request_semaphore = Arc::new(Semaphore::new(10000)); // Large initial capacity
        
        Self {
            config: Arc::new(config),
            metrics: ShutdownMetrics::default(),
            shutdown_sender,
            shutdown_receiver,
            request_semaphore,
            hooks: Vec::new(),
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Register a shutdown hook
    pub fn register_hook(&mut self, hook: Box<dyn ShutdownHook>) {
        info!("Registered shutdown hook: {}", hook.name());
        self.hooks.push(hook);
    }
    
    /// Start tracking a new request
    pub async fn start_request(&self) -> GatewayResult<RequestGuard> {
        // Check if shutdown has been initiated
        if self.shutdown_initiated.load(Ordering::Acquire) {
            if self.config.immediate_rejection {
                return Err(GatewayError::ServiceUnavailable);
            }
            
            // Check current phase
            let phase = *self.metrics.current_phase.read().await;
            match phase {
                ShutdownPhase::Running | ShutdownPhase::PreShutdown => {
                    // Still accepting requests
                }
                _ => {
                    return Err(GatewayError::ServiceUnavailable);
                }
            }
        }
        
        // Acquire semaphore permit
        let permit = self.request_semaphore.clone().try_acquire_owned()
            .map_err(|_| GatewayError::ServiceUnavailable)?;
        
        // Increment in-flight counter
        self.metrics.in_flight_requests.fetch_add(1, Ordering::Relaxed);
        
        Ok(RequestGuard {
            permit: Some(permit),
            metrics: self.metrics.clone(),
        })
    }
    
    /// Get a shutdown signal receiver
    pub fn subscribe(&self) -> broadcast::Receiver<ShutdownPhase> {
        self.shutdown_sender.subscribe()
    }
    
    /// Initiate graceful shutdown
    pub async fn initiate_shutdown(&self) -> GatewayResult<()> {
        if self.shutdown_initiated.swap(true, Ordering::AcqRel) {
            warn!("Shutdown already initiated");
            return Ok(());
        }
        
        info!("Initiating graceful shutdown");
        *self.metrics.shutdown_started_at.write().await = Some(Instant::now());
        
        // Execute shutdown sequence
        self.execute_shutdown_sequence().await
    }
    
    /// Execute the complete shutdown sequence
    async fn execute_shutdown_sequence(&self) -> GatewayResult<()> {
        let phases = [
            ShutdownPhase::PreShutdown,
            ShutdownPhase::StopAccepting,
            ShutdownPhase::Draining,
            ShutdownPhase::ForceClose,
        ];
        
        for (i, &phase) in phases.iter().enumerate() {
            let phase_start = Instant::now();
            
            info!("Entering shutdown phase: {:?}", phase);
            *self.metrics.current_phase.write().await = phase;
            
            // Send phase notification
            if let Err(e) = self.shutdown_sender.send(phase) {
                warn!("Failed to send shutdown phase notification: {}", e);
            }
            
            // Execute phase-specific logic
            if let Err(e) = self.execute_shutdown_phase(phase).await {
                error!("Error in shutdown phase {:?}: {}", phase, e);
                
                // Check if we should abort shutdown
                if self.should_abort_shutdown(&e) {
                    error!("Aborting shutdown due to critical error");
                    return Err(e);
                }
            }
            
            // Record phase duration
            let phase_duration = phase_start.elapsed();
            self.metrics.phase_durations.write().await.push(phase_duration);
            
            debug!("Completed shutdown phase {:?} in {:?}", phase, phase_duration);
            
            // Wait between phases (except for the last one)
            if i < phases.len() - 1 {
                sleep(self.config.phase_interval).await;
            }
        }
        
        // Mark shutdown as complete
        *self.metrics.current_phase.write().await = ShutdownPhase::Complete;
        info!("Graceful shutdown completed");
        
        Ok(())
    }
    
    /// Execute logic for a specific shutdown phase
    async fn execute_shutdown_phase(&self, phase: ShutdownPhase) -> GatewayResult<()> {
        match phase {
            ShutdownPhase::PreShutdown => {
                self.execute_pre_shutdown().await
            }
            ShutdownPhase::StopAccepting => {
                self.execute_stop_accepting().await
            }
            ShutdownPhase::Draining => {
                self.execute_draining().await
            }
            ShutdownPhase::ForceClose => {
                self.execute_force_close().await
            }
            _ => Ok(()),
        }
    }
    
    /// Execute pre-shutdown phase
    async fn execute_pre_shutdown(&self) -> GatewayResult<()> {
        info!("Pre-shutdown delay: {:?}", self.config.pre_shutdown_delay);
        
        // Execute pre-shutdown hooks
        self.execute_hooks(0).await?;
        
        // Wait for pre-shutdown delay
        sleep(self.config.pre_shutdown_delay).await;
        
        // Notify upstream services if configured
        if self.config.notify_upstream {
            self.notify_upstream_services().await?;
        }
        
        Ok(())
    }
    
    /// Execute stop accepting phase
    async fn execute_stop_accepting(&self) -> GatewayResult<()> {
        info!("Stopping acceptance of new requests");
        
        // Close the semaphore to prevent new requests
        self.request_semaphore.close();
        
        // Execute phase 1 hooks
        self.execute_hooks(1).await?;
        
        Ok(())
    }
    
    /// Execute draining phase
    async fn execute_draining(&self) -> GatewayResult<()> {
        info!("Draining in-flight requests");
        
        // Execute phase 2 hooks
        self.execute_hooks(2).await?;
        
        // Wait for in-flight requests to complete
        let drain_timeout = self.config.graceful_timeout;
        let drain_result = timeout(drain_timeout, self.wait_for_requests_to_complete()).await;
        
        match drain_result {
            Ok(Ok(())) => {
                info!("All in-flight requests completed successfully");
            }
            Ok(Err(e)) => {
                warn!("Error while draining requests: {}", e);
            }
            Err(_) => {
                let remaining = self.metrics.in_flight_requests.load(Ordering::Relaxed);
                warn!("Drain timeout exceeded. {} requests still in-flight", remaining);
            }
        }
        
        Ok(())
    }
    
    /// Execute force close phase
    async fn execute_force_close(&self) -> GatewayResult<()> {
        let remaining = self.metrics.in_flight_requests.load(Ordering::Relaxed);
        
        if remaining > 0 {
            warn!("Force closing {} remaining in-flight requests", remaining);
            self.metrics.forced_shutdown.store(true, Ordering::Relaxed);
        }
        
        // Execute phase 3 hooks
        self.execute_hooks(3).await?;
        
        // Force close any remaining connections
        // In a real implementation, this would close network connections
        info!("Force close phase completed");
        
        Ok(())
    }
    
    /// Execute hooks for a specific phase
    async fn execute_hooks(&self, phase: u8) -> GatewayResult<()> {
        let phase_enum = match phase {
            0 => ShutdownPhase::PreShutdown,
            1 => ShutdownPhase::StopAccepting,
            2 => ShutdownPhase::Draining,
            3 => ShutdownPhase::ForceClose,
            _ => return Ok(()),
        };
        
        for hook in &self.hooks {
            if hook.phase() == phase {
                let hook_timeout = Duration::from_secs(30); // Default timeout
                let hook_result = timeout(hook_timeout, hook.execute(phase_enum)).await;
                
                match hook_result {
                    Ok(Ok(())) => {
                        debug!("Shutdown hook '{}' completed successfully", hook.name());
                    }
                    Ok(Err(e)) => {
                        error!("Shutdown hook '{}' failed: {}", hook.name(), e);
                        if hook.is_critical() {
                            return Err(e);
                        }
                    }
                    Err(_) => {
                        error!("Shutdown hook '{}' timed out", hook.name());
                        if hook.is_critical() {
                            return Err(GatewayError::Timeout);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Wait for all in-flight requests to complete
    async fn wait_for_requests_to_complete(&self) -> GatewayResult<()> {
        let check_interval = Duration::from_millis(100);
        
        loop {
            let in_flight = self.metrics.in_flight_requests.load(Ordering::Relaxed);
            
            if in_flight == 0 {
                break;
            }
            
            debug!("Waiting for {} in-flight requests to complete", in_flight);
            sleep(check_interval).await;
        }
        
        Ok(())
    }
    
    /// Notify upstream services about shutdown
    async fn notify_upstream_services(&self) -> GatewayResult<()> {
        // In a real implementation, this would send notifications to:
        // - Service discovery systems
        // - Load balancers
        // - Monitoring systems
        // - Other dependent services
        
        info!("Notifying upstream services about shutdown");
        
        // Simulate notification delay
        sleep(Duration::from_millis(500)).await;
        
        Ok(())
    }
    
    /// Check if shutdown should be aborted due to error
    fn should_abort_shutdown(&self, _error: &GatewayError) -> bool {
        // In a real implementation, you might want to abort shutdown
        // for certain critical errors
        false
    }
    
    /// Get current shutdown metrics
    pub fn metrics(&self) -> &ShutdownMetrics {
        &self.metrics
    }
    
    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(Ordering::Acquire)
    }
    
    /// Get current shutdown phase
    pub async fn current_phase(&self) -> ShutdownPhase {
        *self.metrics.current_phase.read().await
    }
    
    /// Force immediate shutdown (skip graceful phases)
    pub async fn force_shutdown(&self) -> GatewayResult<()> {
        warn!("Forcing immediate shutdown");
        
        self.shutdown_initiated.store(true, Ordering::Release);
        self.metrics.forced_shutdown.store(true, Ordering::Relaxed);
        
        *self.metrics.current_phase.write().await = ShutdownPhase::ForceClose;
        
        // Send force close notification
        if let Err(e) = self.shutdown_sender.send(ShutdownPhase::ForceClose) {
            warn!("Failed to send force shutdown notification: {}", e);
        }
        
        // Execute force close hooks
        self.execute_hooks(3).await?;
        
        *self.metrics.current_phase.write().await = ShutdownPhase::Complete;
        
        Ok(())
    }
}

/// RAII guard for tracking request lifecycle
pub struct RequestGuard {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    metrics: ShutdownMetrics,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        // Decrement in-flight counter when request completes
        self.metrics.in_flight_requests.fetch_sub(1, Ordering::Relaxed);
        
        // Drop the semaphore permit
        self.permit.take();
    }
}

/// Example shutdown hook implementation
pub struct LoggingShutdownHook {
    name: String,
    phase: u8,
    critical: bool,
}

impl LoggingShutdownHook {
    pub fn new(name: String, phase: u8, critical: bool) -> Self {
        Self { name, phase, critical }
    }
}

#[async_trait::async_trait]
impl ShutdownHook for LoggingShutdownHook {
    async fn execute(&self, phase: ShutdownPhase) -> GatewayResult<()> {
        info!("Executing logging shutdown hook '{}' in phase {:?}", self.name, phase);
        
        // Simulate some cleanup work
        sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn phase(&self) -> u8 {
        self.phase
    }
    
    fn is_critical(&self) -> bool {
        self.critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_request_tracking() {
        let config = ShutdownConfig::default();
        let shutdown = GracefulShutdown::new(config);
        
        // Start a request
        let guard = shutdown.start_request().await.unwrap();
        assert_eq!(shutdown.metrics.in_flight_requests.load(Ordering::Relaxed), 1);
        
        // Drop the guard
        drop(guard);
        
        // Give it a moment for the drop to be processed
        sleep(Duration::from_millis(10)).await;
        assert_eq!(shutdown.metrics.in_flight_requests.load(Ordering::Relaxed), 0);
    }
    
    #[tokio::test]
    async fn test_shutdown_phases() {
        let config = ShutdownConfig {
            graceful_timeout: Duration::from_millis(100),
            pre_shutdown_delay: Duration::from_millis(50),
            phase_interval: Duration::from_millis(10),
            ..Default::default()
        };
        
        let shutdown = GracefulShutdown::new(config);
        
        // Subscribe to shutdown notifications
        let mut receiver = shutdown.subscribe();
        
        // Start shutdown in background
        let shutdown_handle = {
            let shutdown = &shutdown;
            tokio::spawn(async move {
                shutdown.initiate_shutdown().await
            })
        };
        
        // Verify we receive phase notifications
        let phase1 = receiver.recv().await.unwrap();
        assert_eq!(phase1, ShutdownPhase::PreShutdown);
        
        let phase2 = receiver.recv().await.unwrap();
        assert_eq!(phase2, ShutdownPhase::StopAccepting);
        
        // Wait for shutdown to complete
        shutdown_handle.await.unwrap().unwrap();
        
        assert_eq!(shutdown.current_phase().await, ShutdownPhase::Complete);
    }
    
    #[tokio::test]
    async fn test_request_rejection_during_shutdown() {
        let config = ShutdownConfig {
            immediate_rejection: true,
            ..Default::default()
        };
        
        let shutdown = GracefulShutdown::new(config);
        
        // Should accept requests initially
        assert!(shutdown.start_request().await.is_ok());
        
        // Initiate shutdown
        shutdown.shutdown_initiated.store(true, Ordering::Release);
        
        // Should reject new requests
        assert!(shutdown.start_request().await.is_err());
    }
    
    #[tokio::test]
    async fn test_shutdown_hooks() {
        let config = ShutdownConfig::default();
        let mut shutdown = GracefulShutdown::new(config);
        
        // Register a test hook
        let hook = LoggingShutdownHook::new("test_hook".to_string(), 1, false);
        shutdown.register_hook(Box::new(hook));
        
        // Shutdown should complete successfully
        assert!(shutdown.initiate_shutdown().await.is_ok());
    }
}
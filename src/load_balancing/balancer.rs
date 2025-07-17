//! # Load Balancer Module
//!
//! This module provides comprehensive load balancing strategies for upstream services.
//! It supports multiple algorithms including round-robin, least connections, weighted,
//! and consistent hashing for session affinity.
//!
//! ## Rust Concepts Explained
//!
//! - `Arc<T>` (Atomically Reference Counted) allows multiple owners of the same data
//! - `AtomicUsize` provides thread-safe atomic operations for counters
//! - `DashMap` is a concurrent HashMap that allows safe multi-threaded access
//! - `async_trait` enables async methods in traits
//! - `Send + Sync` traits ensure types can be safely shared between threads
//!
//! ## Load Balancing Algorithms
//!
//! 1. **Round Robin**: Distributes requests evenly across all instances
//! 2. **Least Connections**: Routes to the instance with fewest active connections
//! 3. **Weighted**: Distributes based on configured weights
//! 4. **Consistent Hashing**: Provides session affinity using request characteristics
//!
//! ## Usage Example
//!
//! ```rust
//! use crate::load_balancing::{LoadBalancer, RoundRobinBalancer};
//! use std::sync::Arc;
//!
//! let balancer = Arc::new(RoundRobinBalancer::new());
//! let selected = balancer.select_instance(&instances, &request).await;
//! ```

use async_trait::async_trait;
use crate::core::types::{ServiceInstance, IncomingRequest};
use dashmap::DashMap;
use metrics::{counter, histogram, gauge};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn, error};

/// Core trait for load balancing algorithms
///
/// This trait defines the interface that all load balancing strategies must implement.
/// It uses async methods to allow for future extensions that might need async operations
/// (e.g., consulting external state or metrics).
#[async_trait]
pub trait LoadBalancer: Send + Sync {
    /// Select an instance from the available pool
    ///
    /// # Arguments
    /// * `instances` - Available service instances (should be healthy)
    /// * `request` - The incoming request (used for session affinity, etc.)
    ///
    /// # Returns
    /// * `Some(index)` - Index of selected instance in the instances slice
    /// * `None` - No suitable instance available
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        request: &IncomingRequest,
    ) -> Option<usize>;

    /// Get the algorithm name for metrics and logging
    fn algorithm_name(&self) -> &'static str;

    /// Get current statistics for this load balancer
    async fn get_stats(&self) -> LoadBalancerStats;

    /// Reset internal state (useful for testing or reconfiguration)
    async fn reset(&self);
}

/// Load balancer statistics for monitoring
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadBalancerStats {
    pub algorithm: String,
    pub total_requests: u64,
    pub total_selections: u64,
    pub failed_selections: u64,
    pub instance_stats: std::collections::HashMap<String, InstanceStats>,
}

/// Per-instance statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstanceStats {
    pub selections: u64,
    pub active_connections: u64,
    pub last_selected: Option<chrono::DateTime<chrono::Utc>>,
}

/// Round-robin load balancer with atomic counter
///
/// This implementation uses an atomic counter to ensure thread-safe round-robin
/// distribution across all available instances. The counter wraps around when
/// it reaches the maximum value to prevent overflow.
pub struct RoundRobinBalancer {
    counter: AtomicUsize,
    stats: Arc<DashMap<String, InstanceStats>>,
    total_requests: AtomicUsize,
    failed_selections: AtomicUsize,
}

impl RoundRobinBalancer {
    /// Create a new round-robin load balancer
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
            stats: Arc::new(DashMap::new()),
            total_requests: AtomicUsize::new(0),
            failed_selections: AtomicUsize::new(0),
        }
    }

    /// Update instance statistics
    fn update_stats(&self, instance_id: &str) {
        let mut stats = self.stats.entry(instance_id.to_string()).or_insert_with(|| InstanceStats {
            selections: 0,
            active_connections: 0,
            last_selected: None,
        });
        stats.selections += 1;
        stats.last_selected = Some(chrono::Utc::now());
    }
}

#[async_trait]
impl LoadBalancer for RoundRobinBalancer {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        _request: &IncomingRequest,
    ) -> Option<usize> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if instances.is_empty() {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
            counter!("load_balancer_failed_selections").increment(1);
            return None;
        }

        // Use fetch_add to get the current value and increment atomically
        let index = self.counter.fetch_add(1, Ordering::Relaxed) % instances.len();
        let selected = &instances[index];
        
        self.update_stats(&selected.id);
        
        // Record metrics
        counter!("load_balancer_selections").increment(1);
        
        debug!(
            instance_id = %selected.id,
            instance_address = %selected.address,
            algorithm = "round_robin",
            "Selected instance for load balancing"
        );

        Some(index)
    }

    fn algorithm_name(&self) -> &'static str {
        "round_robin"
    }

    async fn get_stats(&self) -> LoadBalancerStats {
        let instance_stats = self.stats.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        LoadBalancerStats {
            algorithm: "round_robin".to_string(),
            total_requests: self.total_requests.load(Ordering::Relaxed) as u64,
            total_selections: self.total_requests.load(Ordering::Relaxed) as u64,
            failed_selections: self.failed_selections.load(Ordering::Relaxed) as u64,
            instance_stats,
        }
    }

    async fn reset(&self) {
        self.counter.store(0, Ordering::Relaxed);
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_selections.store(0, Ordering::Relaxed);
        self.stats.clear();
    }
}

/// Least connections load balancer
///
/// This balancer tracks active connections per instance and routes new requests
/// to the instance with the fewest active connections. It uses DashMap for
/// thread-safe concurrent access to connection counts.
pub struct LeastConnectionsBalancer {
    connection_counts: Arc<DashMap<String, AtomicUsize>>,
    stats: Arc<DashMap<String, InstanceStats>>,
    total_requests: AtomicUsize,
    failed_selections: AtomicUsize,
}

impl LeastConnectionsBalancer {
    /// Create a new least connections load balancer
    pub fn new() -> Self {
        Self {
            connection_counts: Arc::new(DashMap::new()),
            stats: Arc::new(DashMap::new()),
            total_requests: AtomicUsize::new(0),
            failed_selections: AtomicUsize::new(0),
        }
    }

    /// Increment connection count for an instance
    pub fn increment_connections(&self, instance_id: &str) {
        let counter = self.connection_counts
            .entry(instance_id.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        
        // Update gauge metric
        gauge!("load_balancer_active_connections").set(counter.load(Ordering::Relaxed) as f64);
    }

    /// Decrement connection count for an instance
    pub fn decrement_connections(&self, instance_id: &str) {
        if let Some(counter) = self.connection_counts.get(instance_id) {
            let current = counter.fetch_sub(1, Ordering::Relaxed);
            // Prevent underflow
            if current == 0 {
                counter.store(0, Ordering::Relaxed);
            }
            
            // Update gauge metric
            gauge!("load_balancer_active_connections").set(counter.load(Ordering::Relaxed) as f64);
        }
    }

    /// Get current connection count for an instance
    pub fn get_connection_count(&self, instance_id: &str) -> usize {
        self.connection_counts
            .get(instance_id)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Update instance statistics
    fn update_stats(&self, instance_id: &str, connections: usize) {
        let mut stats = self.stats.entry(instance_id.to_string()).or_insert_with(|| InstanceStats {
            selections: 0,
            active_connections: 0,
            last_selected: None,
        });
        stats.selections += 1;
        stats.active_connections = connections as u64;
        stats.last_selected = Some(chrono::Utc::now());
    }
}

#[async_trait]
impl LoadBalancer for LeastConnectionsBalancer {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        _request: &IncomingRequest,
    ) -> Option<usize> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if instances.is_empty() {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
            counter!("load_balancer_failed_selections").increment(1);
            return None;
        }

        // Find instance with minimum connections
        let mut min_connections = usize::MAX;
        let mut selected_index = None;

        for (index, instance) in instances.iter().enumerate() {
            let connections = self.get_connection_count(&instance.id);
            if connections < min_connections {
                min_connections = connections;
                selected_index = Some(index);
            }
        }

        if let Some(index) = selected_index {
            let selected = &instances[index];
            self.update_stats(&selected.id, min_connections);
            
            counter!("load_balancer_selections").increment(1);
            
            debug!(
                instance_id = %selected.id,
                instance_address = %selected.address,
                connections = min_connections,
                algorithm = "least_connections",
                "Selected instance with least connections"
            );
        } else {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
        }

        selected_index
    }

    fn algorithm_name(&self) -> &'static str {
        "least_connections"
    }

    async fn get_stats(&self) -> LoadBalancerStats {
        let mut instance_stats = std::collections::HashMap::new();
        
        // Combine stats from both maps
        for entry in self.stats.iter() {
            let mut stats = entry.value().clone();
            if let Some(connections) = self.connection_counts.get(entry.key()) {
                stats.active_connections = connections.load(Ordering::Relaxed) as u64;
            }
            instance_stats.insert(entry.key().clone(), stats);
        }

        LoadBalancerStats {
            algorithm: "least_connections".to_string(),
            total_requests: self.total_requests.load(Ordering::Relaxed) as u64,
            total_selections: self.total_requests.load(Ordering::Relaxed) as u64,
            failed_selections: self.failed_selections.load(Ordering::Relaxed) as u64,
            instance_stats,
        }
    }

    async fn reset(&self) {
        self.connection_counts.clear();
        self.stats.clear();
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_selections.store(0, Ordering::Relaxed);
    }
}

/// Weighted load balancer
///
/// This balancer distributes requests based on configured weights. Instances with
/// higher weights receive proportionally more traffic. It uses a weighted random
/// selection algorithm for distribution.
pub struct WeightedBalancer {
    stats: Arc<DashMap<String, InstanceStats>>,
    total_requests: AtomicUsize,
    failed_selections: AtomicUsize,
}

impl WeightedBalancer {
    /// Create a new weighted load balancer
    pub fn new() -> Self {
        Self {
            stats: Arc::new(DashMap::new()),
            total_requests: AtomicUsize::new(0),
            failed_selections: AtomicUsize::new(0),
        }
    }

    /// Update instance statistics
    fn update_stats(&self, instance_id: &str) {
        let mut stats = self.stats.entry(instance_id.to_string()).or_insert_with(|| InstanceStats {
            selections: 0,
            active_connections: 0,
            last_selected: None,
        });
        stats.selections += 1;
        stats.last_selected = Some(chrono::Utc::now());
    }
}

#[async_trait]
impl LoadBalancer for WeightedBalancer {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        _request: &IncomingRequest,
    ) -> Option<usize> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if instances.is_empty() {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
            counter!("load_balancer_failed_selections").increment(1);
            return None;
        }

        // Calculate total weight
        let total_weight: u32 = instances.iter().map(|i| i.weight).sum();
        
        if total_weight == 0 {
            // Fallback to round-robin if no weights are set
            let index = self.total_requests.load(Ordering::Relaxed) % instances.len();
            let selected = &instances[index];
            self.update_stats(&selected.id);
            return Some(index);
        }

        // Generate random number in range [0, total_weight)
        let mut rng = rand::thread_rng();
        let mut random_weight = rng.gen_range(0..total_weight);

        // Find the instance corresponding to this weight
        for (index, instance) in instances.iter().enumerate() {
            if random_weight < instance.weight {
                self.update_stats(&instance.id);
                
                counter!("load_balancer_selections").increment(1);
                
                debug!(
                    instance_id = %instance.id,
                    instance_address = %instance.address,
                    weight = instance.weight,
                    algorithm = "weighted",
                    "Selected instance based on weight"
                );
                
                return Some(index);
            }
            random_weight -= instance.weight;
        }

        // Fallback (shouldn't happen with correct logic)
        self.failed_selections.fetch_add(1, Ordering::Relaxed);
        warn!("Weighted load balancer failed to select instance despite non-empty pool");
        None
    }

    fn algorithm_name(&self) -> &'static str {
        "weighted"
    }

    async fn get_stats(&self) -> LoadBalancerStats {
        let instance_stats = self.stats.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        LoadBalancerStats {
            algorithm: "weighted".to_string(),
            total_requests: self.total_requests.load(Ordering::Relaxed) as u64,
            total_selections: self.total_requests.load(Ordering::Relaxed) as u64,
            failed_selections: self.failed_selections.load(Ordering::Relaxed) as u64,
            instance_stats,
        }
    }

    async fn reset(&self) {
        self.stats.clear();
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_selections.store(0, Ordering::Relaxed);
    }
}

/// Consistent hashing load balancer for session affinity
///
/// This balancer uses consistent hashing to ensure that requests with the same
/// characteristics (e.g., user ID, session ID) are always routed to the same
/// instance, providing session affinity.
pub struct ConsistentHashBalancer {
    stats: Arc<DashMap<String, InstanceStats>>,
    total_requests: AtomicUsize,
    failed_selections: AtomicUsize,
    virtual_nodes: usize, // Number of virtual nodes per instance
}

impl ConsistentHashBalancer {
    /// Create a new consistent hash load balancer
    ///
    /// # Arguments
    /// * `virtual_nodes` - Number of virtual nodes per instance (default: 150)
    pub fn new(virtual_nodes: Option<usize>) -> Self {
        Self {
            stats: Arc::new(DashMap::new()),
            total_requests: AtomicUsize::new(0),
            failed_selections: AtomicUsize::new(0),
            virtual_nodes: virtual_nodes.unwrap_or(150),
        }
    }

    /// Extract hash key from request
    ///
    /// This method determines what part of the request to use for hashing.
    /// Priority order:
    /// 1. X-Session-ID header
    /// 2. X-User-ID header
    /// 3. Authorization header (for user-based affinity)
    /// 4. Client IP address (fallback)
    fn extract_hash_key(&self, request: &IncomingRequest) -> String {
        // Try session ID first
        if let Some(session_id) = request.header("x-session-id") {
            return format!("session:{}", session_id);
        }

        // Try user ID
        if let Some(user_id) = request.header("x-user-id") {
            return format!("user:{}", user_id);
        }

        // Try to extract user from Authorization header
        if let Some(auth) = request.header("authorization") {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                // Use first 16 characters of token for consistency
                let token_prefix = token.chars().take(16).collect::<String>();
                return format!("token:{}", token_prefix);
            }
        }

        // Fallback to client IP
        format!("ip:{}", request.remote_addr.ip())
    }

    /// Create hash ring for consistent hashing
    fn create_hash_ring(&self, instances: &[ServiceInstance]) -> BTreeMap<u64, String> {
        let mut ring = BTreeMap::new();
        
        for instance in instances {
            for i in 0..self.virtual_nodes {
                let virtual_key = format!("{}:{}", instance.id, i);
                let hash = self.hash_string(&virtual_key);
                ring.insert(hash, instance.id.clone());
            }
        }
        
        ring
    }

    /// Hash a string to u64
    fn hash_string(&self, s: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        
        // Take first 8 bytes and convert to u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result[0..8]);
        u64::from_be_bytes(bytes)
    }

    /// Find instance in hash ring
    fn find_instance_in_ring(&self, ring: &BTreeMap<u64, String>, key_hash: u64) -> Option<String> {
        // Find the first instance with hash >= key_hash
        if let Some((_, instance_id)) = ring.range(key_hash..).next() {
            Some(instance_id.clone())
        } else {
            // Wrap around to the beginning of the ring
            ring.values().next().cloned()
        }
    }

    /// Update instance statistics
    fn update_stats(&self, instance_id: &str) {
        let mut stats = self.stats.entry(instance_id.to_string()).or_insert_with(|| InstanceStats {
            selections: 0,
            active_connections: 0,
            last_selected: None,
        });
        stats.selections += 1;
        stats.last_selected = Some(chrono::Utc::now());
    }
}

#[async_trait]
impl LoadBalancer for ConsistentHashBalancer {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        request: &IncomingRequest,
    ) -> Option<usize> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if instances.is_empty() {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
            counter!("load_balancer_failed_selections").increment(1);
            return None;
        }

        // Extract hash key from request
        let hash_key = self.extract_hash_key(request);
        let key_hash = self.hash_string(&hash_key);

        // Create hash ring
        let ring = self.create_hash_ring(instances);
        
        // Find instance in ring
        if let Some(instance_id) = self.find_instance_in_ring(&ring, key_hash) {
            // Find the actual instance
            if let Some((index, selected)) = instances.iter().enumerate().find(|(_, i)| i.id == instance_id) {
                self.update_stats(&selected.id);
                
                counter!("load_balancer_selections").increment(1);
                
                debug!(
                    instance_id = %selected.id,
                    instance_address = %selected.address,
                    hash_key = %hash_key,
                    key_hash = key_hash,
                    algorithm = "consistent_hash",
                    "Selected instance using consistent hashing"
                );
                
                return Some(index);
            }
        }

        self.failed_selections.fetch_add(1, Ordering::Relaxed);
        error!("Consistent hash balancer failed to find instance in ring");
        None
    }

    fn algorithm_name(&self) -> &'static str {
        "consistent_hash"
    }

    async fn get_stats(&self) -> LoadBalancerStats {
        let instance_stats = self.stats.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        LoadBalancerStats {
            algorithm: "consistent_hash".to_string(),
            total_requests: self.total_requests.load(Ordering::Relaxed) as u64,
            total_selections: self.total_requests.load(Ordering::Relaxed) as u64,
            failed_selections: self.failed_selections.load(Ordering::Relaxed) as u64,
            instance_stats,
        }
    }

    async fn reset(&self) {
        self.stats.clear();
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_selections.store(0, Ordering::Relaxed);
    }
}

/// Load balancer manager that can switch between algorithms
///
/// This manager allows runtime switching between different load balancing algorithms
/// and provides a unified interface for load balancing operations.
pub struct LoadBalancerManager {
    current_balancer: Arc<parking_lot::RwLock<Arc<dyn LoadBalancer + Send + Sync + 'static>>>,
    balancers: Arc<DashMap<String, Arc<dyn LoadBalancer + Send + Sync + 'static>>>,
}

impl LoadBalancerManager {
    /// Create a new load balancer manager with default round-robin algorithm
    pub fn new() -> Self {
        let round_robin = Arc::new(RoundRobinBalancer::new()) as Arc<dyn LoadBalancer + Send + Sync + 'static>;
        let balancers = Arc::new(DashMap::new());
        
        // Register default algorithms
        balancers.insert("round_robin".to_string(), Arc::new(RoundRobinBalancer::new()) as Arc<dyn LoadBalancer + Send + Sync + 'static>);
        balancers.insert("least_connections".to_string(), Arc::new(LeastConnectionsBalancer::new()) as Arc<dyn LoadBalancer + Send + Sync + 'static>);
        balancers.insert("weighted".to_string(), Arc::new(WeightedBalancer::new()) as Arc<dyn LoadBalancer + Send + Sync + 'static>);
        balancers.insert("consistent_hash".to_string(), Arc::new(ConsistentHashBalancer::new(None)) as Arc<dyn LoadBalancer + Send + Sync + 'static>);

        Self {
            current_balancer: Arc::new(parking_lot::RwLock::new(round_robin)),
            balancers,
        }
    }

    /// Switch to a different load balancing algorithm
    pub fn switch_algorithm(&self, algorithm: &str) -> Result<(), String> {
        if let Some(balancer) = self.balancers.get(algorithm) {
            let mut current = self.current_balancer.write();
            *current = balancer.clone();
            
            counter!("load_balancer_algorithm_switches").increment(1);
            
            debug!(
                algorithm = algorithm,
                "Switched load balancing algorithm"
            );
            
            Ok(())
        } else {
            Err(format!("Unknown load balancing algorithm: {}", algorithm))
        }
    }

    /// Get current algorithm name
    pub fn current_algorithm(&self) -> String {
        let current = self.current_balancer.read();
        current.algorithm_name().to_string()
    }

    /// Get available algorithms
    pub fn available_algorithms(&self) -> Vec<String> {
        self.balancers.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Register a custom load balancer
    pub fn register_balancer(&self, name: String, balancer: Arc<dyn LoadBalancer + Send + Sync + 'static>) {
        self.balancers.insert(name, balancer);
    }

    /// Get statistics for current balancer
    pub async fn get_current_stats(&self) -> LoadBalancerStats {
        let current = {
            let guard = self.current_balancer.read();
            guard.clone()
        };
        current.get_stats().await
    }

    /// Get statistics for all balancers
    pub async fn get_all_stats(&self) -> std::collections::HashMap<String, LoadBalancerStats> {
        let mut all_stats = std::collections::HashMap::new();
        
        // Collect entries first to avoid lifetime issues
        let entries: Vec<_> = self.balancers.iter().map(|entry| (entry.key().clone(), entry.value().clone())).collect();
        
        for (name, balancer) in entries {
            let stats = balancer.get_stats().await;
            all_stats.insert(name, stats);
        }
        
        all_stats
    }
}

#[async_trait]
impl LoadBalancer for LoadBalancerManager {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        request: &IncomingRequest,
    ) -> Option<usize> {
        let current = {
            let guard = self.current_balancer.read();
            guard.clone()
        };
        let start = Instant::now();
        
        let result = current.select_instance(instances, request).await;
        
        let duration = start.elapsed();
        histogram!("load_balancer_selection_duration").record(duration.as_secs_f64());
        
        result
    }

    fn algorithm_name(&self) -> &'static str {
        let current = self.current_balancer.read();
        current.algorithm_name()
    }

    async fn get_stats(&self) -> LoadBalancerStats {
        self.get_current_stats().await
    }

    async fn reset(&self) {
        let current = {
            let guard = self.current_balancer.read();
            guard.clone()
        };
        current.reset().await;
    }
}

impl Default for LoadBalancerManager {
    fn default() -> Self {
        Self::new()
    }
}
//! # Connection Pool Module
//!
//! This module provides connection pooling for upstream services to improve performance
//! by reusing HTTP/gRPC connections instead of creating new ones for each request.
//!
//! ## Rust Concepts Used
//!
//! - `Arc<T>` for shared ownership of connection pools across threads
//! - `DashMap` for thread-safe concurrent access to connection pools per service
//! - `tokio::sync::Semaphore` for limiting concurrent connections
//! - `tokio::time::Instant` for connection lifecycle tracking
//! - `async_trait` for async methods in traits

use async_trait::async_trait;
use dashmap::DashMap;
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector as HyperUtilConnector};
use hyper_util::rt::TokioExecutor;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};
use metrics::{counter, gauge, histogram};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::ServiceInstance;

/// Configuration for connection pooling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections per service
    pub max_connections_per_service: usize,
    /// Maximum idle time before closing a connection
    pub max_idle_time: Duration,
    /// Connection timeout for new connections
    pub connection_timeout: Duration,
    /// Keep-alive timeout for connections
    pub keep_alive_timeout: Duration,
    /// Enable HTTP/2 for connections
    pub enable_http2: bool,
    /// Pool cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_service: 50,
            max_idle_time: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(90),
            enable_http2: true,
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// A pooled connection wrapper
#[derive(Debug)]
pub struct PooledConnection {
    /// The actual HTTP client
    pub client: HyperClient<HyperUtilConnector, hyper::body::Incoming>,
    /// When this connection was created
    pub created_at: Instant,
    /// When this connection was last used
    pub last_used: Instant,
    /// Target service address
    pub target_addr: SocketAddr,
    /// Connection ID for tracking
    pub connection_id: String,
}

impl PooledConnection {
    /// Create a new pooled connection
    pub fn new(target_addr: SocketAddr, config: &ConnectionPoolConfig) -> GatewayResult<Self> {
        let mut connector = HyperUtilConnector::new();
        connector.set_connect_timeout(Some(config.connection_timeout));
        connector.set_keepalive(Some(config.keep_alive_timeout));
        
        let client = HyperClient::builder(TokioExecutor::new())
            .build(connector);

        let connection_id = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();

        Ok(Self {
            client,
            created_at: now,
            last_used: now,
            target_addr,
            connection_id,
        })
    }

    /// Check if this connection is expired
    pub fn is_expired(&self, max_idle_time: Duration) -> bool {
        self.last_used.elapsed() > max_idle_time
    }

    /// Update last used timestamp
    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

/// Connection pool for a specific service
#[derive(Debug)]
pub struct ServiceConnectionPool {
    /// Available connections
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    /// Semaphore to limit concurrent connections
    semaphore: Arc<Semaphore>,
    /// Pool configuration
    config: ConnectionPoolConfig,
    /// Service identifier
    service_id: String,
    /// Target address for this pool
    target_addr: SocketAddr,
}

impl ServiceConnectionPool {
    /// Create a new service connection pool
    pub fn new(service_id: String, target_addr: SocketAddr, config: ConnectionPoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_connections_per_service));
        
        Self {
            connections: Arc::new(Mutex::new(VecDeque::new())),
            semaphore,
            config,
            service_id,
            target_addr,
        }
    }

    /// Get a connection from the pool or create a new one
    pub async fn get_connection(&self) -> GatewayResult<PooledConnection> {
        // Try to get an existing connection first
        {
            let mut connections = self.connections.lock().await;
            while let Some(mut conn) = connections.pop_front() {
                if !conn.is_expired(self.config.max_idle_time) {
                    conn.mark_used();
                    
                    counter!("connection_pool_reused").increment(1);
                    gauge!("connection_pool_active_connections").increment(1.0);
                    
                    debug!(
                        service_id = %self.service_id,
                        connection_id = %conn.connection_id,
                        "Reused pooled connection"
                    );
                    
                    return Ok(conn);
                } else {
                    counter!("connection_pool_expired").increment(1);
                    debug!(
                        service_id = %self.service_id,
                        connection_id = %conn.connection_id,
                        "Discarded expired connection"
                    );
                }
            }
        }

        // Acquire semaphore permit for new connection
        let _permit = self.semaphore.acquire().await
            .map_err(|e| GatewayError::internal(format!("Failed to acquire connection permit: {}", e)))?;

        // Create new connection
        let connection = PooledConnection::new(self.target_addr, &self.config)?;
        
        counter!("connection_pool_created").increment(1);
        gauge!("connection_pool_active_connections").increment(1.0);
        
        debug!(
            service_id = %self.service_id,
            connection_id = %connection.connection_id,
            target_addr = %self.target_addr,
            "Created new pooled connection"
        );

        Ok(connection)
    }

    /// Return a connection to the pool
    pub async fn return_connection(&self, connection: PooledConnection) {
        if connection.is_expired(self.config.max_idle_time) {
            counter!("connection_pool_expired_on_return").increment(1);
            gauge!("connection_pool_active_connections").decrement(1.0);
            
            debug!(
                service_id = %self.service_id,
                connection_id = %connection.connection_id,
                "Connection expired on return, not pooling"
            );
            return;
        }

        let mut connections = self.connections.lock().await;
        connections.push_back(connection);
        
        counter!("connection_pool_returned").increment(1);
        
        debug!(
            service_id = %self.service_id,
            "Returned connection to pool"
        );
    }

    /// Clean up expired connections
    pub async fn cleanup_expired(&self) -> usize {
        let mut connections = self.connections.lock().await;
        let initial_count = connections.len();
        
        connections.retain(|conn| {
            let expired = conn.is_expired(self.config.max_idle_time);
            if expired {
                gauge!("connection_pool_active_connections").decrement(1.0);
            }
            !expired
        });
        
        let cleaned_count = initial_count - connections.len();
        
        if cleaned_count > 0 {
            counter!("connection_pool_cleaned_up").increment(cleaned_count as u64);
            debug!(
                service_id = %self.service_id,
                cleaned_count = cleaned_count,
                "Cleaned up expired connections"
            );
        }
        
        cleaned_count
    }

    /// Get pool statistics
    pub async fn get_stats(&self) -> PoolStats {
        let connections = self.connections.lock().await;
        let available_connections = connections.len();
        let total_permits = self.config.max_connections_per_service;
        let available_permits = self.semaphore.available_permits();
        let active_connections = total_permits - available_permits;

        PoolStats {
            service_id: self.service_id.clone(),
            target_addr: self.target_addr,
            available_connections,
            active_connections,
            max_connections: total_permits,
            oldest_connection_age: connections.front().map(|c| c.age()),
            newest_connection_age: connections.back().map(|c| c.age()),
        }
    }
}

/// Connection pool statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolStats {
    pub service_id: String,
    pub target_addr: SocketAddr,
    pub available_connections: usize,
    pub active_connections: usize,
    pub max_connections: usize,
    pub oldest_connection_age: Option<Duration>,
    pub newest_connection_age: Option<Duration>,
}

/// Global connection pool manager
pub struct ConnectionPoolManager {
    /// Connection pools per service
    pools: DashMap<String, Arc<ServiceConnectionPool>>,
    /// Global configuration
    config: ConnectionPoolConfig,
}

impl ConnectionPoolManager {
    /// Create a new connection pool manager
    pub fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            pools: DashMap::new(),
            config,
        }
    }

    /// Get or create a connection pool for a service
    pub fn get_or_create_pool(&self, service: &ServiceInstance) -> Arc<ServiceConnectionPool> {
        let pool_key = format!("{}:{}", service.name, service.address);
        
        self.pools.entry(pool_key.clone()).or_insert_with(|| {
            info!(
                service_id = %service.id,
                service_name = %service.name,
                target_addr = %service.address,
                "Creating new connection pool"
            );
            
            Arc::new(ServiceConnectionPool::new(
                service.id.clone(),
                service.address,
                self.config.clone(),
            ))
        }).clone()
    }

    /// Get a connection for a service
    pub async fn get_connection(&self, service: &ServiceInstance) -> GatewayResult<PooledConnection> {
        let pool = self.get_or_create_pool(service);
        let start_time = Instant::now();
        
        let connection = pool.get_connection().await?;
        
        let duration = start_time.elapsed();
        histogram!("connection_pool_get_duration").record(duration.as_secs_f64());
        
        Ok(connection)
    }

    /// Return a connection to its pool
    pub async fn return_connection(&self, service: &ServiceInstance, connection: PooledConnection) {
        let pool_key = format!("{}:{}", service.name, service.address);
        
        if let Some(pool) = self.pools.get(&pool_key) {
            pool.return_connection(connection).await;
        } else {
            warn!(
                service_id = %service.id,
                "No pool found for returning connection"
            );
            gauge!("connection_pool_active_connections").decrement(1.0);
        }
    }

    /// Clean up expired connections in all pools
    pub async fn cleanup_all_pools(&self) -> usize {
        let mut total_cleaned = 0;
        
        for entry in self.pools.iter() {
            let cleaned = entry.value().cleanup_expired().await;
            total_cleaned += cleaned;
        }
        
        if total_cleaned > 0 {
            info!(
                total_cleaned = total_cleaned,
                "Cleaned up expired connections across all pools"
            );
        }
        
        total_cleaned
    }

    /// Remove unused pools
    pub async fn cleanup_unused_pools(&self) -> usize {
        let mut pools_to_remove = Vec::new();
        
        for entry in self.pools.iter() {
            let stats = entry.value().get_stats().await;
            if stats.active_connections == 0 && stats.available_connections == 0 {
                pools_to_remove.push(entry.key().clone());
            }
        }
        
        let removed_count = pools_to_remove.len();
        for pool_key in pools_to_remove {
            self.pools.remove(&pool_key);
            debug!(pool_key = %pool_key, "Removed unused connection pool");
        }
        
        if removed_count > 0 {
            info!(
                removed_count = removed_count,
                "Removed unused connection pools"
            );
        }
        
        removed_count
    }

    /// Get statistics for all pools
    pub async fn get_all_stats(&self) -> Vec<PoolStats> {
        let mut stats = Vec::new();
        
        for entry in self.pools.iter() {
            let pool_stats = entry.value().get_stats().await;
            stats.push(pool_stats);
        }
        
        stats
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = self.config.cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let start_time = Instant::now();
                
                // Clean up expired connections
                let expired_cleaned = self.cleanup_all_pools().await;
                
                // Clean up unused pools
                let pools_removed = self.cleanup_unused_pools().await;
                
                let cleanup_duration = start_time.elapsed();
                
                histogram!("connection_pool_cleanup_duration").record(cleanup_duration.as_secs_f64());
                counter!("connection_pool_cleanup_cycles").increment(1);
                
                if expired_cleaned > 0 || pools_removed > 0 {
                    info!(
                        expired_cleaned = expired_cleaned,
                        pools_removed = pools_removed,
                        cleanup_duration_ms = cleanup_duration.as_millis(),
                        "Connection pool cleanup completed"
                    );
                }
            }
        });
    }

    /// Get global pool statistics
    pub async fn get_global_stats(&self) -> GlobalPoolStats {
        let all_stats = self.get_all_stats().await;
        
        let total_pools = all_stats.len();
        let total_available_connections: usize = all_stats.iter().map(|s| s.available_connections).sum();
        let total_active_connections: usize = all_stats.iter().map(|s| s.active_connections).sum();
        let total_max_connections: usize = all_stats.iter().map(|s| s.max_connections).sum();
        
        GlobalPoolStats {
            total_pools,
            total_available_connections,
            total_active_connections,
            total_max_connections,
            pool_utilization: if total_max_connections > 0 {
                (total_active_connections as f64 / total_max_connections as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Global connection pool statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalPoolStats {
    pub total_pools: usize,
    pub total_available_connections: usize,
    pub total_active_connections: usize,
    pub total_max_connections: usize,
    pub pool_utilization: f64, // Percentage
}

/// Connection pool trait for different protocols
#[async_trait]
pub trait ConnectionPool: Send + Sync {
    type Connection;
    
    /// Get a connection from the pool
    async fn get_connection(&self, service: &ServiceInstance) -> GatewayResult<Self::Connection>;
    
    /// Return a connection to the pool
    async fn return_connection(&self, service: &ServiceInstance, connection: Self::Connection);
    
    /// Get pool statistics
    async fn get_stats(&self) -> Vec<PoolStats>;
}

#[async_trait]
impl ConnectionPool for ConnectionPoolManager {
    type Connection = PooledConnection;
    
    async fn get_connection(&self, service: &ServiceInstance) -> GatewayResult<Self::Connection> {
        self.get_connection(service).await
    }
    
    async fn return_connection(&self, service: &ServiceInstance, connection: Self::Connection) {
        self.return_connection(service, connection).await
    }
    
    async fn get_stats(&self) -> Vec<PoolStats> {
        self.get_all_stats().await
    }
}

impl Default for ConnectionPoolManager {
    fn default() -> Self {
        Self::new(ConnectionPoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::types::{HealthStatus, Protocol};

    fn create_test_service() -> ServiceInstance {
        ServiceInstance {
            id: "test-service-1".to_string(),
            name: "test-service".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            metadata: std::collections::HashMap::new(),
            health_status: HealthStatus::Healthy,
            protocol: Protocol::Http,
            weight: 1,
            last_health_check: None,
        }
    }

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let config = ConnectionPoolConfig::default();
        let manager = ConnectionPoolManager::new(config);
        let service = create_test_service();
        
        let pool = manager.get_or_create_pool(&service);
        assert_eq!(pool.service_id, service.id);
        assert_eq!(pool.target_addr, service.address);
    }

    #[tokio::test]
    async fn test_connection_pool_stats() {
        let config = ConnectionPoolConfig::default();
        let manager = Arc::new(ConnectionPoolManager::new(config));
        let service = create_test_service();
        
        let stats = manager.get_global_stats().await;
        assert_eq!(stats.total_pools, 0);
        
        // Create a pool by getting a connection
        let _pool = manager.get_or_create_pool(&service);
        
        let stats = manager.get_global_stats().await;
        assert_eq!(stats.total_pools, 1);
    }

    #[tokio::test]
    async fn test_connection_expiration() {
        let mut config = ConnectionPoolConfig::default();
        config.max_idle_time = Duration::from_millis(10); // Very short for testing
        
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let connection = PooledConnection::new(target_addr, &config).unwrap();
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        assert!(connection.is_expired(config.max_idle_time));
    }
}
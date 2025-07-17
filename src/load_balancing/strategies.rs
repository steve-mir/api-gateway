//! # Load Balancing Strategies
//!
//! This module provides legacy strategy implementations that are now superseded
//! by the comprehensive LoadBalancer trait implementations in the balancer module.
//! These are kept for backward compatibility but new code should use the
//! LoadBalancer trait implementations instead.
//!
//! ## Migration Guide
//!
//! Old usage:
//! ```rust
//! let strategy = RoundRobin::new();
//! let selected = strategy.select(&instances);
//! ```
//!
//! New usage:
//! ```rust
//! let balancer = RoundRobinBalancer::new();
//! let selected = balancer.select_instance(&instances, &request).await;
//! ```

use crate::core::types::{ServiceInstance, IncomingRequest};
use crate::load_balancing::balancer::{
    LoadBalancer, RoundRobinBalancer, LeastConnectionsBalancer, 
    WeightedBalancer, ConsistentHashBalancer
};
use std::sync::Arc;

/// Legacy trait for load balancing strategies
///
/// This trait is deprecated in favor of the async LoadBalancer trait.
/// It's kept for backward compatibility with existing code.
#[deprecated(note = "Use LoadBalancer trait instead")]
pub trait BalancingStrategy: Send + Sync {
    fn select<'a>(&self, instances: &'a [ServiceInstance]) -> Option<&'a ServiceInstance>;
}

/// Legacy round-robin strategy
///
/// This is a simplified version of the RoundRobinBalancer.
/// Use RoundRobinBalancer for new implementations.
#[deprecated(note = "Use RoundRobinBalancer instead")]
pub struct RoundRobin {
    counter: std::sync::atomic::AtomicUsize,
}

#[allow(deprecated)]
impl RoundRobin {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[allow(deprecated)]
impl BalancingStrategy for RoundRobin {
    fn select<'a>(&self, instances: &'a [ServiceInstance]) -> Option<&'a ServiceInstance> {
        if instances.is_empty() {
            return None;
        }
        
        let index = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % instances.len();
        instances.get(index)
    }
}

/// Legacy weighted round-robin strategy
///
/// This is a simplified version that doesn't implement proper weighted selection.
/// Use WeightedBalancer for new implementations.
#[deprecated(note = "Use WeightedBalancer instead")]
pub struct WeightedRoundRobin {
    counter: std::sync::atomic::AtomicUsize,
}

#[allow(deprecated)]
impl WeightedRoundRobin {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[allow(deprecated)]
impl BalancingStrategy for WeightedRoundRobin {
    fn select<'a>(&self, instances: &'a [ServiceInstance]) -> Option<&'a ServiceInstance> {
        if instances.is_empty() {
            return None;
        }
        
        // Simple fallback to round-robin for legacy compatibility
        let index = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % instances.len();
        instances.get(index)
    }
}

/// Legacy least connections strategy
///
/// This is a simplified version that doesn't track actual connections.
/// Use LeastConnectionsBalancer for new implementations.
#[deprecated(note = "Use LeastConnectionsBalancer instead")]
pub struct LeastConnections {
    // Simplified implementation without connection tracking
}

#[allow(deprecated)]
impl LeastConnections {
    pub fn new() -> Self {
        Self {}
    }
}

#[allow(deprecated)]
impl BalancingStrategy for LeastConnections {
    fn select<'a>(&self, instances: &'a [ServiceInstance]) -> Option<&'a ServiceInstance> {
        // Fallback to first instance for legacy compatibility
        instances.first()
    }
}

/// Strategy adapter that wraps new LoadBalancer implementations
/// to work with the legacy BalancingStrategy trait
pub struct StrategyAdapter {
    balancer: Arc<dyn LoadBalancer>,
}

impl StrategyAdapter {
    /// Create a new strategy adapter
    pub fn new(balancer: Arc<dyn LoadBalancer>) -> Self {
        Self { balancer }
    }

    /// Create adapter for round-robin balancer
    pub fn round_robin() -> Self {
        Self::new(Arc::new(RoundRobinBalancer::new()))
    }

    /// Create adapter for least connections balancer
    pub fn least_connections() -> Self {
        Self::new(Arc::new(LeastConnectionsBalancer::new()))
    }

    /// Create adapter for weighted balancer
    pub fn weighted() -> Self {
        Self::new(Arc::new(WeightedBalancer::new()))
    }

    /// Create adapter for consistent hash balancer
    pub fn consistent_hash() -> Self {
        Self::new(Arc::new(ConsistentHashBalancer::new(None)))
    }
}

#[allow(deprecated)]
impl BalancingStrategy for StrategyAdapter {
    fn select<'a>(&self, instances: &'a [ServiceInstance]) -> Option<&'a ServiceInstance> {
        // Create a dummy request for the LoadBalancer interface
        // This is not ideal but necessary for backward compatibility
        let dummy_request = IncomingRequest::new(
            crate::core::types::Protocol::Http,
            axum::http::Method::GET,
            "/".parse().unwrap(),
            axum::http::Version::HTTP_11,
            axum::http::HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:0".parse().unwrap(),
        );

        // Use tokio::task::block_in_place to handle the async call in sync context
        let index = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.balancer.select_instance(instances, &dummy_request).await
            })
        });

        // Convert index back to reference
        index.and_then(|i| instances.get(i))
    }
}

/// Factory for creating load balancing strategies
pub struct StrategyFactory;

#[allow(deprecated)]
impl StrategyFactory {
    /// Create a round-robin strategy
    pub fn round_robin() -> Box<dyn BalancingStrategy> {
        Box::new(StrategyAdapter::round_robin())
    }

    /// Create a least connections strategy
    pub fn least_connections() -> Box<dyn BalancingStrategy> {
        Box::new(StrategyAdapter::least_connections())
    }

    /// Create a weighted strategy
    pub fn weighted() -> Box<dyn BalancingStrategy> {
        Box::new(StrategyAdapter::weighted())
    }

    /// Create a consistent hash strategy
    pub fn consistent_hash() -> Box<dyn BalancingStrategy> {
        Box::new(StrategyAdapter::consistent_hash())
    }

    /// Create a strategy by name
    pub fn by_name(name: &str) -> Result<Box<dyn BalancingStrategy>, String> {
        match name {
            "round_robin" => Ok(Self::round_robin()),
            "least_connections" => Ok(Self::least_connections()),
            "weighted" => Ok(Self::weighted()),
            "consistent_hash" => Ok(Self::consistent_hash()),
            _ => Err(format!("Unknown strategy: {}", name)),
        }
    }
}
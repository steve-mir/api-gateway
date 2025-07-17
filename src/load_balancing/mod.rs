pub mod balancer;
pub mod strategies;

pub use balancer::{
    LoadBalancer, LoadBalancerManager, LoadBalancerStats, InstanceStats,
    RoundRobinBalancer, LeastConnectionsBalancer, WeightedBalancer, ConsistentHashBalancer
};

// Legacy exports for backward compatibility
#[allow(deprecated)]
pub use strategies::{BalancingStrategy, RoundRobin, WeightedRoundRobin, LeastConnections};
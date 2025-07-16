//! # Load Balancer Module
//!
//! This module will contain load balancing strategies for upstream services.
//! It will be implemented in subsequent tasks.

// Placeholder for load balancer implementation
// This will be implemented in task 5: "Load Balancing Implementation"

use async_trait::async_trait;
use crate::types::{ServiceInstance, IncomingRequest};

#[async_trait]
pub trait LoadBalancer: Send + Sync {
    async fn select_instance(
        &self,
        instances: &[ServiceInstance],
        request: &IncomingRequest,
    ) -> Option<&ServiceInstance>;
}

pub struct RoundRobinBalancer {
    // TODO: Implement round-robin load balancing
}

pub struct LeastConnectionsBalancer {
    // TODO: Implement least connections load balancing
}
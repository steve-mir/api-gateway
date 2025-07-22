//! # Traffic Management Module
//! 
//! This module provides comprehensive traffic management capabilities including:
//! - Request queuing with backpressure handling
//! - Traffic shaping and throttling
//! - Request prioritization
//! - Graceful shutdown handling
//! - Traffic splitting for A/B testing
//! 
//! ## Key Components
//! 
//! - `RequestQueue`: Manages incoming request queuing with backpressure
//! - `TrafficShaper`: Controls request flow and throttling
//! - `PriorityManager`: Handles request prioritization
//! - `GracefulShutdown`: Manages shutdown with in-flight request handling
//! - `TrafficSplitter`: Implements A/B testing and traffic splitting
//! - `TrafficManager`: Coordinates all traffic management components

// Temporarily disabled modules with compilation errors
// pub mod queue;
// pub mod shaper;
// pub mod priority;
// pub mod shutdown;
// pub mod splitter;
// pub mod manager;
pub mod admin_stub;

// Re-export main types (temporarily disabled)
// pub use manager::TrafficManager;
// pub use queue::{RequestQueue, BackpressureConfig, QueueMetrics};
// pub use shaper::{TrafficShaper, ThrottleConfig, ShapingMetrics};
// pub use priority::{PriorityManager, PriorityConfig, RequestPriority};
// pub use shutdown::{GracefulShutdown, ShutdownConfig};
// pub use splitter::{TrafficSplitter, SplitConfig, ABTestConfig};

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for traffic management features (stub)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    /// Enabled flag
    pub enabled: bool,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false,
        }
    }
}

// Stub types for compilation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureConfig {
    pub enabled: bool,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleConfig {
    pub enabled: bool,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityConfig {
    pub enabled: bool,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    pub enabled: bool,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitConfig {
    pub enabled: bool,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}
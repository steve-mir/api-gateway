//! # Health Checking System
//!
//! This module provides comprehensive health check functionality for the API gateway and its dependencies.
//! It includes HTTP health check probes, health status aggregation, automatic service instance removal,
//! and admin endpoints for health check configuration.
//!
//! ## Key Features
//! - Configurable HTTP health check probes with intervals
//! - Health status aggregation and reporting
//! - Automatic service instance removal on health check failures
//! - Gateway self-health endpoints
//! - Admin endpoints for health check configuration and manual overrides
//!
//! ## Rust Concepts Used
//! - `Arc<T>` for shared ownership across async tasks
//! - `DashMap` for thread-safe concurrent access to health check data
//! - `tokio::time::interval` for scheduled health checks
//! - `async_trait` for async methods in traits

use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{HealthStatus as CoreHealthStatus, ServiceInstance};
use crate::discovery::ServiceRegistry;

/// Overall health status of the gateway or a service
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service is healthy and ready to receive traffic
    Healthy,
    /// Service is partially degraded but still functional
    Degraded,
    /// Service is unhealthy and should not receive traffic
    Unhealthy,
    /// Health status is unknown (e.g., not yet checked)
    Unknown,
}

impl From<CoreHealthStatus> for ServiceStatus {
    fn from(status: CoreHealthStatus) -> Self {
        match status {
            CoreHealthStatus::Healthy => ServiceStatus::Healthy,
            CoreHealthStatus::Unhealthy => ServiceStatus::Unhealthy,
            CoreHealthStatus::Unknown => ServiceStatus::Unknown,
            CoreHealthStatus::Starting => ServiceStatus::Unknown,
            CoreHealthStatus::Stopping => ServiceStatus::Unhealthy,
        }
    }
}

impl From<ServiceStatus> for CoreHealthStatus {
    fn from(status: ServiceStatus) -> Self {
        match status {
            ServiceStatus::Healthy => CoreHealthStatus::Healthy,
            ServiceStatus::Degraded => CoreHealthStatus::Healthy, // Treat degraded as healthy for routing
            ServiceStatus::Unhealthy => CoreHealthStatus::Unhealthy,
            ServiceStatus::Unknown => CoreHealthStatus::Unknown,
        }
    }
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCh
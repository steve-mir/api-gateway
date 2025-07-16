//! # API Gateway Library
//! 
//! A high-performance API Gateway built in Rust for containerized deployment in Kubernetes clusters.
//! This library provides all the core functionality for building and running an API gateway.

// Core modules - order matters for dependency resolution
pub mod error;
pub mod types;
pub mod router;
pub mod middleware;
pub mod protocols;
pub mod auth;
pub mod load_balancer;
pub mod service_discovery;
pub mod config;
pub mod observability;

// Re-export commonly used types
pub use error::{GatewayError, GatewayResult};
pub use config::{GatewayConfig, ConfigManager};
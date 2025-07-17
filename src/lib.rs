//! # API Gateway Library
//! 
//! A high-performance API Gateway built in Rust for containerized deployment in Kubernetes clusters.
//! This library provides all the core functionality for building and running an API gateway.

// Core modules - order matters for dependency resolution
pub mod core;
pub mod gateway;
pub mod middleware;
pub mod protocols;
pub mod auth;
pub mod load_balancing;
pub mod discovery;
pub mod routing;
pub mod observability;
pub mod admin;

// Re-export commonly used types
pub use core::error::{GatewayError, GatewayResult};
pub use core::config::{GatewayConfig, ConfigManager};
//! # API Gateway
//! 
//! A high-performance API Gateway built in Rust for containerized deployment in Kubernetes clusters.
//! This gateway serves as a unified entry point for multiple communication protocols (gRPC, REST, WebSocket)
//! with advanced traffic management, security, and observability features.
//!
//! ## Architecture Overview
//!
//! The gateway is built around several core modules:
//! - `error`: Comprehensive error handling with proper HTTP status mapping
//! - `types`: Core data structures for requests, responses, and contexts
//! - `router`: Request routing with path matching and parameter extraction
//! - `middleware`: Pluggable middleware pipeline for request/response processing
//! - `protocols`: Protocol-specific handlers (HTTP, gRPC, WebSocket)
//! - `auth`: Authentication and authorization providers
//! - `load_balancer`: Load balancing strategies for upstream services
//! - `service_discovery`: Service discovery integrations
//! - `config`: Configuration management with hot reloading
//! - `observability`: Metrics, logging, and distributed tracing
//!
//! ## Rust Concepts for Developers from Other Languages
//!
//! This codebase extensively uses Rust's ownership system and async programming model:
//!
//! ### Ownership and Borrowing
//! - `Arc<T>` (Atomically Reference Counted) is used for shared ownership of immutable data
//! - `Mutex<T>` and `RwLock<T>` provide thread-safe mutable access
//! - References (`&T`) are used for borrowing data without taking ownership
//! - `Clone` trait is implemented for types that need to be duplicated
//!
//! ### Async Programming
//! - All I/O operations use `async/await` for non-blocking execution
//! - `tokio` runtime manages the async task scheduler
//! - `Arc` is used to share data between async tasks
//! - Channels (`mpsc`, `broadcast`) are used for communication between tasks

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

use tokio::signal;
use tracing::{info, error};

use crate::config::GatewayConfig;
use crate::error::GatewayResult;

#[tokio::main]
async fn main() -> GatewayResult<()> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting API Gateway...");

    // Load configuration
    let _config = GatewayConfig::load_from_file("config/gateway.yaml").await?;
    info!("Configuration loaded successfully");

    // TODO: Initialize gateway components (will be implemented in subsequent tasks)
    // - Service discovery
    // - Load balancers  
    // - Authentication providers
    // - Middleware pipeline
    // - Protocol handlers
    // - HTTP server

    info!("API Gateway started successfully");

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal, gracefully shutting down...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}

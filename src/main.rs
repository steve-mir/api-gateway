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

use tokio::signal;
use tracing::{info, error};

// Use the library modules
use api_gateway::{GatewayConfig, GatewayResult};
use api_gateway::routing::router::RouterBuilder;
use api_gateway::gateway::server::{GatewayServer, ServerConfig};

#[tokio::main]
async fn main() -> GatewayResult<()> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting API Gateway...");

    // Load configuration
    let config = GatewayConfig::load_from_file("config/gateway.yaml").await?;
    info!("Configuration loaded successfully");

    // Create a basic router with some example routes for testing
    // TODO: In future tasks, this will be loaded from configuration
    let router = RouterBuilder::new()
        .get("/health", "health-service")
        .get("/ready", "health-service")
        .get("/api/users", "user-service")
        .get("/api/users/{id}", "user-service")
        .post("/api/users", "user-service")
        .put("/api/users/{id}", "user-service")
        .delete("/api/users/{id}", "user-service")
        .get("/api/posts", "post-service")
        .get("/api/posts/{id}", "post-service")
        .post("/api/posts", "post-service")
        .default_route("default-service")
        .build();

    // Create server configuration using the loaded config
    let server_config = ServerConfig {
        bind_addr: format!("{}:{}", config.server.bind_address, config.server.http_port).parse().unwrap(),
        admin_bind_addr: "127.0.0.1:8081".parse().unwrap(),  // Admin routes
        ..Default::default()
    };
    
    // Create and start HTTP server
    let server = GatewayServer::new(router, server_config);
    let gateway_addr = server.bind_addr();
    let admin_addr = server.admin_bind_addr();
    
    info!("API Gateway started successfully on {}", gateway_addr);
    info!("Admin interface started successfully on {}", admin_addr);

    // Start server in a separate task so we can handle shutdown signals
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.start().await {
            error!("Server error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal, gracefully shutting down...");
        }
        _ = server_handle => {
            info!("Server task completed");
        }
    }

    info!("API Gateway shutdown complete");
    Ok(())
}

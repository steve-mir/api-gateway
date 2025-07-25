//! # API Gateway Library - Core Library Crate
//! 
//! A high-performance API Gateway built in Rust for containerized deployment in Kubernetes clusters.
//! This library provides all the core functionality for building and running an API gateway.
//!
//! ## Rust Module System Explained (For Developers from Other Languages)
//!
//! Unlike languages with file-based imports (Python, JavaScript), Rust uses a hierarchical module system:
//!
//! ### Module Declaration vs Import
//! - `mod module_name;` declares a module (like `#include` in C++)
//! - `use module_name::item;` imports specific items (like `import` in Python/JS)
//! - Modules form a tree structure starting from the crate root (this file)
//!
//! ### Visibility Rules
//! - Items are private by default (unlike Python where everything is public)
//! - `pub` keyword makes items public (like `export` in JavaScript)
//! - `pub(crate)` makes items visible within the entire crate
//! - `pub(super)` makes items visible to the parent module
//!
//! ### Crate vs Module
//! - A "crate" is like a package/library (this entire project is one crate)
//! - A "module" is a namespace within a crate (like packages in Java)
//! - External crates are imported in Cargo.toml (like package.json or requirements.txt)
//!
//! ### Re-exports
//! - `pub use` re-exports items from other modules
//! - This creates a public API surface (like __all__ in Python __init__.py)
//! - Users can import commonly used types directly from the crate root

// Core modules - order matters for dependency resolution in Rust
// Unlike dynamic languages, Rust resolves dependencies at compile time
// Each `mod` declaration tells the compiler to include that module's code

/// Core functionality including error types, configuration, and basic data structures
/// This module contains the fundamental building blocks used throughout the gateway
pub mod core;

/// Main gateway server implementation and HTTP handling
/// Contains the primary server logic that ties all other modules together
pub mod gateway;

/// Middleware pipeline system for request/response processing
/// Implements the chain-of-responsibility pattern for extensible request handling
pub mod middleware;

/// Protocol-specific handlers (HTTP, gRPC, WebSocket)
/// Each protocol has its own handler that implements the common protocol interface
pub mod protocols;

/// Authentication and authorization providers
/// Supports multiple auth methods: JWT, OAuth2, API keys, custom providers
pub mod auth;

/// Load balancing strategies for distributing requests across upstream services
/// Implements various algorithms: round-robin, least connections, weighted, etc.
pub mod load_balancing;

/// Service discovery integrations (Kubernetes, Consul, static configuration)
/// Automatically discovers and tracks available backend services
pub mod discovery;

/// Request routing system with path matching and parameter extraction
/// Uses efficient data structures (radix trees) for fast route matching
pub mod routing;

/// Observability features: metrics, logging, distributed tracing
/// Provides comprehensive monitoring and debugging capabilities
pub mod observability;

/// Caching system for request/response caching and performance optimization
/// Supports multiple storage backends: in-memory, Redis, etc.
pub mod caching;

/// Traffic management: rate limiting, circuit breakers, request queuing
/// Implements patterns for handling high load and service failures
pub mod traffic;

/// Admin API and dashboard for gateway management
/// Provides web-based interface and REST API for configuration and monitoring
pub mod admin;

// Re-export commonly used types for easier access
// This is similar to creating a "public API" in other languages
// Users can write `use api_gateway::GatewayError` instead of `use api_gateway::core::error::GatewayError`

/// Main error type used throughout the gateway
/// Re-exported for convenience - users don't need to know it's in `core::error`
pub use core::error::{GatewayError, GatewayResult};

/// Main configuration structure for the gateway
/// Re-exported because it's needed by anyone using this library
pub use core::config::{GatewayConfig, ConfigManager};

// Additional re-exports for common types that users will need
/// Common result type used throughout the gateway
/// This is a type alias: `type GatewayResult<T> = Result<T, GatewayError>`
/// Similar to how many languages define custom result/error types
pub use core::types::{IncomingRequest as Request, GatewayResponse as Response, RequestContext};

/// Router builder for creating request routing configurations
/// Re-exported because it's part of the main public API
pub use routing::router::{Router, RouterBuilder};

/// Server configuration and main server struct
/// These are the primary entry points for using this library
pub use gateway::server::{GatewayServer, ServerConfig};
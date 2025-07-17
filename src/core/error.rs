//! # Error Handling Module
//!
//! This module provides comprehensive error handling for the API Gateway using the `thiserror` crate.
//! It defines all possible error types that can occur during gateway operations and provides
//! proper HTTP status code mappings for client responses.
//!
//! ## Rust Error Handling Concepts
//!
//! Rust uses `Result<T, E>` for error handling instead of exceptions:
//! - `Ok(value)` represents success with a value
//! - `Err(error)` represents failure with an error
//! - The `?` operator propagates errors up the call stack
//! - `thiserror` provides ergonomic error type definitions with automatic `Display` and `Error` trait implementations

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

/// Main result type used throughout the gateway
/// 
/// This is a type alias that makes error handling more ergonomic.
/// Instead of writing `Result<T, GatewayError>` everywhere, we can use `GatewayResult<T>`.
pub type GatewayResult<T> = Result<T, GatewayError>;

/// Comprehensive error types for the API Gateway
///
/// Each variant represents a different category of error that can occur.
/// The `#[error("...")]` attribute from `thiserror` automatically implements
/// the `Display` trait with the specified error message.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Configuration-related errors (invalid config, missing files, etc.)
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// Authentication failures (invalid tokens, expired credentials, etc.)
    #[error("Authentication failed: {reason}")]
    Authentication { reason: String },

    /// Authorization failures (insufficient permissions, access denied, etc.)
    #[error("Authorization failed: {reason}")]
    Authorization { reason: String },

    /// Rate limiting errors when request limits are exceeded
    #[error("Rate limit exceeded: {limit} requests per {window}")]
    RateLimitExceeded { limit: u32, window: String },

    /// Circuit breaker is open, preventing requests to failing services
    #[error("Circuit breaker open for service: {service}")]
    CircuitBreakerOpen { service: String },

    /// Upstream service is unavailable or unreachable
    #[error("Service unavailable: {service} - {reason}")]
    ServiceUnavailable { service: String, reason: String },

    /// Request timeout errors
    #[error("Request timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Service discovery errors (service not found, discovery backend unavailable, etc.)
    #[error("Service discovery error: {message}")]
    ServiceDiscovery { message: String },

    /// Load balancing errors (no healthy instances, balancer failure, etc.)
    #[error("Load balancing error: {message}")]
    LoadBalancing { message: String },

    /// Protocol-specific errors (invalid HTTP, gRPC failures, WebSocket errors, etc.)
    #[error("Protocol error ({protocol}): {message}")]
    Protocol { protocol: String, message: String },

    /// Request validation errors (invalid headers, malformed body, etc.)
    #[error("Request validation failed: {field} - {reason}")]
    RequestValidation { field: String, reason: String },

    /// Response transformation errors
    #[error("Response transformation failed: {reason}")]
    ResponseTransformation { reason: String },

    /// Middleware execution errors
    #[error("Middleware error ({middleware}): {message}")]
    Middleware { middleware: String, message: String },

    /// Internal server errors for unexpected failures
    #[error("Internal server error: {message}")]
    Internal { message: String },

    /// I/O errors (file operations, network errors, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML parsing errors for configuration files
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// HTTP client errors when making upstream requests
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// JWT token validation errors
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl GatewayError {
    /// Create a configuration error with a custom message
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create an authentication error with a custom reason
    pub fn auth<S: Into<String>>(reason: S) -> Self {
        Self::Authentication {
            reason: reason.into(),
        }
    }

    /// Create an authorization error with a custom reason
    pub fn authz<S: Into<String>>(reason: S) -> Self {
        Self::Authorization {
            reason: reason.into(),
        }
    }

    /// Create a service unavailable error
    pub fn service_unavailable<S: Into<String>>(service: S, reason: S) -> Self {
        Self::ServiceUnavailable {
            service: service.into(),
            reason: reason.into(),
        }
    }

    /// Create a service discovery error with a custom message
    pub fn service_discovery<S: Into<String>>(message: S) -> Self {
        Self::ServiceDiscovery {
            message: message.into(),
        }
    }

    /// Create an internal error with a custom message
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Get the appropriate HTTP status code for this error
    ///
    /// This method maps internal error types to HTTP status codes that should
    /// be returned to clients. This is crucial for proper API behavior.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication { .. } => StatusCode::UNAUTHORIZED,
            Self::Authorization { .. } => StatusCode::FORBIDDEN,
            Self::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestValidation { .. } => StatusCode::BAD_REQUEST,
            Self::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::CircuitBreakerOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
            Self::Configuration { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceDiscovery { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::LoadBalancing { .. } => StatusCode::BAD_GATEWAY,
            Self::Protocol { .. } => StatusCode::BAD_REQUEST,
            Self::ResponseTransformation { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Middleware { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Json(_) => StatusCode::BAD_REQUEST,
            Self::Yaml(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::HttpClient(_) => StatusCode::BAD_GATEWAY,
            Self::Jwt(_) => StatusCode::UNAUTHORIZED,
        }
    }

    /// Check if this error should be retried
    ///
    /// Some errors are transient and requests can be safely retried,
    /// while others are permanent and should not be retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ServiceUnavailable { .. } => true,
            Self::Timeout { .. } => true,
            Self::LoadBalancing { .. } => true,
            Self::HttpClient(err) => err.is_timeout() || err.is_connect(),
            Self::Io(_) => true,
            _ => false,
        }
    }

    /// Check if this error should trigger circuit breaker
    ///
    /// Circuit breakers should open when there are failures that indicate
    /// the upstream service is unhealthy.
    pub fn should_trigger_circuit_breaker(&self) -> bool {
        match self {
            Self::ServiceUnavailable { .. } => true,
            Self::Timeout { .. } => true,
            Self::HttpClient(err) => err.is_timeout() || err.is_connect(),
            _ => false,
        }
    }
}

/// Implement `IntoResponse` for `GatewayError` to automatically convert errors into HTTP responses
///
/// This trait implementation allows Axum to automatically convert our custom errors
/// into proper HTTP responses with appropriate status codes and error messages.
/// This is a key part of Rust's type system - we can define how our types behave
/// in different contexts.
impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        
        // Create a structured error response
        let error_response = json!({
            "error": {
                "code": status.as_u16(),
                "message": self.to_string(),
                "type": self.error_type(),
                "retryable": self.is_retryable(),
            }
        });

        (status, Json(error_response)).into_response()
    }
}

impl GatewayError {
    /// Get a string representation of the error type for API responses
    fn error_type(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "configuration_error",
            Self::Authentication { .. } => "authentication_error",
            Self::Authorization { .. } => "authorization_error",
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
            Self::CircuitBreakerOpen { .. } => "circuit_breaker_open",
            Self::ServiceUnavailable { .. } => "service_unavailable",
            Self::Timeout { .. } => "timeout",
            Self::ServiceDiscovery { .. } => "service_discovery_error",
            Self::LoadBalancing { .. } => "load_balancing_error",
            Self::Protocol { .. } => "protocol_error",
            Self::RequestValidation { .. } => "request_validation_error",
            Self::ResponseTransformation { .. } => "response_transformation_error",
            Self::Middleware { .. } => "middleware_error",
            Self::Internal { .. } => "internal_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Yaml(_) => "yaml_error",
            Self::HttpClient(_) => "http_client_error",
            Self::Jwt(_) => "jwt_error",
        }
    }
}

/// Convenience macro for creating internal errors
///
/// This macro makes it easy to create internal errors with formatted messages.
/// Usage: `internal_error!("Failed to process request: {}", request_id)`
#[macro_export]
macro_rules! internal_error {
    ($($arg:tt)*) => {
        $crate::error::GatewayError::internal(format!($($arg)*))
    };
}

/// Convenience macro for creating configuration errors
///
/// Usage: `config_error!("Invalid port: {}", port)`
#[macro_export]
macro_rules! config_error {
    ($($arg:tt)*) => {
        $crate::error::GatewayError::config(format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            GatewayError::auth("invalid token").status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            GatewayError::authz("insufficient permissions").status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            GatewayError::RateLimitExceeded {
                limit: 100,
                window: "minute".to_string()
            }
            .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_retryable_errors() {
        assert!(GatewayError::service_unavailable("api", "connection refused").is_retryable());
        assert!(GatewayError::Timeout { timeout_ms: 5000 }.is_retryable());
        assert!(!GatewayError::auth("invalid token").is_retryable());
        assert!(!GatewayError::authz("forbidden").is_retryable());
    }

    #[test]
    fn test_circuit_breaker_triggers() {
        assert!(GatewayError::service_unavailable("api", "down").should_trigger_circuit_breaker());
        assert!(GatewayError::Timeout { timeout_ms: 5000 }.should_trigger_circuit_breaker());
        assert!(!GatewayError::auth("invalid").should_trigger_circuit_breaker());
    }
}
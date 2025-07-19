//! # Middleware Factory
//!
//! This module provides a factory for creating middleware instances from configuration.
//! It handles the instantiation of built-in middleware types and supports plugin registration.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::core::error::{GatewayError, GatewayResult};
use crate::middleware::pipeline_fixed::MiddlewareConfig;
use crate::middleware::pipeline_fixed::Middleware;
use crate::middleware::builtin::{
    RequestLoggingMiddleware, RequestLoggingConfig,
    MetricsMiddleware, MetricsConfig,
    TracingMiddleware, TracingConfig,
    SecurityHeadersMiddleware, SecurityHeadersConfig,
};

/// Trait for middleware constructors
#[async_trait]
pub trait MiddlewareConstructor: Send + Sync + std::fmt::Debug {
    async fn create(&self, config: &MiddlewareConfig) -> GatewayResult<Arc<dyn Middleware>>;
}

/// Middleware factory for creating middleware instances
#[derive(Debug)]
pub struct MiddlewareFactory {
    /// Registry of middleware constructors
    constructors: Arc<RwLock<HashMap<String, Box<dyn MiddlewareConstructor>>>>,
}

impl MiddlewareFactory {
    pub fn new() -> Self {
        Self {
            constructors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new factory with built-in middleware registered
    pub async fn new_with_builtin() -> Self {
        let factory = Self::new();
        factory.register_builtin_middleware().await;
        factory
    }

    /// Register all built-in middleware types
    async fn register_builtin_middleware(&self) {
        let mut constructors = self.constructors.write().await;
        
        // Register request logging middleware
        constructors.insert(
            "request_logging".to_string(),
            Box::new(RequestLoggingConstructor),
        );
        
        // Register metrics middleware
        constructors.insert(
            "metrics".to_string(),
            Box::new(MetricsConstructor),
        );
        
        // Register tracing middleware
        constructors.insert(
            "tracing".to_string(),
            Box::new(TracingConstructor),
        );
        
        // Register security headers middleware
        constructors.insert(
            "security_headers".to_string(),
            Box::new(SecurityHeadersConstructor),
        );
        
        debug!("Registered {} built-in middleware constructors", constructors.len());
    }

    /// Create middleware instance from configuration
    pub async fn create_middleware(
        &self,
        config: &MiddlewareConfig,
    ) -> GatewayResult<Arc<dyn Middleware>> {
        let constructors = self.constructors.read().await;
        
        if let Some(constructor) = constructors.get(&config.middleware_type) {
            debug!("Creating middleware '{}' of type '{}'", config.name, config.middleware_type);
            constructor.create(config).await
        } else {
            Err(GatewayError::Configuration {
                message: format!("Unknown middleware type: {}", config.middleware_type),
            })
        }
    }

    /// Register a custom middleware constructor
    pub async fn register_middleware_type(
        &self,
        middleware_type: String,
        constructor: Box<dyn MiddlewareConstructor>,
    ) {
        let mut constructors = self.constructors.write().await;
        constructors.insert(middleware_type.clone(), constructor);
        debug!("Registered custom middleware type: {}", middleware_type);
    }

    /// Get list of available middleware types
    pub async fn get_available_types(&self) -> Vec<String> {
        let constructors = self.constructors.read().await;
        constructors.keys().cloned().collect()
    }
}

impl Clone for MiddlewareFactory {
    fn clone(&self) -> Self {
        Self {
            constructors: self.constructors.clone(),
        }
    }
}

/// Constructor for request logging middleware
#[derive(Debug)]
struct RequestLoggingConstructor;

#[async_trait]
impl MiddlewareConstructor for RequestLoggingConstructor {
    async fn create(&self, config: &MiddlewareConfig) -> GatewayResult<Arc<dyn Middleware>> {
        let middleware_config: RequestLoggingConfig = serde_json::from_value(config.config.clone())
            .map_err(|e| GatewayError::Configuration {
                message: format!("Invalid request_logging configuration: {}", e),
            })?;
        
        Ok(Arc::new(RequestLoggingMiddleware::new(middleware_config)))
    }
}

/// Constructor for metrics middleware
#[derive(Debug)]
struct MetricsConstructor;

#[async_trait]
impl MiddlewareConstructor for MetricsConstructor {
    async fn create(&self, config: &MiddlewareConfig) -> GatewayResult<Arc<dyn Middleware>> {
        let middleware_config: MetricsConfig = serde_json::from_value(config.config.clone())
            .map_err(|e| GatewayError::Configuration {
                message: format!("Invalid metrics configuration: {}", e),
            })?;
        
        Ok(Arc::new(MetricsMiddleware::new(middleware_config)))
    }
}

/// Constructor for tracing middleware
#[derive(Debug)]
struct TracingConstructor;

#[async_trait]
impl MiddlewareConstructor for TracingConstructor {
    async fn create(&self, config: &MiddlewareConfig) -> GatewayResult<Arc<dyn Middleware>> {
        let middleware_config: TracingConfig = serde_json::from_value(config.config.clone())
            .map_err(|e| GatewayError::Configuration {
                message: format!("Invalid tracing configuration: {}", e),
            })?;
        
        Ok(Arc::new(TracingMiddleware::new(middleware_config)))
    }
}

/// Constructor for security headers middleware
#[derive(Debug)]
struct SecurityHeadersConstructor;

#[async_trait]
impl MiddlewareConstructor for SecurityHeadersConstructor {
    async fn create(&self, config: &MiddlewareConfig) -> GatewayResult<Arc<dyn Middleware>> {
        let middleware_config: SecurityHeadersConfig = serde_json::from_value(config.config.clone())
            .map_err(|e| GatewayError::Configuration {
                message: format!("Invalid security_headers configuration: {}", e),
            })?;
        
        Ok(Arc::new(SecurityHeadersMiddleware::new(middleware_config)))
    }
}

/// Helper function to parse configuration with defaults
pub fn parse_config_with_defaults<T>(config: &Value, default: T) -> GatewayResult<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if config.is_null() {
        Ok(default)
    } else {
        serde_json::from_value(config.clone()).map_err(|e| GatewayError::Configuration {
            message: format!("Configuration parsing error: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::pipeline_fixed::{MiddlewareConfig, MiddlewareCondition};
    use serde_json::json;

    #[tokio::test]
    async fn test_factory_creation() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let available_types = factory.get_available_types().await;
        assert!(available_types.contains(&"request_logging".to_string()));
        assert!(available_types.contains(&"metrics".to_string()));
        assert!(available_types.contains(&"tracing".to_string()));
        assert!(available_types.contains(&"security_headers".to_string()));
    }

    #[tokio::test]
    async fn test_request_logging_middleware_creation() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_logging".to_string(),
            middleware_type: "request_logging".to_string(),
            priority: 10,
            enabled: true,
            conditions: vec![],
            config: json!({
                "log_headers": true,
                "log_body": false,
                "max_body_size": 1024,
                "excluded_headers": ["authorization"],
                "log_level": "info"
            }),
        };

        let middleware = factory.create_middleware(&config).await.unwrap();
        assert_eq!(middleware.name(), "request_logging");
        assert_eq!(middleware.priority(), 10);
    }

    #[tokio::test]
    async fn test_metrics_middleware_creation() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_metrics".to_string(),
            middleware_type: "metrics".to_string(),
            priority: 5,
            enabled: true,
            conditions: vec![],
            config: json!({
                "detailed_metrics": true,
                "per_route_metrics": true,
                "per_upstream_metrics": true,
                "custom_labels": {}
            }),
        };

        let middleware = factory.create_middleware(&config).await.unwrap();
        assert_eq!(middleware.name(), "metrics");
        assert_eq!(middleware.priority(), 5);
    }

    #[tokio::test]
    async fn test_tracing_middleware_creation() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_tracing".to_string(),
            middleware_type: "tracing".to_string(),
            priority: 1,
            enabled: true,
            conditions: vec![],
            config: json!({
                "service_name": "test-gateway",
                "trace_bodies": false,
                "trace_headers": true,
                "excluded_headers": ["authorization"],
                "custom_tags": {}
            }),
        };

        let middleware = factory.create_middleware(&config).await.unwrap();
        assert_eq!(middleware.name(), "tracing");
        assert_eq!(middleware.priority(), 1);
    }

    #[tokio::test]
    async fn test_security_headers_middleware_creation() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_security".to_string(),
            middleware_type: "security_headers".to_string(),
            priority: 90,
            enabled: true,
            conditions: vec![],
            config: json!({
                "x_frame_options": "DENY",
                "x_content_type_options": true,
                "x_xss_protection": "1; mode=block",
                "custom_headers": {}
            }),
        };

        let middleware = factory.create_middleware(&config).await.unwrap();
        assert_eq!(middleware.name(), "security_headers");
        assert_eq!(middleware.priority(), 90);
    }

    #[tokio::test]
    async fn test_unknown_middleware_type() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_unknown".to_string(),
            middleware_type: "unknown_type".to_string(),
            priority: 50,
            enabled: true,
            conditions: vec![],
            config: json!({}),
        };

        let result = factory.create_middleware(&config).await;
        assert!(result.is_err());
        
        if let Err(GatewayError::Configuration { message }) = result {
            assert!(message.contains("Unknown middleware type: unknown_type"));
        } else {
            panic!("Expected configuration error");
        }
    }

    #[tokio::test]
    async fn test_invalid_configuration() {
        let factory = MiddlewareFactory::new_with_builtin().await;
        
        let config = MiddlewareConfig {
            name: "test_invalid".to_string(),
            middleware_type: "request_logging".to_string(),
            priority: 10,
            enabled: true,
            conditions: vec![],
            config: json!({
                "invalid_field": "invalid_value",
                "log_headers": "not_a_boolean"  // Invalid type
            }),
        };

        let result = factory.create_middleware(&config).await;
        assert!(result.is_err());
    }
}
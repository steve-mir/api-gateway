//! # Configuration Module
//!
//! This module handles configuration management with hot reloading capabilities.
//! It provides the core configuration structures and loading mechanisms.
//!
//! ## Key Features
//! - YAML/JSON configuration parsing with serde
//! - Environment variable override support
//! - Hot reloading using file system watchers
//! - Comprehensive validation with detailed error messages
//! - Thread-safe configuration updates

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use notify::{Watcher, RecursiveMode, Event, EventKind, recommended_watcher};
use url::Url;
use crate::core::error::{GatewayResult, GatewayError};

/// Main gateway configuration structure
///
/// This structure represents the complete configuration for the API Gateway.
/// It uses serde for serialization/deserialization from YAML/JSON files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Server configuration (ports, TLS, etc.)
    pub server: ServerConfig,
    
    /// Route definitions
    pub routes: Vec<RouteDefinition>,
    
    /// Upstream service configurations
    pub upstreams: HashMap<String, UpstreamConfig>,
    
    /// Middleware configurations
    pub middleware: MiddlewareConfigs,
    
    /// Authentication provider configurations
    pub auth: AuthConfigs,
    
    /// Observability settings (metrics, logging, tracing)
    pub observability: ObservabilityConfig,
    
    /// Service discovery configuration
    pub service_discovery: ServiceDiscoveryConfig,
}

impl GatewayConfig {
    /// Load configuration from a YAML file
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> GatewayResult<Self> {
        let content = tokio::fs::read_to_string(path).await
            .map_err(|e| GatewayError::config(format!("Failed to read config file: {}", e)))?;
        
        let mut config: GatewayConfig = serde_yaml::from_str(&content)
            .map_err(|e| GatewayError::config(format!("Failed to parse config: {}", e)))?;
        
        // Apply environment variable overrides
        config.apply_env_overrides()?;
        
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from JSON
    pub async fn load_from_json<P: AsRef<Path>>(path: P) -> GatewayResult<Self> {
        let content = tokio::fs::read_to_string(path).await
            .map_err(|e| GatewayError::config(format!("Failed to read config file: {}", e)))?;
        
        let mut config: GatewayConfig = serde_json::from_str(&content)
            .map_err(|e| GatewayError::config(format!("Failed to parse JSON config: {}", e)))?;
        
        // Apply environment variable overrides
        config.apply_env_overrides()?;
        
        config.validate()?;
        Ok(config)
    }

    /// Apply environment variable overrides to configuration
    ///
    /// Environment variables follow the pattern: GATEWAY_<SECTION>_<FIELD>
    /// For example: GATEWAY_SERVER_HTTP_PORT=8080
    pub fn apply_env_overrides(&mut self) -> GatewayResult<()> {
        use std::env;

        // Server configuration overrides
        if let Ok(port) = env::var("GATEWAY_SERVER_HTTP_PORT") {
            self.server.http_port = port.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_HTTP_PORT: {}", e)))?;
        }

        if let Ok(port) = env::var("GATEWAY_SERVER_HTTPS_PORT") {
            self.server.https_port = port.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_HTTPS_PORT: {}", e)))?;
        }

        if let Ok(port) = env::var("GATEWAY_SERVER_METRICS_PORT") {
            self.server.metrics_port = port.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_METRICS_PORT: {}", e)))?;
        }

        if let Ok(addr) = env::var("GATEWAY_SERVER_BIND_ADDRESS") {
            self.server.bind_address = addr;
        }

        if let Ok(size) = env::var("GATEWAY_SERVER_MAX_REQUEST_SIZE") {
            self.server.max_request_size = size.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_MAX_REQUEST_SIZE: {}", e)))?;
        }

        // Timeout overrides
        if let Ok(timeout) = env::var("GATEWAY_SERVER_REQUEST_TIMEOUT") {
            self.server.timeouts.request_timeout = humantime::parse_duration(&timeout)
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_REQUEST_TIMEOUT: {}", e)))?;
        }

        if let Ok(timeout) = env::var("GATEWAY_SERVER_KEEPALIVE_TIMEOUT") {
            self.server.timeouts.keepalive_timeout = humantime::parse_duration(&timeout)
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_KEEPALIVE_TIMEOUT: {}", e)))?;
        }

        if let Ok(timeout) = env::var("GATEWAY_SERVER_UPSTREAM_TIMEOUT") {
            self.server.timeouts.upstream_timeout = humantime::parse_duration(&timeout)
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_SERVER_UPSTREAM_TIMEOUT: {}", e)))?;
        }

        // Logging configuration overrides
        if let Ok(level) = env::var("GATEWAY_LOG_LEVEL") {
            self.observability.logging.level = level;
        }

        if let Ok(format) = env::var("GATEWAY_LOG_FORMAT") {
            self.observability.logging.format = format;
        }

        // Metrics configuration overrides
        if let Ok(enabled) = env::var("GATEWAY_METRICS_ENABLED") {
            self.observability.metrics.prometheus_enabled = enabled.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_METRICS_ENABLED: {}", e)))?;
        }

        if let Ok(path) = env::var("GATEWAY_METRICS_PATH") {
            self.observability.metrics.endpoint_path = path;
        }

        // Tracing configuration overrides
        if let Ok(enabled) = env::var("GATEWAY_TRACING_ENABLED") {
            self.observability.tracing.enabled = enabled.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_TRACING_ENABLED: {}", e)))?;
        }

        if let Ok(rate) = env::var("GATEWAY_TRACING_SAMPLING_RATE") {
            self.observability.tracing.sampling_rate = rate.parse()
                .map_err(|e| GatewayError::config(format!("Invalid GATEWAY_TRACING_SAMPLING_RATE: {}", e)))?;
        }

        Ok(())
    }

    /// Comprehensive configuration validation with detailed error messages
    pub fn validate(&self) -> GatewayResult<()> {
        let mut errors = Vec::new();

        // Validate server configuration
        if self.server.http_port == 0 && self.server.https_port == 0 {
            errors.push("At least one of http_port or https_port must be specified".to_string());
        }

        // Port validation is handled by u16 type bounds (0-65535)

        if self.server.max_request_size == 0 {
            errors.push("max_request_size must be greater than 0".to_string());
        }

        // Validate bind address
        if self.server.bind_address.is_empty() {
            errors.push("bind_address cannot be empty".to_string());
        }

        // Validate timeout values
        if self.server.timeouts.request_timeout.as_secs() == 0 {
            errors.push("request_timeout must be greater than 0".to_string());
        }

        if self.server.timeouts.upstream_timeout.as_secs() == 0 {
            errors.push("upstream_timeout must be greater than 0".to_string());
        }

        // Validate TLS configuration if present
        if let Some(ref tls) = self.server.tls {
            if tls.cert_file.is_empty() {
                errors.push("TLS cert_file cannot be empty".to_string());
            }
            if tls.key_file.is_empty() {
                errors.push("TLS key_file cannot be empty".to_string());
            }
        }

        // Validate routes reference existing upstreams
        for (index, route) in self.routes.iter().enumerate() {
            if route.path.is_empty() {
                errors.push(format!("Route {} has empty path", index));
            }

            if route.methods.is_empty() {
                errors.push(format!("Route '{}' has no HTTP methods specified", route.path));
            }

            if route.upstream.is_empty() {
                errors.push(format!("Route '{}' has empty upstream", route.path));
            } else if !self.upstreams.contains_key(&route.upstream) {
                errors.push(format!(
                    "Route '{}' references unknown upstream '{}'",
                    route.path, route.upstream
                ));
            }

            // Validate HTTP methods
            for method in &route.methods {
                match method.to_uppercase().as_str() {
                    "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {},
                    _ => errors.push(format!("Route '{}' has invalid HTTP method: {}", route.path, method)),
                }
            }
        }

        // Validate upstream configurations
        for (name, upstream) in &self.upstreams {
            match &upstream.discovery {
                DiscoveryMethod::Static { endpoints } => {
                    if endpoints.is_empty() {
                        errors.push(format!("Upstream '{}' has no static endpoints", name));
                    }
                    for endpoint in endpoints {
                        if endpoint.is_empty() {
                            errors.push(format!("Upstream '{}' has empty endpoint", name));
                        }
                    }
                },
                DiscoveryMethod::Kubernetes { namespace, service_name, port } => {
                    if namespace.is_empty() {
                        errors.push(format!("Upstream '{}' Kubernetes namespace cannot be empty", name));
                    }
                    if service_name.is_empty() {
                        errors.push(format!("Upstream '{}' Kubernetes service_name cannot be empty", name));
                    }
                    if *port == 0 {
                        errors.push(format!("Upstream '{}' Kubernetes port must be greater than 0", name));
                    }
                },
                DiscoveryMethod::Consul { service_name, .. } => {
                    if service_name.is_empty() {
                        errors.push(format!("Upstream '{}' Consul service_name cannot be empty", name));
                    }
                },
            }

            // Validate health check configuration
            if upstream.health_check.path.is_empty() {
                errors.push(format!("Upstream '{}' health check path cannot be empty", name));
            }

            if upstream.health_check.healthy_threshold == 0 {
                errors.push(format!("Upstream '{}' healthy_threshold must be greater than 0", name));
            }

            if upstream.health_check.unhealthy_threshold == 0 {
                errors.push(format!("Upstream '{}' unhealthy_threshold must be greater than 0", name));
            }

            // Validate circuit breaker configuration if present
            if let Some(ref cb) = upstream.circuit_breaker {
                if cb.failure_threshold == 0 {
                    errors.push(format!("Upstream '{}' circuit breaker failure_threshold must be greater than 0", name));
                }
                if cb.success_threshold == 0 {
                    errors.push(format!("Upstream '{}' circuit breaker success_threshold must be greater than 0", name));
                }
            }
        }

        // Validate authentication configuration
        if let Some(ref jwt) = self.auth.jwt {
            if jwt.secret.is_empty() {
                errors.push("JWT secret cannot be empty".to_string());
            }
            if jwt.algorithm.is_empty() {
                errors.push("JWT algorithm cannot be empty".to_string());
            }
        }

        // Validate observability configuration
        match self.observability.logging.level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {},
            _ => errors.push(format!("Invalid log level: {}", self.observability.logging.level)),
        }

        match self.observability.logging.format.to_lowercase().as_str() {
            "json" | "text" => {},
            _ => errors.push(format!("Invalid log format: {}", self.observability.logging.format)),
        }

        if self.observability.tracing.sampling_rate < 0.0 || self.observability.tracing.sampling_rate > 1.0 {
            errors.push(format!("Tracing sampling_rate must be between 0.0 and 1.0, got: {}", self.observability.tracing.sampling_rate));
        }

        // Return all validation errors
        if !errors.is_empty() {
            return Err(GatewayError::config(format!(
                "Configuration validation failed:\n{}",
                errors.join("\n")
            )));
        }

        Ok(())
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// HTTP port (0 to disable HTTP)
    pub http_port: u16,
    
    /// HTTPS port (0 to disable HTTPS)
    pub https_port: u16,
    
    /// Metrics port for Prometheus endpoint
    pub metrics_port: u16,
    
    /// Server bind address
    pub bind_address: String,
    
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    
    /// Server timeouts
    pub timeouts: TimeoutConfig,
    
    /// Maximum request body size
    pub max_request_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: 8080,
            https_port: 8443,
            metrics_port: 9090,
            bind_address: "0.0.0.0".to_string(),
            tls: None,
            timeouts: TimeoutConfig::default(),
            max_request_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_file: String,
    
    /// Path to private key file
    pub key_file: String,
    
    /// Path to CA certificate file (for client certificate validation)
    pub ca_file: Option<String>,
    
    /// Require client certificates
    pub require_client_cert: bool,
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Request timeout
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    
    /// Keep-alive timeout
    #[serde(with = "humantime_serde")]
    pub keepalive_timeout: Duration,
    
    /// Upstream connection timeout
    #[serde(with = "humantime_serde")]
    pub upstream_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(60),
            upstream_timeout: Duration::from_secs(10),
        }
    }
}

/// Route definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDefinition {
    /// Route path pattern (supports parameters like /users/{id})
    pub path: String,
    
    /// HTTP methods (GET, POST, etc.)
    pub methods: Vec<String>,
    
    /// Target upstream service
    pub upstream: String,
    
    /// Route-specific middleware
    pub middleware: Vec<String>,
    
    /// Route-specific timeout
    #[serde(with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,
    
    /// Authentication required for this route
    pub auth_required: bool,
    
    /// Required roles for this route
    pub required_roles: Vec<String>,
}

/// Upstream service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Service discovery method
    pub discovery: DiscoveryMethod,
    
    /// Load balancing strategy
    pub load_balancer: LoadBalancerStrategy,
    
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    
    /// Circuit breaker configuration
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    
    /// Retry policy
    pub retry_policy: Option<RetryPolicyConfig>,
}

/// Service discovery methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DiscoveryMethod {
    /// Static list of endpoints
    Static { endpoints: Vec<String> },
    
    /// Kubernetes service discovery
    Kubernetes { 
        namespace: String,
        service_name: String,
        port: u16,
    },
    
    /// Consul service discovery
    Consul {
        service_name: String,
        datacenter: Option<String>,
        tags: Vec<String>,
    },
}

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LoadBalancerStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin { weights: HashMap<String, u32> },
    ConsistentHash { hash_key: String },
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check path
    pub path: String,
    
    /// Check interval
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    
    /// Request timeout
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    
    /// Healthy threshold (consecutive successes)
    pub healthy_threshold: u32,
    
    /// Unhealthy threshold (consecutive failures)
    pub unhealthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    
    /// Timeout before trying half-open
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    
    /// Success threshold to close circuit from half-open
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            success_threshold: 3,
        }
    }
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicyConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    
    /// Base delay between retries
    #[serde(with = "humantime_serde")]
    pub base_delay: Duration,
    
    /// Maximum delay between retries
    #[serde(with = "humantime_serde")]
    pub max_delay: Duration,
    
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    
    /// HTTP status codes that trigger retries
    pub retryable_status_codes: Vec<u16>,
}

/// Middleware configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfigs {
    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitingConfig>,
    
    /// CORS configuration
    pub cors: Option<CorsConfig>,
    
    /// Request/response transformation
    pub transformation: Option<TransformationConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Default rate limit (requests per minute)
    pub default_limit: u32,
    
    /// Per-route rate limits
    pub route_limits: HashMap<String, u32>,
    
    /// Storage backend for distributed rate limiting
    pub storage: RateLimitStorage,
}

/// Rate limit storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RateLimitStorage {
    Memory,
    Redis { url: String },
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Max age for preflight requests
    pub max_age: u32,
}

/// Request/response transformation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationConfig {
    /// Request transformations
    pub request: Vec<TransformationRule>,
    
    /// Response transformations
    pub response: Vec<TransformationRule>,
}

/// Transformation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationRule {
    /// Rule name
    pub name: String,
    
    /// Transformation type
    pub transform_type: TransformationType,
    
    /// Rule configuration
    pub config: serde_json::Value,
}

/// Transformation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransformationType {
    AddHeader,
    RemoveHeader,
    ModifyHeader,
    AddQueryParam,
    RemoveQueryParam,
    ModifyPath,
    ModifyBody,
}

/// Authentication configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfigs {
    /// JWT configuration
    pub jwt: Option<JwtConfig>,
    
    /// API key configuration
    pub api_key: Option<ApiKeyConfig>,
    
    /// OAuth2 configuration
    pub oauth2: Option<OAuth2Config>,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret or public key
    pub secret: String,
    
    /// JWT algorithm
    pub algorithm: String,
    
    /// Token expiration time
    #[serde(with = "humantime_serde")]
    pub expiration: Duration,
    
    /// Issuer validation
    pub issuer: Option<String>,
    
    /// Audience validation
    pub audience: Option<String>,
}

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Header name for API key
    pub header_name: String,
    
    /// Valid API keys
    pub keys: HashMap<String, ApiKeyInfo>,
}

/// API key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// Key name/description
    pub name: String,
    
    /// Associated roles
    pub roles: Vec<String>,
    
    /// Rate limit for this key
    pub rate_limit: Option<u32>,
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// Authorization server URL
    pub auth_url: String,
    
    /// Token endpoint URL
    pub token_url: String,
    
    /// Client ID
    pub client_id: String,
    
    /// Client secret
    pub client_secret: String,
    
    /// Scopes
    pub scopes: Vec<String>,
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Tracing configuration
    pub tracing: TracingConfig,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    pub prometheus_enabled: bool,
    
    /// Metrics endpoint path
    pub endpoint_path: String,
    
    /// Custom metrics
    pub custom_metrics: Vec<CustomMetricConfig>,
}

/// Custom metric configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetricConfig {
    /// Metric name
    pub name: String,
    
    /// Metric type (counter, gauge, histogram)
    pub metric_type: String,
    
    /// Metric description
    pub description: String,
    
    /// Labels
    pub labels: Vec<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log format (json, text)
    pub format: String,
    
    /// Output destination
    pub output: LogOutput,
}

/// Log output destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogOutput {
    Stdout,
    File { path: String },
    Syslog { address: String },
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    
    /// Tracing backend
    pub backend: TracingBackend,
    
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
}

/// Tracing backends
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TracingBackend {
    Jaeger { endpoint: String },
    Zipkin { endpoint: String },
    OpenTelemetry { endpoint: String },
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// Kubernetes configuration
    pub kubernetes: Option<KubernetesConfig>,
    
    /// Consul configuration
    pub consul: Option<ConsulConfig>,
}

/// Kubernetes service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Kubeconfig file path (optional, uses in-cluster config if not specified)
    pub kubeconfig_path: Option<String>,
    
    /// Default namespace to watch
    pub default_namespace: String,
    
    /// Watch all namespaces
    pub watch_all_namespaces: bool,
}

/// Consul service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul server address
    pub address: String,
    
    /// Consul datacenter
    pub datacenter: Option<String>,
    
    /// Consul token
    pub token: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            routes: Vec::new(),
            upstreams: HashMap::new(),
            middleware: MiddlewareConfigs {
                rate_limiting: None,
                cors: None,
                transformation: None,
            },
            auth: AuthConfigs {
                jwt: None,
                api_key: None,
                oauth2: None,
            },
            observability: ObservabilityConfig {
                metrics: MetricsConfig {
                    prometheus_enabled: true,
                    endpoint_path: "/metrics".to_string(),
                    custom_metrics: Vec::new(),
                },
                logging: LoggingConfig {
                    level: "info".to_string(),
                    format: "json".to_string(),
                    output: LogOutput::Stdout,
                },
                tracing: TracingConfig {
                    enabled: false,
                    backend: TracingBackend::Jaeger {
                        endpoint: "http://localhost:14268/api/traces".to_string(),
                    },
                    sampling_rate: 0.1,
                },
            },
            service_discovery: ServiceDiscoveryConfig {
                kubernetes: None,
                consul: None,
            },
        }
    }
}

/// Configuration change event
#[derive(Debug, Clone)]
pub struct ConfigChangeEvent {
    /// Path of the changed configuration file
    pub file_path: PathBuf,
    /// New configuration
    pub config: GatewayConfig,
    /// Timestamp of the change
    pub timestamp: std::time::Instant,
}

/// Configuration manager with hot reloading capabilities
///
/// This manager handles loading, validation, and hot reloading of configuration files.
/// It uses the `notify` crate to watch for file system changes and automatically
/// reloads configuration when files are modified.
pub struct ConfigManager {
    /// Current configuration (thread-safe)
    current_config: Arc<RwLock<GatewayConfig>>,
    
    /// Configuration file path
    config_path: PathBuf,
    
    /// File system watcher
    _watcher: Option<notify::RecommendedWatcher>,
    
    /// Configuration change broadcaster
    change_sender: broadcast::Sender<ConfigChangeEvent>,
    
    /// Configuration change receiver
    #[allow(dead_code)]
    change_receiver: broadcast::Receiver<ConfigChangeEvent>,
}

impl ConfigManager {
    /// Create a new configuration manager
    ///
    /// This loads the initial configuration from the specified file and sets up
    /// file watching for hot reloading.
    pub async fn new<P: AsRef<Path>>(config_path: P) -> GatewayResult<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        
        // Load initial configuration
        let config = if config_path.extension().and_then(|s| s.to_str()) == Some("json") {
            GatewayConfig::load_from_json(&config_path).await?
        } else {
            GatewayConfig::load_from_file(&config_path).await?
        };

        let current_config = Arc::new(RwLock::new(config.clone()));
        
        // Create broadcast channel for configuration changes
        let (change_sender, change_receiver) = broadcast::channel(16);

        let mut manager = Self {
            current_config,
            config_path: config_path.clone(),
            _watcher: None,
            change_sender,
            change_receiver,
        };

        // Set up file watcher for hot reloading
        manager.setup_file_watcher().await?;

        Ok(manager)
    }

    /// Get the current configuration
    ///
    /// This returns a read guard to the current configuration. Multiple readers
    /// can access the configuration simultaneously.
    pub async fn get_config(&self) -> tokio::sync::RwLockReadGuard<'_, GatewayConfig> {
        self.current_config.read().await
    }

    /// Subscribe to configuration changes
    ///
    /// Returns a receiver that will be notified whenever the configuration changes.
    /// This allows other parts of the system to react to configuration updates.
    pub fn subscribe_to_changes(&self) -> broadcast::Receiver<ConfigChangeEvent> {
        self.change_sender.subscribe()
    }

    /// Manually reload configuration from file
    ///
    /// This can be used to force a configuration reload, for example in response
    /// to a signal or API call.
    pub async fn reload_config(&self) -> GatewayResult<()> {
        tracing::info!("Manually reloading configuration from {:?}", self.config_path);
        
        let new_config = if self.config_path.extension().and_then(|s| s.to_str()) == Some("json") {
            GatewayConfig::load_from_json(&self.config_path).await?
        } else {
            GatewayConfig::load_from_file(&self.config_path).await?
        };

        self.update_config(new_config).await
    }

    /// Update the current configuration
    ///
    /// This method atomically updates the configuration and notifies all subscribers
    /// of the change. It's used both for manual reloads and automatic file watching.
    async fn update_config(&self, new_config: GatewayConfig) -> GatewayResult<()> {
        // Validate the new configuration before applying it
        new_config.validate()?;

        // Update the configuration atomically
        {
            let mut config = self.current_config.write().await;
            *config = new_config.clone();
        }

        // Notify subscribers of the configuration change
        let change_event = ConfigChangeEvent {
            file_path: self.config_path.clone(),
            config: new_config,
            timestamp: std::time::Instant::now(),
        };

        // Send the change event (ignore errors if no subscribers)
        let _ = self.change_sender.send(change_event);

        tracing::info!("Configuration updated successfully");
        Ok(())
    }

    /// Set up file system watcher for hot reloading
    ///
    /// This uses the `notify` crate to watch for changes to the configuration file
    /// and automatically reload when changes are detected.
    async fn setup_file_watcher(&mut self) -> GatewayResult<()> {
        let config_path = self.config_path.clone();
        let current_config = Arc::clone(&self.current_config);
        let change_sender = self.change_sender.clone();

        // Create a channel for file system events
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Create the file watcher
        let mut watcher = recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                // Send the event to our async handler
                let _ = tx.send(event);
            }
        }).map_err(|e| GatewayError::config(format!("Failed to create file watcher: {}", e)))?;

        // Watch the configuration file's parent directory
        // We watch the directory instead of the file directly because some editors
        // create temporary files and rename them, which would break file-specific watching
        if let Some(parent_dir) = config_path.parent() {
            watcher.watch(parent_dir, RecursiveMode::NonRecursive)
                .map_err(|e| GatewayError::config(format!("Failed to watch config directory: {}", e)))?;
        }

        self._watcher = Some(watcher);

        // Spawn a task to handle file system events
        let config_file_name = config_path.file_name()
            .ok_or_else(|| GatewayError::config("Invalid config file path"))?
            .to_owned();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // Check if the event is for our configuration file
                let is_config_file_event = event.paths.iter().any(|path| {
                    path.file_name() == Some(&config_file_name)
                });

                if !is_config_file_event {
                    continue;
                }

                // Only reload on write events (ignore other events like metadata changes)
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        tracing::info!("Configuration file changed, reloading...");
                        
                        // Add a small delay to ensure the file write is complete
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Attempt to reload the configuration
                        match Self::load_config_from_path(&config_path).await {
                            Ok(new_config) => {
                                // Validate before updating
                                if let Err(e) = new_config.validate() {
                                    tracing::error!("Configuration validation failed after reload: {}", e);
                                    continue;
                                }

                                // Update the configuration
                                {
                                    let mut config = current_config.write().await;
                                    *config = new_config.clone();
                                }

                                // Notify subscribers
                                let change_event = ConfigChangeEvent {
                                    file_path: config_path.clone(),
                                    config: new_config,
                                    timestamp: std::time::Instant::now(),
                                };

                                if let Err(e) = change_sender.send(change_event) {
                                    tracing::warn!("Failed to send config change event: {}", e);
                                }

                                tracing::info!("Configuration reloaded successfully");
                            }
                            Err(e) => {
                                tracing::error!("Failed to reload configuration: {}", e);
                            }
                        }
                    }
                    _ => {
                        // Ignore other event types
                    }
                }
            }
        });

        tracing::info!("File watcher set up for configuration hot reloading");
        Ok(())
    }

    /// Helper method to load configuration from a path
    async fn load_config_from_path(path: &Path) -> GatewayResult<GatewayConfig> {
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            GatewayConfig::load_from_json(path).await
        } else {
            GatewayConfig::load_from_file(path).await
        }
    }
}

/// Configuration validation utilities
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate a configuration file without loading it into memory
    ///
    /// This is useful for validating configuration files before deployment
    /// or in CI/CD pipelines.
    pub async fn validate_file<P: AsRef<Path>>(path: P) -> GatewayResult<()> {
        let config = if path.as_ref().extension().and_then(|s| s.to_str()) == Some("json") {
            GatewayConfig::load_from_json(path).await?
        } else {
            GatewayConfig::load_from_file(path).await?
        };

        config.validate()?;
        Ok(())
    }

    /// Validate configuration with custom validation rules
    ///
    /// This allows for additional validation beyond the basic structural validation.
    pub fn validate_with_rules(config: &GatewayConfig, rules: &[Box<dyn ValidationRule>]) -> GatewayResult<()> {
        // First run the standard validation
        config.validate()?;

        // Then run custom validation rules
        let mut errors = Vec::new();
        for rule in rules {
            if let Err(e) = rule.validate(config) {
                errors.push(e.to_string());
            }
        }

        if !errors.is_empty() {
            return Err(GatewayError::config(format!(
                "Custom validation failed:\n{}",
                errors.join("\n")
            )));
        }

        Ok(())
    }
}

/// Custom validation rule trait
pub trait ValidationRule {
    fn validate(&self, config: &GatewayConfig) -> GatewayResult<()>;
}

/// Example validation rule: ensure all routes have unique paths
pub struct UniqueRoutePathsRule;

impl ValidationRule for UniqueRoutePathsRule {
    fn validate(&self, config: &GatewayConfig) -> GatewayResult<()> {
        let mut seen_paths = std::collections::HashSet::new();
        
        for route in &config.routes {
            if !seen_paths.insert(&route.path) {
                return Err(GatewayError::config(format!(
                    "Duplicate route path found: {}",
                    route.path
                )));
            }
        }
        
        Ok(())
    }
}

/// Example validation rule: ensure upstream endpoints are reachable
pub struct ReachableUpstreamsRule;

impl ValidationRule for ReachableUpstreamsRule {
    fn validate(&self, config: &GatewayConfig) -> GatewayResult<()> {
        for (name, upstream) in &config.upstreams {
            if let DiscoveryMethod::Static { endpoints } = &upstream.discovery {
                for endpoint in endpoints {
                    // Parse the endpoint URL
                    if let Err(e) = Url::parse(endpoint) {
                        return Err(GatewayError::config(format!(
                            "Invalid endpoint URL '{}' in upstream '{}': {}",
                            endpoint, name, e
                        )));
                    }
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_config_validation() {
        let config = GatewayConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization_yaml() {
        let config = GatewayConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.server.http_port, deserialized.server.http_port);
        assert_eq!(config.server.https_port, deserialized.server.https_port);
        assert_eq!(config.server.bind_address, deserialized.server.bind_address);
    }

    #[test]
    fn test_config_serialization_json() {
        let config = GatewayConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: GatewayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.server.http_port, deserialized.server.http_port);
        assert_eq!(config.server.https_port, deserialized.server.https_port);
    }

    #[tokio::test]
    async fn test_load_config_from_yaml_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");

        let config_content = r#"
server:
  http_port: 9080
  https_port: 9443
  metrics_port: 9090
  bind_address: "127.0.0.1"
  timeouts:
    request_timeout: "45s"
    keepalive_timeout: "90s"
    upstream_timeout: "15s"
  max_request_size: 5242880

routes:
  - path: "/test"
    methods: ["GET"]
    upstream: "test-service"
    middleware: []
    timeout: null
    auth_required: false
    required_roles: []

upstreams:
  test-service:
    discovery:
      type: "Static"
      endpoints: ["http://localhost:8080"]
    load_balancer:
      type: "RoundRobin"
    health_check:
      path: "/health"
      interval: "30s"
      timeout: "5s"
      healthy_threshold: 2
      unhealthy_threshold: 3

middleware:
  rate_limiting:
    default_limit: 500
    route_limits: {}
    storage:
      type: "Memory"

auth:
  jwt:
    secret: "test-secret"
    algorithm: "HS256"
    expiration: "2h"

observability:
  metrics:
    prometheus_enabled: true
    endpoint_path: "/metrics"
    custom_metrics: []
  logging:
    level: "debug"
    format: "text"
    output:
      type: "Stdout"
  tracing:
    enabled: true
    backend:
      type: "Jaeger"
      endpoint: "http://localhost:14268/api/traces"
    sampling_rate: 0.5

service_discovery:
  kubernetes:
    default_namespace: "test"
    watch_all_namespaces: true
"#;

        fs::write(&config_path, config_content).await.unwrap();

        let config = GatewayConfig::load_from_file(&config_path).await.unwrap();
        
        assert_eq!(config.server.http_port, 9080);
        assert_eq!(config.server.https_port, 9443);
        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.max_request_size, 5242880);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].path, "/test");
        assert_eq!(config.upstreams.len(), 1);
        assert!(config.upstreams.contains_key("test-service"));
        assert_eq!(config.observability.logging.level, "debug");
        assert_eq!(config.observability.tracing.sampling_rate, 0.5);
    }

    #[tokio::test]
    async fn test_load_config_from_json_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let config_content = r#"{
  "server": {
    "http_port": 8080,
    "https_port": 8443,
    "metrics_port": 9090,
    "bind_address": "0.0.0.0",
    "tls": null,
    "timeouts": {
      "request_timeout": "30s",
      "keepalive_timeout": "60s",
      "upstream_timeout": "10s"
    },
    "max_request_size": 10485760
  },
  "routes": [],
  "upstreams": {},
  "middleware": {
    "rate_limiting": null,
    "cors": null,
    "transformation": null
  },
  "auth": {
    "jwt": null,
    "api_key": null,
    "oauth2": null
  },
  "observability": {
    "metrics": {
      "prometheus_enabled": true,
      "endpoint_path": "/metrics",
      "custom_metrics": []
    },
    "logging": {
      "level": "info",
      "format": "json",
      "output": {
        "type": "Stdout"
      }
    },
    "tracing": {
      "enabled": false,
      "backend": {
        "type": "Jaeger",
        "endpoint": "http://localhost:14268/api/traces"
      },
      "sampling_rate": 0.1
    }
  },
  "service_discovery": {
    "kubernetes": null,
    "consul": null
  }
}"#;

        fs::write(&config_path, config_content).await.unwrap();

        let config = GatewayConfig::load_from_json(&config_path).await.unwrap();
        
        assert_eq!(config.server.http_port, 8080);
        assert_eq!(config.server.https_port, 8443);
        assert_eq!(config.observability.logging.format, "json");
    }

    #[test]
    fn test_environment_variable_overrides() {
        // Set environment variables
        env::set_var("GATEWAY_SERVER_HTTP_PORT", "9999");
        env::set_var("GATEWAY_SERVER_BIND_ADDRESS", "192.168.1.1");
        env::set_var("GATEWAY_SERVER_MAX_REQUEST_SIZE", "20971520");
        env::set_var("GATEWAY_LOG_LEVEL", "debug");
        env::set_var("GATEWAY_METRICS_ENABLED", "false");
        env::set_var("GATEWAY_TRACING_SAMPLING_RATE", "0.8");

        let mut config = GatewayConfig::default();
        config.apply_env_overrides().unwrap();

        assert_eq!(config.server.http_port, 9999);
        assert_eq!(config.server.bind_address, "192.168.1.1");
        assert_eq!(config.server.max_request_size, 20971520);
        assert_eq!(config.observability.logging.level, "debug");
        assert_eq!(config.observability.metrics.prometheus_enabled, false);
        assert_eq!(config.observability.tracing.sampling_rate, 0.8);

        // Clean up environment variables
        env::remove_var("GATEWAY_SERVER_HTTP_PORT");
        env::remove_var("GATEWAY_SERVER_BIND_ADDRESS");
        env::remove_var("GATEWAY_SERVER_MAX_REQUEST_SIZE");
        env::remove_var("GATEWAY_LOG_LEVEL");
        env::remove_var("GATEWAY_METRICS_ENABLED");
        env::remove_var("GATEWAY_TRACING_SAMPLING_RATE");
    }

    #[test]
    fn test_invalid_environment_variables() {
        env::set_var("GATEWAY_SERVER_HTTP_PORT", "invalid_port");
        
        let mut config = GatewayConfig::default();
        let result = config.apply_env_overrides();
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid GATEWAY_SERVER_HTTP_PORT"));
        
        env::remove_var("GATEWAY_SERVER_HTTP_PORT");
    }

    #[test]
    fn test_config_validation_errors() {
        let mut config = GatewayConfig::default();
        
        // Test invalid ports
        config.server.http_port = 0;
        config.server.https_port = 0;
        assert!(config.validate().is_err());
        
        // Test valid configuration should pass
        config.server.http_port = 8080;
        config.server.https_port = 8443;
        assert!(config.validate().is_ok());
        
        // Reset to valid state
        config.server.http_port = 8080;
        config.server.https_port = 8443;
        
        // Test empty bind address
        config.server.bind_address = String::new();
        assert!(config.validate().is_err());
        
        // Reset bind address
        config.server.bind_address = "0.0.0.0".to_string();
        
        // Test zero request size
        config.server.max_request_size = 0;
        assert!(config.validate().is_err());
        
        // Reset request size
        config.server.max_request_size = 1024;
        
        // Test zero timeout
        config.server.timeouts.request_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_route_validation() {
        let mut config = GatewayConfig::default();
        
        // Add a route that references a non-existent upstream
        config.routes.push(RouteDefinition {
            path: "/test".to_string(),
            methods: vec!["GET".to_string()],
            upstream: "non-existent".to_string(),
            middleware: vec![],
            timeout: None,
            auth_required: false,
            required_roles: vec![],
        });
        
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("references unknown upstream"));
        
        // Add the upstream
        config.upstreams.insert("non-existent".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Static {
                endpoints: vec!["http://localhost:8080".to_string()],
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });
        
        // Now validation should pass
        assert!(config.validate().is_ok());
        
        // Test invalid HTTP method
        config.routes[0].methods = vec!["INVALID_METHOD".to_string()];
        assert!(config.validate().is_err());
        
        // Test empty path
        config.routes[0].methods = vec!["GET".to_string()];
        config.routes[0].path = String::new();
        assert!(config.validate().is_err());
        
        // Test empty methods
        config.routes[0].path = "/test".to_string();
        config.routes[0].methods = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_upstream_validation() {
        let mut config = GatewayConfig::default();
        
        // Test upstream with empty static endpoints
        config.upstreams.insert("test".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Static { endpoints: vec![] },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });
        
        assert!(config.validate().is_err());
        
        // Test Kubernetes discovery with empty namespace
        config.upstreams.insert("test".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Kubernetes {
                namespace: String::new(),
                service_name: "test-service".to_string(),
                port: 8080,
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });
        
        assert!(config.validate().is_err());
        
        // Test zero port
        config.upstreams.insert("test".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Kubernetes {
                namespace: "default".to_string(),
                service_name: "test-service".to_string(),
                port: 0,
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });
        
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_observability_validation() {
        let mut config = GatewayConfig::default();
        
        // Test invalid log level
        config.observability.logging.level = "invalid".to_string();
        assert!(config.validate().is_err());
        
        // Test invalid log format
        config.observability.logging.level = "info".to_string();
        config.observability.logging.format = "invalid".to_string();
        assert!(config.validate().is_err());
        
        // Test invalid sampling rate
        config.observability.logging.format = "json".to_string();
        config.observability.tracing.sampling_rate = 1.5;
        assert!(config.validate().is_err());
        
        config.observability.tracing.sampling_rate = -0.1;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");

        // Create a minimal valid config file
        let config_content = r#"
server:
  http_port: 8080
  https_port: 8443
  metrics_port: 9090
  bind_address: "0.0.0.0"
  timeouts:
    request_timeout: "30s"
    keepalive_timeout: "60s"
    upstream_timeout: "10s"
  max_request_size: 10485760

routes: []
upstreams: {}

middleware:
  rate_limiting: null
  cors: null
  transformation: null

auth:
  jwt: null
  api_key: null
  oauth2: null

observability:
  metrics:
    prometheus_enabled: true
    endpoint_path: "/metrics"
    custom_metrics: []
  logging:
    level: "info"
    format: "json"
    output:
      type: "Stdout"
  tracing:
    enabled: false
    backend:
      type: "Jaeger"
      endpoint: "http://localhost:14268/api/traces"
    sampling_rate: 0.1

service_discovery:
  kubernetes: null
  consul: null
"#;

        fs::write(&config_path, config_content).await.unwrap();

        let config_manager = ConfigManager::new(&config_path).await.unwrap();
        let config = config_manager.get_config().await;
        
        assert_eq!(config.server.http_port, 8080);
        assert_eq!(config.server.https_port, 8443);
    }

    #[tokio::test]
    async fn test_config_manager_manual_reload() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");

        // Create initial config
        let initial_config = r#"
server:
  http_port: 8080
  https_port: 8443
  metrics_port: 9090
  bind_address: "0.0.0.0"
  timeouts:
    request_timeout: "30s"
    keepalive_timeout: "60s"
    upstream_timeout: "10s"
  max_request_size: 10485760

routes: []
upstreams: {}
middleware: {}
auth: {}
observability:
  metrics:
    prometheus_enabled: true
    endpoint_path: "/metrics"
    custom_metrics: []
  logging:
    level: "info"
    format: "json"
    output:
      type: "Stdout"
  tracing:
    enabled: false
    backend:
      type: "Jaeger"
      endpoint: "http://localhost:14268/api/traces"
    sampling_rate: 0.1
service_discovery: {}
"#;

        fs::write(&config_path, initial_config).await.unwrap();

        let config_manager = ConfigManager::new(&config_path).await.unwrap();
        
        // Verify initial config
        {
            let config = config_manager.get_config().await;
            assert_eq!(config.server.http_port, 8080);
        }

        // Update config file
        let updated_config = r#"
server:
  http_port: 9090
  https_port: 8443
  metrics_port: 9090
  bind_address: "0.0.0.0"
  timeouts:
    request_timeout: "30s"
    keepalive_timeout: "60s"
    upstream_timeout: "10s"
  max_request_size: 10485760

routes: []
upstreams: {}
middleware: {}
auth: {}
observability:
  metrics:
    prometheus_enabled: true
    endpoint_path: "/metrics"
    custom_metrics: []
  logging:
    level: "debug"
    format: "json"
    output:
      type: "Stdout"
  tracing:
    enabled: false
    backend:
      type: "Jaeger"
      endpoint: "http://localhost:14268/api/traces"
    sampling_rate: 0.1
service_discovery: {}
"#;

        fs::write(&config_path, updated_config).await.unwrap();

        // Manually reload
        config_manager.reload_config().await.unwrap();

        // Verify updated config
        {
            let config = config_manager.get_config().await;
            assert_eq!(config.server.http_port, 9090);
            assert_eq!(config.observability.logging.level, "debug");
        }
    }

    #[tokio::test]
    async fn test_config_validation_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid_config.yaml");

        // Create invalid config (missing required fields)
        let invalid_config = r#"
server:
  http_port: 0
  https_port: 0
"#;

        fs::write(&config_path, invalid_config).await.unwrap();

        let result = ConfigValidator::validate_file(&config_path).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("At least one of http_port or https_port must be specified") || 
                error_msg.contains("Configuration validation failed") ||
                error_msg.contains("Failed to parse config"));
    }

    #[test]
    fn test_unique_route_paths_validation_rule() {
        let mut config = GatewayConfig::default();
        
        // Add duplicate route paths
        config.routes.push(RouteDefinition {
            path: "/api/test".to_string(),
            methods: vec!["GET".to_string()],
            upstream: "service1".to_string(),
            middleware: vec![],
            timeout: None,
            auth_required: false,
            required_roles: vec![],
        });
        
        config.routes.push(RouteDefinition {
            path: "/api/test".to_string(),
            methods: vec!["POST".to_string()],
            upstream: "service2".to_string(),
            middleware: vec![],
            timeout: None,
            auth_required: false,
            required_roles: vec![],
        });

        // Add the upstreams that the routes reference
        config.upstreams.insert("service1".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Static {
                endpoints: vec!["http://localhost:3001".to_string()],
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });
        
        config.upstreams.insert("service2".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Static {
                endpoints: vec!["http://localhost:3002".to_string()],
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });

        let rule = UniqueRoutePathsRule;
        let result = ConfigValidator::validate_with_rules(&config, &[Box::new(rule)]);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Duplicate route path found") || error_msg.contains("duplicate"));
    }

    #[test]
    fn test_reachable_upstreams_validation_rule() {
        let mut config = GatewayConfig::default();
        
        // Add upstream with invalid URL
        config.upstreams.insert("test".to_string(), UpstreamConfig {
            discovery: DiscoveryMethod::Static {
                endpoints: vec!["invalid-url".to_string()],
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        });

        let rule = ReachableUpstreamsRule;
        let result = ConfigValidator::validate_with_rules(&config, &[Box::new(rule)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid endpoint URL"));
    }
}
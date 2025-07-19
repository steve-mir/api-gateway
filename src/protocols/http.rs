//! # HTTP Protocol Handler
//!
//! This module handles HTTP protocol-specific functionality including:
//! - HTTP/1.1 and HTTP/2 support
//! - Request/response compression (gzip, brotli)
//! - CORS handling with configurable policies
//! - OpenAPI/Swagger integration for request validation
//! - Request timeout and deadline propagation
//!
//! ## Rust Concepts Used
//!
//! - `Arc<T>` for sharing configuration across async tasks
//! - `async/await` for non-blocking I/O operations
//! - Tower middleware for request/response processing
//! - Hyper for low-level HTTP handling

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::RequestContext;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue, Method, StatusCode, Version},
    response::Response,
};
// use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tower_http::compression::{CompressionLayer, CompressionLevel};
use tower_http::cors::{CorsLayer, Any};
use tracing::{debug, info, warn, instrument};

/// HTTP handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Enable HTTP/2 support
    pub http2_enabled: bool,
    
    /// HTTP/2 configuration
    pub http2: Http2Config,
    
    /// Compression configuration
    pub compression: CompressionConfig,
    
    /// CORS configuration
    pub cors: CorsConfig,
    
    /// OpenAPI validation configuration
    pub openapi: Option<OpenApiConfig>,
    
    /// Timeout configuration
    pub timeouts: HttpTimeoutConfig,
    
    /// Maximum request body size
    pub max_body_size: usize,
    
    /// Keep-alive settings
    pub keep_alive: KeepAliveConfig,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            http2_enabled: true,
            http2: Http2Config::default(),
            compression: CompressionConfig::default(),
            cors: CorsConfig::default(),
            openapi: None,
            timeouts: HttpTimeoutConfig::default(),
            max_body_size: 16 * 1024 * 1024, // 16MB
            keep_alive: KeepAliveConfig::default(),
        }
    }
}

/// HTTP/2 specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    /// Maximum concurrent streams per connection
    pub max_concurrent_streams: u32,
    
    /// Initial connection window size
    pub initial_connection_window_size: u32,
    
    /// Initial stream window size
    pub initial_stream_window_size: u32,
    
    /// Maximum frame size
    pub max_frame_size: u32,
    
    /// Enable server push (HTTP/2 feature)
    pub enable_push: bool,
    
    /// Keep alive interval
    pub keep_alive_interval: Duration,
    
    /// Keep alive timeout
    pub keep_alive_timeout: Duration,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            initial_connection_window_size: 1024 * 1024, // 1MB
            initial_stream_window_size: 64 * 1024,       // 64KB
            max_frame_size: 16 * 1024,                   // 16KB
            enable_push: false,
            keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(10),
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Enable compression
    pub enabled: bool,
    
    /// Supported compression algorithms
    pub algorithms: Vec<CompressionAlgorithm>,
    
    /// Compression level (1-9, where 9 is maximum compression)
    pub level: u8,
    
    /// Minimum response size to compress (bytes)
    pub min_size: usize,
    
    /// Content types to compress
    pub content_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithms: vec![
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Deflate,
            ],
            level: 6, // Balanced compression level
            min_size: 1024, // 1KB minimum
            content_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "text/javascript".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/xml".to_string(),
                "text/plain".to_string(),
            ],
        }
    }
}

/// Supported compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    Deflate,
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::Gzip => write!(f, "gzip"),
            CompressionAlgorithm::Brotli => write!(f, "br"),
            CompressionAlgorithm::Deflate => write!(f, "deflate"),
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Enable CORS
    pub enabled: bool,
    
    /// Allowed origins (use "*" for any origin)
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Exposed headers
    pub exposed_headers: Vec<String>,
    
    /// Allow credentials
    pub allow_credentials: bool,
    
    /// Max age for preflight requests (seconds)
    pub max_age: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "content-type".to_string(),
                "authorization".to_string(),
                "x-requested-with".to_string(),
                "x-api-key".to_string(),
            ],
            exposed_headers: vec![
                "x-request-id".to_string(),
                "x-response-time".to_string(),
            ],
            allow_credentials: false,
            max_age: 86400, // 24 hours
        }
    }
}

/// OpenAPI validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiConfig {
    /// Path to OpenAPI specification file
    pub spec_path: String,
    
    /// Enable request validation
    pub validate_requests: bool,
    
    /// Enable response validation
    pub validate_responses: bool,
    
    /// Strict validation mode
    pub strict_mode: bool,
    
    /// Custom error responses
    pub custom_error_responses: HashMap<String, String>,
}

/// HTTP timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTimeoutConfig {
    /// Request timeout
    pub request_timeout: Duration,
    
    /// Header timeout
    pub header_timeout: Duration,
    
    /// Body timeout
    pub body_timeout: Duration,
    
    /// Keep-alive timeout
    pub keep_alive_timeout: Duration,
    
    /// Upstream timeout
    pub upstream_timeout: Duration,
}

impl Default for HttpTimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            upstream_timeout: Duration::from_secs(30),
        }
    }
}

/// Keep-alive configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepAliveConfig {
    /// Enable keep-alive
    pub enabled: bool,
    
    /// Keep-alive timeout
    pub timeout: Duration,
    
    /// Maximum requests per connection
    pub max_requests: Option<u32>,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_secs(60),
            max_requests: Some(1000),
        }
    }
}

/// HTTP protocol handler
pub struct HttpHandler {
    /// Handler configuration
    config: Arc<HttpConfig>,
    
    /// OpenAPI validator (if configured)
    openapi_validator: Option<Arc<OpenApiValidator>>,
    
    /// Compression layer
    compression_layer: Option<CompressionLayer>,
    
    /// CORS layer
    cors_layer: Option<CorsLayer>,
}

impl HttpHandler {
    /// Create a new HTTP handler with configuration
    pub fn new(config: HttpConfig) -> GatewayResult<Self> {
        let config = Arc::new(config);
        
        // Initialize OpenAPI validator if configured
        let openapi_validator = if let Some(ref openapi_config) = config.openapi {
            Some(Arc::new(OpenApiValidator::new(openapi_config.clone())?))
        } else {
            None
        };
        
        // Create compression layer if enabled
        let compression_layer = if config.compression.enabled {
            let level = match config.compression.level {
                1..=3 => CompressionLevel::Fastest,
                4..=6 => CompressionLevel::Default,
                7..=9 => CompressionLevel::Best,
                _ => CompressionLevel::Default,
            };
            Some(CompressionLayer::new().quality(level))
        } else {
            None
        };
        
        // Create CORS layer if enabled
        let cors_layer = if config.cors.enabled {
            let mut cors = CorsLayer::new();
            
            // Configure allowed origins
            if config.cors.allowed_origins.contains(&"*".to_string()) {
                cors = cors.allow_origin(Any);
            } else {
                for origin in &config.cors.allowed_origins {
                    if let Ok(origin_header) = origin.parse::<HeaderValue>() {
                        cors = cors.allow_origin(origin_header);
                    }
                }
            }
            
            // Configure allowed methods
            let methods: Result<Vec<Method>, _> = config.cors.allowed_methods
                .iter()
                .map(|m| m.parse())
                .collect();
            
            if let Ok(methods) = methods {
                cors = cors.allow_methods(methods);
            }
            
            // Configure allowed headers
            let headers: Result<Vec<HeaderName>, _> = config.cors.allowed_headers
                .iter()
                .map(|h| h.parse())
                .collect();
            
            if let Ok(headers) = headers {
                cors = cors.allow_headers(headers);
            }
            
            // Configure exposed headers
            let exposed: Result<Vec<HeaderName>, _> = config.cors.exposed_headers
                .iter()
                .map(|h| h.parse())
                .collect();
            
            if let Ok(exposed) = exposed {
                cors = cors.expose_headers(exposed);
            }
            
            // Configure credentials and max age
            cors = cors.allow_credentials(config.cors.allow_credentials);
            cors = cors.max_age(Duration::from_secs(config.cors.max_age as u64));
            
            Some(cors)
        } else {
            None
        };
        
        Ok(Self {
            config,
            openapi_validator,
            compression_layer,
            cors_layer,
        })
    }
    
    /// Handle HTTP request with advanced features
    #[instrument(skip(self, request, context), fields(request_id = %context.request.id))]
    pub async fn handle_request(
        &self,
        request: Request,
        context: &mut RequestContext,
    ) -> GatewayResult<Response> {
        let start_time = Instant::now();
        
        debug!(
            request_id = %context.request.id,
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            "Processing HTTP request with advanced features"
        );
        
        // Apply request timeout
        let result = timeout(
            self.config.timeouts.request_timeout,
            self.process_request_with_features(request, context)
        ).await;
        
        match result {
            Ok(response) => {
                let processing_time = start_time.elapsed();
                debug!(
                    request_id = %context.request.id,
                    processing_time_ms = processing_time.as_millis(),
                    "HTTP request processed successfully"
                );
                response
            }
            Err(_) => {
                warn!(
                    request_id = %context.request.id,
                    timeout_ms = self.config.timeouts.request_timeout.as_millis(),
                    "HTTP request timed out"
                );
                Ok(self.create_timeout_response())
            }
        }
    }
    
    /// Process request with all advanced HTTP features
    async fn process_request_with_features(
        &self,
        request: Request,
        context: &mut RequestContext,
    ) -> GatewayResult<Response> {
        // 1. Validate request against OpenAPI spec if configured
        if let Some(ref validator) = self.openapi_validator {
            if let Err(validation_error) = validator.validate_request(&request).await {
                return Ok(self.create_validation_error_response(validation_error));
            }
        }
        
        // 2. Check HTTP version and apply version-specific handling
        let response = match request.version() {
            Version::HTTP_2 => {
                debug!(
                    request_id = %context.request.id,
                    "Processing HTTP/2 request with stream management"
                );
                self.handle_http2_request(request, context).await?
            }
            Version::HTTP_11 | Version::HTTP_10 => {
                debug!(
                    request_id = %context.request.id,
                    version = ?request.version(),
                    "Processing HTTP/1.x request"
                );
                self.handle_http1_request(request, context).await?
            }
            _ => {
                warn!(
                    request_id = %context.request.id,
                    version = ?request.version(),
                    "Unsupported HTTP version"
                );
                return Ok(self.create_error_response(
                    StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                    "Unsupported HTTP version".to_string(),
                ));
            }
        };
        
        // 3. Apply response transformations and compression
        let mut response = self.apply_response_features(response, context).await?;
        
        // 4. Validate response against OpenAPI spec if configured
        if let Some(ref validator) = self.openapi_validator {
            if let Err(validation_error) = validator.validate_response(&response).await {
                warn!(
                    request_id = %context.request.id,
                    error = %validation_error,
                    "Response validation failed"
                );
                // Log validation error but don't fail the request
            }
        }
        
        // 5. Add standard HTTP headers
        self.add_standard_headers(&mut response, context);
        
        Ok(response)
    }
    
    /// Handle HTTP/2 specific features
    async fn handle_http2_request(
        &self,
        request: Request,
        context: &mut RequestContext,
    ) -> GatewayResult<Response> {
        // HTTP/2 specific handling
        // - Stream management
        // - Server push (if enabled)
        // - Flow control
        
        // For now, delegate to standard HTTP handling
        // In a full implementation, this would include HTTP/2 specific optimizations
        self.handle_standard_request(request, context).await
    }
    
    /// Handle HTTP/1.x requests
    async fn handle_http1_request(
        &self,
        request: Request,
        context: &mut RequestContext,
    ) -> GatewayResult<Response> {
        // HTTP/1.x specific handling
        // - Connection keep-alive management
        // - Chunked transfer encoding
        
        self.handle_standard_request(request, context).await
    }
    
    /// Standard HTTP request handling
    async fn handle_standard_request(
        &self,
        request: Request,
        context: &mut RequestContext,
    ) -> GatewayResult<Response> {
        // This is a placeholder for the actual request processing
        // In the full implementation, this would:
        // 1. Route the request to the appropriate upstream service
        // 2. Apply load balancing
        // 3. Handle retries and circuit breaking
        // 4. Transform the request/response as needed
        
        // For now, return a simple response
        let response_body = serde_json::json!({
            "message": "HTTP request processed with advanced features",
            "request_id": context.request.id,
            "method": request.method().as_str(),
            "uri": request.uri().to_string(),
            "version": format!("{:?}", request.version()),
            "features": {
                "http2_enabled": self.config.http2_enabled,
                "compression_enabled": self.config.compression.enabled,
                "cors_enabled": self.config.cors.enabled,
                "openapi_validation": self.openapi_validator.is_some(),
            }
        });
        
        let response_body_bytes = serde_json::to_vec(&response_body)?;
        
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(response_body_bytes))
            .map_err(|e| GatewayError::internal(format!("Failed to build response: {}", e)))?)
    }
    
    /// Apply response features (compression, headers, etc.)
    async fn apply_response_features(
        &self,
        mut response: Response,
        context: &RequestContext,
    ) -> GatewayResult<Response> {
        // Add response timing header
        let processing_time = context.start_time.elapsed();
        if let Ok(timing_header) = HeaderValue::from_str(&format!("{}ms", processing_time.as_millis())) {
            response.headers_mut().insert("x-response-time", timing_header);
        }
        
        // Add request ID header
        if let Ok(request_id_header) = HeaderValue::from_str(&context.request.id) {
            response.headers_mut().insert("x-request-id", request_id_header);
        }
        
        // Compression is handled by the CompressionLayer middleware
        // CORS headers are handled by the CorsLayer middleware
        
        Ok(response)
    }
    
    /// Add standard HTTP headers
    fn add_standard_headers(&self, response: &mut Response, context: &RequestContext) {
        let headers = response.headers_mut();
        
        // Add server header
        headers.insert("server", HeaderValue::from_static("rust-api-gateway/0.1.0"));
        
        // Add trace ID for distributed tracing
        if let Ok(trace_header) = HeaderValue::from_str(&context.trace_id) {
            headers.insert("x-trace-id", trace_header);
        }
        
        // Add cache control headers for API responses
        if !headers.contains_key("cache-control") {
            headers.insert("cache-control", HeaderValue::from_static("no-cache, no-store, must-revalidate"));
        }
        
        // Add security headers
        headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert("x-xss-protection", HeaderValue::from_static("1; mode=block"));
    }
    
    /// Create timeout response
    fn create_timeout_response(&self) -> Response {
        let error_body = serde_json::json!({
            "error": {
                "code": 408,
                "message": "Request timeout",
                "type": "REQUEST_TIMEOUT"
            }
        });
        
        Response::builder()
            .status(StatusCode::REQUEST_TIMEOUT)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&error_body).unwrap()))
            .unwrap()
    }
    
    /// Create validation error response
    fn create_validation_error_response(&self, error: ValidationError) -> Response {
        let error_body = serde_json::json!({
            "error": {
                "code": 400,
                "message": "Request validation failed",
                "type": "VALIDATION_ERROR",
                "details": error.details
            }
        });
        
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&error_body).unwrap()))
            .unwrap()
    }
    
    /// Create generic error response
    fn create_error_response(&self, status: StatusCode, message: String) -> Response {
        let error_body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message
            }
        });
        
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&error_body).unwrap()))
            .unwrap()
    }
    
    /// Get handler configuration
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }
    
    /// Get compression layer for middleware stack
    pub fn compression_layer(&self) -> Option<&CompressionLayer> {
        self.compression_layer.as_ref()
    }
    
    /// Get CORS layer for middleware stack
    pub fn cors_layer(&self) -> Option<&CorsLayer> {
        self.cors_layer.as_ref()
    }
}

/// OpenAPI validator for request/response validation
pub struct OpenApiValidator {
    config: OpenApiConfig,
    // In a full implementation, this would contain the parsed OpenAPI spec
    // and validation logic using crates like `openapi` or `utoipa`
}

impl OpenApiValidator {
    /// Create new OpenAPI validator
    pub fn new(config: OpenApiConfig) -> GatewayResult<Self> {
        // In a full implementation, this would:
        // 1. Load and parse the OpenAPI specification file
        // 2. Build validation schemas
        // 3. Set up request/response validators
        
        info!(
            spec_path = %config.spec_path,
            validate_requests = config.validate_requests,
            validate_responses = config.validate_responses,
            "OpenAPI validator initialized"
        );
        
        Ok(Self { config })
    }
    
    /// Validate request against OpenAPI spec
    pub async fn validate_request(&self, _request: &Request) -> Result<(), ValidationError> {
        // Placeholder implementation
        // In a full implementation, this would:
        // 1. Extract the operation from the OpenAPI spec based on path and method
        // 2. Validate request parameters, headers, and body
        // 3. Return detailed validation errors
        
        if self.config.validate_requests {
            debug!("Validating request against OpenAPI specification");
            // Simulate validation - in real implementation, this would do actual validation
        }
        
        Ok(())
    }
    
    /// Validate response against OpenAPI spec
    pub async fn validate_response(&self, _response: &Response) -> Result<(), ValidationError> {
        // Placeholder implementation
        // In a full implementation, this would:
        // 1. Validate response status code, headers, and body
        // 2. Check against the OpenAPI response schema
        // 3. Return detailed validation errors
        
        if self.config.validate_responses {
            debug!("Validating response against OpenAPI specification");
            // Simulate validation - in real implementation, this would do actual validation
        }
        
        Ok(())
    }
}

/// Validation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub message: String,
    pub details: Vec<ValidationErrorDetail>,
}

/// Individual validation error detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub message: String,
    pub value: Option<serde_json::Value>,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} errors", self.message, self.details.len())
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Uri};

    #[test]
    fn test_http_config_default() {
        let config = HttpConfig::default();
        assert!(config.http2_enabled);
        assert!(config.compression.enabled);
        assert!(config.cors.enabled);
        assert_eq!(config.compression.level, 6);
        assert_eq!(config.max_body_size, 16 * 1024 * 1024);
    }

    #[test]
    fn test_compression_config() {
        let config = CompressionConfig::default();
        assert!(config.enabled);
        assert!(config.algorithms.contains(&CompressionAlgorithm::Gzip));
        assert!(config.algorithms.contains(&CompressionAlgorithm::Brotli));
        assert_eq!(config.min_size, 1024);
    }

    #[test]
    fn test_cors_config() {
        let config = CorsConfig::default();
        assert!(config.enabled);
        assert!(config.allowed_origins.contains(&"*".to_string()));
        assert!(config.allowed_methods.contains(&"GET".to_string()));
        assert!(config.allowed_methods.contains(&"POST".to_string()));
        assert_eq!(config.max_age, 86400);
    }

    #[test]
    fn test_http2_config() {
        let config = Http2Config::default();
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.initial_connection_window_size, 1024 * 1024);
        assert!(!config.enable_push); // Server push disabled by default
    }

    #[tokio::test]
    async fn test_http_handler_creation() {
        let config = HttpConfig::default();
        let handler = HttpHandler::new(config).unwrap();
        
        assert!(handler.compression_layer.is_some());
        assert!(handler.cors_layer.is_some());
        assert!(handler.openapi_validator.is_none());
    }

    #[tokio::test]
    async fn test_openapi_validator_creation() {
        let openapi_config = OpenApiConfig {
            spec_path: "test-spec.yaml".to_string(),
            validate_requests: true,
            validate_responses: true,
            strict_mode: false,
            custom_error_responses: HashMap::new(),
        };
        
        let validator = OpenApiValidator::new(openapi_config).unwrap();
        assert!(validator.config.validate_requests);
        assert!(validator.config.validate_responses);
    }

    #[test]
    fn test_compression_algorithm_display() {
        assert_eq!(CompressionAlgorithm::Gzip.to_string(), "gzip");
        assert_eq!(CompressionAlgorithm::Brotli.to_string(), "br");
        assert_eq!(CompressionAlgorithm::Deflate.to_string(), "deflate");
    }
}
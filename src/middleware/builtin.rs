//! # Built-in Middleware Components
//!
//! This module provides built-in middleware components for common gateway functionality
//! including logging, metrics collection, and distributed tracing.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, Span};
use uuid::Uuid;

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{GatewayResponse, IncomingRequest, RequestContext};
use crate::middleware::pipeline_fixed::Middleware;

/// Request logging middleware
///
/// This middleware logs request and response information for observability.
/// It can be configured to log headers, body, and other request details.
#[derive(Debug)]
pub struct RequestLoggingMiddleware {
    config: RequestLoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLoggingConfig {
    /// Whether to log request headers
    pub log_headers: bool,
    
    /// Whether to log request body (be careful with sensitive data)
    pub log_body: bool,
    
    /// Whether to log response headers
    pub log_response_headers: bool,
    
    /// Whether to log response body
    pub log_response_body: bool,
    
    /// Maximum body size to log (in bytes)
    pub max_body_size: usize,
    
    /// Headers to exclude from logging (for security)
    pub excluded_headers: Vec<String>,
    
    /// Log level for request/response logging
    pub log_level: String,
}

impl Default for RequestLoggingConfig {
    fn default() -> Self {
        Self {
            log_headers: true,
            log_body: false,
            log_response_headers: false,
            log_response_body: false,
            max_body_size: 1024,
            excluded_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "x-api-key".to_string(),
            ],
            log_level: "info".to_string(),
        }
    }
}

impl RequestLoggingMiddleware {
    pub fn new(config: RequestLoggingConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for RequestLoggingMiddleware {
    fn name(&self) -> &str {
        "request_logging"
    }

    fn priority(&self) -> i32 {
        10 // Execute early to capture original request
    }

    #[instrument(skip(self, request, context), fields(request_id = %request.id))]
    async fn process_request(
        &self,
        request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let start_time = Instant::now();
        
        // Log basic request information
        info!(
            method = %request.method,
            path = %request.path(),
            query = ?request.query(),
            remote_addr = %request.remote_addr,
            protocol = %request.protocol,
            "Request received"
        );

        // Log headers if configured
        if self.config.log_headers {
            let mut headers_to_log = Vec::new();
            for (name, value) in request.headers.iter() {
                let header_name = name.as_str().to_lowercase();
                if !self.config.excluded_headers.contains(&header_name) {
                    if let Ok(value_str) = value.to_str() {
                        headers_to_log.push(format!("{}={}", name, value_str));
                    }
                }
            }
            if !headers_to_log.is_empty() {
                debug!(headers = %headers_to_log.join(", "), "Request headers");
            }
        }

        // Log body if configured and not too large
        if self.config.log_body && request.body.len() <= self.config.max_body_size {
            if let Ok(body_str) = String::from_utf8(request.body.as_ref().clone()) {
                debug!(body = %body_str, "Request body");
            }
        }

        // Store start time in context for duration calculation
        context.data.insert(
            "request_start_time".to_string(),
            serde_json::json!(start_time.elapsed().as_nanos() as u64),
        );

        Ok(request)
    }

    #[instrument(skip(self, response, context), fields(request_id = %context.request.id))]
    async fn process_response(
        &self,
        response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Calculate request duration
        let duration = if let Some(start_nanos) = context.data.get("request_start_time") {
            let start_nanos = start_nanos.as_u64().unwrap_or(0);
            let current_nanos = context.start_time.elapsed().as_nanos() as u64;
            std::time::Duration::from_nanos(current_nanos - start_nanos)
        } else {
            context.elapsed()
        };

        // Log response information
        info!(
            status = %response.status,
            duration_ms = duration.as_millis(),
            body_size = response.body.len(),
            "Request completed"
        );

        // Log response headers if configured
        if self.config.log_response_headers {
            let mut headers_to_log = Vec::new();
            for (name, value) in response.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    headers_to_log.push(format!("{}={}", name, value_str));
                }
            }
            if !headers_to_log.is_empty() {
                debug!(headers = %headers_to_log.join(", "), "Response headers");
            }
        }

        // Log response body if configured and not too large
        if self.config.log_response_body && response.body.len() <= self.config.max_body_size {
            if let Ok(body_str) = String::from_utf8(response.body.as_ref().clone()) {
                debug!(body = %body_str, "Response body");
            }
        }

        Ok(response)
    }

    async fn handle_error(
        &self,
        error: GatewayError,
        context: &RequestContext,
    ) -> GatewayResult<Option<GatewayResponse>> {
        let duration = context.elapsed();
        
        error!(
            error = %error,
            duration_ms = duration.as_millis(),
            "Request failed"
        );

        // Don't provide a fallback response, just log the error
        Err(error)
    }
}



/// Metrics collection middleware
///
/// This middleware collects metrics about request processing for monitoring and alerting.
#[derive(Debug)]
pub struct MetricsMiddleware {
    config: MetricsConfig,
    metrics: Arc<GatewayMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Whether to collect detailed metrics
    pub detailed_metrics: bool,
    
    /// Whether to collect per-route metrics
    pub per_route_metrics: bool,
    
    /// Whether to collect per-upstream metrics
    pub per_upstream_metrics: bool,
    
    /// Custom labels to add to metrics
    pub custom_labels: std::collections::HashMap<String, String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            detailed_metrics: true,
            per_route_metrics: true,
            per_upstream_metrics: true,
            custom_labels: std::collections::HashMap::new(),
        }
    }
}

/// Gateway metrics collector
#[derive(Debug)]
pub struct GatewayMetrics {
    /// Total requests counter
    pub total_requests: std::sync::atomic::AtomicU64,
    
    /// Total responses counter
    pub total_responses: std::sync::atomic::AtomicU64,
    
    /// Error counter
    pub total_errors: std::sync::atomic::AtomicU64,
    
    /// Request duration histogram (simplified)
    pub request_durations: tokio::sync::RwLock<Vec<std::time::Duration>>,
    
    /// Status code counters
    pub status_codes: tokio::sync::RwLock<std::collections::HashMap<u16, u64>>,
    
    /// Per-route metrics
    pub route_metrics: tokio::sync::RwLock<std::collections::HashMap<String, RouteMetrics>>,
}

#[derive(Debug, Clone)]
pub struct RouteMetrics {
    pub requests: u64,
    pub errors: u64,
    pub avg_duration: std::time::Duration,
}

impl GatewayMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: std::sync::atomic::AtomicU64::new(0),
            total_responses: std::sync::atomic::AtomicU64::new(0),
            total_errors: std::sync::atomic::AtomicU64::new(0),
            request_durations: tokio::sync::RwLock::new(Vec::new()),
            status_codes: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            route_metrics: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn increment_requests(&self) {
        use std::sync::atomic::Ordering;
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_responses(&self) {
        use std::sync::atomic::Ordering;
        self.total_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        use std::sync::atomic::Ordering;
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_duration(&self, duration: std::time::Duration) {
        let mut durations = self.request_durations.write().await;
        durations.push(duration);
        
        // Keep only the last 1000 durations to prevent memory growth
        if durations.len() > 1000 {
            durations.drain(0..500);
        }
    }

    pub async fn record_status_code(&self, status_code: u16) {
        let mut status_codes = self.status_codes.write().await;
        *status_codes.entry(status_code).or_insert(0) += 1;
    }

    pub async fn record_route_metrics(&self, route: &str, duration: std::time::Duration, is_error: bool) {
        let mut route_metrics = self.route_metrics.write().await;
        let metrics = route_metrics.entry(route.to_string()).or_insert(RouteMetrics {
            requests: 0,
            errors: 0,
            avg_duration: std::time::Duration::from_millis(0),
        });

        metrics.requests += 1;
        if is_error {
            metrics.errors += 1;
        }
        
        // Update average duration (simplified)
        metrics.avg_duration = (metrics.avg_duration + duration) / 2;
    }

    pub async fn get_snapshot(&self) -> MetricsSnapshot {
        use std::sync::atomic::Ordering;
        
        let durations = self.request_durations.read().await;
        let avg_duration = if !durations.is_empty() {
            durations.iter().sum::<std::time::Duration>() / durations.len() as u32
        } else {
            std::time::Duration::from_millis(0)
        };

        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_responses: self.total_responses.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            avg_duration_ms: avg_duration.as_millis() as u64,
            status_codes: self.status_codes.read().await.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_errors: u64,
    pub avg_duration_ms: u64,
    pub status_codes: std::collections::HashMap<u16, u64>,
}

impl MetricsMiddleware {
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(GatewayMetrics::new()),
        }
    }

    pub fn get_metrics(&self) -> Arc<GatewayMetrics> {
        self.metrics.clone()
    }
}

#[async_trait]
impl Middleware for MetricsMiddleware {
    fn name(&self) -> &str {
        "metrics"
    }

    fn priority(&self) -> i32 {
        5 // Execute very early to capture all requests
    }

    async fn process_request(
        &self,
        request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        self.metrics.increment_requests();
        
        // Store start time for duration calculation
        context.data.insert(
            "metrics_start_time".to_string(),
            serde_json::json!(Instant::now().elapsed().as_nanos() as u64),
        );

        Ok(request)
    }

    async fn process_response(
        &self,
        response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        self.metrics.increment_responses();
        
        // Record status code
        self.metrics.record_status_code(response.status.as_u16()).await;
        
        // Calculate and record duration
        let duration = context.elapsed();
        self.metrics.record_duration(duration).await;
        
        // Record per-route metrics if configured
        if self.config.per_route_metrics {
            if let Some(route) = &context.route {
                self.metrics.record_route_metrics(&route.pattern, duration, false).await;
            }
        }

        Ok(response)
    }

    async fn handle_error(
        &self,
        error: GatewayError,
        context: &RequestContext,
    ) -> GatewayResult<Option<GatewayResponse>> {
        self.metrics.increment_errors();
        
        // Record error metrics for route if available
        if self.config.per_route_metrics {
            if let Some(route) = &context.route {
                let duration = context.elapsed();
                self.metrics.record_route_metrics(&route.pattern, duration, true).await;
            }
        }

        // Don't provide a fallback response
        Err(error)
    }
}



/// Distributed tracing middleware
///
/// This middleware adds distributed tracing support using OpenTelemetry standards.
#[derive(Debug)]
pub struct TracingMiddleware {
    config: TracingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Service name for tracing
    pub service_name: String,
    
    /// Whether to trace request/response bodies
    pub trace_bodies: bool,
    
    /// Whether to trace headers
    pub trace_headers: bool,
    
    /// Headers to exclude from tracing
    pub excluded_headers: Vec<String>,
    
    /// Custom tags to add to spans
    pub custom_tags: std::collections::HashMap<String, String>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "api-gateway".to_string(),
            trace_bodies: false,
            trace_headers: true,
            excluded_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "x-api-key".to_string(),
            ],
            custom_tags: std::collections::HashMap::new(),
        }
    }
}

impl TracingMiddleware {
    pub fn new(config: TracingConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for TracingMiddleware {
    fn name(&self) -> &str {
        "tracing"
    }

    fn priority(&self) -> i32 {
        1 // Execute first to create the root span
    }

    #[instrument(
        skip(self, request, context),
        fields(
            request_id = %request.id,
            method = %request.method,
            path = %request.path(),
            remote_addr = %request.remote_addr
        )
    )]
    async fn process_request(
        &self,
        request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let span = Span::current();
        
        // Add custom tags to the span
        for (key, value) in &self.config.custom_tags {
            span.record(key.as_str(), value.as_str());
        }
        
        // Add trace ID to context
        let trace_id = Uuid::new_v4().to_string();
        context.trace_id = trace_id.clone();
        span.record("trace_id", &trace_id);
        
        // Add protocol information
        span.record("protocol", &format!("{}", request.protocol));
        
        // Add headers to span if configured
        if self.config.trace_headers {
            for (name, value) in request.headers.iter() {
                let header_name = name.as_str().to_lowercase();
                if !self.config.excluded_headers.contains(&header_name) {
                    if let Ok(value_str) = value.to_str() {
                        let header_field = format!("http.header.{}", header_name);
                        span.record(header_field.as_str(), value_str);
                    }
                }
            }
        }
        
        // Add query parameters
        if let Some(query) = request.query() {
            span.record("http.query", query);
        }
        
        debug!("Created tracing span for request");
        Ok(request)
    }

    #[instrument(skip(self, response, context), fields(request_id = %context.request.id))]
    async fn process_response(
        &self,
        response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        let span = Span::current();
        
        // Add response information to span
        span.record("http.status_code", response.status.as_u16());
        span.record("http.response_size", response.body.len());
        span.record("duration_ms", context.elapsed().as_millis());
        
        // Add upstream information if available
        if let Some(instance) = &response.upstream_instance {
            span.record("upstream.service", &instance.name);
            span.record("upstream.address", &instance.address.to_string());
        }
        
        debug!("Updated tracing span with response information");
        Ok(response)
    }

    #[instrument(skip(self, error, context), fields(request_id = %context.request.id))]
    async fn handle_error(
        &self,
        error: GatewayError,
        context: &RequestContext,
    ) -> GatewayResult<Option<GatewayResponse>> {
        let span = Span::current();
        
        // Add error information to span
        span.record("error", true);
        span.record("error.message", &error.to_string());
        span.record("duration_ms", context.elapsed().as_millis());
        
        error!("Request failed with error in tracing span");
        
        // Don't provide a fallback response
        Err(error)
    }
}



/// Security headers middleware
///
/// This middleware adds common security headers to responses.
#[derive(Debug)]
pub struct SecurityHeadersMiddleware {
    config: SecurityHeadersConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Add X-Frame-Options header
    pub x_frame_options: Option<String>,
    
    /// Add X-Content-Type-Options header
    pub x_content_type_options: bool,
    
    /// Add X-XSS-Protection header
    pub x_xss_protection: Option<String>,
    
    /// Add Strict-Transport-Security header
    pub strict_transport_security: Option<String>,
    
    /// Add Content-Security-Policy header
    pub content_security_policy: Option<String>,
    
    /// Add Referrer-Policy header
    pub referrer_policy: Option<String>,
    
    /// Custom headers to add
    pub custom_headers: std::collections::HashMap<String, String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: true,
            x_xss_protection: Some("1; mode=block".to_string()),
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            content_security_policy: None,
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            custom_headers: std::collections::HashMap::new(),
        }
    }
}

impl SecurityHeadersMiddleware {
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for SecurityHeadersMiddleware {
    fn name(&self) -> &str {
        "security_headers"
    }

    fn priority(&self) -> i32 {
        90 // Execute late to add headers to final response
    }

    async fn process_response(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Add X-Frame-Options
        if let Some(ref value) = self.config.x_frame_options {
            response.headers.insert("x-frame-options", value.parse().unwrap());
        }

        // Add X-Content-Type-Options
        if self.config.x_content_type_options {
            response.headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        }

        // Add X-XSS-Protection
        if let Some(ref value) = self.config.x_xss_protection {
            response.headers.insert("x-xss-protection", value.parse().unwrap());
        }

        // Add Strict-Transport-Security
        if let Some(ref value) = self.config.strict_transport_security {
            response.headers.insert("strict-transport-security", value.parse().unwrap());
        }

        // Add Content-Security-Policy
        if let Some(ref value) = self.config.content_security_policy {
            response.headers.insert("content-security-policy", value.parse().unwrap());
        }

        // Add Referrer-Policy
        if let Some(ref value) = self.config.referrer_policy {
            response.headers.insert("referrer-policy", value.parse().unwrap());
        }

        // Add custom headers
        for (name, value) in &self.config.custom_headers {
            if let (Ok(header_name), Ok(header_value)) = (name.parse::<axum::http::HeaderName>(), value.parse()) {
                response.headers.insert(header_name, header_value);
            }
        }

        Ok(response)
    }
}


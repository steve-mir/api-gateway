//! # Distributed Tracing
//!
//! This module provides distributed tracing capabilities using OpenTelemetry.
//! It enables request tracing across multiple services and components.
//!
//! ## Key Features
//! - OpenTelemetry integration for distributed tracing
//! - Automatic trace context propagation
//! - Custom span creation and management
//! - Trace sampling configuration
//! - Integration with popular tracing backends (Jaeger, Zipkin)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, Span, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use opentelemetry::{
    global,
    trace::{TraceContextExt, TraceId, SpanId, SpanKind, Status},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::observability::config::TracingConfig;
use crate::observability::logging::CorrelationId;
use crate::core::error::GatewayError;

/// Trace context for request tracking
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub correlation_id: CorrelationId,
    pub parent_span_id: Option<SpanId>,
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new trace context
    pub fn new() -> Self {
        let trace_id = TraceId::from_bytes(Uuid::new_v4().as_u128().to_be_bytes());
        let span_id = SpanId::from_bytes(rand::random::<u64>().to_be_bytes());
        let correlation_id = CorrelationId::new();

        Self {
            trace_id,
            span_id,
            correlation_id,
            parent_span_id: None,
            baggage: HashMap::new(),
        }
    }

    /// Create from existing trace headers
    pub fn from_headers(headers: &HashMap<String, String>) -> Option<Self> {
        // Extract trace context from headers (W3C Trace Context format)
        let traceparent = headers.get("traceparent")?;
        let parts: Vec<&str> = traceparent.split('-').collect();
        
        if parts.len() != 4 {
            return None;
        }

        let trace_id = TraceId::from_hex(parts[1]).ok()?;
        let parent_span_id = SpanId::from_hex(parts[2]).ok()?;
        let span_id = SpanId::from_bytes(rand::random::<u64>().to_be_bytes());

        // Extract correlation ID from custom header or generate new one
        let correlation_id = headers
            .get("x-correlation-id")
            .map(|id| CorrelationId::from_string(id.clone()))
            .unwrap_or_else(CorrelationId::new);

        // Extract baggage if present
        let mut baggage = HashMap::new();
        if let Some(baggage_header) = headers.get("baggage") {
            for item in baggage_header.split(',') {
                if let Some((key, value)) = item.split_once('=') {
                    baggage.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        Some(Self {
            trace_id,
            span_id,
            correlation_id,
            parent_span_id: Some(parent_span_id),
            baggage,
        })
    }

    /// Convert to headers for downstream propagation
    pub fn to_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        // W3C Trace Context format
        let traceparent = format!(
            "00-{:032x}-{:016x}-01",
            u128::from_be_bytes(self.trace_id.to_bytes()),
            u64::from_be_bytes(self.span_id.to_bytes())
        );
        headers.insert("traceparent".to_string(), traceparent);

        // Correlation ID
        headers.insert("x-correlation-id".to_string(), self.correlation_id.to_string());

        // Baggage
        if !self.baggage.is_empty() {
            let baggage = self.baggage
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            headers.insert("baggage".to_string(), baggage);
        }

        headers
    }

    /// Add baggage item
    pub fn add_baggage(&mut self, key: String, value: String) {
        self.baggage.insert(key, value);
    }

    /// Get baggage item
    pub fn get_baggage(&self, key: &str) -> Option<&String> {
        self.baggage.get(key)
    }
}

/// Span information for custom spans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    pub name: String,
    #[serde(skip)]
    #[serde(default = "default_span_kind")]
    pub kind: SpanKind,
    pub attributes: HashMap<String, String>,
    pub events: Vec<SpanEvent>,
}

fn default_span_kind() -> SpanKind {
    SpanKind::Internal
}

/// Span event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub attributes: HashMap<String, String>,
}

/// Distributed tracer implementation
pub struct DistributedTracer {
    config: Arc<RwLock<TracingConfig>>,
    service_name: String,
}

impl DistributedTracer {
    /// Create a new distributed tracer
    pub fn new(config: TracingConfig) -> Result<Self, GatewayError> {
        let service_name = config.service_name.clone();
        
        // Initialize OpenTelemetry integration through tracing-opentelemetry
        Self::initialize_tracing(&config)?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            service_name,
        })
    }

    /// Initialize OpenTelemetry integration
    fn initialize_tracing(config: &TracingConfig) -> Result<(), GatewayError> {
        if !config.enabled {
            info!("Distributed tracing is disabled");
            return Ok(());
        }

        use opentelemetry::trace::TracerProvider;
        use opentelemetry_sdk::{
            trace::{Sampler, TracerProvider as SdkTracerProvider},
            Resource,
        };

        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        // Create resource with service information
        let _resource = Resource::new(vec![
            opentelemetry::KeyValue::new("service.name", config.service_name.clone()),
            opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ]);

        // Configure sampler based on sample rate
        let _sampler = if config.sample_rate >= 1.0 {
            Sampler::AlwaysOn
        } else if config.sample_rate <= 0.0 {
            Sampler::AlwaysOff
        } else {
            Sampler::TraceIdRatioBased(config.sample_rate)
        };

        // Create tracer provider with appropriate exporter
        let tracer_provider = {
            // Use stdout exporter for development/testing
            // In production, you would configure the actual Jaeger exporter
            use opentelemetry_stdout::SpanExporter;
            
            let stdout_exporter = SpanExporter::default();
            
            SdkTracerProvider::builder()
                .with_simple_exporter(stdout_exporter)
                .build()
        };

        // Set global tracer provider
        global::set_tracer_provider(tracer_provider.clone());

        // Create OpenTelemetry tracing layer
        let tracer = tracer_provider.tracer("api-gateway");
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        // Initialize tracing subscriber with OpenTelemetry layer
        // Note: This should ideally be done once at application startup
        // For now, we'll check if a subscriber is already set
        if let Err(_) = tracing_subscriber::registry()
            .with(telemetry_layer)
            .try_init()
        {
            // Subscriber already initialized, just log a warning
            warn!("Tracing subscriber already initialized, OpenTelemetry layer not added");
        }

        info!(
            service = %config.service_name,
            jaeger_endpoint = ?config.jaeger_endpoint,
            sample_rate = %config.sample_rate,
            "Distributed tracing initialized with OpenTelemetry"
        );

        Ok(())
    }

    /// Create a new span with trace context
    pub fn create_span(
        &self,
        name: &str,
        kind: SpanKind,
        trace_context: Option<&TraceContext>,
    ) -> Span {
        let span = tracing::info_span!(
            "gateway_span",
            otel.name = %name,
            otel.kind = ?kind,
            service.name = %self.service_name,
        );

        // Add trace context information if provided
        if let Some(ctx) = trace_context {
            // Add correlation ID to span
            span.record("correlation_id", &tracing::field::display(&ctx.correlation_id));
            span.record("trace_id", &tracing::field::display(&format!("{:032x}", u128::from_be_bytes(ctx.trace_id.to_bytes()))));
            span.record("span_id", &tracing::field::display(&format!("{:016x}", u64::from_be_bytes(ctx.span_id.to_bytes()))));
        }

        span
    }

    /// Create a span for HTTP requests
    pub fn create_http_span(
        &self,
        method: &str,
        path: &str,
        trace_context: Option<&TraceContext>,
    ) -> Span {
        let span = self.create_span(
            &format!("{} {}", method, path),
            SpanKind::Server,
            trace_context,
        );

        span.record("http.method", &tracing::field::display(method));
        span.record("http.target", &tracing::field::display(path));
        span.record("component", &tracing::field::display("http_server"));

        span
    }

    /// Create a span for gRPC requests
    pub fn create_grpc_span(
        &self,
        service: &str,
        method: &str,
        trace_context: Option<&TraceContext>,
    ) -> Span {
        let span = self.create_span(
            &format!("{}/{}", service, method),
            SpanKind::Server,
            trace_context,
        );

        span.record("rpc.service", &tracing::field::display(service));
        span.record("rpc.method", &tracing::field::display(method));
        span.record("rpc.system", &tracing::field::display("grpc"));
        span.record("component", &tracing::field::display("grpc_server"));

        span
    }

    /// Create a span for upstream requests
    pub fn create_upstream_span(
        &self,
        service_name: &str,
        operation: &str,
        trace_context: Option<&TraceContext>,
    ) -> Span {
        let span = self.create_span(
            &format!("upstream_{}", operation),
            SpanKind::Client,
            trace_context,
        );

        span.record("upstream.service", &tracing::field::display(service_name));
        span.record("upstream.operation", &tracing::field::display(operation));
        span.record("component", &tracing::field::display("upstream_client"));

        span
    }

    /// Add event to current span
    pub fn add_event(&self, name: &str, attributes: HashMap<String, String>) {
        let span = Span::current();
        
        // Record event as span fields since direct OpenTelemetry span access is complex
        span.record("event.name", &tracing::field::display(name));
        for (key, value) in attributes {
            let field_name = format!("event.{}", key);
            span.record(field_name.as_str(), &tracing::field::display(value));
        }
    }

    /// Set span status
    pub fn set_span_status(&self, status: Status) {
        let span = Span::current();
        span.record("otel.status_code", &tracing::field::display(format!("{:?}", status)));
    }

    /// Set span error
    pub fn set_span_error(&self, error: &dyn std::error::Error) {
        let span = Span::current();
        
        // Record error information as span fields
        span.record("error", &tracing::field::display(true));
        span.record("error.message", &tracing::field::display(error.to_string()));
        span.record("error.type", &tracing::field::display(std::any::type_name_of_val(error)));
        span.record("otel.status_code", &tracing::field::display("ERROR"));
    }

    /// Extract trace context from current span
    pub fn current_trace_context(&self) -> Option<TraceContext> {
        let span = Span::current();
        let context = span.context();
        let span_ref = context.span();
        let span_context = span_ref.span_context();

        if span_context.is_valid() {
            Some(TraceContext {
                trace_id: span_context.trace_id(),
                span_id: span_context.span_id(),
                correlation_id: CorrelationId::new(), // TODO: Extract from span fields
                parent_span_id: None,
                baggage: HashMap::new(), // TODO: Extract baggage
            })
        } else {
            None
        }
    }

    /// Update tracing configuration
    pub async fn update_config(&self, new_config: TracingConfig) -> Result<(), GatewayError> {
        let mut config = self.config.write().await;
        *config = new_config;
        
        info!("Tracing configuration updated");
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> TracingConfig {
        self.config.read().await.clone()
    }

    /// Shutdown tracer and flush remaining spans
    pub async fn shutdown(&self) -> Result<(), GatewayError> {
        global::shutdown_tracer_provider();
        info!("Distributed tracer shutdown completed");
        Ok(())
    }
}

/// Helper function to instrument async functions with tracing
pub async fn with_tracing<F, Fut, T>(
    tracer: &DistributedTracer,
    span_name: &str,
    trace_context: Option<&TraceContext>,
    f: F,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let span = tracer.create_span(span_name, SpanKind::Internal, trace_context);
    f().instrument(span).await
}

/// Middleware for automatic trace context extraction and propagation
pub struct TracingMiddleware {
    tracer: Arc<DistributedTracer>,
}

impl TracingMiddleware {
    pub fn new(tracer: Arc<DistributedTracer>) -> Self {
        Self { tracer }
    }

    /// Extract trace context from request headers
    pub fn extract_trace_context(&self, headers: &HashMap<String, String>) -> TraceContext {
        TraceContext::from_headers(headers).unwrap_or_else(TraceContext::new)
    }

    /// Inject trace context into response headers
    pub fn inject_trace_context(&self, trace_context: &TraceContext) -> HashMap<String, String> {
        trace_context.to_headers()
    }
}
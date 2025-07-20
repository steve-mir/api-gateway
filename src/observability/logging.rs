//! # Structured Logging
//!
//! This module provides structured logging capabilities with correlation ID generation,
//! sensitive data sanitization, and audit logging for security events.
//!
//! ## Key Features
//! - Structured JSON logging with correlation IDs
//! - Automatic sensitive data sanitization
//! - Audit logging for security and admin operations
//! - Dynamic log level configuration
//! - Request/response logging with configurable verbosity

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level, Span};
use tracing_subscriber::{
    fmt::{self},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::observability::config::{LogConfig, LogFormat};
use crate::core::error::GatewayError;

/// Correlation ID for tracking requests across services
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Generate a new correlation ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from existing string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get the correlation ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Log entry for structured logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub service: String,
    pub component: String,
    pub fields: HashMap<String, serde_json::Value>,
}

/// Audit log entry for security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub correlation_id: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, serde_json::Value>,
}

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    AdminOperation,
    ConfigurationChange,
    SecurityViolation,
    DataAccess,
}

/// Outcome of audited operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

/// Request/Response logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLoggingConfig {
    pub enabled: bool,
    pub log_headers: bool,
    pub log_body: bool,
    pub max_body_size: usize,
    pub sanitize_sensitive_data: bool,
    pub sensitive_headers: Vec<String>,
    pub sensitive_fields: Vec<String>,
}

impl Default for RequestLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_headers: true,
            log_body: false,
            max_body_size: 1024,
            sanitize_sensitive_data: true,
            sensitive_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "x-api-key".to_string(),
                "x-auth-token".to_string(),
            ],
            sensitive_fields: vec![
                "password".to_string(),
                "token".to_string(),
                "secret".to_string(),
                "key".to_string(),
                "ssn".to_string(),
                "credit_card".to_string(),
            ],
        }
    }
}

/// Sensitive data sanitizer
pub struct DataSanitizer {
    sensitive_patterns: Vec<Regex>,
    replacement: String,
}

impl DataSanitizer {
    pub fn new(sensitive_fields: Vec<String>) -> Result<Self, GatewayError> {
        let mut patterns = Vec::new();
        
        // Create regex patterns for sensitive fields
        for field in sensitive_fields {
            let pattern = format!(r#"(?i)"{}"\s*:\s*"[^"]*""#, regex::escape(&field));
            patterns.push(Regex::new(&pattern).map_err(|e| {
                GatewayError::internal(format!("Failed to compile regex pattern: {}", e))
            })?);
        }
        
        // Add common patterns for sensitive data
        patterns.push(Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap()); // Credit card
        patterns.push(Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()); // SSN
        patterns.push(Regex::new(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*").unwrap()); // Bearer tokens
        
        Ok(Self {
            sensitive_patterns: patterns,
            replacement: "[REDACTED]".to_string(),
        })
    }

    pub fn sanitize(&self, data: &str) -> String {
        let mut sanitized = data.to_string();
        
        for pattern in &self.sensitive_patterns {
            sanitized = pattern.replace_all(&sanitized, &self.replacement).to_string();
        }
        
        sanitized
    }
}

/// Main structured logger implementation
pub struct StructuredLogger {
    config: Arc<RwLock<LogConfig>>,
    request_config: Arc<RwLock<RequestLoggingConfig>>,
    sanitizer: Arc<DataSanitizer>,
    service_name: String,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub async fn new(config: LogConfig, service_name: String) -> Result<Self, GatewayError> {
        let request_config = RequestLoggingConfig::default();
        let sanitizer = DataSanitizer::new(request_config.sensitive_fields.clone())?;
        
        let logger = Self {
            config: Arc::new(RwLock::new(config)),
            request_config: Arc::new(RwLock::new(request_config)),
            sanitizer: Arc::new(sanitizer),
            service_name,
        };
        
        logger.initialize_subscriber().await?;
        
        Ok(logger)
    }

    /// Initialize the tracing subscriber
    async fn initialize_subscriber(&self) -> Result<(), GatewayError> {
        let config = self.config.read().await;
        
        // Parse log level
        let level = match config.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        };

        // Create environment filter
        let env_filter = EnvFilter::from_default_env()
            .add_directive(level.into());

        // Create subscriber based on format
        match config.format {
            LogFormat::Json => {
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(
                        fmt::layer()
                            .json()
                            .with_current_span(true)
                            .with_span_list(true)
                            .with_target(true)
                            .with_thread_ids(true)
                            .with_thread_names(true)
                    );
                
                // Try to initialize, but don't fail if already initialized
                if let Err(_) = subscriber.try_init() {
                    warn!("Tracing subscriber already initialized, skipping initialization");
                }
            }
            LogFormat::Text => {
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(
                        fmt::layer()
                            .with_target(true)
                            .with_thread_ids(true)
                            .with_thread_names(true)
                    );
                
                // Try to initialize, but don't fail if already initialized
                if let Err(_) = subscriber.try_init() {
                    warn!("Tracing subscriber already initialized, skipping initialization");
                }
            }
        }

        info!(
            service = %self.service_name,
            "Structured logging initialized"
        );

        Ok(())
    }

    /// Update log configuration dynamically
    pub async fn update_config(&self, new_config: LogConfig) -> Result<(), GatewayError> {
        let mut config = self.config.write().await;
        *config = new_config;
        
        info!("Log configuration updated");
        Ok(())
    }

    /// Update request logging configuration
    pub async fn update_request_config(&self, new_config: RequestLoggingConfig) -> Result<(), GatewayError> {
        let mut config = self.request_config.write().await;
        *config = new_config;
        
        info!("Request logging configuration updated");
        Ok(())
    }

    /// Log a request with correlation ID
    pub async fn log_request(
        &self,
        correlation_id: &CorrelationId,
        method: &str,
        path: &str,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) {
        let config = self.request_config.read().await;
        
        if !config.enabled {
            return;
        }

        let mut fields = HashMap::new();
        fields.insert("method".to_string(), serde_json::Value::String(method.to_string()));
        fields.insert("path".to_string(), serde_json::Value::String(path.to_string()));

        if config.log_headers {
            if let Some(headers) = headers {
                let sanitized_headers = self.sanitize_headers(headers, &config.sensitive_headers);
                fields.insert("headers".to_string(), serde_json::to_value(sanitized_headers).unwrap_or_default());
            }
        }

        if config.log_body {
            if let Some(body) = body {
                let sanitized_body = if config.sanitize_sensitive_data {
                    self.sanitizer.sanitize(body)
                } else {
                    body.to_string()
                };
                
                let truncated_body = if sanitized_body.len() > config.max_body_size {
                    format!("{}...[truncated]", &sanitized_body[..config.max_body_size])
                } else {
                    sanitized_body
                };
                
                fields.insert("body".to_string(), serde_json::Value::String(truncated_body));
            }
        }

        info!(
            correlation_id = %correlation_id,
            event_type = "request",
            fields = ?fields,
            "Incoming request"
        );
    }

    /// Log a response with correlation ID
    pub async fn log_response(
        &self,
        correlation_id: &CorrelationId,
        status_code: u16,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
        processing_time_ms: u64,
    ) {
        let config = self.request_config.read().await;
        
        if !config.enabled {
            return;
        }

        let mut fields = HashMap::new();
        fields.insert("status_code".to_string(), serde_json::Value::Number(status_code.into()));
        fields.insert("processing_time_ms".to_string(), serde_json::Value::Number(processing_time_ms.into()));

        if config.log_headers {
            if let Some(headers) = headers {
                let sanitized_headers = self.sanitize_headers(headers, &config.sensitive_headers);
                fields.insert("headers".to_string(), serde_json::to_value(sanitized_headers).unwrap_or_default());
            }
        }

        if config.log_body {
            if let Some(body) = body {
                let sanitized_body = if config.sanitize_sensitive_data {
                    self.sanitizer.sanitize(body)
                } else {
                    body.to_string()
                };
                
                let truncated_body = if sanitized_body.len() > config.max_body_size {
                    format!("{}...[truncated]", &sanitized_body[..config.max_body_size])
                } else {
                    sanitized_body
                };
                
                fields.insert("body".to_string(), serde_json::Value::String(truncated_body));
            }
        }

        info!(
            correlation_id = %correlation_id,
            event_type = "response",
            fields = ?fields,
            "Outgoing response"
        );
    }

    /// Log an audit event
    pub fn log_audit_event(&self, entry: AuditLogEntry) {
        warn!(
            event_type = ?entry.event_type,
            user_id = ?entry.user_id,
            correlation_id = %entry.correlation_id,
            resource = %entry.resource,
            action = %entry.action,
            outcome = ?entry.outcome,
            source_ip = ?entry.source_ip,
            details = ?entry.details,
            "Audit event"
        );
    }

    /// Log a security event
    pub fn log_security_event(
        &self,
        correlation_id: &CorrelationId,
        event_type: &str,
        severity: &str,
        details: HashMap<String, serde_json::Value>,
    ) {
        error!(
            correlation_id = %correlation_id,
            event_type = %event_type,
            severity = %severity,
            details = ?details,
            "Security event"
        );
    }

    /// Sanitize headers by removing sensitive ones
    fn sanitize_headers(
        &self,
        headers: &HashMap<String, String>,
        sensitive_headers: &[String],
    ) -> HashMap<String, String> {
        let mut sanitized = HashMap::new();
        
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            if sensitive_headers.iter().any(|h| h.to_lowercase() == key_lower) {
                sanitized.insert(key.clone(), "[REDACTED]".to_string());
            } else {
                sanitized.insert(key.clone(), value.clone());
            }
        }
        
        sanitized
    }

    /// Get current log configuration
    pub async fn get_config(&self) -> LogConfig {
        self.config.read().await.clone()
    }

    /// Get current request logging configuration
    pub async fn get_request_config(&self) -> RequestLoggingConfig {
        self.request_config.read().await.clone()
    }
}

/// Helper function to create correlation ID from span context
pub fn correlation_id_from_span() -> CorrelationId {
    let span = Span::current();
    if let Some(id) = span.field("correlation_id") {
        CorrelationId::from_string(format!("{:?}", id))
    } else {
        CorrelationId::new()
    }
}

/// Helper macro for logging with correlation ID
#[macro_export]
macro_rules! log_with_correlation {
    ($level:ident, $correlation_id:expr, $($arg:tt)*) => {
        tracing::$level!(
            correlation_id = %$correlation_id,
            $($arg)*
        );
    };
}
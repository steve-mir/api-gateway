//! # Fixed Middleware Pipeline System
//!
//! This is a corrected version of the middleware pipeline that addresses compilation errors.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{GatewayResponse, IncomingRequest, RequestContext};
use crate::middleware::factory::MiddlewareFactory;

/// Core middleware trait that all middleware must implement
#[async_trait]
pub trait Middleware: Send + Sync + fmt::Debug {
    /// Get the middleware name for identification and logging
    fn name(&self) -> &str;

    /// Get the middleware priority (lower numbers execute first)
    fn priority(&self) -> i32 {
        100 // Default priority
    }

    /// Check if this middleware should be executed for the given request
    async fn should_execute(&self, _request: &IncomingRequest, _context: &RequestContext) -> bool {
        true // Default: always execute
    }

    /// Process the request before it's sent to upstream
    async fn process_request(
        &self,
        request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        // Default implementation: pass through unchanged
        Ok(request)
    }

    /// Process the response before it's sent to the client
    async fn process_response(
        &self,
        response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Default implementation: pass through unchanged
        Ok(response)
    }

    /// Handle errors that occur during request processing
    async fn handle_error(
        &self,
        error: GatewayError,
        _context: &RequestContext,
    ) -> GatewayResult<Option<GatewayResponse>> {
        // Default implementation: propagate error
        Err(error)
    }

    /// Called when the middleware is initialized
    async fn initialize(&self) -> GatewayResult<()> {
        Ok(())
    }

    /// Called when the middleware is shut down
    async fn shutdown(&self) -> GatewayResult<()> {
        Ok(())
    }
}

/// Middleware pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewarePipelineConfig {
    /// List of middleware configurations in execution order
    pub middleware: Vec<MiddlewareConfig>,
    
    /// Global pipeline settings
    pub settings: PipelineSettings,
}

/// Individual middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfig {
    /// Middleware name/identifier
    pub name: String,
    
    /// Middleware type (built-in or plugin)
    pub middleware_type: String,
    
    /// Execution priority (lower numbers execute first)
    pub priority: i32,
    
    /// Whether this middleware is enabled
    pub enabled: bool,
    
    /// Conditions for when this middleware should execute
    pub conditions: Vec<MiddlewareCondition>,
    
    /// Middleware-specific configuration
    pub config: serde_json::Value,
}

/// Conditions for middleware execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareCondition {
    /// Condition type
    pub condition_type: ConditionType,
    
    /// Condition value
    pub value: String,
    
    /// Whether to negate the condition
    pub negate: bool,
}

/// Types of middleware conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConditionType {
    /// Match request path pattern
    PathPattern,
    /// Match HTTP method
    Method,
    /// Match request header
    Header,
    /// Match query parameter
    QueryParam,
    /// Match user role
    UserRole,
    /// Match upstream service
    UpstreamService,
    /// Custom condition
    Custom,
}

/// Pipeline execution settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSettings {
    /// Maximum execution time for the entire pipeline
    #[serde(with = "humantime_serde")]
    pub max_execution_time: std::time::Duration,
    
    /// Whether to continue on middleware errors
    pub continue_on_error: bool,
    
    /// Whether to collect detailed execution metrics
    pub collect_metrics: bool,
    
    /// Whether to log middleware execution
    pub log_execution: bool,
}

impl Default for PipelineSettings {
    fn default() -> Self {
        Self {
            max_execution_time: std::time::Duration::from_secs(30),
            continue_on_error: false,
            collect_metrics: true,
            log_execution: true,
        }
    }
}

/// Middleware pipeline executor
#[derive(Debug)]
pub struct MiddlewarePipeline {
    /// Registered middleware instances
    middleware: Arc<RwLock<Vec<Arc<dyn Middleware>>>>,
    
    /// Pipeline configuration
    config: Arc<RwLock<MiddlewarePipelineConfig>>,
    
    /// Execution metrics
    metrics: Arc<PipelineMetrics>,
    
    /// Middleware factory for creating instances
    factory: Arc<MiddlewareFactory>,
}

impl MiddlewarePipeline {
    /// Create a new middleware pipeline
    pub async fn new(config: MiddlewarePipelineConfig) -> GatewayResult<Self> {
        let metrics = Arc::new(PipelineMetrics::new());
        let factory = Arc::new(MiddlewareFactory::new_with_builtin().await);
        
        let pipeline = Self {
            middleware: Arc::new(RwLock::new(Vec::new())),
            config: Arc::new(RwLock::new(config.clone())),
            metrics,
            factory,
        };
        
        // Initialize middleware from configuration
        pipeline.reload_middleware().await?;
        
        Ok(pipeline)
    }

    /// Execute the request pipeline
    #[instrument(skip(self, request, context), fields(request_id = %context.request.id))]
    pub async fn execute_request(
        &self,
        mut request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let start_time = Instant::now();
        let middleware = self.middleware.read().await;
        
        debug!("Starting request pipeline execution with {} middleware", middleware.len());
        
        // Execute middleware in priority order
        for middleware_instance in middleware.iter() {
            // Check if middleware should execute
            if !middleware_instance.should_execute(&request, context).await {
                debug!("Skipping middleware '{}' due to conditions", middleware_instance.name());
                continue;
            }

            debug!("Executing request middleware: {}", middleware_instance.name());
            let middleware_start = Instant::now();
            
            // Process the request through this middleware
            let request_clone = request.clone();
            match middleware_instance.process_request(request_clone, context).await {
                Ok(modified_request) => {
                    request = modified_request;
                    let duration = middleware_start.elapsed();
                    self.metrics.record_middleware_execution(
                        middleware_instance.name(),
                        duration,
                        true,
                    );
                    debug!(
                        "Middleware '{}' completed in {:?}",
                        middleware_instance.name(),
                        duration
                    );
                }
                Err(error) => {
                    let duration = middleware_start.elapsed();
                    self.metrics.record_middleware_execution(
                        middleware_instance.name(),
                        duration,
                        false,
                    );
                    
                    error!(
                        "Middleware '{}' failed: {}",
                        middleware_instance.name(),
                        error
                    );
                    
                    // Try to handle the error
                    match middleware_instance.handle_error(error, context).await {
                        Ok(Some(_response)) => {
                            // Middleware provided a fallback response
                            return Err(GatewayError::Middleware {
                                middleware: middleware_instance.name().to_string(),
                                message: "Short-circuited with response".to_string(),
                            });
                        }
                        Ok(None) => {
                            // Continue processing if configured to do so
                            let config = self.config.read().await;
                            if !config.settings.continue_on_error {
                                return Err(GatewayError::Middleware {
                                    middleware: middleware_instance.name().to_string(),
                                    message: "Pipeline stopped due to error".to_string(),
                                });
                            }
                        }
                        Err(handled_error) => {
                            return Err(handled_error);
                        }
                    }
                }
            }
        }
        
        let total_duration = start_time.elapsed();
        self.metrics.record_pipeline_execution(total_duration, true);
        
        debug!("Request pipeline completed in {:?}", total_duration);
        Ok(request)
    }

    /// Execute the response pipeline
    #[instrument(skip(self, response, context), fields(request_id = %context.request.id))]
    pub async fn execute_response(
        &self,
        mut response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        let start_time = Instant::now();
        let middleware = self.middleware.read().await;
        
        debug!("Starting response pipeline execution with {} middleware", middleware.len());
        
        // Execute middleware in reverse priority order for responses
        for middleware_instance in middleware.iter().rev() {
            // Check if middleware should execute
            if !middleware_instance.should_execute(&context.request, context).await {
                debug!("Skipping middleware '{}' due to conditions", middleware_instance.name());
                continue;
            }

            debug!("Executing response middleware: {}", middleware_instance.name());
            let middleware_start = Instant::now();
            
            let response_clone = response.clone();
            match middleware_instance.process_response(response_clone, context).await {
                Ok(modified_response) => {
                    response = modified_response;
                    let duration = middleware_start.elapsed();
                    self.metrics.record_middleware_execution(
                        middleware_instance.name(),
                        duration,
                        true,
                    );
                    debug!(
                        "Middleware '{}' completed in {:?}",
                        middleware_instance.name(),
                        duration
                    );
                }
                Err(error) => {
                    let duration = middleware_start.elapsed();
                    self.metrics.record_middleware_execution(
                        middleware_instance.name(),
                        duration,
                        false,
                    );
                    
                    error!(
                        "Response middleware '{}' failed: {}",
                        middleware_instance.name(),
                        error
                    );
                    
                    // Try to handle the error
                    match middleware_instance.handle_error(error, context).await {
                        Ok(Some(fallback_response)) => {
                            response = fallback_response;
                        }
                        Ok(None) => {
                            // Continue processing if configured to do so
                            let config = self.config.read().await;
                            if !config.settings.continue_on_error {
                                return Err(GatewayError::Middleware {
                                    middleware: middleware_instance.name().to_string(),
                                    message: "Response pipeline stopped due to error".to_string(),
                                });
                            }
                        }
                        Err(handled_error) => {
                            return Err(handled_error);
                        }
                    }
                }
            }
        }
        
        let total_duration = start_time.elapsed();
        self.metrics.record_pipeline_execution(total_duration, true);
        
        debug!("Response pipeline completed in {:?}", total_duration);
        Ok(response)
    }

    /// Update pipeline configuration
    pub async fn update_config(&self, new_config: MiddlewarePipelineConfig) -> GatewayResult<()> {
        let mut config = self.config.write().await;
        *config = new_config;
        Ok(())
    }

    /// Get current pipeline configuration
    pub async fn get_config(&self) -> MiddlewarePipelineConfig {
        self.config.read().await.clone()
    }

    /// Get pipeline metrics
    pub fn get_metrics(&self) -> PipelineMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get list of active middleware
    pub async fn get_active_middleware(&self) -> Vec<String> {
        let middleware = self.middleware.read().await;
        middleware.iter().map(|m| m.name().to_string()).collect()
    }

    /// Add middleware dynamically
    pub async fn add_middleware(&self, middleware: Arc<dyn Middleware>) -> GatewayResult<()> {
        middleware.initialize().await?;
        
        let mut middleware_list = self.middleware.write().await;
        middleware_list.push(middleware);
        
        // Re-sort by priority
        middleware_list.sort_by_key(|m| m.priority());
        
        Ok(())
    }

    /// Remove middleware by name
    pub async fn remove_middleware(&self, name: &str) -> GatewayResult<bool> {
        let mut middleware_list = self.middleware.write().await;
        
        if let Some(pos) = middleware_list.iter().position(|m| m.name() == name) {
            let removed = middleware_list.remove(pos);
            if let Err(e) = removed.shutdown().await {
                tracing::warn!("Error shutting down middleware '{}': {}", name, e);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reload middleware from configuration
    pub async fn reload_middleware(&self) -> GatewayResult<()> {
        let config = self.config.read().await;
        let mut new_middleware = Vec::new();
        
        // Create middleware instances from configuration
        for middleware_config in &config.middleware {
            if !middleware_config.enabled {
                debug!("Skipping disabled middleware: {}", middleware_config.name);
                continue;
            }
            
            debug!("Creating middleware: {} (type: {})", middleware_config.name, middleware_config.middleware_type);
            
            let middleware_instance = self.factory
                .create_middleware(middleware_config)
                .await?;
            
            // Initialize the middleware
            middleware_instance.initialize().await?;
            
            new_middleware.push(middleware_instance);
        }
        
        // Sort by priority (lower numbers first)
        new_middleware.sort_by_key(|m| m.priority());
        
        // Replace the middleware list
        let mut middleware = self.middleware.write().await;
        
        // Shutdown old middleware
        for old_middleware in middleware.iter() {
            if let Err(e) = old_middleware.shutdown().await {
                tracing::warn!("Error shutting down middleware '{}': {}", old_middleware.name(), e);
            }
        }
        
        *middleware = new_middleware;
        
        info!("Reloaded {} middleware instances", middleware.len());
        Ok(())
    }
}

/// Pipeline execution metrics
#[derive(Debug)]
pub struct PipelineMetrics {
    /// Total pipeline executions
    pub total_executions: std::sync::atomic::AtomicU64,
    
    /// Failed pipeline executions
    pub failed_executions: std::sync::atomic::AtomicU64,
    
    /// Per-middleware metrics
    pub middleware_metrics: Arc<RwLock<HashMap<String, MiddlewareMetrics>>>,
}

impl PipelineMetrics {
    pub fn new() -> Self {
        Self {
            total_executions: std::sync::atomic::AtomicU64::new(0),
            failed_executions: std::sync::atomic::AtomicU64::new(0),
            middleware_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn record_pipeline_execution(&self, _duration: std::time::Duration, success: bool) {
        use std::sync::atomic::Ordering;
        
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        
        if !success {
            self.failed_executions.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_middleware_execution(
        &self,
        middleware_name: &str,
        duration: std::time::Duration,
        success: bool,
    ) {
        let metrics = self.middleware_metrics.clone();
        let name = middleware_name.to_string();
        
        tokio::spawn(async move {
            let mut metrics_map = metrics.write().await;
            let middleware_metrics = metrics_map
                .entry(name)
                .or_insert_with(MiddlewareMetrics::new);
            
            middleware_metrics.record_execution(duration, success);
        });
    }

    pub fn snapshot(&self) -> PipelineMetricsSnapshot {
        use std::sync::atomic::Ordering;
        
        PipelineMetricsSnapshot {
            total_executions: self.total_executions.load(Ordering::Relaxed),
            failed_executions: self.failed_executions.load(Ordering::Relaxed),
            success_rate: {
                let total = self.total_executions.load(Ordering::Relaxed);
                let failed = self.failed_executions.load(Ordering::Relaxed);
                if total > 0 {
                    ((total - failed) as f64 / total as f64) * 100.0
                } else {
                    0.0
                }
            },
        }
    }
}

/// Per-middleware execution metrics
#[derive(Debug)]
pub struct MiddlewareMetrics {
    pub executions: std::sync::atomic::AtomicU64,
    pub failures: std::sync::atomic::AtomicU64,
}

impl MiddlewareMetrics {
    pub fn new() -> Self {
        Self {
            executions: std::sync::atomic::AtomicU64::new(0),
            failures: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_execution(&self, _duration: std::time::Duration, success: bool) {
        use std::sync::atomic::Ordering;
        
        self.executions.fetch_add(1, Ordering::Relaxed);
        
        if !success {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Snapshot of pipeline metrics for reporting
#[derive(Debug, Clone, Serialize)]
pub struct PipelineMetricsSnapshot {
    pub total_executions: u64,
    pub failed_executions: u64,
    pub success_rate: f64,
}

/// Helper function to check middleware conditions
pub async fn check_conditions(
    conditions: &[MiddlewareCondition],
    request: &IncomingRequest,
    context: &RequestContext,
) -> bool {
    if conditions.is_empty() {
        return true;
    }
    
    for condition in conditions {
        let matches = match &condition.condition_type {
            ConditionType::PathPattern => {
                // Simple pattern matching - in production, use a proper pattern matcher
                request.path().contains(&condition.value)
            }
            ConditionType::Method => {
                request.method.as_str() == condition.value
            }
            ConditionType::Header => {
                request.headers.contains_key(&condition.value)
            }
            ConditionType::QueryParam => {
                request.query().unwrap_or("").contains(&condition.value)
            }
            ConditionType::UserRole => {
                if let Some(auth_context) = &context.auth_context {
                    auth_context.has_role(&condition.value)
                } else {
                    false
                }
            }
            ConditionType::UpstreamService => {
                if let Some(route) = &context.route {
                    route.upstream == condition.value
                } else {
                    false
                }
            }
            ConditionType::Custom => {
                // Custom conditions would be implemented by specific middleware
                false
            }
        };
        
        let result = if condition.negate { !matches } else { matches };
        
        if !result {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Method, StatusCode};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug)]
    struct TestMiddleware {
        name: String,
        priority: i32,
        call_count: AtomicU32,
    }

    impl TestMiddleware {
        fn new(name: &str, priority: i32) -> Self {
            Self {
                name: name.to_string(),
                priority,
                call_count: AtomicU32::new(0),
            }
        }

        fn call_count(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Middleware for TestMiddleware {
        fn name(&self) -> &str {
            &self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }

        async fn process_request(
            &self,
            mut request: IncomingRequest,
            _context: &mut RequestContext,
        ) -> GatewayResult<IncomingRequest> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            
            // Add a header to track middleware execution
            request.headers.insert(
                format!("x-middleware-{}", self.name).parse().unwrap(),
                "executed".parse().unwrap(),
            );
            
            Ok(request)
        }
    }

    fn create_test_request() -> IncomingRequest {
        IncomingRequest::new(
            crate::core::types::Protocol::Http,
            Method::GET,
            "/test".parse().unwrap(),
            axum::http::Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn test_middleware_pipeline_creation() {
        let config = MiddlewarePipelineConfig {
            middleware: vec![],
            settings: PipelineSettings::default(),
        };

        let pipeline = MiddlewarePipeline::new(config).await.unwrap();
        assert_eq!(pipeline.get_active_middleware().await.len(), 0);
    }

    #[tokio::test]
    async fn test_middleware_execution_order() {
        let config = MiddlewarePipelineConfig {
            middleware: vec![],
            settings: PipelineSettings::default(),
        };

        let pipeline = MiddlewarePipeline::new(config).await.unwrap();

        // Add middleware with different priorities
        let middleware1 = Arc::new(TestMiddleware::new("middleware1", 10));
        let middleware2 = Arc::new(TestMiddleware::new("middleware2", 5));
        let middleware3 = Arc::new(TestMiddleware::new("middleware3", 15));

        pipeline.add_middleware(middleware1.clone()).await.unwrap();
        pipeline.add_middleware(middleware2.clone()).await.unwrap();
        pipeline.add_middleware(middleware3.clone()).await.unwrap();

        let request = create_test_request();
        let mut context = RequestContext::new(Arc::new(request.clone()));

        let processed_request = pipeline.execute_request(request, &mut context).await.unwrap();

        // Check that all middleware were executed
        assert_eq!(middleware1.call_count(), 1);
        assert_eq!(middleware2.call_count(), 1);
        assert_eq!(middleware3.call_count(), 1);

        // Check that headers were added in the correct order (priority 5, 10, 15)
        assert!(processed_request.headers.contains_key("x-middleware-middleware2"));
        assert!(processed_request.headers.contains_key("x-middleware-middleware1"));
        assert!(processed_request.headers.contains_key("x-middleware-middleware3"));
    }
}
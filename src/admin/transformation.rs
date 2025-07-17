//! # Transformation Admin Module
//!
//! This module provides administrative endpoints for managing request/response transformation rules.
//! It allows administrators to:
//! - View current transformation rules
//! - Add new transformation rules
//! - Update existing transformation rules
//! - Delete transformation rules
//! - Test transformation rules
//!
//! ## Security Note
//! These endpoints should be protected with appropriate authentication and authorization
//! as they can modify the gateway's request/response processing behavior.

use crate::core::config::{TransformationConfig, TransformationRule, TransformationType};
use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, GatewayResponse, RequestContext};
use crate::middleware::transformation::{TransformationMiddleware, ContentNegotiator, ContentFormat};
use axum::{
    extract::{Path, State},
    http::{StatusCode, HeaderMap, HeaderValue},
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Transformation admin router state
#[derive(Clone)]
pub struct TransformationAdminState {
    /// Current transformation configuration
    pub transformation_config: Arc<RwLock<TransformationConfig>>,
    /// Transformation middleware instance for testing
    pub transformation_middleware: Arc<RwLock<Option<TransformationMiddleware>>>,
}

impl TransformationAdminState {
    /// Create new transformation admin state
    pub fn new(config: TransformationConfig) -> GatewayResult<Self> {
        let middleware = TransformationMiddleware::new(&config)?;
        Ok(Self {
            transformation_config: Arc::new(RwLock::new(config)),
            transformation_middleware: Arc::new(RwLock::new(Some(middleware))),
        })
    }

    /// Update transformation middleware with new configuration
    async fn update_middleware(&self) -> GatewayResult<()> {
        let config = self.transformation_config.read().await;
        let new_middleware = TransformationMiddleware::new(&config)?;
        let mut middleware_guard = self.transformation_middleware.write().await;
        *middleware_guard = Some(new_middleware);
        Ok(())
    }
}

/// Transformation admin router
pub struct TransformationAdminRouter;

impl TransformationAdminRouter {
    /// Create the transformation admin router with all endpoints
    pub fn create_router(state: TransformationAdminState) -> Router {
        Router::new()
            // Configuration endpoints
            .route("/config", get(get_transformation_config))
            .route("/config", put(update_transformation_config))
            
            // Request transformation rule endpoints
            .route("/rules/request", get(get_request_rules))
            .route("/rules/request", post(add_request_rule))
            .route("/rules/request/:rule_id", get(get_request_rule))
            .route("/rules/request/:rule_id", put(update_request_rule))
            .route("/rules/request/:rule_id", delete(delete_request_rule))
            
            // Response transformation rule endpoints
            .route("/rules/response", get(get_response_rules))
            .route("/rules/response", post(add_response_rule))
            .route("/rules/response/:rule_id", get(get_response_rule))
            .route("/rules/response/:rule_id", put(update_response_rule))
            .route("/rules/response/:rule_id", delete(delete_response_rule))
            
            // Testing endpoints
            .route("/test/request", post(test_request_transformation))
            .route("/test/response", post(test_response_transformation))
            .route("/test/content-negotiation", post(test_content_negotiation))
            
            // Statistics and monitoring
            .route("/stats", get(get_transformation_stats))
            .route("/supported-formats", get(get_supported_formats))
            
            .with_state(state)
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for transformation configuration
#[derive(Debug, Serialize)]
pub struct TransformationConfigResponse {
    pub config: TransformationConfig,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub rule_count: TransformationRuleCount,
}

/// Count of transformation rules by type
#[derive(Debug, Serialize)]
pub struct TransformationRuleCount {
    pub request_rules: usize,
    pub response_rules: usize,
    pub total: usize,
}

/// Request to add or update a transformation rule
#[derive(Debug, Deserialize)]
pub struct TransformationRuleRequest {
    pub name: String,
    pub transform_type: TransformationType,
    pub config: serde_json::Value,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

/// Response for a transformation rule
#[derive(Debug, Serialize)]
pub struct TransformationRuleResponse {
    pub id: String,
    pub rule: TransformationRule,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Request to test transformation
#[derive(Debug, Deserialize)]
pub struct TransformationTestRequest {
    pub rule: TransformationRuleRequest,
    pub test_data: TestData,
}

/// Test data for transformation testing
#[derive(Debug, Deserialize)]
pub struct TestData {
    pub headers: HashMap<String, String>,
    pub body: String,
    pub content_type: Option<String>,
}

/// Response for transformation test
#[derive(Debug, Serialize)]
pub struct TransformationTestResponse {
    pub success: bool,
    pub result: Option<TestResult>,
    pub error: Option<String>,
}

/// Test result data
#[derive(Debug, Serialize)]
pub struct TestResult {
    pub headers: HashMap<String, String>,
    pub body: String,
    pub content_type: Option<String>,
}

/// Content negotiation test request
#[derive(Debug, Deserialize)]
pub struct ContentNegotiationTestRequest {
    pub source_format: String,
    pub target_format: String,
    pub content: String,
}

/// Content negotiation test response
#[derive(Debug, Serialize)]
pub struct ContentNegotiationTestResponse {
    pub success: bool,
    pub converted_content: Option<String>,
    pub error: Option<String>,
}

/// Transformation statistics
#[derive(Debug, Serialize)]
pub struct TransformationStats {
    pub total_rules: usize,
    pub request_rules: usize,
    pub response_rules: usize,
    pub rules_by_type: HashMap<String, usize>,
    pub supported_formats: Vec<String>,
}

/// Supported content formats
#[derive(Debug, Serialize)]
pub struct SupportedFormatsResponse {
    pub formats: Vec<FormatInfo>,
    pub conversions: Vec<ConversionInfo>,
}

/// Information about a supported format
#[derive(Debug, Serialize)]
pub struct FormatInfo {
    pub name: String,
    pub content_type: String,
    pub description: String,
}

/// Information about supported conversions
#[derive(Debug, Serialize)]
pub struct ConversionInfo {
    pub from: String,
    pub to: String,
    pub description: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

// ============================================================================
// Configuration Management Endpoints
// ============================================================================

/// Get current transformation configuration
async fn get_transformation_config(
    State(state): State<TransformationAdminState>,
) -> Result<Json<TransformationConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let rule_count = TransformationRuleCount {
        request_rules: config.request.len(),
        response_rules: config.response.len(),
        total: config.request.len() + config.response.len(),
    };

    Ok(Json(TransformationConfigResponse {
        config: config.clone(),
        last_modified: chrono::Utc::now(), // In a real implementation, track actual modification time
        rule_count,
    }))
}

/// Update transformation configuration
async fn update_transformation_config(
    State(state): State<TransformationAdminState>,
    Json(new_config): Json<TransformationConfig>,
) -> Result<Json<TransformationConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate the new configuration by trying to create middleware
    if let Err(e) = TransformationMiddleware::new(&new_config) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid transformation configuration".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Update configuration
    {
        let mut config = state.transformation_config.write().await;
        *config = new_config;
    }

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Return updated configuration
    get_transformation_config(State(state)).await
}

// ============================================================================
// Request Rule Management Endpoints
// ============================================================================

/// Get all request transformation rules
async fn get_request_rules(
    State(state): State<TransformationAdminState>,
) -> Result<Json<Vec<TransformationRuleResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let rules: Vec<TransformationRuleResponse> = config
        .request
        .iter()
        .enumerate()
        .map(|(index, rule)| TransformationRuleResponse {
            id: index.to_string(), // In a real implementation, use proper IDs
            rule: rule.clone(),
            enabled: true, // In a real implementation, track enabled state
            description: None, // In a real implementation, store descriptions
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .collect();

    Ok(Json(rules))
}

/// Add a new request transformation rule
async fn add_request_rule(
    State(state): State<TransformationAdminState>,
    Json(rule_request): Json<TransformationRuleRequest>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let new_rule = TransformationRule {
        name: rule_request.name.clone(),
        transform_type: rule_request.transform_type,
        config: rule_request.config,
    };

    // Validate the rule by testing it
    if let Err(e) = validate_transformation_rule(&new_rule) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid transformation rule".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Add rule to configuration
    let rule_id = {
        let mut config = state.transformation_config.write().await;
        config.request.push(new_rule.clone());
        (config.request.len() - 1).to_string()
    };

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: new_rule,
        enabled: rule_request.enabled.unwrap_or(true),
        description: rule_request.description,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Get a specific request transformation rule
async fn get_request_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    let rule = config.request.get(index).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Rule not found".to_string(),
                details: None,
            }),
        )
    })?;

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: rule.clone(),
        enabled: true,
        description: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Update a request transformation rule
async fn update_request_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
    Json(rule_request): Json<TransformationRuleRequest>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    let updated_rule = TransformationRule {
        name: rule_request.name.clone(),
        transform_type: rule_request.transform_type,
        config: rule_request.config,
    };

    // Validate the updated rule
    if let Err(e) = validate_transformation_rule(&updated_rule) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid transformation rule".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Update rule in configuration
    {
        let mut config = state.transformation_config.write().await;
        if index >= config.request.len() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Rule not found".to_string(),
                    details: None,
                }),
            ));
        }
        config.request[index] = updated_rule.clone();
    }

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: updated_rule,
        enabled: rule_request.enabled.unwrap_or(true),
        description: rule_request.description,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Delete a request transformation rule
async fn delete_request_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    // Remove rule from configuration
    {
        let mut config = state.transformation_config.write().await;
        if index >= config.request.len() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Rule not found".to_string(),
                    details: None,
                }),
            ));
        }
        config.request.remove(index);
    }

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Response Rule Management Endpoints (similar to request rules)
// ============================================================================

/// Get all response transformation rules
async fn get_response_rules(
    State(state): State<TransformationAdminState>,
) -> Result<Json<Vec<TransformationRuleResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let rules: Vec<TransformationRuleResponse> = config
        .response
        .iter()
        .enumerate()
        .map(|(index, rule)| TransformationRuleResponse {
            id: index.to_string(),
            rule: rule.clone(),
            enabled: true,
            description: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .collect();

    Ok(Json(rules))
}

/// Add a new response transformation rule
async fn add_response_rule(
    State(state): State<TransformationAdminState>,
    Json(rule_request): Json<TransformationRuleRequest>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let new_rule = TransformationRule {
        name: rule_request.name.clone(),
        transform_type: rule_request.transform_type,
        config: rule_request.config,
    };

    // Validate the rule
    if let Err(e) = validate_transformation_rule(&new_rule) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid transformation rule".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Add rule to configuration
    let rule_id = {
        let mut config = state.transformation_config.write().await;
        config.response.push(new_rule.clone());
        (config.response.len() - 1).to_string()
    };

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: new_rule,
        enabled: rule_request.enabled.unwrap_or(true),
        description: rule_request.description,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Get a specific response transformation rule
async fn get_response_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    let rule = config.response.get(index).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Rule not found".to_string(),
                details: None,
            }),
        )
    })?;

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: rule.clone(),
        enabled: true,
        description: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Update a response transformation rule
async fn update_response_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
    Json(rule_request): Json<TransformationRuleRequest>,
) -> Result<Json<TransformationRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    let updated_rule = TransformationRule {
        name: rule_request.name.clone(),
        transform_type: rule_request.transform_type,
        config: rule_request.config,
    };

    // Validate the updated rule
    if let Err(e) = validate_transformation_rule(&updated_rule) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid transformation rule".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    // Update rule in configuration
    {
        let mut config = state.transformation_config.write().await;
        if index >= config.response.len() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Rule not found".to_string(),
                    details: None,
                }),
            ));
        }
        config.response[index] = updated_rule.clone();
    }

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(Json(TransformationRuleResponse {
        id: rule_id,
        rule: updated_rule,
        enabled: rule_request.enabled.unwrap_or(true),
        description: rule_request.description,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }))
}

/// Delete a response transformation rule
async fn delete_response_rule(
    State(state): State<TransformationAdminState>,
    Path(rule_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let index: usize = rule_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid rule ID".to_string(),
                details: None,
            }),
        )
    })?;

    // Remove rule from configuration
    {
        let mut config = state.transformation_config.write().await;
        if index >= config.response.len() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Rule not found".to_string(),
                    details: None,
                }),
            ));
        }
        config.response.remove(index);
    }

    // Update middleware
    if let Err(e) = state.update_middleware().await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update transformation middleware".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Testing Endpoints
// ============================================================================

/// Test request transformation
async fn test_request_transformation(
    State(_state): State<TransformationAdminState>,
    Json(test_request): Json<TransformationTestRequest>,
) -> Result<Json<TransformationTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Create a test transformation rule
    let rule = TransformationRule {
        name: test_request.rule.name,
        transform_type: test_request.rule.transform_type,
        config: test_request.rule.config,
    };

    // Create test configuration with just this rule
    let test_config = TransformationConfig {
        request: vec![rule],
        response: vec![],
    };

    // Create test middleware
    let test_middleware = match TransformationMiddleware::new(&test_config) {
        Ok(middleware) => middleware,
        Err(e) => {
            return Ok(Json(TransformationTestResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            }));
        }
    };

    // Create test request
    let test_req = create_test_request(&test_request.test_data);
    let mut context = RequestContext::new(Arc::new(test_req.clone()));

    // Apply transformation
    match test_middleware.transform_request(test_req, &mut context).await {
        Ok(transformed_req) => {
            let result = TestResult {
                headers: transformed_req
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
                body: String::from_utf8_lossy(&transformed_req.body).to_string(),
                content_type: transformed_req.header("content-type").map(|s| s.to_string()),
            };

            Ok(Json(TransformationTestResponse {
                success: true,
                result: Some(result),
                error: None,
            }))
        }
        Err(e) => Ok(Json(TransformationTestResponse {
            success: false,
            result: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Test response transformation
async fn test_response_transformation(
    State(_state): State<TransformationAdminState>,
    Json(test_request): Json<TransformationTestRequest>,
) -> Result<Json<TransformationTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Create a test transformation rule
    let rule = TransformationRule {
        name: test_request.rule.name,
        transform_type: test_request.rule.transform_type,
        config: test_request.rule.config,
    };

    // Create test configuration with just this rule
    let test_config = TransformationConfig {
        request: vec![],
        response: vec![rule],
    };

    // Create test middleware
    let test_middleware = match TransformationMiddleware::new(&test_config) {
        Ok(middleware) => middleware,
        Err(e) => {
            return Ok(Json(TransformationTestResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            }));
        }
    };

    // Create test response
    let test_resp = create_test_response(&test_request.test_data);
    let test_req = create_test_request(&test_request.test_data);
    let context = RequestContext::new(Arc::new(test_req));

    // Apply transformation
    match test_middleware.transform_response(test_resp, &context).await {
        Ok(transformed_resp) => {
            let result = TestResult {
                headers: transformed_resp
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
                body: String::from_utf8_lossy(&transformed_resp.body).to_string(),
                content_type: transformed_resp
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
            };

            Ok(Json(TransformationTestResponse {
                success: true,
                result: Some(result),
                error: None,
            }))
        }
        Err(e) => Ok(Json(TransformationTestResponse {
            success: false,
            result: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Test content negotiation
async fn test_content_negotiation(
    Json(test_request): Json<ContentNegotiationTestRequest>,
) -> Result<Json<ContentNegotiationTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let _negotiator = ContentNegotiator::new();

    // Parse formats
    let source_format = match test_request.source_format.to_lowercase().as_str() {
        "json" => ContentFormat::Json,
        "xml" => ContentFormat::Xml,
        "html" => ContentFormat::Html,
        "text" => ContentFormat::PlainText,
        "form" => ContentFormat::FormUrlEncoded,
        _ => {
            return Ok(Json(ContentNegotiationTestResponse {
                success: false,
                converted_content: None,
                error: Some("Unsupported source format".to_string()),
            }));
        }
    };

    let target_format = match test_request.target_format.to_lowercase().as_str() {
        "json" => ContentFormat::Json,
        "xml" => ContentFormat::Xml,
        "html" => ContentFormat::Html,
        "text" => ContentFormat::PlainText,
        "form" => ContentFormat::FormUrlEncoded,
        _ => {
            return Ok(Json(ContentNegotiationTestResponse {
                success: false,
                converted_content: None,
                error: Some("Unsupported target format".to_string()),
            }));
        }
    };

    // Perform conversion - create a simple test conversion for now
    let converted_content = match (source_format, target_format) {
        (ContentFormat::Json, ContentFormat::Xml) => {
            // Simple JSON to XML conversion for testing
            format!("<data>{}</data>", test_request.content)
        }
        (ContentFormat::Xml, ContentFormat::Json) => {
            // Simple XML to JSON conversion for testing
            format!("{{\"data\": \"{}\"}}", test_request.content.replace('"', "\\\""))
        }
        _ => {
            // For other conversions, just return the original content
            test_request.content.clone()
        }
    };

    Ok(Json(ContentNegotiationTestResponse {
        success: true,
        converted_content: Some(converted_content),
        error: None,
    }))
}

// ============================================================================
// Statistics and Monitoring Endpoints
// ============================================================================

/// Get transformation statistics
async fn get_transformation_stats(
    State(state): State<TransformationAdminState>,
) -> Result<Json<TransformationStats>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.transformation_config.read().await;
    
    let mut rules_by_type = HashMap::new();
    
    // Count request rules by type
    for rule in &config.request {
        let type_name = format!("{:?}", rule.transform_type);
        *rules_by_type.entry(type_name).or_insert(0) += 1;
    }
    
    // Count response rules by type
    for rule in &config.response {
        let type_name = format!("{:?}", rule.transform_type);
        *rules_by_type.entry(type_name).or_insert(0) += 1;
    }

    let stats = TransformationStats {
        total_rules: config.request.len() + config.response.len(),
        request_rules: config.request.len(),
        response_rules: config.response.len(),
        rules_by_type,
        supported_formats: vec![
            "json".to_string(),
            "xml".to_string(),
            "html".to_string(),
            "text".to_string(),
            "form".to_string(),
        ],
    };

    Ok(Json(stats))
}

/// Get supported formats
async fn get_supported_formats() -> Result<Json<SupportedFormatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let formats = vec![
        FormatInfo {
            name: "json".to_string(),
            content_type: "application/json".to_string(),
            description: "JavaScript Object Notation".to_string(),
        },
        FormatInfo {
            name: "xml".to_string(),
            content_type: "application/xml".to_string(),
            description: "Extensible Markup Language".to_string(),
        },
        FormatInfo {
            name: "html".to_string(),
            content_type: "text/html".to_string(),
            description: "HyperText Markup Language".to_string(),
        },
        FormatInfo {
            name: "text".to_string(),
            content_type: "text/plain".to_string(),
            description: "Plain text".to_string(),
        },
        FormatInfo {
            name: "form".to_string(),
            content_type: "application/x-www-form-urlencoded".to_string(),
            description: "URL-encoded form data".to_string(),
        },
    ];

    let conversions = vec![
        ConversionInfo {
            from: "json".to_string(),
            to: "xml".to_string(),
            description: "Convert JSON to XML format".to_string(),
        },
        ConversionInfo {
            from: "xml".to_string(),
            to: "json".to_string(),
            description: "Convert XML to JSON format".to_string(),
        },
        ConversionInfo {
            from: "json".to_string(),
            to: "html".to_string(),
            description: "Convert JSON to HTML table format".to_string(),
        },
        ConversionInfo {
            from: "form".to_string(),
            to: "json".to_string(),
            description: "Convert form data to JSON".to_string(),
        },
    ];

    Ok(Json(SupportedFormatsResponse {
        formats,
        conversions,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate a transformation rule
fn validate_transformation_rule(rule: &TransformationRule) -> GatewayResult<()> {
    // Basic validation - check if required fields are present
    match rule.transform_type {
        TransformationType::AddHeader | TransformationType::RemoveHeader | TransformationType::ModifyHeader => {
            if rule.config.get("name").is_none() {
                return Err(GatewayError::Configuration {
                    message: "Header transformation requires 'name' field".to_string(),
                });
            }
            if matches!(rule.transform_type, TransformationType::AddHeader | TransformationType::ModifyHeader) {
                if rule.config.get("value").is_none() {
                    return Err(GatewayError::Configuration {
                        message: "Add/Modify header transformation requires 'value' field".to_string(),
                    });
                }
            }
        }
        TransformationType::AddQueryParam | TransformationType::RemoveQueryParam => {
            if rule.config.get("name").is_none() {
                return Err(GatewayError::Configuration {
                    message: "Query param transformation requires 'name' field".to_string(),
                });
            }
            if matches!(rule.transform_type, TransformationType::AddQueryParam) {
                if rule.config.get("value").is_none() {
                    return Err(GatewayError::Configuration {
                        message: "Add query param transformation requires 'value' field".to_string(),
                    });
                }
            }
        }
        TransformationType::ModifyPath => {
            if rule.config.get("pattern").is_none() || rule.config.get("replacement").is_none() {
                return Err(GatewayError::Configuration {
                    message: "Path modification requires 'pattern' and 'replacement' fields".to_string(),
                });
            }
        }
        TransformationType::ModifyBody => {
            if rule.config.get("type").is_none() {
                return Err(GatewayError::Configuration {
                    message: "Body modification requires 'type' field".to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Create a test request from test data
fn create_test_request(test_data: &TestData) -> IncomingRequest {
    let mut headers = HeaderMap::new();
    
    // Add headers from test data
    for (name, value) in &test_data.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            name.parse::<axum::http::HeaderName>(),
            value.parse::<HeaderValue>()
        ) {
            headers.insert(header_name, header_value);
        }
    }
    
    // Set content type if provided
    if let Some(content_type) = &test_data.content_type {
        if let Ok(header_value) = content_type.parse::<HeaderValue>() {
            headers.insert("content-type", header_value);
        }
    }

    IncomingRequest::new(
        crate::core::types::Protocol::Http,
        axum::http::Method::POST,
        "/test".parse().unwrap(),
        axum::http::Version::HTTP_11,
        headers,
        test_data.body.as_bytes().to_vec(),
        "127.0.0.1:8080".parse().unwrap(),
    )
}

/// Create a test response from test data
fn create_test_response(test_data: &TestData) -> GatewayResponse {
    let mut headers = HeaderMap::new();
    
    // Add headers from test data
    for (name, value) in &test_data.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            name.parse::<axum::http::HeaderName>(),
            value.parse::<HeaderValue>()
        ) {
            headers.insert(header_name, header_value);
        }
    }
    
    // Set content type if provided
    if let Some(content_type) = &test_data.content_type {
        if let Ok(header_value) = content_type.parse::<HeaderValue>() {
            headers.insert("content-type", header_value);
        }
    }

    GatewayResponse {
        status: axum::http::StatusCode::OK,
        headers,
        body: Arc::new(test_data.body.as_bytes().to_vec()),
        processing_time: std::time::Duration::from_millis(0),
        upstream_instance: None,
    }
}
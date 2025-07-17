//! # Request/Response Transformation Middleware
//!
//! This module provides comprehensive request and response transformation capabilities
//! for the API Gateway. It supports header manipulation, payload transformation,
//! content negotiation, and protocol translation.
//!
//! ## Key Features
//! - Header manipulation (add, remove, modify)
//! - JSON/XML payload transformation
//! - Content negotiation and protocol translation
//! - Configurable transformation rules
//! - Pipeline-based transformation processing
//!
//! ## Rust Concepts Used
//! - `async_trait` for async trait methods
//! - `Arc<T>` for shared ownership of transformation rules
//! - `serde_json` and `quick-xml` for payload transformation
//! - Pattern matching for transformation type dispatch

use async_trait::async_trait;
use axum::http::{HeaderName, HeaderValue};
use serde_json::Value as JsonValue;
use std::str::FromStr;
use std::sync::Arc;
use tower::{Layer, Service};

use crate::core::config::{TransformationConfig, TransformationRule, TransformationType};
use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{GatewayResponse, IncomingRequest, RequestContext};

/// Transformation middleware that applies configured transformations to requests and responses
#[derive(Clone)]
pub struct TransformationMiddleware {
    /// Request transformation rules
    request_transformers: Arc<Vec<Box<dyn RequestTransformer>>>,
    
    /// Response transformation rules  
    response_transformers: Arc<Vec<Box<dyn ResponseTransformer>>>,
    
    /// Content negotiation handler
    content_negotiator: Arc<ContentNegotiator>,
}

impl TransformationMiddleware {
    /// Create a new transformation middleware from configuration
    pub fn new(config: &TransformationConfig) -> GatewayResult<Self> {
        let request_transformers = Self::build_request_transformers(&config.request)?;
        let response_transformers = Self::build_response_transformers(&config.response)?;
        let content_negotiator = Arc::new(ContentNegotiator::new());

        Ok(Self {
            request_transformers: Arc::new(request_transformers),
            response_transformers: Arc::new(response_transformers),
            content_negotiator,
        })
    }

    /// Build request transformers from configuration rules
    fn build_request_transformers(
        rules: &[TransformationRule],
    ) -> GatewayResult<Vec<Box<dyn RequestTransformer>>> {
        let mut transformers = Vec::new();

        for rule in rules {
            let transformer: Box<dyn RequestTransformer> = match rule.transform_type {
                TransformationType::AddHeader => {
                    Box::new(AddHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::RemoveHeader => {
                    Box::new(RemoveHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::ModifyHeader => {
                    Box::new(ModifyHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::AddQueryParam => {
                    Box::new(AddQueryParamTransformer::from_config(&rule.config)?)
                }
                TransformationType::RemoveQueryParam => {
                    Box::new(RemoveQueryParamTransformer::from_config(&rule.config)?)
                }
                TransformationType::ModifyPath => {
                    Box::new(ModifyPathTransformer::from_config(&rule.config)?)
                }
                TransformationType::ModifyBody => {
                    Box::new(ModifyBodyTransformer::from_config(&rule.config)?)
                }
            };
            transformers.push(transformer);
        }

        Ok(transformers)
    }

    /// Build response transformers from configuration rules
    fn build_response_transformers(
        rules: &[TransformationRule],
    ) -> GatewayResult<Vec<Box<dyn ResponseTransformer>>> {
        let mut transformers = Vec::new();

        for rule in rules {
            let transformer: Box<dyn ResponseTransformer> = match rule.transform_type {
                TransformationType::AddHeader => {
                    Box::new(ResponseAddHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::RemoveHeader => {
                    Box::new(ResponseRemoveHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::ModifyHeader => {
                    Box::new(ResponseModifyHeaderTransformer::from_config(&rule.config)?)
                }
                TransformationType::ModifyBody => {
                    Box::new(ResponseModifyBodyTransformer::from_config(&rule.config)?)
                }
                _ => continue, // Skip non-response transformations
            };
            transformers.push(transformer);
        }

        Ok(transformers)
    }

    /// Apply request transformations
    pub async fn transform_request(
        &self,
        mut request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        // Apply content negotiation first
        request = self.content_negotiator.negotiate_request(request).await?;

        // Apply configured transformations
        for transformer in self.request_transformers.iter() {
            request = transformer.transform(request, context).await?;
        }

        Ok(request)
    }

    /// Apply response transformations
    pub async fn transform_response(
        &self,
        mut response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Apply configured transformations
        for transformer in self.response_transformers.iter() {
            response = transformer.transform(response, context).await?;
        }

        // Apply content negotiation
        response = self.content_negotiator.negotiate_response(response, context).await?;

        Ok(response)
    }
}

/// Trait for request transformers
#[async_trait]
pub trait RequestTransformer: Send + Sync {
    /// Transform a request
    async fn transform(
        &self,
        request: IncomingRequest,
        context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest>;
}

/// Trait for response transformers
#[async_trait]
pub trait ResponseTransformer: Send + Sync {
    /// Transform a response
    async fn transform(
        &self,
        response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse>;
}

/// Add header transformer for requests
#[derive(Debug, Clone)]
pub struct AddHeaderTransformer {
    header_name: HeaderName,
    header_value: HeaderValue,
}

impl AddHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in AddHeader config".to_string(),
            })?;
        let value = config["value"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header value in AddHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
            header_value: HeaderValue::from_str(value).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header value '{}': {}", value, e),
            })?,
        })
    }
}

#[async_trait]
impl RequestTransformer for AddHeaderTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        request.headers.insert(self.header_name.clone(), self.header_value.clone());
        Ok(request)
    }
}

/// Remove header transformer for requests
#[derive(Debug, Clone)]
pub struct RemoveHeaderTransformer {
    header_name: HeaderName,
}

impl RemoveHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in RemoveHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
        })
    }
}

#[async_trait]
impl RequestTransformer for RemoveHeaderTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        request.headers.remove(&self.header_name);
        Ok(request)
    }
}

/// Modify header transformer for requests
#[derive(Debug, Clone)]
pub struct ModifyHeaderTransformer {
    header_name: HeaderName,
    header_value: HeaderValue,
}

impl ModifyHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in ModifyHeader config".to_string(),
            })?;
        let value = config["value"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header value in ModifyHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
            header_value: HeaderValue::from_str(value).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header value '{}': {}", value, e),
            })?,
        })
    }
}

#[async_trait]
impl RequestTransformer for ModifyHeaderTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        request.headers.insert(self.header_name.clone(), self.header_value.clone());
        Ok(request)
    }
}

/// Add query parameter transformer for requests
#[derive(Debug, Clone)]
pub struct AddQueryParamTransformer {
    param_name: String,
    param_value: String,
}

impl AddQueryParamTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing param name in AddQueryParam config".to_string(),
            })?;
        let value = config["value"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing param value in AddQueryParam config".to_string(),
            })?;

        Ok(Self {
            param_name: name.to_string(),
            param_value: value.to_string(),
        })
    }
}

#[async_trait]
impl RequestTransformer for AddQueryParamTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let mut parts = request.uri.clone().into_parts();
        let query = parts.path_and_query
            .as_ref()
            .and_then(|pq| pq.query())
            .unwrap_or("");
        
        let new_query = if query.is_empty() {
            format!("{}={}", self.param_name, self.param_value)
        } else {
            format!("{}&{}={}", query, self.param_name, self.param_value)
        };

        let path = parts.path_and_query
            .as_ref()
            .map(|pq| pq.path())
            .unwrap_or("/");

        parts.path_and_query = Some(
            format!("{}?{}", path, new_query)
                .parse()
                .map_err(|e| GatewayError::Configuration {
                    message: format!("Invalid URI after adding query param: {}", e),
                })?,
        );

        request.uri = axum::http::Uri::from_parts(parts).map_err(|e| GatewayError::Configuration {
            message: format!("Failed to reconstruct URI: {}", e),
        })?;

        Ok(request)
    }
}

/// Remove query parameter transformer for requests
#[derive(Debug, Clone)]
pub struct RemoveQueryParamTransformer {
    param_name: String,
}

impl RemoveQueryParamTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing param name in RemoveQueryParam config".to_string(),
            })?;

        Ok(Self {
            param_name: name.to_string(),
        })
    }
}

#[async_trait]
impl RequestTransformer for RemoveQueryParamTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let mut parts = request.uri.clone().into_parts();
        
        if let Some(path_and_query) = &parts.path_and_query {
            if let Some(query) = path_and_query.query() {
                let params: Vec<&str> = query
                    .split('&')
                    .filter(|param| !param.starts_with(&format!("{}=", self.param_name)))
                    .collect();

                let path = path_and_query.path();
                let new_uri = if params.is_empty() {
                    path.to_string()
                } else {
                    format!("{}?{}", path, params.join("&"))
                };

                parts.path_and_query = Some(
                    new_uri
                        .parse()
                        .map_err(|e| GatewayError::Configuration {
                            message: format!("Invalid URI after removing query param: {}", e),
                        })?,
                );

                request.uri = axum::http::Uri::from_parts(parts).map_err(|e| GatewayError::Configuration {
                    message: format!("Failed to reconstruct URI: {}", e),
                })?;
            }
        }

        Ok(request)
    }
}

/// Modify path transformer for requests
#[derive(Debug, Clone)]
pub struct ModifyPathTransformer {
    pattern: String,
    replacement: String,
}

impl ModifyPathTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let pattern = config["pattern"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing pattern in ModifyPath config".to_string(),
            })?;
        let replacement = config["replacement"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing replacement in ModifyPath config".to_string(),
            })?;

        Ok(Self {
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
        })
    }
}

#[async_trait]
impl RequestTransformer for ModifyPathTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let mut parts = request.uri.clone().into_parts();
        
        if let Some(path_and_query) = &parts.path_and_query {
            let old_path = path_and_query.path();
            let new_path = old_path.replace(&self.pattern, &self.replacement);
            
            let new_uri = if let Some(query) = path_and_query.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path
            };

            parts.path_and_query = Some(
                new_uri
                    .parse()
                    .map_err(|e| GatewayError::Configuration {
                        message: format!("Invalid URI after path modification: {}", e),
                    })?,
            );

            request.uri = axum::http::Uri::from_parts(parts).map_err(|e| GatewayError::Configuration {
                message: format!("Failed to reconstruct URI: {}", e),
            })?;
        }

        Ok(request)
    }
}

/// Modify body transformer for requests
#[derive(Debug, Clone)]
pub struct ModifyBodyTransformer {
    transformation_type: BodyTransformationType,
    config: JsonValue,
}

#[derive(Debug, Clone)]
pub enum BodyTransformationType {
    JsonTransform,
    XmlTransform,
    TextReplace,
}

impl ModifyBodyTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let transform_type = config["type"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing transformation type in ModifyBody config".to_string(),
            })?;

        let transformation_type = match transform_type {
            "json" => BodyTransformationType::JsonTransform,
            "xml" => BodyTransformationType::XmlTransform,
            "text" => BodyTransformationType::TextReplace,
            _ => return Err(GatewayError::Configuration {
                message: format!("Unknown body transformation type: {}", transform_type),
            }),
        };

        Ok(Self {
            transformation_type,
            config: config.clone(),
        })
    }
}

#[async_trait]
impl RequestTransformer for ModifyBodyTransformer {
    async fn transform(
        &self,
        mut request: IncomingRequest,
        _context: &mut RequestContext,
    ) -> GatewayResult<IncomingRequest> {
        let body_bytes = Arc::try_unwrap(request.body)
            .unwrap_or_else(|arc| (*arc).clone());

        let transformed_body = match self.transformation_type {
            BodyTransformationType::JsonTransform => {
                self.transform_json_body(body_bytes).await?
            }
            BodyTransformationType::XmlTransform => {
                self.transform_xml_body(body_bytes).await?
            }
            BodyTransformationType::TextReplace => {
                self.transform_text_body(body_bytes).await?
            }
        };

        request.body = Arc::new(transformed_body);
        Ok(request)
    }
}

impl ModifyBodyTransformer {
    async fn transform_json_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in request body: {}", e),
        })?;

        let mut json: JsonValue = serde_json::from_str(&body_str).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Invalid JSON in request body: {}", e),
            }
        })?;

        // Apply JSON transformations based on config
        if let Some(transformations) = self.config["transformations"].as_array() {
            for transform in transformations {
                self.apply_json_transformation(&mut json, transform)?;
            }
        }

        let transformed_json = serde_json::to_vec(&json).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Failed to serialize transformed JSON: {}", e),
            }
        })?;

        Ok(transformed_json)
    }

    async fn transform_xml_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in request body: {}", e),
        })?;

        // For XML transformation, we'll implement basic find/replace for now
        // A full XML transformation would require more complex parsing
        let mut transformed = body_str;
        
        if let Some(replacements) = self.config["replacements"].as_array() {
            for replacement in replacements {
                if let (Some(from), Some(to)) = (
                    replacement["from"].as_str(),
                    replacement["to"].as_str(),
                ) {
                    transformed = transformed.replace(from, to);
                }
            }
        }

        Ok(transformed.into_bytes())
    }

    async fn transform_text_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in request body: {}", e),
        })?;

        let mut transformed = body_str;
        
        if let Some(replacements) = self.config["replacements"].as_array() {
            for replacement in replacements {
                if let (Some(from), Some(to)) = (
                    replacement["from"].as_str(),
                    replacement["to"].as_str(),
                ) {
                    transformed = transformed.replace(from, to);
                }
            }
        }

        Ok(transformed.into_bytes())
    }

    fn apply_json_transformation(
        &self,
        json: &mut JsonValue,
        transform: &JsonValue,
    ) -> GatewayResult<()> {
        let operation = transform["operation"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing operation in JSON transformation".to_string(),
            })?;

        match operation {
            "add" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON add operation".to_string(),
                })?;
                let value = &transform["value"];
                self.json_add(json, path, value.clone())?;
            }
            "remove" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON remove operation".to_string(),
                })?;
                self.json_remove(json, path)?;
            }
            "replace" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON replace operation".to_string(),
                })?;
                let value = &transform["value"];
                self.json_replace(json, path, value.clone())?;
            }
            _ => {
                return Err(GatewayError::Configuration {
                    message: format!("Unknown JSON operation: {}", operation),
                });
            }
        }

        Ok(())
    }

    fn json_add(&self, json: &mut JsonValue, path: &str, value: JsonValue) -> GatewayResult<()> {
        // Simple path implementation - for production, consider using a JSON path library
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.insert(key.to_string(), value.clone());
            }
        })
    }

    fn json_remove(&self, json: &mut JsonValue, path: &str) -> GatewayResult<()> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.remove(key);
            }
        })
    }

    fn json_replace(&self, json: &mut JsonValue, path: &str, value: JsonValue) -> GatewayResult<()> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.insert(key.to_string(), value.clone());
            }
        })
    }

    fn json_navigate_and_modify<F>(
        &self,
        json: &mut JsonValue,
        parts: &[&str],
        modify_fn: F,
    ) -> GatewayResult<()>
    where
        F: FnOnce(&mut JsonValue, &str),
    {
        if parts.is_empty() {
            return Ok(());
        }

        if parts.len() == 1 {
            modify_fn(json, parts[0]);
            return Ok(());
        }

        let (current, remaining) = parts.split_first().unwrap();
        
        if let JsonValue::Object(ref mut map) = json {
            if let Some(next_value) = map.get_mut(*current) {
                self.json_navigate_and_modify(next_value, remaining, modify_fn)?;
            }
        }

        Ok(())
    }
}

// Response Transformers

/// Add header transformer for responses
#[derive(Debug, Clone)]
pub struct ResponseAddHeaderTransformer {
    header_name: HeaderName,
    header_value: HeaderValue,
}

impl ResponseAddHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in AddHeader config".to_string(),
            })?;
        let value = config["value"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header value in AddHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
            header_value: HeaderValue::from_str(value).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header value '{}': {}", value, e),
            })?,
        })
    }
}

#[async_trait]
impl ResponseTransformer for ResponseAddHeaderTransformer {
    async fn transform(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        response.headers.insert(self.header_name.clone(), self.header_value.clone());
        Ok(response)
    }
}

/// Remove header transformer for responses
#[derive(Debug, Clone)]
pub struct ResponseRemoveHeaderTransformer {
    header_name: HeaderName,
}

impl ResponseRemoveHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in RemoveHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
        })
    }
}

#[async_trait]
impl ResponseTransformer for ResponseRemoveHeaderTransformer {
    async fn transform(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        response.headers.remove(&self.header_name);
        Ok(response)
    }
}

/// Modify header transformer for responses
#[derive(Debug, Clone)]
pub struct ResponseModifyHeaderTransformer {
    header_name: HeaderName,
    header_value: HeaderValue,
}

impl ResponseModifyHeaderTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let name = config["name"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header name in ModifyHeader config".to_string(),
            })?;
        let value = config["value"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing header value in ModifyHeader config".to_string(),
            })?;

        Ok(Self {
            header_name: HeaderName::from_str(name).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header name '{}': {}", name, e),
            })?,
            header_value: HeaderValue::from_str(value).map_err(|e| GatewayError::Configuration {
                message: format!("Invalid header value '{}': {}", value, e),
            })?,
        })
    }
}

#[async_trait]
impl ResponseTransformer for ResponseModifyHeaderTransformer {
    async fn transform(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        response.headers.insert(self.header_name.clone(), self.header_value.clone());
        Ok(response)
    }
}

/// Modify body transformer for responses
#[derive(Debug, Clone)]
pub struct ResponseModifyBodyTransformer {
    transformation_type: BodyTransformationType,
    config: JsonValue,
}

impl ResponseModifyBodyTransformer {
    pub fn from_config(config: &JsonValue) -> GatewayResult<Self> {
        let transform_type = config["type"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing transformation type in ModifyBody config".to_string(),
            })?;

        let transformation_type = match transform_type {
            "json" => BodyTransformationType::JsonTransform,
            "xml" => BodyTransformationType::XmlTransform,
            "text" => BodyTransformationType::TextReplace,
            _ => return Err(GatewayError::Configuration {
                message: format!("Unknown body transformation type: {}", transform_type),
            }),
        };

        Ok(Self {
            transformation_type,
            config: config.clone(),
        })
    }
}

#[async_trait]
impl ResponseTransformer for ResponseModifyBodyTransformer {
    async fn transform(
        &self,
        mut response: GatewayResponse,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        let body_bytes = Arc::try_unwrap(response.body)
            .unwrap_or_else(|arc| (*arc).clone());

        let transformed_body = match self.transformation_type {
            BodyTransformationType::JsonTransform => {
                self.transform_json_body(body_bytes).await?
            }
            BodyTransformationType::XmlTransform => {
                self.transform_xml_body(body_bytes).await?
            }
            BodyTransformationType::TextReplace => {
                self.transform_text_body(body_bytes).await?
            }
        };

        response.body = Arc::new(transformed_body);
        Ok(response)
    }
}

impl ResponseModifyBodyTransformer {
    async fn transform_json_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in response body: {}", e),
        })?;

        let mut json: JsonValue = serde_json::from_str(&body_str).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Invalid JSON in response body: {}", e),
            }
        })?;

        // Apply JSON transformations based on config
        if let Some(transformations) = self.config["transformations"].as_array() {
            for transform in transformations {
                self.apply_json_transformation(&mut json, transform)?;
            }
        }

        let transformed_json = serde_json::to_vec(&json).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Failed to serialize transformed JSON: {}", e),
            }
        })?;

        Ok(transformed_json)
    }

    async fn transform_xml_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in response body: {}", e),
        })?;

        let mut transformed = body_str;
        
        if let Some(replacements) = self.config["replacements"].as_array() {
            for replacement in replacements {
                if let (Some(from), Some(to)) = (
                    replacement["from"].as_str(),
                    replacement["to"].as_str(),
                ) {
                    transformed = transformed.replace(from, to);
                }
            }
        }

        Ok(transformed.into_bytes())
    }

    async fn transform_text_body(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in response body: {}", e),
        })?;

        let mut transformed = body_str;
        
        if let Some(replacements) = self.config["replacements"].as_array() {
            for replacement in replacements {
                if let (Some(from), Some(to)) = (
                    replacement["from"].as_str(),
                    replacement["to"].as_str(),
                ) {
                    transformed = transformed.replace(from, to);
                }
            }
        }

        Ok(transformed.into_bytes())
    }

    fn apply_json_transformation(
        &self,
        json: &mut JsonValue,
        transform: &JsonValue,
    ) -> GatewayResult<()> {
        let operation = transform["operation"]
            .as_str()
            .ok_or_else(|| GatewayError::Configuration {
                message: "Missing operation in JSON transformation".to_string(),
            })?;

        match operation {
            "add" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON add operation".to_string(),
                })?;
                let value = &transform["value"];
                self.json_add(json, path, value.clone())?;
            }
            "remove" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON remove operation".to_string(),
                })?;
                self.json_remove(json, path)?;
            }
            "replace" => {
                let path = transform["path"].as_str().ok_or_else(|| GatewayError::Configuration {
                    message: "Missing path in JSON replace operation".to_string(),
                })?;
                let value = &transform["value"];
                self.json_replace(json, path, value.clone())?;
            }
            _ => {
                return Err(GatewayError::Configuration {
                    message: format!("Unknown JSON operation: {}", operation),
                });
            }
        }

        Ok(())
    }

    fn json_add(&self, json: &mut JsonValue, path: &str, value: JsonValue) -> GatewayResult<()> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.insert(key.to_string(), value.clone());
            }
        })
    }

    fn json_remove(&self, json: &mut JsonValue, path: &str) -> GatewayResult<()> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.remove(key);
            }
        })
    }

    fn json_replace(&self, json: &mut JsonValue, path: &str, value: JsonValue) -> GatewayResult<()> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        self.json_navigate_and_modify(json, &parts, |target, key| {
            if let JsonValue::Object(ref mut map) = target {
                map.insert(key.to_string(), value.clone());
            }
        })
    }

    fn json_navigate_and_modify<F>(
        &self,
        json: &mut JsonValue,
        parts: &[&str],
        modify_fn: F,
    ) -> GatewayResult<()>
    where
        F: FnOnce(&mut JsonValue, &str),
    {
        if parts.is_empty() {
            return Ok(());
        }

        if parts.len() == 1 {
            modify_fn(json, parts[0]);
            return Ok(());
        }

        let (current, remaining) = parts.split_first().unwrap();
        
        if let JsonValue::Object(ref mut map) = json {
            if let Some(next_value) = map.get_mut(*current) {
                self.json_navigate_and_modify(next_value, remaining, modify_fn)?;
            }
        }

        Ok(())
    }
}

/// Content negotiation and protocol translation handler
#[derive(Debug, Clone)]
pub struct ContentNegotiator {
    supported_formats: Vec<ContentFormat>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentFormat {
    Json,
    Xml,
    Html,
    PlainText,
    FormUrlEncoded,
}

impl ContentFormat {
    fn from_content_type(content_type: &str) -> Option<Self> {
        match content_type.to_lowercase().as_str() {
            ct if ct.contains("application/json") => Some(ContentFormat::Json),
            ct if ct.contains("application/xml") || ct.contains("text/xml") => Some(ContentFormat::Xml),
            ct if ct.contains("text/html") => Some(ContentFormat::Html),
            ct if ct.contains("text/plain") => Some(ContentFormat::PlainText),
            ct if ct.contains("application/x-www-form-urlencoded") => Some(ContentFormat::FormUrlEncoded),
            _ => None,
        }
    }

    fn to_content_type(&self) -> &'static str {
        match self {
            ContentFormat::Json => "application/json",
            ContentFormat::Xml => "application/xml",
            ContentFormat::Html => "text/html",
            ContentFormat::PlainText => "text/plain",
            ContentFormat::FormUrlEncoded => "application/x-www-form-urlencoded",
        }
    }
}

impl ContentNegotiator {
    pub fn new() -> Self {
        Self {
            supported_formats: vec![
                ContentFormat::Json,
                ContentFormat::Xml,
                ContentFormat::Html,
                ContentFormat::PlainText,
                ContentFormat::FormUrlEncoded,
            ],
        }
    }

    /// Negotiate content format for incoming requests
    pub async fn negotiate_request(
        &self,
        mut request: IncomingRequest,
    ) -> GatewayResult<IncomingRequest> {
        // Check if content type conversion is needed
        if let Some(content_type) = request.header("content-type") {
            if let Some(accept) = request.header("accept") {
                let source_format = ContentFormat::from_content_type(content_type);
                let target_format = self.parse_accept_header(accept);

                if let (Some(source), Some(target)) = (source_format, target_format) {
                    if source != target {
                        request = self.convert_request_content(request, source, target).await?;
                    }
                }
            }
        }

        Ok(request)
    }

    /// Negotiate content format for outgoing responses
    pub async fn negotiate_response(
        &self,
        mut response: GatewayResponse,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Check if the client requested a specific format via Accept header
        if let Some(accept) = context.request.header("accept") {
            if let Some(target_format) = self.parse_accept_header(accept) {
                // Determine current response format
                let current_content_type = response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream");

                if let Some(source_format) = ContentFormat::from_content_type(current_content_type) {
                    if source_format != target_format {
                        response = self.convert_response_content(response, source_format, target_format).await?;
                    }
                }
            }
        }

        Ok(response)
    }

    fn parse_accept_header(&self, accept: &str) -> Option<ContentFormat> {
        // Parse Accept header and find the best matching format
        // This is a simplified implementation - a full implementation would handle q-values
        let formats: Vec<&str> = accept.split(',').map(|s| s.trim()).collect();
        
        for format in formats {
            if let Some(content_format) = ContentFormat::from_content_type(format) {
                if self.supported_formats.contains(&content_format) {
                    return Some(content_format);
                }
            }
        }

        None
    }

    async fn convert_request_content(
        &self,
        mut request: IncomingRequest,
        source: ContentFormat,
        target: ContentFormat,
    ) -> GatewayResult<IncomingRequest> {
        let body_bytes = Arc::try_unwrap(request.body)
            .unwrap_or_else(|arc| (*arc).clone());

        let converted_body = self.convert_content(body_bytes, source, target.clone()).await?;
        
        // Update content-type header
        request.headers.insert(
            "content-type",
            HeaderValue::from_str(target.to_content_type()).unwrap(),
        );

        request.body = Arc::new(converted_body);
        Ok(request)
    }

    async fn convert_response_content(
        &self,
        mut response: GatewayResponse,
        source: ContentFormat,
        target: ContentFormat,
    ) -> GatewayResult<GatewayResponse> {
        let body_bytes = Arc::try_unwrap(response.body)
            .unwrap_or_else(|arc| (*arc).clone());

        let converted_body = self.convert_content(body_bytes, source, target.clone()).await?;
        
        // Update content-type header
        response.headers.insert(
            "content-type",
            HeaderValue::from_str(target.to_content_type()).unwrap(),
        );

        response.body = Arc::new(converted_body);
        Ok(response)
    }

    pub async fn convert_content(
        &self,
        body: Vec<u8>,
        source: ContentFormat,
        target: ContentFormat,
    ) -> GatewayResult<Vec<u8>> {
        match (source, target) {
            (ContentFormat::Json, ContentFormat::Xml) => self.json_to_xml(body).await,
            (ContentFormat::Xml, ContentFormat::Json) => self.xml_to_json(body).await,
            (ContentFormat::Json, ContentFormat::PlainText) => self.json_to_text(body).await,
            (ContentFormat::Xml, ContentFormat::PlainText) => self.xml_to_text(body).await,
            (ContentFormat::FormUrlEncoded, ContentFormat::Json) => self.form_to_json(body).await,
            (ContentFormat::Json, ContentFormat::FormUrlEncoded) => self.json_to_form(body).await,
            _ => {
                // For unsupported conversions, return the original body
                Ok(body)
            }
        }
    }

    async fn json_to_xml(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        let json: JsonValue = serde_json::from_str(&body_str).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Invalid JSON: {}", e),
            }
        })?;

        // Simple JSON to XML conversion
        let xml = self.json_value_to_xml(&json, "root");
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml).into_bytes())
    }

    async fn xml_to_json(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        // This is a simplified XML to JSON conversion
        // For production use, consider using a proper XML parser like quick-xml
        let json = serde_json::json!({
            "xml_content": body_str
        });

        serde_json::to_vec(&json).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Failed to serialize JSON: {}", e),
        })
    }

    async fn json_to_text(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        let json: JsonValue = serde_json::from_str(&body_str).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Invalid JSON: {}", e),
            }
        })?;

        let text = self.json_value_to_text(&json);
        Ok(text.into_bytes())
    }

    async fn xml_to_text(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        // Simple XML to text conversion - strip tags
        let text = body_str
            .replace('<', " <")
            .replace('>', "> ")
            .split_whitespace()
            .filter(|word| !word.starts_with('<') || !word.ends_with('>'))
            .collect::<Vec<_>>()
            .join(" ");

        Ok(text.into_bytes())
    }

    async fn form_to_json(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        let mut json_map = serde_json::Map::new();
        
        for pair in body_str.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_key = urlencoding::decode(key).map_err(|e| {
                    GatewayError::ResponseTransformation {
                        reason: format!("Failed to decode form key: {}", e),
                    }
                })?;
                let decoded_value = urlencoding::decode(value).map_err(|e| {
                    GatewayError::ResponseTransformation {
                        reason: format!("Failed to decode form value: {}", e),
                    }
                })?;
                
                json_map.insert(decoded_key.to_string(), JsonValue::String(decoded_value.to_string()));
            }
        }

        let json = JsonValue::Object(json_map);
        serde_json::to_vec(&json).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Failed to serialize JSON: {}", e),
        })
    }

    async fn json_to_form(&self, body: Vec<u8>) -> GatewayResult<Vec<u8>> {
        let body_str = String::from_utf8(body).map_err(|e| GatewayError::ResponseTransformation {
            reason: format!("Invalid UTF-8 in body: {}", e),
        })?;

        let json: JsonValue = serde_json::from_str(&body_str).map_err(|e| {
            GatewayError::ResponseTransformation {
                reason: format!("Invalid JSON: {}", e),
            }
        })?;

        let mut form_pairs = Vec::new();
        
        if let JsonValue::Object(map) = json {
            for (key, value) in map {
                let value_str = match value {
                    JsonValue::String(s) => s,
                    JsonValue::Number(n) => n.to_string(),
                    JsonValue::Bool(b) => b.to_string(),
                    _ => serde_json::to_string(&value).unwrap_or_default(),
                };
                
                let encoded_key = urlencoding::encode(&key);
                let encoded_value = urlencoding::encode(&value_str);
                form_pairs.push(format!("{}={}", encoded_key, encoded_value));
            }
        }

        Ok(form_pairs.join("&").into_bytes())
    }

    fn json_value_to_xml(&self, value: &JsonValue, tag_name: &str) -> String {
        match value {
            JsonValue::Object(map) => {
                let mut xml = format!("<{}>", tag_name);
                for (key, val) in map {
                    xml.push_str(&self.json_value_to_xml(val, key));
                }
                xml.push_str(&format!("</{}>", tag_name));
                xml
            }
            JsonValue::Array(arr) => {
                let mut xml = String::new();
                for item in arr {
                    xml.push_str(&self.json_value_to_xml(item, "item"));
                }
                xml
            }
            JsonValue::String(s) => format!("<{}>{}</{}>", tag_name, s, tag_name),
            JsonValue::Number(n) => format!("<{}>{}</{}>", tag_name, n, tag_name),
            JsonValue::Bool(b) => format!("<{}>{}</{}>", tag_name, b, tag_name),
            JsonValue::Null => format!("<{} nil=\"true\"/>", tag_name),
        }
    }

    fn json_value_to_text(&self, value: &JsonValue) -> String {
        match value {
            JsonValue::Object(map) => {
                let mut text = String::new();
                for (key, val) in map {
                    text.push_str(&format!("{}: {}\n", key, self.json_value_to_text(val)));
                }
                text
            }
            JsonValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| self.json_value_to_text(v)).collect();
                format!("[{}]", items.join(", "))
            }
            JsonValue::String(s) => s.clone(),
            JsonValue::Number(n) => n.to_string(),
            JsonValue::Bool(b) => b.to_string(),
            JsonValue::Null => "null".to_string(),
        }
    }
}

/// Tower layer for transformation middleware
#[derive(Clone)]
pub struct TransformationLayer {
    middleware: TransformationMiddleware,
}

impl TransformationLayer {
    pub fn new(config: &TransformationConfig) -> GatewayResult<Self> {
        Ok(Self {
            middleware: TransformationMiddleware::new(config)?,
        })
    }
}

impl<S> Layer<S> for TransformationLayer {
    type Service = TransformationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TransformationService {
            inner,
            middleware: self.middleware.clone(),
        }
    }
}

/// Tower service for transformation middleware
#[derive(Clone)]
pub struct TransformationService<S> {
    inner: S,
    middleware: TransformationMiddleware,
}

impl<S, ReqBody, ResBody> Service<axum::http::Request<ReqBody>> for TransformationService<S>
where
    S: Service<axum::http::Request<ReqBody>, Response = axum::http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let _middleware = self.middleware.clone();

        Box::pin(async move {
            // Note: This is a simplified implementation
            // In a real implementation, you would need to properly handle the request/response transformation
            // within the context of the gateway's request processing pipeline
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, StatusCode, Uri, Version};
    use std::net::SocketAddr;

    fn create_test_request() -> IncomingRequest {
        IncomingRequest::new(
            crate::core::types::Protocol::Http,
            Method::GET,
            Uri::from_static("/test"),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        )
    }

    #[tokio::test]
    async fn test_add_header_transformer() {
        let config = serde_json::json!({
            "name": "x-custom-header",
            "value": "test-value"
        });

        let transformer = AddHeaderTransformer::from_config(&config).unwrap();
        let request = create_test_request();
        let mut context = RequestContext::new(Arc::new(request.clone()));

        let transformed = transformer.transform(request, &mut context).await.unwrap();
        
        assert_eq!(
            transformed.header("x-custom-header"),
            Some("test-value")
        );
    }

    #[tokio::test]
    async fn test_remove_header_transformer() {
        let config = serde_json::json!({
            "name": "x-remove-me"
        });

        let transformer = RemoveHeaderTransformer::from_config(&config).unwrap();
        let mut request = create_test_request();
        request.headers.insert("x-remove-me", "should-be-removed".parse().unwrap());
        let mut context = RequestContext::new(Arc::new(request.clone()));

        let transformed = transformer.transform(request, &mut context).await.unwrap();
        
        assert_eq!(transformed.header("x-remove-me"), None);
    }

    #[tokio::test]
    async fn test_content_negotiator_json_to_xml() {
        let negotiator = ContentNegotiator::new();
        let json_body = r#"{"name": "test", "value": 123}"#.as_bytes().to_vec();
        
        let result = negotiator.convert_content(
            json_body,
            ContentFormat::Json,
            ContentFormat::Xml,
        ).await.unwrap();
        
        let xml_str = String::from_utf8(result).unwrap();
        assert!(xml_str.contains("<root>"));
        assert!(xml_str.contains("<name>test</name>"));
        assert!(xml_str.contains("<value>123</value>"));
    }

    #[tokio::test]
    async fn test_json_transformation() {
        let config = serde_json::json!({
            "type": "json",
            "transformations": [
                {
                    "operation": "add",
                    "path": "/new_field",
                    "value": "added_value"
                }
            ]
        });

        let transformer = ModifyBodyTransformer::from_config(&config).unwrap();
        let json_body = r#"{"existing": "value"}"#.as_bytes().to_vec();
        let mut request = create_test_request();
        request.body = Arc::new(json_body);
        let mut context = RequestContext::new(Arc::new(request.clone()));

        let transformed = transformer.transform(request, &mut context).await.unwrap();
        let body_str = String::from_utf8((*transformed.body).clone()).unwrap();
        let json: JsonValue = serde_json::from_str(&body_str).unwrap();
        
        assert_eq!(json["existing"], "value");
        assert_eq!(json["new_field"], "added_value");
    }
}
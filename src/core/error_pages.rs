//! # Custom Error Pages Module
//!
//! This module provides custom error page generation for the API Gateway.
//! It supports both HTML and JSON error responses with customizable templates
//! and branding.
//!
//! ## Features
//! - Custom HTML error pages with templates
//! - JSON error responses for API clients
//! - Configurable error page templates
//! - Branding and customization support
//! - Content negotiation based on Accept headers

use crate::core::error::{GatewayError, GatewayResult};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tera::{Context, Tera};
use tracing::{debug, warn};

/// Error page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPageConfig {
    /// Enable custom error pages
    pub enabled: bool,
    
    /// Default error page template directory
    pub template_dir: String,
    
    /// Brand name to display on error pages
    pub brand_name: String,
    
    /// Support contact information
    pub support_contact: Option<String>,
    
    /// Custom CSS for error pages
    pub custom_css: Option<String>,
    
    /// Custom JavaScript for error pages
    pub custom_js: Option<String>,
    
    /// Show detailed error information (for development)
    pub show_details: bool,
    
    /// Custom error messages by status code
    pub custom_messages: HashMap<u16, String>,
    
    /// Custom error page templates by status code
    pub custom_templates: HashMap<u16, String>,
}

impl Default for ErrorPageConfig {
    fn default() -> Self {
        let mut custom_messages = HashMap::new();
        custom_messages.insert(400, "Bad Request - The request could not be understood.".to_string());
        custom_messages.insert(401, "Unauthorized - Authentication is required.".to_string());
        custom_messages.insert(403, "Forbidden - Access to this resource is denied.".to_string());
        custom_messages.insert(404, "Not Found - The requested resource could not be found.".to_string());
        custom_messages.insert(429, "Too Many Requests - Rate limit exceeded.".to_string());
        custom_messages.insert(500, "Internal Server Error - Something went wrong on our end.".to_string());
        custom_messages.insert(502, "Bad Gateway - The upstream service is unavailable.".to_string());
        custom_messages.insert(503, "Service Unavailable - The service is temporarily unavailable.".to_string());
        custom_messages.insert(504, "Gateway Timeout - The upstream service did not respond in time.".to_string());
        
        Self {
            enabled: true,
            template_dir: "templates/errors".to_string(),
            brand_name: "API Gateway".to_string(),
            support_contact: None,
            custom_css: None,
            custom_js: None,
            show_details: false,
            custom_messages,
            custom_templates: HashMap::new(),
        }
    }
}

/// Error response format based on content negotiation
#[derive(Debug, Clone)]
pub enum ErrorResponseFormat {
    /// HTML error page
    Html,
    /// JSON error response
    Json,
    /// Plain text error response
    Text,
}

/// Custom error page generator
pub struct ErrorPageGenerator {
    /// Configuration for error pages
    config: ErrorPageConfig,
    
    /// Tera template engine
    tera: Tera,
}

impl ErrorPageGenerator {
    /// Create a new error page generator
    pub fn new(config: ErrorPageConfig) -> GatewayResult<Self> {
        let mut tera = Tera::new(&format!("{}/**/*", config.template_dir))
            .unwrap_or_else(|_| {
                debug!("No custom templates found, using built-in templates");
                Tera::new("").unwrap()
            });
        
        // Add built-in templates
        Self::add_builtin_templates(&mut tera)?;
        
        Ok(Self { config, tera })
    }
    
    /// Add built-in error page templates
    fn add_builtin_templates(tera: &mut Tera) -> GatewayResult<()> {
        // Default HTML error page template
        let default_html_template = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ status_code }} - {{ status_text }} | {{ brand_name }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 3rem;
            text-align: center;
            max-width: 500px;
            margin: 2rem;
        }
        .error-code {
            font-size: 4rem;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 1rem;
        }
        .error-title {
            font-size: 1.5rem;
            color: #2c3e50;
            margin-bottom: 1rem;
        }
        .error-message {
            color: #7f8c8d;
            margin-bottom: 2rem;
            line-height: 1.6;
        }
        .error-details {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            font-family: monospace;
            font-size: 0.9rem;
            color: #6c757d;
            text-align: left;
        }
        .back-button {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.3s;
        }
        .back-button:hover {
            background: #2980b9;
        }
        .support-info {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #ecf0f1;
            color: #95a5a6;
            font-size: 0.9rem;
        }
        {% if custom_css %}
        {{ custom_css | safe }}
        {% endif %}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">{{ status_code }}</div>
        <div class="error-title">{{ status_text }}</div>
        <div class="error-message">{{ message }}</div>
        
        {% if show_details and error_details %}
        <div class="error-details">
            <strong>Error Details:</strong><br>
            {{ error_details }}
        </div>
        {% endif %}
        
        <a href="javascript:history.back()" class="back-button">Go Back</a>
        
        {% if support_contact %}
        <div class="support-info">
            Need help? Contact support: {{ support_contact }}
        </div>
        {% endif %}
    </div>
    
    {% if custom_js %}
    <script>
        {{ custom_js | safe }}
    </script>
    {% endif %}
</body>
</html>
        "#;
        
        tera.add_raw_template("default.html", default_html_template)
            .map_err(|e| GatewayError::internal(format!("Failed to add default HTML template: {}", e)))?;
        
        // Minimal error page template for lightweight responses
        let minimal_html_template = r#"
<!DOCTYPE html>
<html>
<head>
    <title>{{ status_code }} {{ status_text }}</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 2rem; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1 class="error">{{ status_code }} - {{ status_text }}</h1>
    <p>{{ message }}</p>
</body>
</html>
        "#;
        
        tera.add_raw_template("minimal.html", minimal_html_template)
            .map_err(|e| GatewayError::internal(format!("Failed to add minimal HTML template: {}", e)))?;
        
        Ok(())
    }
    
    /// Generate an error response based on the request headers and error
    pub fn generate_error_response(
        &self,
        error: &GatewayError,
        headers: &HeaderMap,
        request_path: Option<&str>,
        request_id: Option<&str>,
    ) -> Response {
        if !self.config.enabled {
            // Return default Axum error response if custom pages are disabled
            return error.clone().into_response();
        }
        
        let format = self.determine_response_format(headers);
        let status_code = error.status_code();
        
        match format {
            ErrorResponseFormat::Html => {
                self.generate_html_response(error, status_code, request_path, request_id)
            }
            ErrorResponseFormat::Json => {
                self.generate_json_response(error, status_code, request_id)
            }
            ErrorResponseFormat::Text => {
                self.generate_text_response(error, status_code)
            }
        }
    }
    
    /// Determine the appropriate response format based on Accept headers
    fn determine_response_format(&self, headers: &HeaderMap) -> ErrorResponseFormat {
        if let Some(accept) = headers.get("accept") {
            if let Ok(accept_str) = accept.to_str() {
                let accept_lower = accept_str.to_lowercase();
                
                if accept_lower.contains("application/json") {
                    return ErrorResponseFormat::Json;
                } else if accept_lower.contains("text/html") {
                    return ErrorResponseFormat::Html;
                } else if accept_lower.contains("text/plain") {
                    return ErrorResponseFormat::Text;
                }
            }
        }
        
        // Default to HTML for browser requests
        ErrorResponseFormat::Html
    }
    
    /// Generate HTML error response
    fn generate_html_response(
        &self,
        error: &GatewayError,
        status_code: StatusCode,
        request_path: Option<&str>,
        request_id: Option<&str>,
    ) -> Response {
        let status_code_num = status_code.as_u16();
        
        // Check for custom template for this status code
        let template_name = if self.config.custom_templates.contains_key(&status_code_num) {
            self.config.custom_templates.get(&status_code_num).unwrap()
        } else {
            "default.html"
        };
        
        let mut context = Context::new();
        context.insert("status_code", &status_code_num);
        context.insert("status_text", status_code.canonical_reason().unwrap_or("Unknown Error"));
        context.insert("brand_name", &self.config.brand_name);
        context.insert("show_details", &self.config.show_details);
        
        // Use custom message if available, otherwise use error message
        let message = self.config.custom_messages
            .get(&status_code_num)
            .cloned()
            .unwrap_or_else(|| error.to_string());
        context.insert("message", &message);
        
        if let Some(support) = &self.config.support_contact {
            context.insert("support_contact", support);
        }
        
        if let Some(css) = &self.config.custom_css {
            context.insert("custom_css", css);
        }
        
        if let Some(js) = &self.config.custom_js {
            context.insert("custom_js", js);
        }
        
        // Add error details if enabled
        if self.config.show_details {
            let mut details = Vec::new();
            details.push(format!("Error Type: {}", error.error_type()));
            if let Some(path) = request_path {
                details.push(format!("Request Path: {}", path));
            }
            if let Some(req_id) = request_id {
                details.push(format!("Request ID: {}", req_id));
            }
            details.push(format!("Timestamp: {}", chrono::Utc::now().to_rfc3339()));
            
            context.insert("error_details", &details.join("\n"));
        }
        
        match self.tera.render(template_name, &context) {
            Ok(html) => (status_code, Html(html)).into_response(),
            Err(e) => {
                warn!("Failed to render error template: {}", e);
                // Fallback to minimal template
                match self.tera.render("minimal.html", &context) {
                    Ok(html) => (status_code, Html(html)).into_response(),
                    Err(_) => {
                        // Ultimate fallback to plain text
                        (status_code, format!("{} - {}", status_code_num, message)).into_response()
                    }
                }
            }
        }
    }
    
    /// Generate JSON error response
    fn generate_json_response(
        &self,
        error: &GatewayError,
        status_code: StatusCode,
        request_id: Option<&str>,
    ) -> Response {
        let mut error_response = json!({
            "error": {
                "code": status_code.as_u16(),
                "message": error.to_string(),
                "type": error.error_type(),
                "retryable": error.is_retryable(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }
        });
        
        if let Some(req_id) = request_id {
            error_response["error"]["request_id"] = json!(req_id);
        }
        
        if self.config.show_details {
            error_response["error"]["details"] = json!({
                "status_text": status_code.canonical_reason().unwrap_or("Unknown Error"),
                "should_trigger_circuit_breaker": error.should_trigger_circuit_breaker(),
            });
        }
        
        if let Some(support) = &self.config.support_contact {
            error_response["error"]["support_contact"] = json!(support);
        }
        
        (status_code, Json(error_response)).into_response()
    }
    
    /// Generate plain text error response
    fn generate_text_response(&self, error: &GatewayError, status_code: StatusCode) -> Response {
        let status_code_num = status_code.as_u16();
        let message = self.config.custom_messages
            .get(&status_code_num)
            .cloned()
            .unwrap_or_else(|| error.to_string());
        
        let response_text = format!(
            "{} - {}\n\n{}\n",
            status_code_num,
            status_code.canonical_reason().unwrap_or("Unknown Error"),
            message
        );
        
        (status_code, response_text).into_response()
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: ErrorPageConfig) -> GatewayResult<()> {
        self.config = config;
        
        // Reload templates if template directory changed
        self.tera = Tera::new(&format!("{}/**/*", self.config.template_dir))
            .unwrap_or_else(|_| {
                debug!("No custom templates found, using built-in templates");
                Tera::new("").unwrap()
            });
        
        Self::add_builtin_templates(&mut self.tera)?;
        
        Ok(())
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &ErrorPageConfig {
        &self.config
    }
}

/// Error response builder for custom error handling
pub struct ErrorResponseBuilder {
    error: GatewayError,
    request_path: Option<String>,
    request_id: Option<String>,
    custom_message: Option<String>,
    custom_headers: HeaderMap,
}

impl ErrorResponseBuilder {
    /// Create a new error response builder
    pub fn new(error: GatewayError) -> Self {
        Self {
            error,
            request_path: None,
            request_id: None,
            custom_message: None,
            custom_headers: HeaderMap::new(),
        }
    }
    
    /// Set the request path for context
    pub fn with_request_path<S: Into<String>>(mut self, path: S) -> Self {
        self.request_path = Some(path.into());
        self
    }
    
    /// Set the request ID for correlation
    pub fn with_request_id<S: Into<String>>(mut self, request_id: S) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
    
    /// Set a custom error message
    pub fn with_custom_message<S: Into<String>>(mut self, message: S) -> Self {
        self.custom_message = Some(message.into());
        self
    }
    
    /// Add custom headers to the response
    pub fn with_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: axum::http::header::IntoHeaderName,
        V: TryInto<axum::http::HeaderValue>,
    {
        if let Ok(header_value) = value.try_into() {
            self.custom_headers.insert(key, header_value);
        }
        self
    }
    
    /// Build the error response using the provided error page generator
    pub fn build(self, generator: &ErrorPageGenerator, request_headers: &HeaderMap) -> Response {
        let mut response = generator.generate_error_response(
            &self.error,
            request_headers,
            self.request_path.as_deref(),
            self.request_id.as_deref(),
        );
        
        // Add custom headers
        let headers = response.headers_mut();
        for (key, value) in self.custom_headers {
            if let Some(key) = key {
                headers.insert(key, value);
            }
        }
        
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{ACCEPT, CONTENT_TYPE};

    #[test]
    fn test_error_page_generator_creation() {
        let config = ErrorPageConfig::default();
        let generator = ErrorPageGenerator::new(config);
        assert!(generator.is_ok());
    }
    
    #[test]
    fn test_response_format_detection() {
        let config = ErrorPageConfig::default();
        let generator = ErrorPageGenerator::new(config).unwrap();
        
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "application/json".parse().unwrap());
        
        let format = generator.determine_response_format(&headers);
        matches!(format, ErrorResponseFormat::Json);
        
        headers.insert(ACCEPT, "text/html".parse().unwrap());
        let format = generator.determine_response_format(&headers);
        matches!(format, ErrorResponseFormat::Html);
    }
    
    #[test]
    fn test_json_error_response() {
        let config = ErrorPageConfig::default();
        let generator = ErrorPageGenerator::new(config).unwrap();
        
        let error = GatewayError::internal("test error");
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "application/json".parse().unwrap());
        
        let response = generator.generate_error_response(&error, &headers, None, None);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    #[test]
    fn test_error_response_builder() {
        let config = ErrorPageConfig::default();
        let generator = ErrorPageGenerator::new(config).unwrap();
        
        let error = GatewayError::internal("test error");
        let headers = HeaderMap::new();
        
        let response = ErrorResponseBuilder::new(error)
            .with_request_path("/api/test")
            .with_request_id("req-123")
            .with_custom_message("Custom error message")
            .with_header("X-Custom-Header", "test-value")
            .build(&generator, &headers);
        
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().contains_key("X-Custom-Header"));
    }
}
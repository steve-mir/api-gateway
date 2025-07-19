//! # Cache Key Generator
//!
//! This module provides configurable strategies for generating cache keys
//! from HTTP requests and other context information.

use crate::core::types::{IncomingRequest, RequestContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// Key generation strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyGenerationStrategy {
    /// Simple path-based key generation
    Simple,
    
    /// Include query parameters in key
    WithQuery,
    
    /// Include specific headers in key
    WithHeaders { headers: Vec<String> },
    
    /// Include user context in key
    WithUser,
    
    /// Custom key generation with template
    Custom { template: String },
    
    /// Hash-based key generation for consistent short keys
    Hashed { include_body: bool },
}

impl Default for KeyGenerationStrategy {
    fn default() -> Self {
        Self::Simple
    }
}

/// Cache key generator trait
pub trait KeyGenerator: Send + Sync {
    /// Generate a cache key from request context
    fn generate_key(&self, request: &IncomingRequest, context: Option<&RequestContext>) -> String;
    
    /// Generate a cache key with custom data
    fn generate_custom_key(&self, data: &HashMap<String, String>) -> String;
}

/// Default key generator implementation
#[derive(Debug, Clone)]
pub struct DefaultKeyGenerator {
    strategy: KeyGenerationStrategy,
    prefix: String,
    max_length: usize,
}

impl DefaultKeyGenerator {
    /// Create a new default key generator
    pub fn new(strategy: KeyGenerationStrategy) -> Self {
        Self {
            strategy,
            prefix: "req:".to_string(),
            max_length: 250,
        }
    }

    /// Create with custom prefix
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = prefix;
        self
    }

    /// Create with custom max length
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Generate key components based on strategy
    fn generate_components(&self, request: &IncomingRequest, context: Option<&RequestContext>) -> Vec<String> {
        let mut components = vec![self.prefix.clone()];

        match &self.strategy {
            KeyGenerationStrategy::Simple => {
                components.push(request.method.to_string());
                components.push(request.path().to_string());
            }
            
            KeyGenerationStrategy::WithQuery => {
                components.push(request.method.to_string());
                components.push(request.path().to_string());
                if let Some(query) = request.query() {
                    components.push(query.to_string());
                }
            }
            
            KeyGenerationStrategy::WithHeaders { headers } => {
                components.push(request.method.to_string());
                components.push(request.path().to_string());
                
                for header_name in headers {
                    if let Some(header_value) = request.header(header_name) {
                        components.push(format!("{}:{}", header_name, header_value));
                    }
                }
            }
            
            KeyGenerationStrategy::WithUser => {
                components.push(request.method.to_string());
                components.push(request.path().to_string());
                
                if let Some(ctx) = context {
                    if let Some(auth_ctx) = &ctx.auth_context {
                        components.push(format!("user:{}", auth_ctx.user_id));
                    }
                }
            }
            
            KeyGenerationStrategy::Custom { template } => {
                let key = self.apply_template(template, request, context);
                return vec![key];
            }
            
            KeyGenerationStrategy::Hashed { include_body } => {
                let mut hasher = Sha256::new();
                hasher.update(request.method.as_str());
                hasher.update(request.path());
                
                if let Some(query) = request.query() {
                    hasher.update(query);
                }
                
                if *include_body && !request.body.is_empty() {
                    hasher.update(&*request.body);
                }
                
                if let Some(ctx) = context {
                    if let Some(auth_ctx) = &ctx.auth_context {
                        hasher.update(&auth_ctx.user_id);
                    }
                }
                
                let hash = hasher.finalize();
                return vec![format!("{}hash:{:x}", self.prefix, hash)];
            }
        }

        components
    }

    /// Apply template to generate custom key
    fn apply_template(&self, template: &str, request: &IncomingRequest, context: Option<&RequestContext>) -> String {
        let mut result = template.to_string();
        
        // Replace common placeholders
        result = result.replace("{method}", &request.method.to_string());
        result = result.replace("{path}", request.path());
        result = result.replace("{query}", request.query().unwrap_or(""));
        
        // Replace header placeholders
        for (name, value) in request.headers.iter() {
            let placeholder = format!("{{header:{}}}", name.as_str());
            if let Ok(value_str) = value.to_str() {
                result = result.replace(&placeholder, value_str);
            }
        }
        
        // Replace user context placeholders
        if let Some(ctx) = context {
            if let Some(auth_ctx) = &ctx.auth_context {
                result = result.replace("{user_id}", &auth_ctx.user_id);
                result = result.replace("{auth_method}", &auth_ctx.auth_method);
            }
            
            result = result.replace("{trace_id}", &ctx.trace_id);
        }
        
        result
    }

    /// Truncate key if it exceeds max length
    fn truncate_key(&self, key: String) -> String {
        if key.len() <= self.max_length {
            key
        } else {
            // If key is too long, hash it to ensure consistent length
            let mut hasher = Sha256::new();
            hasher.update(&key);
            let hash = hasher.finalize();
            format!("{}truncated:{:x}", self.prefix, hash)
        }
    }
}

impl KeyGenerator for DefaultKeyGenerator {
    fn generate_key(&self, request: &IncomingRequest, context: Option<&RequestContext>) -> String {
        let components = self.generate_components(request, context);
        let key = components.join(":");
        self.truncate_key(key)
    }

    fn generate_custom_key(&self, data: &HashMap<String, String>) -> String {
        let mut components = vec![self.prefix.clone()];
        
        // Sort keys for consistent ordering
        let mut sorted_data: Vec<_> = data.iter().collect();
        sorted_data.sort_by_key(|(k, _)| *k);
        
        for (key, value) in sorted_data {
            components.push(format!("{}:{}", key, value));
        }
        
        let key = components.join(":");
        self.truncate_key(key)
    }
}

/// Custom key generator that allows for user-defined logic
pub struct CustomKeyGenerator<F>
where
    F: Fn(&IncomingRequest, Option<&RequestContext>) -> String + Send + Sync,
{
    generator_fn: F,
    prefix: String,
    max_length: usize,
}

impl<F> CustomKeyGenerator<F>
where
    F: Fn(&IncomingRequest, Option<&RequestContext>) -> String + Send + Sync,
{
    /// Create a new custom key generator
    pub fn new(generator_fn: F) -> Self {
        Self {
            generator_fn,
            prefix: "custom:".to_string(),
            max_length: 250,
        }
    }

    /// Set custom prefix
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = prefix;
        self
    }

    /// Set max length
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }
}

impl<F> KeyGenerator for CustomKeyGenerator<F>
where
    F: Fn(&IncomingRequest, Option<&RequestContext>) -> String + Send + Sync,
{
    fn generate_key(&self, request: &IncomingRequest, context: Option<&RequestContext>) -> String {
        let key = (self.generator_fn)(request, context);
        
        if key.len() <= self.max_length {
            key
        } else {
            // Hash long keys
            let mut hasher = Sha256::new();
            hasher.update(&key);
            let hash = hasher.finalize();
            format!("{}hash:{:x}", self.prefix, hash)
        }
    }

    fn generate_custom_key(&self, data: &HashMap<String, String>) -> String {
        // For custom generators, we'll create a simple key from the data
        let mut components = vec![self.prefix.clone()];
        
        let mut sorted_data: Vec<_> = data.iter().collect();
        sorted_data.sort_by_key(|(k, _)| *k);
        
        for (key, value) in sorted_data {
            components.push(format!("{}:{}", key, value));
        }
        
        let key = components.join(":");
        
        if key.len() <= self.max_length {
            key
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            let hash = hasher.finalize();
            format!("{}hash:{:x}", self.prefix, hash)
        }
    }
}

impl fmt::Debug for CustomKeyGenerator<fn(&IncomingRequest, Option<&RequestContext>) -> String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomKeyGenerator")
            .field("prefix", &self.prefix)
            .field("max_length", &self.max_length)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{AuthContext, Protocol};
    use axum::http::{HeaderMap, Method, Version};
    use std::sync::Arc;

    fn create_test_request() -> IncomingRequest {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "test-agent".parse().unwrap());
        headers.insert("authorization", "Bearer token123".parse().unwrap());

        IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/api/users/123?sort=name".parse().unwrap(),
            Version::HTTP_11,
            headers,
            b"test body".to_vec(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    fn create_test_context() -> RequestContext {
        let request = Arc::new(create_test_request());
        let mut context = RequestContext::new(request);
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["read".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: None,
        };
        
        context.set_auth_context(auth_context);
        context
    }

    #[test]
    fn test_simple_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::Simple);
        let request = create_test_request();
        
        let key = generator.generate_key(&request, None);
        assert_eq!(key, "req:GET:/api/users/123");
    }

    #[test]
    fn test_with_query_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::WithQuery);
        let request = create_test_request();
        
        let key = generator.generate_key(&request, None);
        assert_eq!(key, "req:GET:/api/users/123:sort=name");
    }

    #[test]
    fn test_with_headers_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::WithHeaders {
            headers: vec!["user-agent".to_string()],
        });
        let request = create_test_request();
        
        let key = generator.generate_key(&request, None);
        assert_eq!(key, "req:GET:/api/users/123:user-agent:test-agent");
    }

    #[test]
    fn test_with_user_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::WithUser);
        let request = create_test_request();
        let context = create_test_context();
        
        let key = generator.generate_key(&request, Some(&context));
        assert_eq!(key, "req:GET:/api/users/123:user:user123");
    }

    #[test]
    fn test_custom_template_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::Custom {
            template: "{method}:{path}:user:{user_id}".to_string(),
        });
        let request = create_test_request();
        let context = create_test_context();
        
        let key = generator.generate_key(&request, Some(&context));
        assert_eq!(key, "GET:/api/users/123:user:user123");
    }

    #[test]
    fn test_hashed_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::Hashed {
            include_body: false,
        });
        let request = create_test_request();
        
        let key = generator.generate_key(&request, None);
        assert!(key.starts_with("req:hash:"));
        assert_eq!(key.len(), 68); // "req:hash:" + 64 hex chars
    }

    #[test]
    fn test_key_truncation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::Simple)
            .with_max_length(10);
        let request = create_test_request();
        
        let key = generator.generate_key(&request, None);
        // Should be truncated and hashed
        assert!(key.starts_with("req:truncated:"));
    }

    #[test]
    fn test_custom_key_generation() {
        let generator = DefaultKeyGenerator::new(KeyGenerationStrategy::Simple);
        let mut data = HashMap::new();
        data.insert("service".to_string(), "user-api".to_string());
        data.insert("version".to_string(), "v1".to_string());
        
        let key = generator.generate_custom_key(&data);
        assert_eq!(key, "req:service:user-api:version:v1");
    }

    #[test]
    fn test_custom_function_generator() {
        let generator = CustomKeyGenerator::new(|request, _context| {
            format!("custom:{}:{}", request.method, request.path())
        });
        
        let request = create_test_request();
        let key = generator.generate_key(&request, None);
        assert_eq!(key, "custom:GET:/api/users/123");
    }
}
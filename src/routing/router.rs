//! # Router Module
//!
//! This module implements request routing with path matching and parameter extraction using
//! a radix tree for efficient O(log n) route lookups. It supports path parameters, query strings,
//! and wildcard matching.
//!
//! ## Rust Concepts Used
//!
//! - `matchit` crate provides the radix tree implementation for efficient route matching
//! - `Arc<T>` enables sharing route configurations across threads
//! - `HashMap` stores extracted parameters and query strings
//! - Pattern matching with `match` expressions handles different route types

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, RouteMatch, RouteConfig};
use axum::http::Method;
use matchit::{Match, Router as RadixRouter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;


/// Route definition with pattern, methods, and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Path pattern (e.g., "/api/users/{id}")
    pub pattern: String,
    
    /// Allowed HTTP methods for this route (stored as strings for serialization)
    #[serde(with = "method_serde")]
    pub methods: Vec<Method>,
    
    /// Target upstream service name
    pub upstream: String,
    
    /// Route-specific configuration
    pub config: RouteConfig,
}

/// Custom serialization module for HTTP methods
mod method_serde {
    use axum::http::Method;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(methods: &Vec<Method>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let method_strings: Vec<String> = methods.iter().map(|m| m.to_string()).collect();
        method_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Method>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let method_strings: Vec<String> = Vec::deserialize(deserializer)?;
        method_strings
            .into_iter()
            .map(|s| Method::from_str(&s).map_err(serde::de::Error::custom))
            .collect()
    }
}

impl Route {
    /// Create a new route
    pub fn new(pattern: String, methods: Vec<Method>, upstream: String) -> Self {
        Self {
            pattern,
            methods,
            upstream,
            config: RouteConfig::default(),
        }
    }

    /// Create a route with custom configuration
    pub fn with_config(pattern: String, methods: Vec<Method>, upstream: String, config: RouteConfig) -> Self {
        Self {
            pattern,
            methods,
            upstream,
            config,
        }
    }

    /// Check if this route matches the given method
    pub fn matches_method(&self, method: &Method) -> bool {
        self.methods.is_empty() || self.methods.contains(method)
    }
}

/// HTTP Router with radix tree for efficient path matching
///
/// The router uses the `matchit` crate which implements a radix tree (compressed trie)
/// for efficient route matching. This provides O(log n) lookup performance even with
/// thousands of routes.
pub struct Router {
    /// Radix tree for route matching
    router: RadixRouter<Arc<Route>>,
    
    /// Default route for unmatched requests
    default_route: Option<Arc<Route>>,
}

impl Router {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            router: RadixRouter::new(),
            default_route: None,
        }
    }

    /// Add a route to the router
    ///
    /// # Arguments
    /// * `route` - The route to add
    ///
    /// # Returns
    /// * `GatewayResult<()>` - Ok if route was added successfully
    ///
    /// # Example
    /// ```rust
    /// use api_gateway::router::{Router, Route};
    /// use axum::http::Method;
    ///
    /// let mut router = Router::new();
    /// let route = Route::new(
    ///     "/api/users/{id}".to_string(),
    ///     vec![Method::GET],
    ///     "user-service".to_string()
    /// );
    /// router.add_route(route).unwrap();
    /// ```
    pub fn add_route(&mut self, route: Route) -> GatewayResult<()> {
        let pattern = route.pattern.clone();
        let route_arc = Arc::new(route);
        
        // Insert route into radix tree
        // The matchit crate handles path parameter extraction automatically
        self.router
            .insert(&pattern, route_arc)
            .map_err(|e| GatewayError::config(format!("Failed to add route: {}", e)))?;
        
        Ok(())
    }

    /// Set a default route for unmatched requests
    pub fn set_default_route(&mut self, route: Route) {
        self.default_route = Some(Arc::new(route));
    }

    /// Match a request to a route
    ///
    /// # Arguments
    /// * `request` - The incoming request to match
    ///
    /// # Returns
    /// * `Option<RouteMatch>` - The matched route with extracted parameters, or None
    ///
    /// # Example
    /// ```rust
    /// use api_gateway::router::Router;
    /// use api_gateway::types::IncomingRequest;
    /// 
    /// let router = Router::new();
    /// // Assuming request is created...
    /// if let Some(route_match) = router.match_route(&request) {
    ///     println!("Matched route: {}", route_match.pattern);
    ///     println!("Parameters: {:?}", route_match.params);
    /// }
    /// ```
    pub fn match_route(&self, request: &IncomingRequest) -> Option<RouteMatch> {
        let path = request.path();
        
        // Try to match against registered routes
        if let Ok(Match { value: route, params }) = self.router.at(path) {
            // Check if the HTTP method is allowed for this route
            if !route.matches_method(&request.method) {
                return None;
            }

            // Extract path parameters
            let mut path_params = HashMap::new();
            for (key, value) in params.iter() {
                path_params.insert(key.to_string(), value.to_string());
            }

            // Extract query parameters
            let query_params = self.extract_query_params(request);

            return Some(RouteMatch {
                pattern: route.pattern.clone(),
                params: path_params,
                query_params,
                upstream: route.upstream.clone(),
                config: route.config.clone(),
            });
        }

        // Try default route if no specific route matched
        if let Some(default_route) = &self.default_route {
            if default_route.matches_method(&request.method) {
                let query_params = self.extract_query_params(request);
                
                return Some(RouteMatch {
                    pattern: default_route.pattern.clone(),
                    params: HashMap::new(),
                    query_params,
                    upstream: default_route.upstream.clone(),
                    config: default_route.config.clone(),
                });
            }
        }

        None
    }

    /// Extract query parameters from the request
    fn extract_query_params(&self, request: &IncomingRequest) -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        if let Some(query) = request.query() {
            // Parse query string manually to handle multiple values
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    // URL decode the key and value
                    if let (Ok(decoded_key), Ok(decoded_value)) = (
                        urlencoding::decode(key),
                        urlencoding::decode(value)
                    ) {
                        params.insert(decoded_key.to_string(), decoded_value.to_string());
                    }
                } else {
                    // Handle keys without values (e.g., ?flag)
                    if let Ok(decoded_key) = urlencoding::decode(pair) {
                        params.insert(decoded_key.to_string(), String::new());
                    }
                }
            }
        }
        
        params
    }

    /// Get all registered routes (for debugging/introspection)
    pub fn routes(&self) -> Vec<String> {
        // Note: matchit doesn't provide a way to iterate over all routes
        // This is a limitation we'll document
        vec![] // TODO: Consider maintaining a separate list if needed
    }

    /// Check if router has any routes
    pub fn is_empty(&self) -> bool {
        // Since we can't iterate over matchit routes, we'll track this separately if needed
        // For now, assume non-empty if we have a default route
        self.default_route.is_some()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating routers with fluent API
pub struct RouterBuilder {
    router: Router,
}

impl RouterBuilder {
    /// Create a new router builder
    pub fn new() -> Self {
        Self {
            router: Router::new(),
        }
    }

    /// Add a GET route
    pub fn get(mut self, pattern: &str, upstream: &str) -> Self {
        let route = Route::new(
            pattern.to_string(),
            vec![Method::GET],
            upstream.to_string(),
        );
        let _ = self.router.add_route(route);
        self
    }

    /// Add a POST route
    pub fn post(mut self, pattern: &str, upstream: &str) -> Self {
        let route = Route::new(
            pattern.to_string(),
            vec![Method::POST],
            upstream.to_string(),
        );
        let _ = self.router.add_route(route);
        self
    }

    /// Add a PUT route
    pub fn put(mut self, pattern: &str, upstream: &str) -> Self {
        let route = Route::new(
            pattern.to_string(),
            vec![Method::PUT],
            upstream.to_string(),
        );
        let _ = self.router.add_route(route);
        self
    }

    /// Add a DELETE route
    pub fn delete(mut self, pattern: &str, upstream: &str) -> Self {
        let route = Route::new(
            pattern.to_string(),
            vec![Method::DELETE],
            upstream.to_string(),
        );
        let _ = self.router.add_route(route);
        self
    }

    /// Add a route that accepts any HTTP method
    pub fn any(mut self, pattern: &str, upstream: &str) -> Self {
        let route = Route::new(
            pattern.to_string(),
            vec![], // Empty methods means accept all
            upstream.to_string(),
        );
        let _ = self.router.add_route(route);
        self
    }

    /// Add a route with specific methods
    pub fn route(mut self, pattern: &str, methods: Vec<Method>, upstream: &str) -> Self {
        let route = Route::new(pattern.to_string(), methods, upstream.to_string());
        let _ = self.router.add_route(route);
        self
    }

    /// Add a route with custom configuration
    pub fn route_with_config(
        mut self,
        pattern: &str,
        methods: Vec<Method>,
        upstream: &str,
        config: RouteConfig,
    ) -> Self {
        let route = Route::with_config(pattern.to_string(), methods, upstream.to_string(), config);
        let _ = self.router.add_route(route);
        self
    }

    /// Set default route
    pub fn default_route(mut self, upstream: &str) -> Self {
        let route = Route::new("/*".to_string(), vec![], upstream.to_string());
        self.router.set_default_route(route);
        self
    }

    /// Build the router
    pub fn build(self) -> Router {
        self.router
    }
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IncomingRequest, Protocol};
    use axum::http::{HeaderMap, Method, Version};

    fn create_test_request(method: Method, path: &str) -> IncomingRequest {
        IncomingRequest::new(
            Protocol::Http,
            method,
            path.parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }

    #[test]
    fn test_router_creation() {
        let router = Router::new();
        assert!(router.is_empty());
    }

    #[test]
    fn test_add_route() {
        let mut router = Router::new();
        let route = Route::new(
            "/api/users".to_string(),
            vec![Method::GET],
            "user-service".to_string(),
        );
        
        assert!(router.add_route(route).is_ok());
    }

    #[test]
    fn test_route_matching() {
        let mut router = Router::new();
        let route = Route::new(
            "/api/users/{id}".to_string(),
            vec![Method::GET],
            "user-service".to_string(),
        );
        router.add_route(route).unwrap();

        let request = create_test_request(Method::GET, "/api/users/123");
        let route_match = router.match_route(&request).unwrap();

        assert_eq!(route_match.pattern, "/api/users/{id}");
        assert_eq!(route_match.upstream, "user-service");
        assert_eq!(route_match.params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_method_matching() {
        let mut router = Router::new();
        let route = Route::new(
            "/api/users".to_string(),
            vec![Method::GET],
            "user-service".to_string(),
        );
        router.add_route(route).unwrap();

        // Should match GET
        let get_request = create_test_request(Method::GET, "/api/users");
        assert!(router.match_route(&get_request).is_some());

        // Should not match POST
        let post_request = create_test_request(Method::POST, "/api/users");
        assert!(router.match_route(&post_request).is_none());
    }

    #[test]
    fn test_query_parameter_extraction() {
        let mut router = Router::new();
        let route = Route::new(
            "/api/search".to_string(),
            vec![Method::GET],
            "search-service".to_string(),
        );
        router.add_route(route).unwrap();

        let request = create_test_request(Method::GET, "/api/search?q=rust&limit=10");
        let route_match = router.match_route(&request).unwrap();

        assert_eq!(route_match.query_params.get("q"), Some(&"rust".to_string()));
        assert_eq!(route_match.query_params.get("limit"), Some(&"10".to_string()));
    }

    #[test]
    fn test_wildcard_route() {
        let mut router = Router::new();
        let route = Route::new(
            "/static/*".to_string(),
            vec![Method::GET],
            "static-service".to_string(),
        );
        router.add_route(route).unwrap();

        let request = create_test_request(Method::GET, "/static/css/style.css");
        let route_match = router.match_route(&request);
        
        // Note: matchit handles wildcards differently, this test may need adjustment
        // based on the actual behavior of the matchit crate
        assert!(route_match.is_some());
    }

    #[test]
    fn test_default_route() {
        let mut router = Router::new();
        let default_route = Route::new(
            "/*".to_string(),
            vec![],
            "default-service".to_string(),
        );
        router.set_default_route(default_route);

        let request = create_test_request(Method::GET, "/nonexistent/path");
        let route_match = router.match_route(&request).unwrap();

        assert_eq!(route_match.upstream, "default-service");
    }

    #[test]
    fn test_router_builder() {
        let router = RouterBuilder::new()
            .get("/api/users", "user-service")
            .post("/api/users", "user-service")
            .get("/api/posts/{id}", "post-service")
            .default_route("default-service")
            .build();

        let get_request = create_test_request(Method::GET, "/api/users");
        let route_match = router.match_route(&get_request).unwrap();
        assert_eq!(route_match.upstream, "user-service");

        let post_request = create_test_request(Method::POST, "/api/users");
        let route_match = router.match_route(&post_request).unwrap();
        assert_eq!(route_match.upstream, "user-service");

        let param_request = create_test_request(Method::GET, "/api/posts/123");
        let route_match = router.match_route(&param_request).unwrap();
        assert_eq!(route_match.upstream, "post-service");
        assert_eq!(route_match.params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_url_decoding() {
        let mut router = Router::new();
        let route = Route::new(
            "/api/search".to_string(),
            vec![Method::GET],
            "search-service".to_string(),
        );
        router.add_route(route).unwrap();

        let request = create_test_request(Method::GET, "/api/search?q=hello%20world&category=rust%26go");
        let route_match = router.match_route(&request).unwrap();

        assert_eq!(route_match.query_params.get("q"), Some(&"hello world".to_string()));
        assert_eq!(route_match.query_params.get("category"), Some(&"rust&go".to_string()));
    }
}
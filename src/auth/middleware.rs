//! # Authentication Middleware
//!
//! This module contains authentication middleware that integrates with the gateway's
//! request processing pipeline. It handles token extraction, authentication, and
//! authorization for incoming requests.
//!
//! ## Rust Concepts Used
//!
//! - `tower::Service` trait for middleware implementation
//! - `Pin<Box<dyn Future>>` for async middleware functions
//! - `Arc<dyn Trait>` for trait objects with shared ownership
//! - Pattern matching for extracting authentication headers

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tower::{Layer, Service};
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;

use crate::auth::providers::AuthProvider;
use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::AuthContext;

/// Authentication middleware configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether authentication is required for all requests
    pub required: bool,
    /// List of paths that don't require authentication
    pub excluded_paths: Vec<String>,
    /// Header name to extract the token from
    pub token_header: String,
    /// Token prefix to strip (e.g., "Bearer ")
    pub token_prefix: Option<String>,
    /// Whether to allow multiple authentication methods
    pub allow_multiple_methods: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            required: true,
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/ready".to_string(),
            ],
            token_header: "authorization".to_string(),
            token_prefix: Some("Bearer ".to_string()),
            allow_multiple_methods: true,
        }
    }
}

/// Authentication middleware that handles token extraction and validation
pub struct AuthMiddleware {
    providers: Vec<Arc<dyn AuthProvider>>,
    config: AuthConfig,
}

impl AuthMiddleware {
    /// Create a new authentication middleware
    pub fn new(providers: Vec<Arc<dyn AuthProvider>>, config: AuthConfig) -> Self {
        Self { providers, config }
    }

    /// Add an authentication provider
    pub fn add_provider(&mut self, provider: Arc<dyn AuthProvider>) {
        self.providers.push(provider);
    }

    /// Extract token from request headers
    fn extract_token(&self, headers: &HeaderMap) -> Option<String> {
        let header_value = headers
            .get(&self.config.token_header)
            .and_then(|value| value.to_str().ok())?;

        if let Some(prefix) = &self.config.token_prefix {
            header_value.strip_prefix(prefix).map(|s| s.to_string())
        } else {
            Some(header_value.to_string())
        }
    }

    /// Check if path is excluded from authentication
    fn is_excluded_path(&self, path: &str) -> bool {
        self.config.excluded_paths.iter().any(|excluded| {
            if excluded.ends_with('*') {
                path.starts_with(&excluded[..excluded.len() - 1])
            } else {
                path == excluded
            }
        })
    }

    /// Authenticate request using available providers
    async fn authenticate_request(&self, token: &str) -> GatewayResult<AuthContext> {
        let mut last_error = GatewayError::auth("No authentication providers available");

        for provider in &self.providers {
            match provider.authenticate(token).await {
                Ok(context) => {
                    // Validate that the context is still valid
                    if provider.validate_context(&context).await? {
                        return Ok(context);
                    } else {
                        last_error = GatewayError::auth("Authentication context expired");
                    }
                }
                Err(err) => {
                    last_error = err;
                    // Continue to next provider if multiple methods are allowed
                    if !self.config.allow_multiple_methods {
                        break;
                    }
                }
            }
        }

        Err(last_error)
    }
}

/// Axum middleware function for authentication
pub async fn auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract authentication middleware from request extensions
    let auth_middleware = request
        .extensions()
        .get::<Arc<AuthMiddleware>>()
        .cloned()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let path = request.uri().path();

    // Skip authentication for excluded paths
    if auth_middleware.is_excluded_path(path) {
        return Ok(next.run(request).await);
    }

    // Extract token from headers
    let token = auth_middleware.extract_token(request.headers());

    match token {
        Some(token) => {
            // Authenticate the request
            match auth_middleware.authenticate_request(&token).await {
                Ok(auth_context) => {
                    // Add authentication context to request extensions
                    request.extensions_mut().insert(Arc::new(auth_context));
                    Ok(next.run(request).await)
                }
                Err(err) => {
                    tracing::warn!("Authentication failed: {}", err);
                    Err(err.status_code())
                }
            }
        }
        None => {
            if auth_middleware.config.required {
                tracing::warn!("Missing authentication token for path: {}", path);
                Err(StatusCode::UNAUTHORIZED)
            } else {
                // Authentication not required, continue without auth context
                Ok(next.run(request).await)
            }
        }
    }
}

/// Authorization middleware that checks permissions for authenticated requests
pub async fn authz_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get authentication context from request extensions
    let auth_context = request.extensions().get::<Arc<AuthContext>>().cloned();

    // Get authorization requirements from request extensions or route config
    let required_roles: Vec<String> = request
        .extensions()
        .get::<Vec<String>>()
        .cloned()
        .unwrap_or_default();

    let required_permissions: Vec<String> = request
        .extensions()
        .get::<Vec<String>>()
        .cloned()
        .unwrap_or_default();

    if let Some(auth_context) = auth_context {
        // Check required roles
        for required_role in &required_roles {
            if !auth_context.has_role(required_role) {
                tracing::warn!(
                    "User {} missing required role: {}",
                    auth_context.user_id,
                    required_role
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }

        // Check required permissions
        for required_permission in &required_permissions {
            if !auth_context.has_permission(required_permission) {
                tracing::warn!(
                    "User {} missing required permission: {}",
                    auth_context.user_id,
                    required_permission
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
    } else if !required_roles.is_empty() || !required_permissions.is_empty() {
        // Authorization required but no auth context available
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

/// Tower layer for authentication middleware
#[derive(Clone)]
pub struct AuthLayer {
    middleware: Arc<AuthMiddleware>,
}

impl AuthLayer {
    pub fn new(middleware: Arc<AuthMiddleware>) -> Self {
        Self { middleware }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            middleware: self.middleware.clone(),
        }
    }
}

/// Tower service for authentication
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    middleware: Arc<AuthMiddleware>,
}

impl<S> Service<Request> for AuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let middleware = self.middleware.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Add middleware to request extensions for the middleware function to use
            request.extensions_mut().insert(middleware.clone());

            // Call the inner service
            inner.call(request).await
        })
    }
}

/// Helper function to create authentication middleware with common providers
pub fn create_auth_middleware(
    jwt_provider: Option<Arc<dyn AuthProvider>>,
    api_key_provider: Option<Arc<dyn AuthProvider>>,
    oauth2_provider: Option<Arc<dyn AuthProvider>>,
    config: AuthConfig,
) -> AuthMiddleware {
    let mut providers = Vec::new();

    if let Some(provider) = jwt_provider {
        providers.push(provider);
    }
    if let Some(provider) = api_key_provider {
        providers.push(provider);
    }
    if let Some(provider) = oauth2_provider {
        providers.push(provider);
    }

    AuthMiddleware::new(providers, config)
}

/// Utility functions for extracting authentication information from requests
pub mod utils {
    use axum::extract::Request;
    use std::sync::Arc;
    use crate::core::types::AuthContext;

    /// Extract authentication context from request
    pub fn get_auth_context(request: &Request) -> Option<Arc<AuthContext>> {
        request.extensions().get::<Arc<AuthContext>>().cloned()
    }

    /// Check if request is authenticated
    pub fn is_authenticated(request: &Request) -> bool {
        get_auth_context(request).is_some()
    }

    /// Get user ID from authenticated request
    pub fn get_user_id(request: &Request) -> Option<String> {
        get_auth_context(request).map(|ctx| ctx.user_id.clone())
    }

    /// Check if user has specific role
    pub fn has_role(request: &Request, role: &str) -> bool {
        get_auth_context(request)
            .map(|ctx| ctx.has_role(role))
            .unwrap_or(false)
    }

    /// Check if user has specific permission
    pub fn has_permission(request: &Request, permission: &str) -> bool {
        get_auth_context(request)
            .map(|ctx| ctx.has_permission(permission))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use crate::auth::providers::{JwtAuthProvider, JwtConfig, RbacManager};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_token_extraction() {
        let config = AuthConfig::default();
        let rbac = Arc::new(RbacManager::new());
        let jwt_provider = Arc::new(JwtAuthProvider::new(JwtConfig::default(), rbac).unwrap());
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test-token"));

        let token = middleware.extract_token(&headers);
        assert_eq!(token, Some("test-token".to_string()));
    }

    #[tokio::test]
    async fn test_excluded_paths() {
        let config = AuthConfig::default();
        let rbac = Arc::new(RbacManager::new());
        let jwt_provider = Arc::new(JwtAuthProvider::new(JwtConfig::default(), rbac).unwrap());
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);

        assert!(middleware.is_excluded_path("/health"));
        assert!(middleware.is_excluded_path("/metrics"));
        assert!(!middleware.is_excluded_path("/api/users"));
    }

    #[test]
    fn test_wildcard_excluded_paths() {
        let mut config = AuthConfig::default();
        config.excluded_paths.push("/public/*".to_string());
        
        let rbac = Arc::new(RbacManager::new());
        let jwt_provider = Arc::new(JwtAuthProvider::new(JwtConfig::default(), rbac).unwrap());
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);

        assert!(middleware.is_excluded_path("/public/assets/style.css"));
        assert!(middleware.is_excluded_path("/public/images/logo.png"));
        assert!(!middleware.is_excluded_path("/private/data"));
    }
}
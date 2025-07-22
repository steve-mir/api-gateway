//! # Admin API Foundation
//!
//! This module provides the foundational components for the admin API including:
//! - Admin-specific authentication and authorization
//! - Session management with secure token validation
//! - API versioning and backward compatibility
//! - Rate limiting and security headers
//! - Separate admin server with dedicated port
//!
//! ## Security Considerations
//!
//! The admin API requires elevated privileges and implements additional security measures:
//! - Mandatory authentication with admin role requirement
//! - Session-based authentication with secure token management
//! - Rate limiting to prevent brute force attacks
//! - Security headers to prevent common web vulnerabilities
//! - Audit logging for all admin operations
//!
//! ## Architecture
//!
//! The admin API runs on a separate port from the main gateway traffic to provide
//! isolation and allow for different security policies. It supports API versioning
//! to maintain backward compatibility as the admin interface evolves.

use crate::auth::{AuthProvider, AdminAuthProvider, JwtAuthProvider, RbacManager};
use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::AuthContext;
use crate::admin::audit::ConfigAudit;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

/// Admin API version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    /// Version string (e.g., "v1", "v2")
    pub version: String,
    /// Whether this version is deprecated
    pub deprecated: bool,
    /// Deprecation date if applicable
    pub deprecated_at: Option<DateTime<Utc>>,
    /// End of life date when version will be removed
    pub end_of_life: Option<DateTime<Utc>>,
    /// Supported features in this version
    pub features: Vec<String>,
}

/// Admin session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    /// Unique session identifier
    pub session_id: String,
    /// Associated user ID
    pub user_id: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// IP address of the session
    pub ip_address: String,
    /// User agent string
    pub user_agent: Option<String>,
    /// Authentication context
    pub auth_context: AuthContext,
    /// Session metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AdminSession {
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is inactive (no activity for too long)
    pub fn is_inactive(&self, max_idle_time: Duration) -> bool {
        Utc::now() - self.last_activity > max_idle_time
    }

    /// Update last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Admin session manager
pub struct AdminSessionManager {
    /// Active sessions
    sessions: Arc<DashMap<String, AdminSession>>,
    /// Session configuration
    config: AdminSessionConfig,
    /// Audit logger
    audit: Arc<ConfigAudit>,
}

/// Admin session configuration
#[derive(Debug, Clone)]
pub struct AdminSessionConfig {
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Maximum idle time before session expires
    pub max_idle_time: Duration,
    /// Maximum number of concurrent sessions per user
    pub max_sessions_per_user: usize,
    /// Whether to allow concurrent sessions
    pub allow_concurrent_sessions: bool,
}

impl Default for AdminSessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::hours(8),
            max_idle_time: Duration::hours(1),
            max_sessions_per_user: 3,
            allow_concurrent_sessions: true,
        }
    }
}

impl AdminSessionManager {
    /// Create a new session manager
    pub fn new(config: AdminSessionConfig, audit: Arc<ConfigAudit>) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            config,
            audit,
        }
    }

    /// Create a new admin session
    pub async fn create_session(
        &self,
        auth_context: AuthContext,
        ip_address: String,
        user_agent: Option<String>,
    ) -> GatewayResult<AdminSession> {
        // Check if user already has too many sessions
        if !self.config.allow_concurrent_sessions {
            self.revoke_user_sessions(&auth_context.user_id).await?;
        } else {
            let user_session_count = self.count_user_sessions(&auth_context.user_id).await;
            if user_session_count >= self.config.max_sessions_per_user {
                return Err(GatewayError::auth("Too many concurrent sessions"));
            }
        }

        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + self.config.session_timeout;

        let session = AdminSession {
            session_id: session_id.clone(),
            user_id: auth_context.user_id.clone(),
            created_at: now,
            last_activity: now,
            expires_at,
            ip_address,
            user_agent,
            auth_context,
            metadata: HashMap::new(),
        };

        self.sessions.insert(session_id.clone(), session.clone());

        // Log session creation
        tracing::info!(
            user_id = %session.user_id,
            session_id = %session_id,
            ip_address = %session.ip_address,
            "Admin session created"
        );

        Ok(session)
    }

    /// Validate and retrieve a session
    pub async fn get_session(&self, session_id: &str) -> GatewayResult<Option<AdminSession>> {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            // Check if session is expired
            if session.is_expired() {
                self.sessions.remove(session_id);
                return Ok(None);
            }

            // Check if session is inactive
            if session.is_inactive(self.config.max_idle_time) {
                self.sessions.remove(session_id);
                return Ok(None);
            }

            // Update last activity
            session.update_activity();
            Ok(Some(session.clone()))
        } else {
            Ok(None)
        }
    }

    /// Revoke a specific session
    pub async fn revoke_session(&self, session_id: &str) -> GatewayResult<()> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            tracing::info!(
                user_id = %session.user_id,
                session_id = %session_id,
                "Admin session revoked"
            );
        }
        Ok(())
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&self, user_id: &str) -> GatewayResult<()> {
        let sessions_to_remove: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| entry.user_id == user_id)
            .map(|entry| entry.session_id.clone())
            .collect();

        for session_id in sessions_to_remove {
            self.sessions.remove(&session_id);
        }

        tracing::info!(user_id = %user_id, "All admin sessions revoked for user");
        Ok(())
    }

    /// Count active sessions for a user
    pub async fn count_user_sessions(&self, user_id: &str) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.user_id == user_id && !entry.is_expired())
            .count()
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let expired_sessions: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| entry.is_expired() || entry.is_inactive(self.config.max_idle_time))
            .map(|entry| entry.session_id.clone())
            .collect();

        let count = expired_sessions.len();
        for session_id in expired_sessions {
            self.sessions.remove(&session_id);
        }

        if count > 0 {
            tracing::debug!(expired_count = count, "Cleaned up expired admin sessions");
        }

        count
    }

    /// Get all active sessions (for admin monitoring)
    pub async fn get_active_sessions(&self) -> Vec<AdminSession> {
        self.sessions
            .iter()
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.clone())
            .collect()
    }
}

/// Admin API rate limiter
pub struct AdminRateLimiter {
    /// Rate limit buckets per IP address
    buckets: Arc<DashMap<String, TokenBucket>>,
    /// Rate limit configuration
    config: AdminRateLimitConfig,
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current token count
    tokens: f64,
    /// Last refill time
    last_refill: DateTime<Utc>,
    /// Maximum tokens
    capacity: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Utc::now(),
            capacity,
            refill_rate,
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Utc::now();
        let elapsed = (now - self.last_refill).num_milliseconds() as f64 / 1000.0;
        let tokens_to_add = elapsed * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }
}

/// Admin rate limit configuration
#[derive(Debug, Clone)]
pub struct AdminRateLimitConfig {
    /// Requests per minute for authentication endpoints
    pub auth_requests_per_minute: u32,
    /// Requests per minute for general admin endpoints
    pub admin_requests_per_minute: u32,
    /// Requests per minute for sensitive operations
    pub sensitive_requests_per_minute: u32,
}

impl Default for AdminRateLimitConfig {
    fn default() -> Self {
        Self {
            auth_requests_per_minute: 10,
            admin_requests_per_minute: 100,
            sensitive_requests_per_minute: 20,
        }
    }
}

impl AdminRateLimiter {
    pub fn new(config: AdminRateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check if request is allowed for the given IP and endpoint type
    pub async fn is_allowed(&self, ip: &str, endpoint_type: AdminEndpointType) -> bool {
        let (capacity, refill_rate) = match endpoint_type {
            AdminEndpointType::Auth => (
                self.config.auth_requests_per_minute as f64,
                self.config.auth_requests_per_minute as f64 / 60.0,
            ),
            AdminEndpointType::General => (
                self.config.admin_requests_per_minute as f64,
                self.config.admin_requests_per_minute as f64 / 60.0,
            ),
            AdminEndpointType::Sensitive => (
                self.config.sensitive_requests_per_minute as f64,
                self.config.sensitive_requests_per_minute as f64 / 60.0,
            ),
        };

        let mut bucket = self
            .buckets
            .entry(ip.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        bucket.try_consume(1.0)
    }
}

/// Admin endpoint types for rate limiting
#[derive(Debug, Clone, Copy)]
pub enum AdminEndpointType {
    /// Authentication endpoints (login, logout)
    Auth,
    /// General admin endpoints
    General,
    /// Sensitive operations (config changes, user management)
    Sensitive,
}

/// Admin API server configuration
#[derive(Debug, Clone)]
pub struct AdminApiConfig {
    /// Server bind address
    pub bind_address: SocketAddr,
    /// Session configuration
    pub session_config: AdminSessionConfig,
    /// Rate limiting configuration
    pub rate_limit_config: AdminRateLimitConfig,
    /// Supported API versions
    pub supported_versions: Vec<ApiVersion>,
    /// Default API version
    pub default_version: String,
    /// CORS configuration
    pub cors_enabled: bool,
    /// Request timeout
    pub request_timeout: std::time::Duration,
    /// Maximum request body size
    pub max_request_size: usize,
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:9090".parse().unwrap(),
            session_config: AdminSessionConfig::default(),
            rate_limit_config: AdminRateLimitConfig::default(),
            supported_versions: vec![
                ApiVersion {
                    version: "v1".to_string(),
                    deprecated: false,
                    deprecated_at: None,
                    end_of_life: None,
                    features: vec![
                        "config_management".to_string(),
                        "service_management".to_string(),
                        "user_management".to_string(),
                    ],
                },
            ],
            default_version: "v1".to_string(),
            cors_enabled: true,
            request_timeout: std::time::Duration::from_secs(30),
            max_request_size: 1024 * 1024, // 1MB
        }
    }
}

/// Admin API server state
#[derive(Clone)]
pub struct AdminApiState {
    /// Authentication provider
    pub auth_provider: Arc<dyn AuthProvider>,
    /// Session manager
    pub session_manager: Arc<AdminSessionManager>,
    /// Rate limiter
    pub rate_limiter: Arc<AdminRateLimiter>,
    /// Configuration
    pub config: AdminApiConfig,
    /// Audit logger
    pub audit: Arc<ConfigAudit>,
}

/// Admin API server
pub struct AdminApiServer {
    /// Server state
    state: AdminApiState,
    /// Router
    router: Router,
}

impl AdminApiServer {
    /// Create a new admin API server
    pub fn new(
        auth_provider: Arc<dyn AuthProvider>,
        audit: Arc<ConfigAudit>,
        config: AdminApiConfig,
    ) -> Self {
        let session_manager = Arc::new(AdminSessionManager::new(
            config.session_config.clone(),
            audit.clone(),
        ));
        let rate_limiter = Arc::new(AdminRateLimiter::new(config.rate_limit_config.clone()));

        let state = AdminApiState {
            auth_provider,
            session_manager,
            rate_limiter,
            config: config.clone(),
            audit,
        };

        let router = Self::create_router(state.clone());

        Self { state, router }
    }

    /// Create the admin API router
    fn create_router(state: AdminApiState) -> Router {
        let mut router = Router::new()
            // API information endpoints
            .route("/api/info", get(get_api_info))
            .route("/api/versions", get(get_api_versions))
            .route("/health", get(health_check))
            
            // Authentication endpoints
            .route("/auth/login", post(admin_login))
            .route("/auth/logout", post(admin_logout))
            .route("/auth/refresh", post(refresh_session))
            .route("/auth/sessions", get(list_sessions))
            .route("/auth/sessions/:session_id", axum::routing::delete(revoke_session))
            
            // Apply middleware
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(middleware::from_fn_with_state(
                        state.clone(),
                        admin_auth_middleware,
                    ))
                    .layer(middleware::from_fn_with_state(
                        state.clone(),
                        rate_limit_middleware,
                    ))
                    .layer(middleware::from_fn(security_headers_middleware))
                    .layer(TimeoutLayer::new(state.config.request_timeout))
                    .layer(RequestBodyLimitLayer::new(state.config.max_request_size))
            )
            .with_state(state.clone());

        // Add CORS if enabled
        if state.config.cors_enabled {
            router = router.layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            );
        }

        router
    }

    /// Get the router
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Start the admin API server
    pub async fn start(&self) -> GatewayResult<()> {
        let listener = tokio::net::TcpListener::bind(self.state.config.bind_address)
            .await
            .map_err(|e| GatewayError::config(format!("Failed to bind admin API server: {}", e)))?;

        tracing::info!(
            address = %self.state.config.bind_address,
            "Admin API server starting"
        );

        // Start session cleanup task
        let session_manager = self.state.session_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                session_manager.cleanup_expired_sessions().await;
            }
        });

        axum::serve(listener, self.router.clone())
            .await
            .map_err(|e| GatewayError::internal(format!("Admin API server error: {}", e)))?;

        Ok(())
    }
}

// ============================================================================
// Middleware Functions
// ============================================================================

/// Admin authentication middleware
async fn admin_auth_middleware(
    State(state): State<AdminApiState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for public endpoints
    let path = request.uri().path();
    if matches!(path, "/health" | "/api/info" | "/api/versions" | "/auth/login") {
        return Ok(next.run(request).await);
    }

    // Extract session token from Authorization header or cookie
    let session_id = extract_session_token(&request)?;

    // Validate session
    let session = state
        .session_manager
        .get_session(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Add auth context to request extensions
    request.extensions_mut().insert(session.auth_context.clone());
    request.extensions_mut().insert(session);

    Ok(next.run(request).await)
}

/// Rate limiting middleware
async fn rate_limit_middleware(
    State(state): State<AdminApiState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client IP
    let client_ip = extract_client_ip(&request);

    // Determine endpoint type
    let endpoint_type = determine_endpoint_type(request.uri().path());

    // Check rate limit
    if !state.rate_limiter.is_allowed(&client_ip, endpoint_type).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

/// Security headers middleware
async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    
    // Add security headers
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    response
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Get API information
async fn get_api_info(State(state): State<AdminApiState>) -> Json<ApiInfoResponse> {
    Json(ApiInfoResponse {
        name: "API Gateway Admin API".to_string(),
        version: state.config.default_version.clone(),
        description: "Administrative API for the API Gateway".to_string(),
        supported_versions: state.config.supported_versions.clone(),
        features: vec![
            "authentication".to_string(),
            "session_management".to_string(),
            "rate_limiting".to_string(),
            "audit_logging".to_string(),
        ],
    })
}

/// Get supported API versions
async fn get_api_versions(State(state): State<AdminApiState>) -> Json<ApiVersionsResponse> {
    Json(ApiVersionsResponse {
        versions: state.config.supported_versions.clone(),
        default_version: state.config.default_version.clone(),
    })
}

/// Health check endpoint
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Admin login endpoint
async fn admin_login(
    State(state): State<AdminApiState>,
    Json(request): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate user
    let auth_context = state
        .auth_provider
        .authenticate(&request.token)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                    details: Some(e.to_string()),
                }),
            )
        })?;

    // Check if user has admin role
    if !auth_context.has_role("admin") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Admin access required".to_string(),
                details: None,
            }),
        ));
    }

    // Create session
    let session = state
        .session_manager
        .create_session(
            auth_context,
            request.ip_address.unwrap_or_else(|| "unknown".to_string()),
            request.user_agent,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create session".to_string(),
                    details: Some(e.to_string()),
                }),
            )
        })?;

    Ok(Json(AdminLoginResponse {
        session_id: session.session_id,
        expires_at: session.expires_at,
        user_id: session.user_id,
        roles: session.auth_context.roles,
    }))
}

/// Admin logout endpoint
async fn admin_logout(
    State(state): State<AdminApiState>,
    Json(request): Json<AdminLogoutRequest>,
) -> Result<Json<AdminLogoutResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .session_manager
        .revoke_session(&request.session_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to revoke session".to_string(),
                    details: Some(e.to_string()),
                }),
            )
        })?;

    Ok(Json(AdminLogoutResponse {
        success: true,
        message: "Session revoked successfully".to_string(),
    }))
}

/// Refresh session endpoint
async fn refresh_session(
    State(state): State<AdminApiState>,
    Json(request): Json<RefreshSessionRequest>,
) -> Result<Json<RefreshSessionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let session = state
        .session_manager
        .get_session(&request.session_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get session".to_string(),
                    details: None,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid session".to_string(),
                    details: None,
                }),
            )
        })?;

    Ok(Json(RefreshSessionResponse {
        session_id: session.session_id,
        expires_at: session.expires_at,
        last_activity: session.last_activity,
    }))
}

/// List active sessions endpoint
async fn list_sessions(
    State(state): State<AdminApiState>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let sessions = state.session_manager.get_active_sessions().await;
    
    let session_info: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|session| SessionInfo {
            session_id: session.session_id,
            user_id: session.user_id,
            created_at: session.created_at,
            last_activity: session.last_activity,
            expires_at: session.expires_at,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
        })
             
  .collect();

    Ok(Json(ListSessionsResponse {
        sessions: session_info,
        total: sessions.len(),
    }))
}

/// Revoke a specific session endpoint
async fn revoke_session(
    State(state): State<AdminApiState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Result<Json<AdminLogoutResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .session_manager
        .revoke_session(&session_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to revoke session".to_string(),
                    details: Some(e.to_string()),
                }),
            )
        })?;

    Ok(Json(AdminLogoutResponse {
        success: true,
        message: "Session revoked successfully".to_string(),
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract session token from request
fn extract_session_token(request: &Request) -> Result<String, StatusCode> {
    // Try Authorization header first
    if let Some(auth_header) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Ok(token.to_string());
            }
        }
    }

    // Try cookie
    if let Some(cookie_header) = request.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(session_id) = cookie.strip_prefix("session_id=") {
                    return Ok(session_id.to_string());
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Extract client IP from request
fn extract_client_ip(request: &Request) -> String {
    // Try X-Forwarded-For header first
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fallback to connection info (would need to be passed through middleware)
    "unknown".to_string()
}

/// Determine endpoint type for rate limiting
fn determine_endpoint_type(path: &str) -> AdminEndpointType {
    if path.starts_with("/auth/") {
        AdminEndpointType::Auth
    } else if path.contains("/config/") || path.contains("/services/") || path.contains("/users/") {
        AdminEndpointType::Sensitive
    } else {
        AdminEndpointType::General
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct ApiInfoResponse {
    name: String,
    version: String,
    description: String,
    supported_versions: Vec<ApiVersion>,
    features: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApiVersionsResponse {
    versions: Vec<ApiVersion>,
    default_version: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: DateTime<Utc>,
    version: String,
}

#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    token: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminLoginResponse {
    session_id: String,
    expires_at: DateTime<Utc>,
    user_id: String,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AdminLogoutRequest {
    session_id: String,
}

#[derive(Debug, Serialize)]
struct AdminLogoutResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RefreshSessionRequest {
    session_id: String,
}

#[derive(Debug, Serialize)]
struct RefreshSessionResponse {
    session_id: String,
    expires_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ListSessionsResponse {
    sessions: Vec<SessionInfo>,
    total: usize,
}

#[derive(Debug, Serialize)]
struct SessionInfo {
    session_id: String,
    user_id: String,
    created_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ip_address: String,
    user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}
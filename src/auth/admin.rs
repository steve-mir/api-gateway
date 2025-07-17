//! # Authentication Admin Endpoints
//!
//! This module provides admin endpoints for managing users, API keys, roles, and permissions.
//! These endpoints allow administrators to:
//! - Create and manage API keys
//! - Assign roles and permissions to users
//! - View authentication statistics
//! - Manage RBAC policies
//!
//! ## Security Note
//! These endpoints require admin-level authentication and should be protected with appropriate
//! access controls. They are typically exposed on a separate admin port or with strict
//! network access controls.
//!
//! ## Rust Concepts Used
//!
//! - `axum::Router` for HTTP routing and endpoint definition
//! - `serde` for JSON serialization/deserialization of request/response bodies
//! - `Arc<T>` for shared ownership of authentication providers and stores
//! - `async/await` for non-blocking I/O operations
//! - Pattern matching for handling different authentication methods

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use uuid::Uuid;

use crate::auth::providers::{
    ApiKey, ApiKeyAuthProvider, ApiKeyRateLimit, ApiKeyStore, Permission, Policy, PolicyRule,
    RbacManager, Role,
};
use crate::core::error::{GatewayError, GatewayResult};


/// Admin API state containing authentication providers and stores
#[derive(Clone)]
pub struct AdminState {
    pub api_key_store: Arc<dyn ApiKeyStore>,
    pub rbac_manager: Arc<RbacManager>,
}

/// Request to create a new API key
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the API key
    pub name: String,
    /// User ID this key belongs to
    pub user_id: String,
    /// Roles to assign to this key
    pub roles: Vec<String>,
    /// Specific permissions to assign to this key
    pub permissions: Vec<String>,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Rate limiting configuration
    pub rate_limit: Option<ApiKeyRateLimit>,
}

/// Response when creating an API key
#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    /// The generated API key (only returned once)
    pub api_key: String,
    /// Key metadata
    pub key_info: ApiKeyInfo,
}

/// API key information for responses (without the actual key)
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub rate_limit: Option<ApiKeyRateLimit>,
}

impl From<ApiKey> for ApiKeyInfo {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            user_id: key.user_id,
            roles: key.roles,
            permissions: key.permissions,
            created_at: key.created_at,
            expires_at: key.expires_at,
            active: key.active,
            rate_limit: key.rate_limit,
        }
    }
}

/// Request to update an API key
#[derive(Debug, Deserialize)]
pub struct UpdateApiKeyRequest {
    /// New name for the key
    pub name: Option<String>,
    /// New roles
    pub roles: Option<Vec<String>>,
    /// New permissions
    pub permissions: Option<Vec<String>>,
    /// New expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key is active
    pub active: Option<bool>,
    /// Rate limiting configuration
    pub rate_limit: Option<ApiKeyRateLimit>,
}

/// Query parameters for listing API keys
#[derive(Debug, Deserialize)]
pub struct ListApiKeysQuery {
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by active status
    pub active: Option<bool>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Page size for pagination
    pub limit: Option<u32>,
}

/// Response for listing API keys
#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
    pub total: u32,
    pub page: u32,
    pub limit: u32,
}

/// Request to create a new role
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub parent_roles: Vec<String>,
}

/// Request to update a role
#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub parent_roles: Option<Vec<String>>,
}

/// Request to create a new permission
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub description: String,
    pub resource: String,
    pub actions: Vec<String>,
}

/// Request to update a permission
#[derive(Debug, Deserialize)]
pub struct UpdatePermissionRequest {
    pub description: Option<String>,
    pub resource: Option<String>,
    pub actions: Option<Vec<String>>,
}

/// Request to create a new policy
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub resource: String,
    pub rules: Vec<PolicyRule>,
}

/// Authentication statistics
#[derive(Debug, Serialize)]
pub struct AuthStats {
    pub total_api_keys: u32,
    pub active_api_keys: u32,
    pub expired_api_keys: u32,
    pub total_roles: u32,
    pub total_permissions: u32,
    pub total_policies: u32,
    pub recent_authentications: u32,
    pub failed_authentications: u32,
}

/// Create the admin router with all authentication management endpoints
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        // API Key management endpoints
        .route("/api-keys", post(create_api_key))
        .route("/api-keys", get(list_api_keys))
        .route("/api-keys/:key_id", get(get_api_key))
        .route("/api-keys/:key_id", put(update_api_key))
        .route("/api-keys/:key_id", delete(delete_api_key))
        .route("/api-keys/:key_id/regenerate", post(regenerate_api_key))
        
        // Role management endpoints
        .route("/roles", post(create_role))
        .route("/roles", get(list_roles))
        .route("/roles/:role_name", get(get_role))
        .route("/roles/:role_name", put(update_role))
        .route("/roles/:role_name", delete(delete_role))
        
        // Permission management endpoints
        .route("/permissions", post(create_permission))
        .route("/permissions", get(list_permissions))
        .route("/permissions/:permission_name", get(get_permission))
        .route("/permissions/:permission_name", put(update_permission))
        .route("/permissions/:permission_name", delete(delete_permission))
        
        // Policy management endpoints
        .route("/policies", post(create_policy))
        .route("/policies", get(list_policies))
        .route("/policies/:resource", get(get_policy))
        .route("/policies/:resource", put(update_policy))
        .route("/policies/:resource", delete(delete_policy))
        
        // Statistics and monitoring endpoints
        .route("/stats", get(get_auth_stats))
        .route("/health", get(health_check))
        
        .with_state(state)
}

/// Create a new API key
async fn create_api_key(
    State(_state): State<AdminState>,
    Json(_request): Json<CreateApiKeyRequest>,
) -> GatewayResult<Json<CreateApiKeyResponse>> {
    // Generate a new API key
    let api_key = ApiKeyAuthProvider::generate_key();
    let key_hash = ApiKeyAuthProvider::hash_key(&api_key);

    // Create the API key record
    let key_record = ApiKey {
        id: Uuid::new_v4().to_string(),
        key_hash,
        user_id: _request.user_id,
        name: _request.name,
        roles: _request.roles,
        permissions: _request.permissions,
        created_at: Utc::now(),
        expires_at: _request.expires_at,
        active: true,
        rate_limit: _request.rate_limit,
    };

    // Store the API key
    _state.api_key_store.store_key(&key_record).await?;

    let response = CreateApiKeyResponse {
        api_key,
        key_info: key_record.into(),
    };

    Ok(Json(response))
}

/// List API keys with optional filtering
async fn list_api_keys(
    State(_state): State<AdminState>,
    Query(query): Query<ListApiKeysQuery>,
) -> GatewayResult<Json<ListApiKeysResponse>> {
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(50).min(100); // Cap at 100

    // For now, we'll implement a simple in-memory filtering
    // In a real implementation, this would be done at the database level
    let all_keys = if let Some(user_id) = &query.user_id {
        _state.api_key_store.list_user_keys(user_id).await?
    } else {
        // This would need to be implemented in the ApiKeyStore trait
        // For now, return empty list
        Vec::new()
    };

    let filtered_keys: Vec<ApiKey> = all_keys
        .into_iter()
        .filter(|key| {
            if let Some(active) = query.active {
                key.active == active
            } else {
                true
            }
        })
        .collect();

    let total = filtered_keys.len() as u32;
    let start = ((page - 1) * limit) as usize;
    let end = (start + limit as usize).min(filtered_keys.len());
    
    let keys: Vec<ApiKeyInfo> = filtered_keys[start..end]
        .iter()
        .cloned()
        .map(ApiKeyInfo::from)
        .collect();

    let response = ListApiKeysResponse {
        keys,
        total,
        page,
        limit,
    };

    Ok(Json(response))
}

/// Get a specific API key by ID
async fn get_api_key(
    State(_state): State<AdminState>,
    Path(_key_id): Path<String>,
) -> GatewayResult<Json<ApiKeyInfo>> {
    // This would need to be implemented in the ApiKeyStore trait
    // For now, return a not found error
    Err(GatewayError::internal("API key lookup by ID not implemented"))
}

/// Update an API key
async fn update_api_key(
    State(_state): State<AdminState>,
    Path(_key_id): Path<String>,
    Json(_request): Json<UpdateApiKeyRequest>,
) -> GatewayResult<Json<ApiKeyInfo>> {
    // This would need to be implemented in the ApiKeyStore trait
    // For now, return a not implemented error
    Err(GatewayError::internal("API key update not implemented"))
}

/// Delete an API key
async fn delete_api_key(
    State(_state): State<AdminState>,
    Path(key_id): Path<String>,
) -> GatewayResult<StatusCode> {
    _state.api_key_store.delete_key(&key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Regenerate an API key (creates new key, invalidates old one)
async fn regenerate_api_key(
    State(_state): State<AdminState>,
    Path(_key_id): Path<String>,
) -> GatewayResult<Json<CreateApiKeyResponse>> {
    // This would need to be implemented by:
    // 1. Looking up the existing key
    // 2. Generating a new key
    // 3. Updating the record with the new key hash
    // 4. Returning the new key
    Err(GatewayError::internal("API key regeneration not implemented"))
}

/// Create a new role
async fn create_role(
    State(_state): State<AdminState>,
    Json(request): Json<CreateRoleRequest>,
) -> GatewayResult<Json<Role>> {
    let role = Role {
        name: request.name,
        description: request.description,
        permissions: request.permissions,
        parent_roles: request.parent_roles,
    };

    _state.rbac_manager.add_role(role.clone()).await?;
    Ok(Json(role))
}

/// List all roles
async fn list_roles(State(_state): State<AdminState>) -> GatewayResult<Json<Vec<Role>>> {
    // This would need to be implemented in the RbacManager
    // For now, return empty list
    Ok(Json(Vec::new()))
}

/// Get a specific role
async fn get_role(
    State(_state): State<AdminState>,
    Path(_role_name): Path<String>,
) -> GatewayResult<Json<Role>> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Role lookup not implemented"))
}

/// Update a role
async fn update_role(
    State(_state): State<AdminState>,
    Path(_role_name): Path<String>,
    Json(_request): Json<UpdateRoleRequest>,
) -> GatewayResult<Json<Role>> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Role update not implemented"))
}

/// Delete a role
async fn delete_role(
    State(_state): State<AdminState>,
    Path(_role_name): Path<String>,
) -> GatewayResult<StatusCode> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Role deletion not implemented"))
}

/// Create a new permission
async fn create_permission(
    State(_state): State<AdminState>,
    Json(request): Json<CreatePermissionRequest>,
) -> GatewayResult<Json<Permission>> {
    let permission = Permission {
        name: request.name,
        description: request.description,
        resource: request.resource,
        actions: request.actions,
    };

    _state.rbac_manager.add_permission(permission.clone()).await?;
    Ok(Json(permission))
}

/// List all permissions
async fn list_permissions(State(_state): State<AdminState>) -> GatewayResult<Json<Vec<Permission>>> {
    // This would need to be implemented in the RbacManager
    Ok(Json(Vec::new()))
}

/// Get a specific permission
async fn get_permission(
    State(_state): State<AdminState>,
    Path(_permission_name): Path<String>,
) -> GatewayResult<Json<Permission>> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Permission lookup not implemented"))
}

/// Update a permission
async fn update_permission(
    State(_state): State<AdminState>,
    Path(_permission_name): Path<String>,
    Json(_request): Json<UpdatePermissionRequest>,
) -> GatewayResult<Json<Permission>> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Permission update not implemented"))
}

/// Delete a permission
async fn delete_permission(
    State(_state): State<AdminState>,
    Path(_permission_name): Path<String>,
) -> GatewayResult<StatusCode> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Permission deletion not implemented"))
}

/// Create a new policy
async fn create_policy(
    State(_state): State<AdminState>,
    Json(request): Json<CreatePolicyRequest>,
) -> GatewayResult<Json<Policy>> {
    let policy = Policy {
        resource: request.resource,
        rules: request.rules,
    };

    _state.rbac_manager.add_policy(policy.clone()).await?;
    Ok(Json(policy))
}

/// List all policies
async fn list_policies(State(_state): State<AdminState>) -> GatewayResult<Json<Vec<Policy>>> {
    // This would need to be implemented in the RbacManager
    Ok(Json(Vec::new()))
}

/// Get a specific policy
async fn get_policy(
    State(_state): State<AdminState>,
    Path(_resource): Path<String>,
) -> GatewayResult<Json<Policy>> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Policy lookup not implemented"))
}

/// Update a policy
async fn update_policy(
    State(_state): State<AdminState>,
    Path(_resource): Path<String>,
    Json(policy): Json<Policy>,
) -> GatewayResult<Json<Policy>> {
    _state.rbac_manager.add_policy(policy.clone()).await?;
    Ok(Json(policy))
}

/// Delete a policy
async fn delete_policy(
    State(_state): State<AdminState>,
    Path(_resource): Path<String>,
) -> GatewayResult<StatusCode> {
    // This would need to be implemented in the RbacManager
    Err(GatewayError::internal("Policy deletion not implemented"))
}

/// Get authentication statistics
async fn get_auth_stats(State(_state): State<AdminState>) -> GatewayResult<Json<AuthStats>> {
    // In a real implementation, these would be collected from various sources
    let stats = AuthStats {
        total_api_keys: 0,
        active_api_keys: 0,
        expired_api_keys: 0,
        total_roles: 0,
        total_permissions: 0,
        total_policies: 0,
        recent_authentications: 0,
        failed_authentications: 0,
    };

    Ok(Json(stats))
}

/// Health check endpoint for the admin API
async fn health_check() -> GatewayResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now(),
        "service": "auth-admin"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::providers::{InMemoryApiKeyStore, RbacManager};
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;

    async fn create_test_state() -> AdminState {
        let api_key_store = Arc::new(InMemoryApiKeyStore::new());
        let rbac_manager = Arc::new(RbacManager::new());
        
        // Initialize default roles
        rbac_manager.initialize_defaults().await.unwrap();
        
        AdminState {
            api_key_store,
            rbac_manager,
        }
    }

    #[tokio::test]
    async fn test_create_api_key() {
        let state = create_test_state().await;
        let app = create_admin_router(state);
        let server = TestServer::new(app).unwrap();

        let request = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            user_id: "user123".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            expires_at: None,
            rate_limit: None,
        };

        let response = server
            .post("/api-keys")
            .json(&request)
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: CreateApiKeyResponse = response.json();
        assert!(body.api_key.starts_with("gw_"));
        assert_eq!(body.key_info.name, "Test Key");
        assert_eq!(body.key_info.user_id, "user123");
    }

    #[tokio::test]
    async fn test_create_role() {
        let state = create_test_state().await;
        let app = create_admin_router(state);
        let server = TestServer::new(app).unwrap();

        let request = CreateRoleRequest {
            name: "test_role".to_string(),
            description: "Test role".to_string(),
            permissions: vec!["read".to_string()],
            parent_roles: vec![],
        };

        let response = server
            .post("/roles")
            .json(&request)
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: Role = response.json();
        assert_eq!(body.name, "test_role");
        assert_eq!(body.description, "Test role");
    }

    #[tokio::test]
    async fn test_health_check() {
        let state = create_test_state().await;
        let app = create_admin_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["service"], "auth-admin");
    }
}
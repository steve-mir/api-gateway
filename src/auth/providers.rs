//! # Authentication Providers
//!
//! This module contains different authentication provider implementations including JWT, PASETO,
//! API keys, and OAuth2/OpenID Connect integration. Each provider implements the `AuthProvider`
//! trait for consistent authentication and authorization behavior.
//!
//! ## Rust Concepts Used
//!
//! - `async_trait` enables async methods in traits (not yet native in Rust)
//! - `Arc<T>` for shared ownership of configuration data
//! - `RwLock<T>` for concurrent read/write access to mutable data
//! - `HashMap` for efficient key-value lookups
//! - `chrono` for time handling and JWT expiration validation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, ClientId, ClientSecret,
    CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl
};
// PASETO support temporarily disabled due to API compatibility issues
// use paseto::{PasetoBuilder, PasetoParser};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::AuthContext;

/// Core authentication provider trait
///
/// This trait defines the interface that all authentication providers must implement.
/// It supports both authentication (verifying identity) and authorization (checking permissions).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Authenticate a request using the provided token/credentials
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext>;
    
    /// Authorize an authenticated user for a specific resource and action
    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool>;
    
    /// Get the authentication method name for this provider
    fn auth_method(&self) -> &'static str;
    
    /// Validate if the authentication context is still valid (not expired)
    async fn validate_context(&self, context: &AuthContext) -> GatewayResult<bool> {
        Ok(!context.is_expired())
    }
}

/// JWT Claims structure for token validation
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Additional custom claims
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// JWT Authentication Provider Configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key for HMAC algorithms or public key for RSA/ECDSA
    pub secret: String,
    /// JWT algorithm to use
    pub algorithm: Algorithm,
    /// Expected issuer
    pub issuer: String,
    /// Expected audience
    pub audience: String,
    /// Clock skew tolerance in seconds
    pub leeway: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key".to_string(),
            algorithm: Algorithm::HS256,
            issuer: "api-gateway".to_string(),
            audience: "api-gateway".to_string(),
            leeway: 60, // 1 minute
        }
    }
}

/// JWT Authentication Provider
///
/// Validates JWT tokens using the jsonwebtoken crate. Supports both HMAC and RSA/ECDSA algorithms.
/// Extracts user information, roles, and permissions from JWT claims.
pub struct JwtAuthProvider {
    config: JwtConfig,
    decoding_key: DecodingKey,
    validation: Validation,
    rbac: Arc<RbacManager>,
}

impl JwtAuthProvider {
    /// Create a new JWT authentication provider
    pub fn new(config: JwtConfig, rbac: Arc<RbacManager>) -> GatewayResult<Self> {
        let decoding_key = match config.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                DecodingKey::from_secret(config.secret.as_bytes())
            }
            _ => {
                // For RSA/ECDSA, assume the secret is a PEM-encoded public key
                DecodingKey::from_rsa_pem(config.secret.as_bytes())
                    .or_else(|_| DecodingKey::from_ec_pem(config.secret.as_bytes()))
                    .map_err(|e| GatewayError::config(format!("Invalid JWT key: {}", e)))?
            }
        };

        let mut validation = Validation::new(config.algorithm);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.leeway = config.leeway;

        Ok(Self {
            config,
            decoding_key,
            validation,
            rbac,
        })
    }

    /// Create a JWT token for testing purposes
    pub fn create_token(&self, claims: &JwtClaims) -> GatewayResult<String> {
        let encoding_key = match self.config.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(self.config.secret.as_bytes())
            }
            _ => {
                return Err(GatewayError::config("Token creation not supported for RSA/ECDSA"));
            }
        };

        let header = Header::new(self.config.algorithm);
        encode(&header, claims, &encoding_key)
            .map_err(|e| GatewayError::auth(format!("Failed to create token: {}", e)))
    }
}

#[async_trait]
impl AuthProvider for JwtAuthProvider {
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext> {
        // Remove "Bearer " prefix if present
        let token = token.strip_prefix("Bearer ").unwrap_or(token);

        // Decode and validate the JWT
        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| GatewayError::auth(format!("Invalid JWT token: {}", e)))?;

        let claims = token_data.claims;

        // Create authentication context
        let auth_context = AuthContext {
            user_id: claims.sub,
            roles: claims.roles,
            permissions: claims.permissions,
            claims: claims.custom_claims,
            auth_method: "jwt".to_string(),
            expires_at: Some(DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now)),
        };

        Ok(auth_context)
    }

    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool> {
        self.rbac.check_permission(context, resource, action).await
    }

    fn auth_method(&self) -> &'static str {
        "jwt"
    }
}

// PASETO support temporarily disabled due to API compatibility issues
// Will be re-implemented with correct API in future version

/// API Key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique key identifier
    pub id: String,
    /// The actual API key (hashed)
    pub key_hash: String,
    /// Associated user ID
    pub user_id: String,
    /// Key name/description
    pub name: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Key creation time
    pub created_at: DateTime<Utc>,
    /// Key expiration time (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key is active
    pub active: bool,
    /// Rate limiting configuration for this key
    pub rate_limit: Option<ApiKeyRateLimit>,
}

/// Rate limiting configuration for API keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRateLimit {
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Requests per hour
    pub requests_per_hour: u32,
    /// Requests per day
    pub requests_per_day: u32,
}

/// API Key storage trait for pluggable storage backends
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Get API key by key hash
    async fn get_key(&self, key_hash: &str) -> GatewayResult<Option<ApiKey>>;
    
    /// Store a new API key
    async fn store_key(&self, key: &ApiKey) -> GatewayResult<()>;
    
    /// Update an existing API key
    async fn update_key(&self, key: &ApiKey) -> GatewayResult<()>;
    
    /// Delete an API key
    async fn delete_key(&self, key_id: &str) -> GatewayResult<()>;
    
    /// List all API keys for a user
    async fn list_user_keys(&self, user_id: &str) -> GatewayResult<Vec<ApiKey>>;
}

/// In-memory API key store for development/testing
pub struct InMemoryApiKeyStore {
    keys: Arc<DashMap<String, ApiKey>>,
}

impl InMemoryApiKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl ApiKeyStore for InMemoryApiKeyStore {
    async fn get_key(&self, key_hash: &str) -> GatewayResult<Option<ApiKey>> {
        Ok(self.keys.iter().find(|entry| entry.key_hash == key_hash).map(|entry| entry.clone()))
    }

    async fn store_key(&self, key: &ApiKey) -> GatewayResult<()> {
        self.keys.insert(key.id.clone(), key.clone());
        Ok(())
    }

    async fn update_key(&self, key: &ApiKey) -> GatewayResult<()> {
        self.keys.insert(key.id.clone(), key.clone());
        Ok(())
    }

    async fn delete_key(&self, key_id: &str) -> GatewayResult<()> {
        self.keys.remove(key_id);
        Ok(())
    }

    async fn list_user_keys(&self, user_id: &str) -> GatewayResult<Vec<ApiKey>> {
        let keys: Vec<ApiKey> = self.keys
            .iter()
            .filter(|entry| entry.user_id == user_id)
            .map(|entry| entry.clone())
            .collect();
        Ok(keys)
    }
}

/// API Key Authentication Provider
pub struct ApiKeyAuthProvider {
    store: Arc<dyn ApiKeyStore>,
    rbac: Arc<RbacManager>,
}

impl ApiKeyAuthProvider {
    pub fn new(store: Arc<dyn ApiKeyStore>, rbac: Arc<RbacManager>) -> Self {
        Self { store, rbac }
    }

    /// Hash an API key for secure storage
    pub fn hash_key(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Generate a new API key
    pub fn generate_key() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let key: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..62);
                match idx {
                    0..=25 => (b'A' + idx) as char,
                    26..=51 => (b'a' + (idx - 26)) as char,
                    _ => (b'0' + (idx - 52)) as char,
                }
            })
            .collect();
        format!("gw_{}", key)
    }
}

#[async_trait]
impl AuthProvider for ApiKeyAuthProvider {
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext> {
        // Remove "ApiKey " prefix if present
        let key = token.strip_prefix("ApiKey ").unwrap_or(token);
        
        // Hash the provided key
        let key_hash = Self::hash_key(key);
        
        // Look up the API key
        let api_key = self.store.get_key(&key_hash).await?
            .ok_or_else(|| GatewayError::auth("Invalid API key"))?;

        // Check if key is active
        if !api_key.active {
            return Err(GatewayError::auth("API key is disabled"));
        }

        // Check if key is expired
        if let Some(expires_at) = api_key.expires_at {
            if Utc::now() > expires_at {
                return Err(GatewayError::auth("API key expired"));
            }
        }

        let auth_context = AuthContext {
            user_id: api_key.user_id,
            roles: api_key.roles,
            permissions: api_key.permissions,
            claims: {
                let mut claims = HashMap::new();
                claims.insert("api_key_id".to_string(), serde_json::Value::String(api_key.id));
                claims.insert("api_key_name".to_string(), serde_json::Value::String(api_key.name));
                claims
            },
            auth_method: "api_key".to_string(),
            expires_at: api_key.expires_at,
        };

        Ok(auth_context)
    }

    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool> {
        self.rbac.check_permission(context, resource, action).await
    }

    fn auth_method(&self) -> &'static str {
        "api_key"
    }
}

/// OAuth2/OpenID Connect Configuration
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub userinfo_url: Option<String>,
}

/// OAuth2 Authentication Provider
pub struct OAuth2AuthProvider {
    client: BasicClient,
    config: OAuth2Config,
    rbac: Arc<RbacManager>,
}

impl OAuth2AuthProvider {
    pub fn new(config: OAuth2Config, rbac: Arc<RbacManager>) -> GatewayResult<Self> {
        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(config.auth_url.clone())
                .map_err(|e| GatewayError::config(format!("Invalid auth URL: {}", e)))?,
            Some(TokenUrl::new(config.token_url.clone())
                .map_err(|e| GatewayError::config(format!("Invalid token URL: {}", e)))?),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| GatewayError::config(format!("Invalid redirect URL: {}", e)))?);

        Ok(Self {
            client,
            config,
            rbac,
        })
    }

    /// Generate authorization URL for OAuth2 flow
    pub fn get_auth_url(&self) -> (String, CsrfToken) {
        let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        let mut auth_request = self.client.authorize_url(CsrfToken::new_random);
        
        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }
        
        let (auth_url, csrf_token) = auth_request
            .set_pkce_challenge(pkce_challenge)
            .url();
            
        (auth_url.to_string(), csrf_token)
    }
}

#[async_trait]
impl AuthProvider for OAuth2AuthProvider {
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext> {
        // For OAuth2, the token should be an access token
        // In a real implementation, you would validate this with the OAuth2 provider
        // and fetch user information
        
        // This is a simplified implementation
        // In practice, you would make a request to the userinfo endpoint
        if let Some(userinfo_url) = &self.config.userinfo_url {
            let client = reqwest::Client::new();
            let response = client
                .get(userinfo_url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| GatewayError::auth(format!("Failed to fetch user info: {}", e)))?;

            if !response.status().is_success() {
                return Err(GatewayError::auth("Invalid OAuth2 token"));
            }

            let user_info: serde_json::Value = response
                .json()
                .await
                .map_err(|e| GatewayError::auth(format!("Invalid user info response: {}", e)))?;

            let user_id = user_info["sub"]
                .as_str()
                .or_else(|| user_info["id"].as_str())
                .ok_or_else(|| GatewayError::auth("No user ID in OAuth2 response"))?
                .to_string();

            let auth_context = AuthContext {
                user_id,
                roles: vec!["user".to_string()], // Default role
                permissions: vec![],
                claims: user_info.as_object().unwrap().clone().into_iter()
                    .map(|(k, v)| (k, v.clone()))
                    .collect(),
                auth_method: "oauth2".to_string(),
                expires_at: None, // OAuth2 tokens typically don't have expiration in the token itself
            };

            Ok(auth_context)
        } else {
            Err(GatewayError::config("OAuth2 userinfo URL not configured"))
        }
    }

    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool> {
        self.rbac.check_permission(context, resource, action).await
    }

    fn auth_method(&self) -> &'static str {
        "oauth2"
    }
}

/// Role-Based Access Control (RBAC) Manager
///
/// Manages roles, permissions, and authorization policies.
/// Supports hierarchical roles and fine-grained permissions.
pub struct RbacManager {
    /// Role definitions with their permissions
    roles: Arc<RwLock<HashMap<String, Role>>>,
    /// Permission definitions
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    /// Resource-based access policies
    policies: Arc<RwLock<HashMap<String, Policy>>>,
}

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub parent_roles: Vec<String>, // For role hierarchy
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub description: String,
    pub resource: String,
    pub actions: Vec<String>,
}

/// Access control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub resource: String,
    pub rules: Vec<PolicyRule>,
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub action: String,
    pub allowed_roles: Vec<String>,
    pub allowed_permissions: Vec<String>,
    pub conditions: Vec<PolicyCondition>,
}

/// Policy condition for dynamic authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

impl RbacManager {
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a role definition
    pub async fn add_role(&self, role: Role) -> GatewayResult<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Add a permission definition
    pub async fn add_permission(&self, permission: Permission) -> GatewayResult<()> {
        let mut permissions = self.permissions.write().await;
        permissions.insert(permission.name.clone(), permission);
        Ok(())
    }

    /// Add an access policy
    pub async fn add_policy(&self, policy: Policy) -> GatewayResult<()> {
        let mut policies = self.policies.write().await;
        policies.insert(policy.resource.clone(), policy);
        Ok(())
    }

    /// Check if a user has permission to perform an action on a resource
    pub async fn check_permission(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool> {
        // First check direct permissions
        if context.has_permission(&format!("{}:{}", resource, action)) {
            return Ok(true);
        }

        // Check role-based permissions
        let roles = self.roles.read().await;
        let permissions = self.permissions.read().await;
        
        for role_name in &context.roles {
            if let Some(role) = roles.get(role_name) {
                // Check role permissions
                for perm_name in &role.permissions {
                    if let Some(permission) = permissions.get(perm_name) {
                        if permission.resource == resource && permission.actions.contains(&action.to_string()) {
                            return Ok(true);
                        }
                    }
                }
                
                // Check parent roles recursively
                if self.check_parent_roles(&roles, &permissions, role, resource, action).await? {
                    return Ok(true);
                }
            }
        }

        // Check resource-specific policies
        let policies = self.policies.read().await;
        if let Some(policy) = policies.get(resource) {
            for rule in &policy.rules {
                if rule.action == action {
                    // Check if user has required roles
                    if rule.allowed_roles.iter().any(|role| context.has_role(role)) {
                        return Ok(true);
                    }
                    
                    // Check if user has required permissions
                    if rule.allowed_permissions.iter().any(|perm| context.has_permission(perm)) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check parent roles recursively
    fn check_parent_roles<'a>(
        &'a self,
        roles: &'a HashMap<String, Role>,
        permissions: &'a HashMap<String, Permission>,
        role: &'a Role,
        resource: &'a str,
        action: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GatewayResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            for parent_role_name in &role.parent_roles {
                if let Some(parent_role) = roles.get(parent_role_name) {
                    // Check parent role permissions
                    for perm_name in &parent_role.permissions {
                        if let Some(permission) = permissions.get(perm_name) {
                            if permission.resource == resource && permission.actions.contains(&action.to_string()) {
                                return Ok(true);
                            }
                        }
                    }
                    
                    // Recursively check parent's parents
                    if self.check_parent_roles(roles, permissions, parent_role, resource, action).await? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    /// Initialize default roles and permissions
    pub async fn initialize_defaults(&self) -> GatewayResult<()> {
        // Admin role with all permissions
        let admin_role = Role {
            name: "admin".to_string(),
            description: "Administrator with full access".to_string(),
            permissions: vec![
                "gateway:*".to_string(),
                "services:*".to_string(),
                "users:*".to_string(),
                "config:*".to_string(),
            ],
            parent_roles: vec![],
        };
        self.add_role(admin_role).await?;

        // User role with basic permissions
        let user_role = Role {
            name: "user".to_string(),
            description: "Regular user with basic access".to_string(),
            permissions: vec![
                "services:read".to_string(),
            ],
            parent_roles: vec![],
        };
        self.add_role(user_role).await?;

        // Service role for service-to-service communication
        let service_role = Role {
            name: "service".to_string(),
            description: "Service account for inter-service communication".to_string(),
            permissions: vec![
                "services:read".to_string(),
                "services:write".to_string(),
            ],
            parent_roles: vec![],
        };
        self.add_role(service_role).await?;

        Ok(())
    }
}

/// Admin-specific authentication provider that requires elevated privileges
pub struct AdminAuthProvider {
    base_provider: Arc<dyn AuthProvider>,
    required_role: String,
}

impl AdminAuthProvider {
    pub fn new(base_provider: Arc<dyn AuthProvider>, required_role: Option<String>) -> Self {
        Self {
            base_provider,
            required_role: required_role.unwrap_or_else(|| "admin".to_string()),
        }
    }
}

#[async_trait]
impl AuthProvider for AdminAuthProvider {
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext> {
        let context = self.base_provider.authenticate(token).await?;
        
        // Check if user has admin role
        if !context.has_role(&self.required_role) {
            return Err(GatewayError::authz("Admin access required"));
        }
        
        Ok(context)
    }

    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool> {
        // Admin users have access to everything
        if context.has_role(&self.required_role) {
            return Ok(true);
        }
        
        // Fall back to base provider authorization
        self.base_provider.authorize(context, resource, action).await
    }

    fn auth_method(&self) -> &'static str {
        "admin"
    }
}
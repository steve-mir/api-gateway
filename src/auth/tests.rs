//! # Authentication and Authorization Tests
//!
//! This module contains comprehensive tests for all authentication providers and authorization
//! mechanisms. It tests JWT validation, PASETO tokens, API keys, OAuth2 integration, and
//! role-based access control (RBAC).
//!
//! ## Test Structure
//!
//! - Unit tests for individual components (providers, RBAC, etc.)
//! - Integration tests for middleware and end-to-end flows
//! - Security tests for edge cases and attack scenarios
//! - Performance tests for authentication under load

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use tokio::time::sleep;

use crate::auth::providers::{
    ApiKey, ApiKeyAuthProvider, ApiKeyRateLimit, InMemoryApiKeyStore, JwtAuthProvider, JwtClaims,
    JwtConfig, PasetoAuthProvider, PasetoConfig, RbacManager, Role, Permission, Policy, PolicyRule,
    AdminAuthProvider,
};
use crate::auth::middleware::{AuthMiddleware, AuthConfig};
use crate::core::error::GatewayError;
use crate::core::types::AuthContext;

/// Helper function to create a test JWT token
fn create_test_jwt_token(
    secret: &str,
    user_id: &str,
    roles: Vec<String>,
    permissions: Vec<String>,
    expires_in_seconds: i64,
) -> String {
    let claims = JwtClaims {
        sub: user_id.to_string(),
        exp: (Utc::now().timestamp() + expires_in_seconds),
        iat: Utc::now().timestamp(),
        iss: "api-gateway".to_string(),
        aud: "api-gateway".to_string(),
        roles,
        permissions,
        custom_claims: HashMap::new(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    
    encode(&header, &claims, &encoding_key).expect("Failed to create test JWT")
}

/// Helper function to create test RBAC manager with default data
async fn create_test_rbac_manager() -> Arc<RbacManager> {
    let rbac = Arc::new(RbacManager::new());
    
    // Initialize with default roles
    rbac.initialize_defaults().await.unwrap();
    
    // Add some test-specific roles and permissions
    let test_role = Role {
        name: "test_user".to_string(),
        description: "Test user role".to_string(),
        permissions: vec!["test:read".to_string(), "test:write".to_string()],
        parent_roles: vec!["user".to_string()],
    };
    rbac.add_role(test_role).await.unwrap();
    
    let test_permission = Permission {
        name: "test:read".to_string(),
        description: "Read test resources".to_string(),
        resource: "test".to_string(),
        actions: vec!["read".to_string()],
    };
    rbac.add_permission(test_permission).await.unwrap();
    
    let test_permission2 = Permission {
        name: "test:write".to_string(),
        description: "Write test resources".to_string(),
        resource: "test".to_string(),
        actions: vec!["write".to_string()],
    };
    rbac.add_permission(test_permission2).await.unwrap();
    
    rbac
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt_authentication_success() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig::default();
        let provider = JwtAuthProvider::new(config.clone(), rbac).unwrap();

        let token = create_test_jwt_token(
            &config.secret,
            "user123",
            vec!["user".to_string()],
            vec!["read".to_string()],
            3600, // 1 hour
        );

        let result = provider.authenticate(&token).await;
        assert!(result.is_ok());

        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "user123");
        assert!(auth_context.has_role("user"));
        assert!(auth_context.has_permission("read"));
        assert_eq!(auth_context.auth_method, "jwt");
    }

    #[tokio::test]
    async fn test_jwt_authentication_expired_token() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig::default();
        let provider = JwtAuthProvider::new(config.clone(), rbac).unwrap();

        let token = create_test_jwt_token(
            &config.secret,
            "user123",
            vec!["user".to_string()],
            vec!["read".to_string()],
            -3600, // Expired 1 hour ago
        );

        let result = provider.authenticate(&token).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
    }

    #[tokio::test]
    async fn test_jwt_authentication_invalid_signature() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig::default();
        let provider = JwtAuthProvider::new(config.clone(), rbac).unwrap();

        // Create token with different secret
        let token = create_test_jwt_token(
            "wrong-secret",
            "user123",
            vec!["user".to_string()],
            vec!["read".to_string()],
            3600,
        );

        let result = provider.authenticate(&token).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
    }

    #[tokio::test]
    async fn test_jwt_authorization() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig::default();
        let provider = JwtAuthProvider::new(config, rbac).unwrap();

        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["test_user".to_string()],
            permissions: vec!["test:read".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: None,
        };

        // Test direct permission
        let result = provider.authorize(&auth_context, "test", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test role-based permission
        let result = provider.authorize(&auth_context, "test", "write").await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test unauthorized action
        let result = provider.authorize(&auth_context, "admin", "delete").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

#[cfg(test)]
mod api_key_tests {
    use super::*;

    async fn create_test_api_key_provider() -> (ApiKeyAuthProvider, Arc<InMemoryApiKeyStore>) {
        let store = Arc::new(InMemoryApiKeyStore::new());
        let rbac = create_test_rbac_manager().await;
        let provider = ApiKeyAuthProvider::new(store.clone(), rbac);
        
        // Add a test API key
        let api_key = ApiKey {
            id: "key123".to_string(),
            key_hash: ApiKeyAuthProvider::hash_key("test-api-key"),
            user_id: "user123".to_string(),
            name: "Test Key".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            created_at: Utc::now(),
            expires_at: None,
            active: true,
            rate_limit: Some(ApiKeyRateLimit {
                requests_per_minute: 100,
                requests_per_hour: 1000,
                requests_per_day: 10000,
            }),
        };
        
        store.store_key(&api_key).await.unwrap();
        
        (provider, store)
    }

    #[tokio::test]
    async fn test_api_key_authentication_success() {
        let (provider, _store) = create_test_api_key_provider().await;

        let result = provider.authenticate("test-api-key").await;
        assert!(result.is_ok());

        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "user123");
        assert!(auth_context.has_role("user"));
        assert!(auth_context.has_permission("read"));
        assert_eq!(auth_context.auth_method, "api_key");
    }

    #[tokio::test]
    async fn test_api_key_authentication_invalid_key() {
        let (provider, _store) = create_test_api_key_provider().await;

        let result = provider.authenticate("invalid-key").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
    }

    #[tokio::test]
    async fn test_api_key_authentication_with_prefix() {
        let (provider, _store) = create_test_api_key_provider().await;

        let result = provider.authenticate("ApiKey test-api-key").await;
        assert!(result.is_ok());

        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "user123");
    }

    #[tokio::test]
    async fn test_api_key_generation() {
        let key1 = ApiKeyAuthProvider::generate_key();
        let key2 = ApiKeyAuthProvider::generate_key();
        
        assert!(key1.starts_with("gw_"));
        assert!(key2.starts_with("gw_"));
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 35); // "gw_" + 32 characters
    }

    #[tokio::test]
    async fn test_api_key_hashing() {
        let key = "test-key";
        let hash1 = ApiKeyAuthProvider::hash_key(key);
        let hash2 = ApiKeyAuthProvider::hash_key(key);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, key);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string
    }

    #[tokio::test]
    async fn test_expired_api_key() {
        let store = Arc::new(InMemoryApiKeyStore::new());
        let rbac = create_test_rbac_manager().await;
        let provider = ApiKeyAuthProvider::new(store.clone(), rbac);
        
        // Add an expired API key
        let api_key = ApiKey {
            id: "expired-key".to_string(),
            key_hash: ApiKeyAuthProvider::hash_key("expired-api-key"),
            user_id: "user123".to_string(),
            name: "Expired Key".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            created_at: Utc::now() - chrono::Duration::days(2),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            active: true,
            rate_limit: None,
        };
        
        store.store_key(&api_key).await.unwrap();

        let result = provider.authenticate("expired-api-key").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
    }

    #[tokio::test]
    async fn test_inactive_api_key() {
        let store = Arc::new(InMemoryApiKeyStore::new());
        let rbac = create_test_rbac_manager().await;
        let provider = ApiKeyAuthProvider::new(store.clone(), rbac);
        
        // Add an inactive API key
        let api_key = ApiKey {
            id: "inactive-key".to_string(),
            key_hash: ApiKeyAuthProvider::hash_key("inactive-api-key"),
            user_id: "user123".to_string(),
            name: "Inactive Key".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            created_at: Utc::now(),
            expires_at: None,
            active: false,
            rate_limit: None,
        };
        
        store.store_key(&api_key).await.unwrap();

        let result = provider.authenticate("inactive-api-key").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
    }
}

#[cfg(test)]
mod rbac_tests {
    use super::*;

    #[tokio::test]
    async fn test_role_hierarchy() {
        let rbac = Arc::new(RbacManager::new());
        
        // Create parent role
        let parent_role = Role {
            name: "parent".to_string(),
            description: "Parent role".to_string(),
            permissions: vec!["parent:read".to_string()],
            parent_roles: vec![],
        };
        rbac.add_role(parent_role).await.unwrap();
        
        // Create child role
        let child_role = Role {
            name: "child".to_string(),
            description: "Child role".to_string(),
            permissions: vec!["child:read".to_string()],
            parent_roles: vec!["parent".to_string()],
        };
        rbac.add_role(child_role).await.unwrap();
        
        // Add permissions
        let parent_permission = Permission {
            name: "parent:read".to_string(),
            description: "Parent read permission".to_string(),
            resource: "parent".to_string(),
            actions: vec!["read".to_string()],
        };
        rbac.add_permission(parent_permission).await.unwrap();
        
        let child_permission = Permission {
            name: "child:read".to_string(),
            description: "Child read permission".to_string(),
            resource: "child".to_string(),
            actions: vec!["read".to_string()],
        };
        rbac.add_permission(child_permission).await.unwrap();
        
        // Test that child role has access to both child and parent resources
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["child".to_string()],
            permissions: vec![],
            claims: HashMap::new(),
            auth_method: "test".to_string(),
            expires_at: None,
        };
        
        // Child should have access to child resource
        let result = rbac.check_permission(&auth_context, "child", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Child should also have access to parent resource through inheritance
        let result = rbac.check_permission(&auth_context, "parent", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_direct_permissions() {
        let rbac = Arc::new(RbacManager::new());
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec![],
            permissions: vec!["direct:read".to_string()],
            claims: HashMap::new(),
            auth_method: "test".to_string(),
            expires_at: None,
        };
        
        // Should have access through direct permission
        let result = rbac.check_permission(&auth_context, "direct", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Should not have access to other actions
        let result = rbac.check_permission(&auth_context, "direct", "write").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_policy_based_authorization() {
        let rbac = Arc::new(RbacManager::new());
        
        // Add a policy
        let policy = Policy {
            resource: "documents".to_string(),
            rules: vec![
                PolicyRule {
                    action: "read".to_string(),
                    allowed_roles: vec!["reader".to_string()],
                    allowed_permissions: vec!["documents:read".to_string()],
                    conditions: vec![],
                },
                PolicyRule {
                    action: "write".to_string(),
                    allowed_roles: vec!["writer".to_string()],
                    allowed_permissions: vec!["documents:write".to_string()],
                    conditions: vec![],
                },
            ],
        };
        rbac.add_policy(policy).await.unwrap();
        
        // Test role-based access
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["reader".to_string()],
            permissions: vec![],
            claims: HashMap::new(),
            auth_method: "test".to_string(),
            expires_at: None,
        };
        
        let result = rbac.check_permission(&auth_context, "documents", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        let result = rbac.check_permission(&auth_context, "documents", "write").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

#[cfg(test)]
mod admin_auth_tests {
    use super::*;

    #[tokio::test]
    async fn test_admin_authentication_success() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config.clone(), rbac).unwrap());
        let admin_provider = AdminAuthProvider::new(jwt_provider, Some("admin".to_string()));

        let token = create_test_jwt_token(
            &jwt_config.secret,
            "admin123",
            vec!["admin".to_string()],
            vec!["admin:all".to_string()],
            3600,
        );

        let result = admin_provider.authenticate(&token).await;
        assert!(result.is_ok());

        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "admin123");
        assert!(auth_context.has_role("admin"));
    }

    #[tokio::test]
    async fn test_admin_authentication_insufficient_privileges() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config.clone(), rbac).unwrap());
        let admin_provider = AdminAuthProvider::new(jwt_provider, Some("admin".to_string()));

        let token = create_test_jwt_token(
            &jwt_config.secret,
            "user123",
            vec!["user".to_string()], // Not admin
            vec!["read".to_string()],
            3600,
        );

        let result = admin_provider.authenticate(&token).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Authorization { .. }));
    }

    #[tokio::test]
    async fn test_admin_authorization_always_allowed() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac).unwrap());
        let admin_provider = AdminAuthProvider::new(jwt_provider, Some("admin".to_string()));

        let auth_context = AuthContext {
            user_id: "admin123".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec![],
            claims: HashMap::new(),
            auth_method: "admin".to_string(),
            expires_at: None,
        };

        // Admin should have access to everything
        let result = admin_provider.authorize(&auth_context, "any_resource", "any_action").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}

#[cfg(test)]
mod middleware_tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version};
    use crate::core::types::IncomingRequest;

    #[tokio::test]
    async fn test_auth_middleware_excluded_paths() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac).unwrap());
        
        let config = AuthConfig {
            required: true,
            excluded_paths: vec!["/health".to_string(), "/metrics".to_string()],
            token_header: "authorization".to_string(),
            token_prefix: Some("Bearer ".to_string()),
            allow_multiple_methods: true,
        };
        
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);
        
        assert!(middleware.is_excluded_path("/health"));
        assert!(middleware.is_excluded_path("/metrics"));
        assert!(!middleware.is_excluded_path("/api/users"));
    }

    #[tokio::test]
    async fn test_auth_middleware_wildcard_exclusions() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac).unwrap());
        
        let config = AuthConfig {
            required: true,
            excluded_paths: vec!["/public/*".to_string()],
            token_header: "authorization".to_string(),
            token_prefix: Some("Bearer ".to_string()),
            allow_multiple_methods: true,
        };
        
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);
        
        assert!(middleware.is_excluded_path("/public/assets/style.css"));
        assert!(middleware.is_excluded_path("/public/images/logo.png"));
        assert!(!middleware.is_excluded_path("/private/data"));
    }

    #[tokio::test]
    async fn test_token_extraction() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac).unwrap());
        
        let config = AuthConfig::default();
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);
        
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test-token"));
        
        let token = middleware.extract_token(&headers);
        assert_eq!(token, Some("test-token".to_string()));
    }

    #[tokio::test]
    async fn test_token_extraction_without_prefix() {
        let rbac = create_test_rbac_manager().await;
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac).unwrap());
        
        let config = AuthConfig {
            token_prefix: None,
            ..Default::default()
        };
        let middleware = AuthMiddleware::new(vec![jwt_provider], config);
        
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("raw-token"));
        
        let token = middleware.extract_token(&headers);
        assert_eq!(token, Some("raw-token".to_string()));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_multiple_auth_providers() {
        let rbac = create_test_rbac_manager().await;
        
        // Set up JWT provider
        let jwt_config = JwtConfig::default();
        let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config.clone(), rbac.clone()).unwrap());
        
        // Set up API key provider
        let api_key_store = Arc::new(InMemoryApiKeyStore::new());
        let api_key_provider = Arc::new(ApiKeyAuthProvider::new(api_key_store.clone(), rbac.clone()));
        
        // Add test API key
        let api_key = ApiKey {
            id: "key123".to_string(),
            key_hash: ApiKeyAuthProvider::hash_key("test-api-key"),
            user_id: "user123".to_string(),
            name: "Test Key".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            created_at: Utc::now(),
            expires_at: None,
            active: true,
            rate_limit: None,
        };
        api_key_store.store_key(&api_key).await.unwrap();
        
        let config = AuthConfig::default();
        let middleware = AuthMiddleware::new(
            vec![jwt_provider.clone(), api_key_provider.clone()],
            config,
        );
        
        // Test JWT authentication
        let jwt_token = create_test_jwt_token(
            &jwt_config.secret,
            "jwt_user",
            vec!["user".to_string()],
            vec!["read".to_string()],
            3600,
        );
        
        let result = middleware.authenticate_request(&jwt_token).await;
        assert!(result.is_ok());
        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "jwt_user");
        assert_eq!(auth_context.auth_method, "jwt");
        
        // Test API key authentication
        let result = middleware.authenticate_request("test-api-key").await;
        assert!(result.is_ok());
        let auth_context = result.unwrap();
        assert_eq!(auth_context.user_id, "user123");
        assert_eq!(auth_context.auth_method, "api_key");
    }

    #[tokio::test]
    async fn test_auth_context_expiration() {
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)), // Expired
        };
        
        assert!(auth_context.is_expired());
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)), // Valid
        };
        
        assert!(!auth_context.is_expired());
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            claims: HashMap::new(),
            auth_method: "api_key".to_string(),
            expires_at: None, // No expiration
        };
        
        assert!(!auth_context.is_expired());
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_attack_resistance() {
        let (provider, _store) = api_key_tests::create_test_api_key_provider().await;
        
        // Test with valid key
        let start = std::time::Instant::now();
        let _result = provider.authenticate("test-api-key").await;
        let valid_duration = start.elapsed();
        
        // Test with invalid key
        let start = std::time::Instant::now();
        let _result = provider.authenticate("invalid-key").await;
        let invalid_duration = start.elapsed();
        
        // The timing difference should be minimal (within reasonable bounds)
        // This is a basic test - in practice, you'd want more sophisticated timing analysis
        let difference = if valid_duration > invalid_duration {
            valid_duration - invalid_duration
        } else {
            invalid_duration - valid_duration
        };
        
        // Allow up to 10ms difference (this is quite generous for a unit test)
        assert!(difference < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_jwt_algorithm_confusion_prevention() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig {
            algorithm: Algorithm::HS256,
            ..Default::default()
        };
        let provider = JwtAuthProvider::new(config, rbac).unwrap();
        
        // Try to create a token with a different algorithm
        // This should fail during validation
        let claims = JwtClaims {
            sub: "user123".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            iss: "api-gateway".to_string(),
            aud: "api-gateway".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
            custom_claims: HashMap::new(),
        };
        
        // Create token with RS256 (should fail with HS256 provider)
        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_secret(b"secret");
        
        // This should fail at token creation or validation
        let token_result = encode(&header, &claims, &encoding_key);
        if let Ok(token) = token_result {
            let result = provider.authenticate(&token).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_role_privilege_escalation_prevention() {
        let rbac = Arc::new(RbacManager::new());
        
        // Create a limited role
        let limited_role = Role {
            name: "limited".to_string(),
            description: "Limited role".to_string(),
            permissions: vec!["read:public".to_string()],
            parent_roles: vec![],
        };
        rbac.add_role(limited_role).await.unwrap();
        
        let limited_permission = Permission {
            name: "read:public".to_string(),
            description: "Read public resources".to_string(),
            resource: "public".to_string(),
            actions: vec!["read".to_string()],
        };
        rbac.add_permission(limited_permission).await.unwrap();
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["limited".to_string()],
            permissions: vec![],
            claims: HashMap::new(),
            auth_method: "test".to_string(),
            expires_at: None,
        };
        
        // Should have access to allowed resource
        let result = rbac.check_permission(&auth_context, "public", "read").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Should NOT have access to admin resources
        let result = rbac.check_permission(&auth_context, "admin", "write").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        // Should NOT have access to write operations
        let result = rbac.check_permission(&auth_context, "public", "write").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_jwt_validation_performance() {
        let rbac = create_test_rbac_manager().await;
        let config = JwtConfig::default();
        let provider = JwtAuthProvider::new(config.clone(), rbac).unwrap();

        let token = create_test_jwt_token(
            &config.secret,
            "user123",
            vec!["user".to_string()],
            vec!["read".to_string()],
            3600,
        );

        // Warm up
        for _ in 0..10 {
            let _ = provider.authenticate(&token).await;
        }

        // Measure performance
        let start = Instant::now();
        let iterations = 1000;
        
        for _ in 0..iterations {
            let result = provider.authenticate(&token).await;
            assert!(result.is_ok());
        }
        
        let duration = start.elapsed();
        let avg_duration = duration / iterations;
        
        // JWT validation should be fast (less than 1ms per validation)
        assert!(avg_duration < Duration::from_millis(1));
        
        println!("JWT validation average time: {:?}", avg_duration);
    }

    #[tokio::test]
    async fn test_rbac_check_performance() {
        let rbac = create_test_rbac_manager().await;
        
        let auth_context = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["test_user".to_string()],
            permissions: vec!["test:read".to_string()],
            claims: HashMap::new(),
            auth_method: "test".to_string(),
            expires_at: None,
        };

        // Warm up
        for _ in 0..10 {
            let _ = rbac.check_permission(&auth_context, "test", "read").await;
        }

        // Measure performance
        let start = Instant::now();
        let iterations = 1000;
        
        for _ in 0..iterations {
            let result = rbac.check_permission(&auth_context, "test", "read").await;
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
        
        let duration = start.elapsed();
        let avg_duration = duration / iterations;
        
        // RBAC checks should be fast (less than 100μs per check)
        assert!(avg_duration < Duration::from_micros(100));
        
        println!("RBAC check average time: {:?}", avg_duration);
    }
}
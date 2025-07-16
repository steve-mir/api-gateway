//! # Authentication Providers
//!
//! This module contains different authentication provider implementations.

use async_trait::async_trait;
use crate::core::types::AuthContext;
use crate::core::error::GatewayResult;

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, token: &str) -> GatewayResult<AuthContext>;
    async fn authorize(&self, context: &AuthContext, resource: &str, action: &str) -> GatewayResult<bool>;
}

pub struct JwtAuthProvider {
    // TODO: Implement JWT authentication
}

pub struct ApiKeyAuthProvider {
    // TODO: Implement API key authentication
}
pub mod providers;
pub mod middleware;
pub mod admin;

#[cfg(test)]
mod tests;

pub use providers::{AuthProvider, JwtAuthProvider, ApiKeyAuthProvider, OAuth2AuthProvider, AdminAuthProvider, RbacManager};
pub use middleware::{AuthMiddleware, AuthConfig, auth_middleware, authz_middleware};
pub use admin::{AdminState, create_admin_router};
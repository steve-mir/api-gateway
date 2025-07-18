//! # Admin Module
//!
//! This module provides administrative endpoints for runtime configuration management.
//! It includes functionality for:
//! - Viewing current configuration
//! - Modifying configuration at runtime
//! - Configuration change audit trail
//! - Configuration rollback capabilities
//!
//! ## Security Considerations
//! Admin endpoints should be protected with appropriate authentication and authorization.
//! These endpoints can modify the gateway's behavior and should only be accessible
//! to authorized administrators.
//!
//! ## Usage Example
//! ```rust
//! use std::sync::Arc;
//! use crate::admin::{ConfigAudit, RuntimeConfigManager, AdminRouter, endpoints::AdminState};
//! use crate::core::config::GatewayConfig;
//!
//! // Create audit trail
//! let audit = Arc::new(ConfigAudit::new(Some("audit.log".into())));
//!
//! // Create runtime config manager
//! let config = GatewayConfig::default();
//! let config_manager = Arc::new(RuntimeConfigManager::new(config, audit.clone()));
//!
//! // Create admin router
//! let admin_state = AdminState { config_manager, audit };
//! let admin_router = AdminRouter::create_router(admin_state);
//! ```

pub mod endpoints;
pub mod audit;
pub mod config_manager;
pub mod service_management;
pub mod load_balancer;
pub mod health;
pub mod rate_limiting;
pub mod circuit_breaker;
pub mod transformation;
pub mod grpc_management;
pub mod websocket_management;
pub mod http_management;

pub use endpoints::{AdminRouter, AdminState};
pub use audit::{ConfigAudit, ConfigChange, ConfigChangeType, AuditStatistics};
pub use config_manager::{RuntimeConfigManager, ConfigChangeEvent};
pub use service_management::{ServiceManagementRouter, ServiceManagementState, ServicePersistence};
pub use load_balancer::{LoadBalancerAdminRouter, LoadBalancerAdminState};
pub use health::{HealthAdminRouter, HealthAdminState};
pub use rate_limiting::{RateLimitAdminRouter, RateLimitAdminState};
pub use circuit_breaker::{CircuitBreakerAdminRouter, CircuitBreakerAdminState};
pub use transformation::{TransformationAdminRouter, TransformationAdminState};
pub use grpc_management::{GrpcAdminRouter, GrpcAdminState};
pub use websocket_management::{WebSocketAdminRouter, WebSocketAdminState};
pub use http_management::{HttpAdminRouter, HttpAdminState};
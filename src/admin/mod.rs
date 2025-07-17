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

pub use endpoints::{AdminRouter, AdminState};
pub use audit::{ConfigAudit, ConfigChange, ConfigChangeType, AuditStatistics};
pub use config_manager::{RuntimeConfigManager, ConfigChangeEvent};
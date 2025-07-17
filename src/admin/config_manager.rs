//! # Runtime Configuration Manager
//!
//! This module provides runtime configuration management capabilities with audit trail integration.
//! It allows for safe configuration updates, validation, and rollback functionality.
//!
//! ## Key Features
//! - Thread-safe configuration updates
//! - Automatic audit trail recording
//! - Configuration validation before applying changes
//! - Rollback to previous configurations
//! - Granular configuration updates (routes, upstreams, etc.)
//!
//! ## Rust Concepts Used
//! - `Arc<RwLock<T>>` for thread-safe shared state
//! - `async/await` for non-blocking operations
//! - Error handling with `Result<T, E>`
//! - Trait objects for extensibility

use crate::core::{config::GatewayConfig, error::{GatewayResult, GatewayError}};
use crate::admin::{ConfigAudit, ConfigChange, ConfigChangeType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Runtime configuration manager with audit trail integration
pub struct RuntimeConfigManager {
    /// Current configuration (thread-safe)
    current_config: Arc<RwLock<GatewayConfig>>,
    
    /// Configuration audit trail
    audit: Arc<ConfigAudit>,
    
    /// Configuration change broadcaster
    change_sender: broadcast::Sender<ConfigChangeEvent>,
    
    /// Last modification timestamp
    last_modified: Arc<RwLock<Option<DateTime<Utc>>>>,
}

/// Configuration change event for broadcasting
#[derive(Debug, Clone)]
pub struct ConfigChangeEvent {
    pub change_id: Uuid,
    pub change_type: ConfigChangeType,
    pub config: GatewayConfig,
    pub timestamp: DateTime<Utc>,
}

impl RuntimeConfigManager {
    /// Create a new runtime configuration manager
    pub fn new(initial_config: GatewayConfig, audit: Arc<ConfigAudit>) -> Self {
        let (change_sender, _) = broadcast::channel(100);
        
        Self {
            current_config: Arc::new(RwLock::new(initial_config)),
            audit,
            change_sender,
            last_modified: Arc::new(RwLock::new(Some(Utc::now()))),
        }
    }

    /// Get the current configuration
    pub async fn get_current_config(&self) -> GatewayResult<GatewayConfig> {
        let config = self.current_config.read().await;
        Ok(config.clone())
    }

    /// Get the last modification timestamp
    pub async fn get_last_modified(&self) -> Option<DateTime<Utc>> {
        let timestamp = self.last_modified.read().await;
        *timestamp
    }

    /// Subscribe to configuration changes
    pub fn subscribe_to_changes(&self) -> broadcast::Receiver<ConfigChangeEvent> {
        self.change_sender.subscribe()
    }

    /// Update the full configuration
    pub async fn update_config(
        &self,
        new_config: GatewayConfig,
        changed_by: String,
        description: String,
        metadata: serde_json::Value,
    ) -> GatewayResult<Uuid> {
        // Validate the new configuration
        new_config.validate()?;

        // Get the current configuration for audit trail
        let previous_config = {
            let config = self.current_config.read().await;
            config.clone()
        };

        // Create audit record
        let mut change = ConfigChange::new(
            ConfigChangeType::FullReplace,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(metadata);

        // Apply the configuration change
        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                // Record successful change
                self.audit.record_change(change.clone()).await?;
                
                // Broadcast change event
                let event = ConfigChangeEvent {
                    change_id: change.id,
                    change_type: change.change_type.clone(),
                    config: new_config,
                    timestamp: change.timestamp,
                };
                
                if let Err(e) = self.change_sender.send(event) {
                    tracing::warn!("Failed to broadcast config change event: {}", e);
                }

                Ok(change.id)
            }
            Err(e) => {
                // Record failed change
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Add a new route
    pub async fn add_route(
        &self,
        route: crate::core::config::RouteDefinition,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Check if route already exists
        if new_config.routes.iter().any(|r| r.path == route.path) {
            return Err(GatewayError::config(format!(
                "Route with path '{}' already exists",
                route.path
            )));
        }

        // Validate that the upstream exists
        if !new_config.upstreams.contains_key(&route.upstream) {
            return Err(GatewayError::config(format!(
                "Upstream '{}' does not exist",
                route.upstream
            )));
        }

        new_config.routes.push(route.clone());
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::RouteAdd,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "route_path": route.path,
            "route_upstream": route.upstream
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::RouteAdd, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Update an existing route
    pub async fn update_route(
        &self,
        route_path: &str,
        updated_route: crate::core::config::RouteDefinition,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Find and update the route
        let route_index = new_config.routes.iter().position(|r| r.path == route_path)
            .ok_or_else(|| GatewayError::config(format!("Route '{}' not found", route_path)))?;

        // Validate that the upstream exists
        if !new_config.upstreams.contains_key(&updated_route.upstream) {
            return Err(GatewayError::config(format!(
                "Upstream '{}' does not exist",
                updated_route.upstream
            )));
        }

        new_config.routes[route_index] = updated_route.clone();
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::RouteModify,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "route_path": route_path,
            "new_upstream": updated_route.upstream
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::RouteModify, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Delete a route
    pub async fn delete_route(
        &self,
        route_path: &str,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Find and remove the route
        let route_index = new_config.routes.iter().position(|r| r.path == route_path)
            .ok_or_else(|| GatewayError::config(format!("Route '{}' not found", route_path)))?;

        let removed_route = new_config.routes.remove(route_index);
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::RouteDelete,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "deleted_route_path": removed_route.path,
            "deleted_route_upstream": removed_route.upstream
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::RouteDelete, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Add a new upstream
    pub async fn add_upstream(
        &self,
        name: String,
        upstream: crate::core::config::UpstreamConfig,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Check if upstream already exists
        if new_config.upstreams.contains_key(&name) {
            return Err(GatewayError::config(format!(
                "Upstream '{}' already exists",
                name
            )));
        }

        new_config.upstreams.insert(name.clone(), upstream);
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::UpstreamAdd,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "upstream_name": name
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::UpstreamAdd, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Update an existing upstream
    pub async fn update_upstream(
        &self,
        name: &str,
        updated_upstream: crate::core::config::UpstreamConfig,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Check if upstream exists
        if !new_config.upstreams.contains_key(name) {
            return Err(GatewayError::config(format!(
                "Upstream '{}' not found",
                name
            )));
        }

        new_config.upstreams.insert(name.to_string(), updated_upstream);
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::UpstreamModify,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "upstream_name": name
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::UpstreamModify, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Delete an upstream
    pub async fn delete_upstream(
        &self,
        name: &str,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        let mut new_config = self.get_current_config().await?;
        
        // Check if upstream exists
        if !new_config.upstreams.contains_key(name) {
            return Err(GatewayError::config(format!(
                "Upstream '{}' not found",
                name
            )));
        }

        // Check if any routes reference this upstream
        let referencing_routes: Vec<_> = new_config.routes.iter()
            .filter(|route| route.upstream == name)
            .map(|route| route.path.clone())
            .collect();

        if !referencing_routes.is_empty() {
            return Err(GatewayError::config(format!(
                "Cannot delete upstream '{}' as it is referenced by routes: {}",
                name,
                referencing_routes.join(", ")
            )));
        }

        new_config.upstreams.remove(name);
        
        // Validate the updated configuration
        new_config.validate()?;

        let previous_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::UpstreamDelete,
            changed_by,
            description,
            Some(previous_config),
            new_config.clone(),
        ).with_metadata(serde_json::json!({
            "deleted_upstream_name": name
        }));

        match self.apply_config_change(new_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::UpstreamDelete, new_config).await;
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Rollback to a specific configuration change
    pub async fn rollback_to_change(
        &self,
        change_id: Uuid,
        changed_by: String,
        description: String,
    ) -> GatewayResult<Uuid> {
        // Get the target change record
        let target_change = self.audit.get_record_by_id(change_id).await
            .ok_or_else(|| GatewayError::config(format!("Change {} not found", change_id)))?;

        // Ensure the change has a previous configuration to rollback to
        let rollback_config = target_change.previous_config
            .ok_or_else(|| GatewayError::config(format!("Change {} has no previous configuration for rollback", change_id)))?;

        // Validate the rollback configuration
        rollback_config.validate()?;

        let current_config = self.get_current_config().await?;
        let mut change = ConfigChange::new(
            ConfigChangeType::FullReplace,
            changed_by,
            description,
            Some(current_config),
            rollback_config.clone(),
        ).with_metadata(serde_json::json!({
            "rollback_to_change_id": change_id,
            "rollback_type": "configuration_rollback"
        }));

        match self.apply_config_change(rollback_config.clone(), &mut change).await {
            Ok(()) => {
                self.audit.record_change(change.clone()).await?;
                self.broadcast_change(change.id, ConfigChangeType::FullReplace, rollback_config).await;
                
                tracing::info!(
                    rollback_change_id = %change.id,
                    target_change_id = %change_id,
                    "Configuration rolled back successfully"
                );
                
                Ok(change.id)
            }
            Err(e) => {
                change.mark_failed(e.to_string());
                self.audit.record_change(change).await?;
                Err(e)
            }
        }
    }

    /// Apply a configuration change atomically
    async fn apply_config_change(
        &self,
        new_config: GatewayConfig,
        change: &mut ConfigChange,
    ) -> GatewayResult<()> {
        // Acquire write lock and update configuration
        {
            let mut config = self.current_config.write().await;
            *config = new_config;
        }

        // Update last modified timestamp
        {
            let mut timestamp = self.last_modified.write().await;
            *timestamp = Some(Utc::now());
        }

        tracing::info!(
            change_id = %change.id,
            change_type = ?change.change_type,
            changed_by = %change.changed_by,
            "Configuration change applied successfully"
        );

        Ok(())
    }

    /// Broadcast configuration change event
    async fn broadcast_change(
        &self,
        change_id: Uuid,
        change_type: ConfigChangeType,
        config: GatewayConfig,
    ) {
        let event = ConfigChangeEvent {
            change_id,
            change_type,
            config,
            timestamp: Utc::now(),
        };

        if let Err(e) = self.change_sender.send(event) {
            tracing::warn!("Failed to broadcast config change event: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{RouteDefinition, UpstreamConfig, DiscoveryMethod, LoadBalancerStrategy, HealthCheckConfig};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn create_test_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        
        // Add a test upstream
        let upstream = UpstreamConfig {
            discovery: DiscoveryMethod::Static {
                endpoints: vec!["http://localhost:8081".to_string()],
            },
            load_balancer: LoadBalancerStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            circuit_breaker: None,
            retry_policy: None,
        };
        config.upstreams.insert("test-upstream".to_string(), upstream);
        
        config
    }

    fn create_test_route() -> RouteDefinition {
        RouteDefinition {
            path: "/api/test".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            upstream: "test-upstream".to_string(),
            middleware: vec![],
            timeout: None,
            auth_required: false,
            required_roles: vec![],
        }
    }

    #[tokio::test]
    async fn test_config_manager_creation() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config.clone(), audit);
        
        let current = manager.get_current_config().await.unwrap();
        assert_eq!(current.upstreams.len(), config.upstreams.len());
    }

    #[tokio::test]
    async fn test_add_route() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit.clone());
        
        let route = create_test_route();
        let change_id = manager.add_route(
            route.clone(),
            "test-user".to_string(),
            "Test route addition".to_string(),
        ).await.unwrap();
        
        let updated_config = manager.get_current_config().await.unwrap();
        assert_eq!(updated_config.routes.len(), 1);
        assert_eq!(updated_config.routes[0].path, route.path);
        
        // Verify audit record
        let audit_record = audit.get_record_by_id(change_id).await.unwrap();
        assert_eq!(audit_record.change_type, ConfigChangeType::RouteAdd);
        assert!(audit_record.success);
    }

    #[tokio::test]
    async fn test_update_route() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit.clone());
        
        // Add initial route
        let route = create_test_route();
        manager.add_route(
            route.clone(),
            "test-user".to_string(),
            "Initial route".to_string(),
        ).await.unwrap();
        
        // Update the route
        let mut updated_route = route.clone();
        updated_route.methods = vec!["GET".to_string()];
        
        let change_id = manager.update_route(
            &route.path,
            updated_route.clone(),
            "test-user".to_string(),
            "Updated route methods".to_string(),
        ).await.unwrap();
        
        let config = manager.get_current_config().await.unwrap();
        assert_eq!(config.routes[0].methods, vec!["GET".to_string()]);
        
        // Verify audit record
        let audit_record = audit.get_record_by_id(change_id).await.unwrap();
        assert_eq!(audit_record.change_type, ConfigChangeType::RouteModify);
        assert!(audit_record.success);
    }

    #[tokio::test]
    async fn test_delete_route() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit.clone());
        
        // Add initial route
        let route = create_test_route();
        manager.add_route(
            route.clone(),
            "test-user".to_string(),
            "Initial route".to_string(),
        ).await.unwrap();
        
        // Delete the route
        let change_id = manager.delete_route(
            &route.path,
            "test-user".to_string(),
            "Deleted test route".to_string(),
        ).await.unwrap();
        
        let config = manager.get_current_config().await.unwrap();
        assert_eq!(config.routes.len(), 0);
        
        // Verify audit record
        let audit_record = audit.get_record_by_id(change_id).await.unwrap();
        assert_eq!(audit_record.change_type, ConfigChangeType::RouteDelete);
        assert!(audit_record.success);
    }

    #[tokio::test]
    async fn test_rollback_functionality() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit.clone());
        
        // Add a route
        let route = create_test_route();
        let add_change_id = manager.add_route(
            route.clone(),
            "test-user".to_string(),
            "Added test route".to_string(),
        ).await.unwrap();
        
        // Verify route was added
        let config_after_add = manager.get_current_config().await.unwrap();
        assert_eq!(config_after_add.routes.len(), 1);
        
        // Rollback the change
        let rollback_change_id = manager.rollback_to_change(
            add_change_id,
            "test-user".to_string(),
            "Rollback route addition".to_string(),
        ).await.unwrap();
        
        // Verify rollback
        let config_after_rollback = manager.get_current_config().await.unwrap();
        assert_eq!(config_after_rollback.routes.len(), 0);
        
        // Verify audit records
        let rollback_record = audit.get_record_by_id(rollback_change_id).await.unwrap();
        assert_eq!(rollback_record.change_type, ConfigChangeType::FullReplace);
        assert!(rollback_record.success);
    }

    #[tokio::test]
    async fn test_upstream_validation() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit);
        
        // Try to add route with non-existent upstream
        let mut route = create_test_route();
        route.upstream = "non-existent-upstream".to_string();
        
        let result = manager.add_route(
            route,
            "test-user".to_string(),
            "Invalid route".to_string(),
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_upstream_deletion_with_references() {
        let config = create_test_config();
        let audit = Arc::new(ConfigAudit::new(None));
        let manager = RuntimeConfigManager::new(config, audit);
        
        // Add a route that references the upstream
        let route = create_test_route();
        manager.add_route(
            route,
            "test-user".to_string(),
            "Test route".to_string(),
        ).await.unwrap();
        
        // Try to delete the upstream
        let result = manager.delete_upstream(
            "test-upstream",
            "test-user".to_string(),
            "Delete upstream".to_string(),
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("referenced by routes"));
    }
}
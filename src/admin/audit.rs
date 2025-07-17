//! # Configuration Audit Trail
//!
//! This module implements a comprehensive audit trail for configuration changes.
//! It tracks all configuration modifications, stores them persistently, and provides
//! rollback capabilities.
//!
//! ## Rust Concepts Used
//! - `serde` for serialization/deserialization of audit records
//! - `tokio::sync::RwLock` for thread-safe access to audit data
//! - `chrono` for timestamp handling
//! - `uuid` for unique change identifiers

use crate::core::{config::GatewayConfig, error::{GatewayResult, GatewayError}};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Maximum number of audit records to keep in memory
const MAX_AUDIT_RECORDS: usize = 1000;

/// Type of configuration change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfigChangeType {
    /// Full configuration replacement
    FullReplace,
    /// Route addition
    RouteAdd,
    /// Route modification
    RouteModify,
    /// Route deletion
    RouteDelete,
    /// Upstream addition
    UpstreamAdd,
    /// Upstream modification
    UpstreamModify,
    /// Upstream deletion
    UpstreamDelete,
    /// Middleware configuration change
    MiddlewareChange,
    /// Authentication configuration change
    AuthChange,
    /// Server configuration change
    ServerChange,
    /// Observability configuration change
    ObservabilityChange,
}

/// Configuration change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    /// Unique identifier for this change
    pub id: Uuid,
    
    /// Timestamp when the change was made
    pub timestamp: DateTime<Utc>,
    
    /// Type of change
    pub change_type: ConfigChangeType,
    
    /// User or system that made the change
    pub changed_by: String,
    
    /// Description of the change
    pub description: String,
    
    /// Configuration before the change (for rollback)
    pub previous_config: Option<GatewayConfig>,
    
    /// Configuration after the change
    pub new_config: GatewayConfig,
    
    /// Additional metadata about the change
    pub metadata: serde_json::Value,
    
    /// Whether this change was successful
    pub success: bool,
    
    /// Error message if the change failed
    pub error_message: Option<String>,
}

impl ConfigChange {
    /// Create a new configuration change record
    pub fn new(
        change_type: ConfigChangeType,
        changed_by: String,
        description: String,
        previous_config: Option<GatewayConfig>,
        new_config: GatewayConfig,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            change_type,
            changed_by,
            description,
            previous_config,
            new_config,
            metadata: serde_json::Value::Null,
            success: true,
            error_message: None,
        }
    }

    /// Mark this change as failed
    pub fn mark_failed(&mut self, error: String) {
        self.success = false;
        self.error_message = Some(error);
    }

    /// Add metadata to the change record
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Configuration audit trail manager
pub struct ConfigAudit {
    /// In-memory audit records (most recent first)
    records: Arc<RwLock<VecDeque<ConfigChange>>>,
    
    /// Path to persistent audit log file
    audit_file_path: Option<PathBuf>,
    
    /// Maximum number of records to keep in memory
    max_records: usize,
}

impl ConfigAudit {
    /// Create a new configuration audit manager
    pub fn new(audit_file_path: Option<PathBuf>) -> Self {
        Self {
            records: Arc::new(RwLock::new(VecDeque::new())),
            audit_file_path,
            max_records: MAX_AUDIT_RECORDS,
        }
    }

    /// Record a configuration change
    pub async fn record_change(&self, mut change: ConfigChange) -> GatewayResult<()> {
        // Write to persistent storage first
        if let Some(ref path) = self.audit_file_path {
            if let Err(e) = self.write_to_file(&change, path).await {
                tracing::warn!("Failed to write audit record to file: {}", e);
                change.mark_failed(format!("Failed to persist audit record: {}", e));
            }
        }

        // Add to in-memory records
        let mut records = self.records.write().await;
        records.push_front(change.clone());

        // Trim records if we exceed the maximum
        while records.len() > self.max_records {
            records.pop_back();
        }

        tracing::info!(
            change_id = %change.id,
            change_type = ?change.change_type,
            changed_by = %change.changed_by,
            success = change.success,
            "Configuration change recorded"
        );

        Ok(())
    }

    /// Get all audit records (most recent first)
    pub async fn get_all_records(&self) -> Vec<ConfigChange> {
        let records = self.records.read().await;
        records.iter().cloned().collect()
    }

    /// Get audit records with pagination
    pub async fn get_records_paginated(&self, offset: usize, limit: usize) -> Vec<ConfigChange> {
        let records = self.records.read().await;
        records
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get audit records by change type
    pub async fn get_records_by_type(&self, change_type: ConfigChangeType) -> Vec<ConfigChange> {
        let records = self.records.read().await;
        records
            .iter()
            .filter(|record| record.change_type == change_type)
            .cloned()
            .collect()
    }

    /// Get audit records by user
    pub async fn get_records_by_user(&self, user: &str) -> Vec<ConfigChange> {
        let records = self.records.read().await;
        records
            .iter()
            .filter(|record| record.changed_by == user)
            .cloned()
            .collect()
    }

    /// Get a specific audit record by ID
    pub async fn get_record_by_id(&self, id: Uuid) -> Option<ConfigChange> {
        let records = self.records.read().await;
        records.iter().find(|record| record.id == id).cloned()
    }

    /// Get the most recent successful configuration
    pub async fn get_last_successful_config(&self) -> Option<GatewayConfig> {
        let records = self.records.read().await;
        records
            .iter()
            .find(|record| record.success)
            .map(|record| record.new_config.clone())
    }

    /// Get configuration at a specific point in time
    pub async fn get_config_at_time(&self, timestamp: DateTime<Utc>) -> Option<GatewayConfig> {
        let records = self.records.read().await;
        records
            .iter()
            .find(|record| record.success && record.timestamp <= timestamp)
            .map(|record| record.new_config.clone())
    }

    /// Get rollback candidates (successful changes with previous config)
    pub async fn get_rollback_candidates(&self, limit: usize) -> Vec<ConfigChange> {
        let records = self.records.read().await;
        records
            .iter()
            .filter(|record| record.success && record.previous_config.is_some())
            .take(limit)
            .cloned()
            .collect()
    }

    /// Clear all audit records (use with caution)
    pub async fn clear_records(&self) -> GatewayResult<()> {
        let mut records = self.records.write().await;
        records.clear();
        
        tracing::warn!("All audit records have been cleared");
        Ok(())
    }

    /// Load audit records from persistent storage
    pub async fn load_from_file(&self) -> GatewayResult<()> {
        if let Some(ref path) = self.audit_file_path {
            if !path.exists() {
                return Ok(());
            }

            let content = tokio::fs::read_to_string(path).await
                .map_err(|e| GatewayError::internal(format!("Failed to read audit file: {}", e)))?;

            let mut records = self.records.write().await;
            records.clear();

            // Parse each line as a JSON record
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<ConfigChange>(line) {
                    Ok(record) => {
                        records.push_back(record);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse audit record: {}", e);
                    }
                }
            }

            // Sort by timestamp (most recent first)
            let mut sorted_records: Vec<_> = records.drain(..).collect();
            sorted_records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            
            // Keep only the most recent records
            sorted_records.truncate(self.max_records);
            
            for record in sorted_records {
                records.push_back(record);
            }

            tracing::info!(
                records_loaded = records.len(),
                "Audit records loaded from file"
            );
        }

        Ok(())
    }

    /// Write a single audit record to file
    async fn write_to_file(&self, record: &ConfigChange, path: &PathBuf) -> GatewayResult<()> {
        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| GatewayError::internal(format!("Failed to create audit directory: {}", e)))?;
        }

        // Serialize the record as JSON
        let json_line = serde_json::to_string(record)
            .map_err(|e| GatewayError::internal(format!("Failed to serialize audit record: {}", e)))?;

        // Append to the audit file
        let mut content = format!("{}\n", json_line);
        
        // Use OpenOptions to append to the file
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| GatewayError::internal(format!("Failed to open audit file: {}", e)))?;

        file.write_all(content.as_bytes()).await
            .map_err(|e| GatewayError::internal(format!("Failed to write to audit file: {}", e)))?;

        file.flush().await
            .map_err(|e| GatewayError::internal(format!("Failed to flush audit file: {}", e)))?;

        Ok(())
    }

    /// Get audit statistics
    pub async fn get_statistics(&self) -> AuditStatistics {
        let records = self.records.read().await;
        
        let total_changes = records.len();
        let successful_changes = records.iter().filter(|r| r.success).count();
        let failed_changes = total_changes - successful_changes;
        
        let mut changes_by_type = std::collections::HashMap::new();
        let mut changes_by_user = std::collections::HashMap::new();
        
        for record in records.iter() {
            *changes_by_type.entry(record.change_type.clone()).or_insert(0) += 1;
            *changes_by_user.entry(record.changed_by.clone()).or_insert(0) += 1;
        }

        let oldest_record = records.back().map(|r| r.timestamp);
        let newest_record = records.front().map(|r| r.timestamp);

        AuditStatistics {
            total_changes,
            successful_changes,
            failed_changes,
            changes_by_type,
            changes_by_user,
            oldest_record,
            newest_record,
        }
    }
}

/// Audit statistics
#[derive(Debug, Serialize)]
pub struct AuditStatistics {
    pub total_changes: usize,
    pub successful_changes: usize,
    pub failed_changes: usize,
    pub changes_by_type: std::collections::HashMap<ConfigChangeType, usize>,
    pub changes_by_user: std::collections::HashMap<String, usize>,
    pub oldest_record: Option<DateTime<Utc>>,
    pub newest_record: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_config_change_creation() {
        let config = GatewayConfig::default();
        let change = ConfigChange::new(
            ConfigChangeType::FullReplace,
            "admin".to_string(),
            "Initial configuration".to_string(),
            None,
            config.clone(),
        );

        assert_eq!(change.change_type, ConfigChangeType::FullReplace);
        assert_eq!(change.changed_by, "admin");
        assert!(change.success);
        assert!(change.error_message.is_none());
    }

    #[tokio::test]
    async fn test_audit_record_management() {
        let audit = ConfigAudit::new(None);
        let config = GatewayConfig::default();

        let change = ConfigChange::new(
            ConfigChangeType::RouteAdd,
            "user1".to_string(),
            "Added new route".to_string(),
            Some(config.clone()),
            config.clone(),
        );

        audit.record_change(change.clone()).await.unwrap();

        let records = audit.get_all_records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, change.id);
    }

    #[tokio::test]
    async fn test_audit_pagination() {
        let audit = ConfigAudit::new(None);
        let config = GatewayConfig::default();

        // Add multiple records
        for i in 0..10 {
            let change = ConfigChange::new(
                ConfigChangeType::RouteAdd,
                format!("user{}", i),
                format!("Change {}", i),
                Some(config.clone()),
                config.clone(),
            );
            audit.record_change(change).await.unwrap();
        }

        let page1 = audit.get_records_paginated(0, 5).await;
        let page2 = audit.get_records_paginated(5, 5).await;

        assert_eq!(page1.len(), 5);
        assert_eq!(page2.len(), 5);
        
        // Ensure no overlap
        let page1_ids: std::collections::HashSet<_> = page1.iter().map(|r| r.id).collect();
        let page2_ids: std::collections::HashSet<_> = page2.iter().map(|r| r.id).collect();
        assert!(page1_ids.is_disjoint(&page2_ids));
    }

    #[tokio::test]
    async fn test_audit_file_persistence() {
        let temp_dir = tempdir().unwrap();
        let audit_file = temp_dir.path().join("audit.log");
        
        let audit = ConfigAudit::new(Some(audit_file.clone()));
        let config = GatewayConfig::default();

        let change = ConfigChange::new(
            ConfigChangeType::FullReplace,
            "admin".to_string(),
            "Test change".to_string(),
            None,
            config,
        );

        audit.record_change(change.clone()).await.unwrap();

        // Verify file was created and contains the record
        assert!(audit_file.exists());
        
        let content = tokio::fs::read_to_string(&audit_file).await.unwrap();
        assert!(content.contains(&change.id.to_string()));
    }

    #[tokio::test]
    async fn test_rollback_candidates() {
        let audit = ConfigAudit::new(None);
        let config1 = GatewayConfig::default();
        let mut config2 = GatewayConfig::default();
        config2.server.http_port = 8081;

        // Record a change with previous config (rollback candidate)
        let change1 = ConfigChange::new(
            ConfigChangeType::ServerChange,
            "admin".to_string(),
            "Changed port".to_string(),
            Some(config1.clone()),
            config2.clone(),
        );
        audit.record_change(change1).await.unwrap();

        // Record a change without previous config (not a rollback candidate)
        let change2 = ConfigChange::new(
            ConfigChangeType::RouteAdd,
            "admin".to_string(),
            "Added route".to_string(),
            None,
            config2,
        );
        audit.record_change(change2).await.unwrap();

        let candidates = audit.get_rollback_candidates(10).await;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].change_type, ConfigChangeType::ServerChange);
    }
}
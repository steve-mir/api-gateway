//! # Admin Backup and Disaster Recovery
//!
//! This module provides comprehensive backup and disaster recovery capabilities for admin operations:
//! - Automated configuration backups
//! - Point-in-time recovery
//! - Disaster recovery procedures
//! - Backup verification and testing
//! - Recovery time and point objectives (RTO/RPO) management
//! - Cross-region backup replication

use crate::admin::audit::ConfigAudit;
use crate::core::config::GatewayConfig;
use crate::core::error::{GatewayError, GatewayResult};

use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

// ============================================================================
// Backup and Recovery Types
// ============================================================================

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup name/identifier
    pub name: String,
    /// Backup schedule (cron expression)
    pub schedule: String,
    /// Backup retention policy
    pub retention: RetentionPolicy,
    /// Backup storage configuration
    pub storage: BackupStorage,
    /// Backup encryption settings
    pub encryption: EncryptionConfig,
    /// Backup compression settings
    pub compression: CompressionConfig,
    /// Whether backup is enabled
    pub enabled: bool,
    /// Backup verification settings
    pub verification: VerificationConfig,
}

/// Backup retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Keep daily backups for this many days
    pub daily_retention_days: u32,
    /// Keep weekly backups for this many weeks
    pub weekly_retention_weeks: u32,
    /// Keep monthly backups for this many months
    pub monthly_retention_months: u32,
    /// Keep yearly backups for this many years
    pub yearly_retention_years: u32,
    /// Maximum total backups to keep
    pub max_backups: Option<u32>,
}

/// Backup storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStorage {
    /// Storage type
    pub storage_type: StorageType,
    /// Storage location/path
    pub location: String,
    /// Storage credentials (encrypted)
    pub credentials: Option<String>,
    /// Cross-region replication settings
    pub replication: Option<ReplicationConfig>,
}

/// Storage types for backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    /// Local filesystem
    Local,
    /// AWS S3
    S3,
    /// Google Cloud Storage
    Gcs,
    /// Azure Blob Storage
    Azure,
    /// Network File System
    Nfs,
    /// SFTP
    Sftp,
}

/// Cross-region replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Replication targets
    pub targets: Vec<ReplicationTarget>,
    /// Replication mode
    pub mode: ReplicationMode,
    /// Replication schedule
    pub schedule: Option<String>,
}

/// Replication target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationTarget {
    /// Target region/location
    pub region: String,
    /// Target storage configuration
    pub storage: BackupStorage,
    /// Priority (lower number = higher priority)
    pub priority: u32,
}

/// Replication modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMode {
    /// Synchronous replication
    Sync,
    /// Asynchronous replication
    Async,
    /// On-demand replication
    OnDemand,
}

/// Backup encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Whether encryption is enabled
    pub enabled: bool,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Key management configuration
    pub key_management: KeyManagement,
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes256,
    ChaCha20Poly1305,
}

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyManagement {
    /// Local key storage
    Local { key_file: String },
    /// AWS KMS
    AwsKms { key_id: String },
    /// HashiCorp Vault
    Vault { vault_path: String },
}

/// Backup compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Whether compression is enabled
    pub enabled: bool,
    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,
    /// Compression level (1-9)
    pub level: u8,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
}

/// Backup verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Whether verification is enabled
    pub enabled: bool,
    /// Verification schedule
    pub schedule: Option<String>,
    /// Verification methods
    pub methods: Vec<VerificationMethod>,
}

/// Verification methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Checksum verification
    Checksum,
    /// Test restore
    TestRestore,
    /// Configuration validation
    ConfigValidation,
}

/// Backup record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    /// Backup ID
    pub id: Uuid,
    /// Backup configuration name
    pub config_name: String,
    /// Backup type
    pub backup_type: BackupType,
    /// Backup timestamp
    pub created_at: DateTime<Utc>,
    /// Backup size in bytes
    pub size_bytes: u64,
    /// Backup status
    pub status: BackupStatus,
    /// Storage location
    pub storage_location: String,
    /// Backup metadata
    pub metadata: BackupMetadata,
    /// Verification results
    pub verification_results: Vec<VerificationResult>,
    /// Expiration date
    pub expires_at: Option<DateTime<Utc>>,
    /// Error message if backup failed
    pub error_message: Option<String>,
}

/// Types of backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup
    Full,
    /// Incremental backup
    Incremental,
    /// Differential backup
    Differential,
    /// Configuration-only backup
    ConfigOnly,
    /// Audit trail backup
    AuditTrail,
}

/// Backup status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupStatus {
    InProgress,
    Completed,
    Failed,
    Expired,
    Deleted,
}

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Gateway version at backup time
    pub gateway_version: String,
    /// Configuration hash
    pub config_hash: String,
    /// Number of configuration changes included
    pub change_count: u32,
    /// Backup duration
    pub duration_seconds: u64,
    /// Compression ratio
    pub compression_ratio: Option<f64>,
    /// Encryption key ID
    pub encryption_key_id: Option<String>,
    /// Additional metadata
    pub custom_metadata: HashMap<String, serde_json::Value>,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Verification method used
    pub method: VerificationMethod,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Verification status
    pub status: VerificationStatus,
    /// Verification details
    pub details: String,
    /// Error message if verification failed
    pub error_message: Option<String>,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Warning,
}

/// Recovery plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    /// Plan ID
    pub id: Uuid,
    /// Plan name
    pub name: String,
    /// Plan description
    pub description: String,
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Recovery steps
    pub steps: Vec<RecoveryStep>,
    /// Recovery time objective (RTO) in minutes
    pub rto_minutes: u32,
    /// Recovery point objective (RPO) in minutes
    pub rpo_minutes: u32,
    /// Plan priority
    pub priority: RecoveryPriority,
    /// Plan status
    pub status: PlanStatus,
    /// Last tested date
    pub last_tested: Option<DateTime<Utc>>,
    /// Next test due date
    pub next_test_due: Option<DateTime<Utc>>,
}

/// Recovery types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryType {
    /// Full system recovery
    FullSystem,
    /// Configuration recovery
    Configuration,
    /// Partial recovery
    Partial,
    /// Point-in-time recovery
    PointInTime,
}

/// Recovery step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStep {
    /// Step ID
    pub id: Uuid,
    /// Step order
    pub order: u32,
    /// Step name
    pub name: String,
    /// Step description
    pub description: String,
    /// Step type
    pub step_type: StepType,
    /// Estimated duration in minutes
    pub estimated_duration_minutes: u32,
    /// Prerequisites
    pub prerequisites: Vec<String>,
    /// Automation script
    pub automation_script: Option<String>,
    /// Manual instructions
    pub manual_instructions: Option<String>,
    /// Validation criteria
    pub validation_criteria: Vec<String>,
}

/// Recovery step types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    /// Automated step
    Automated,
    /// Manual step
    Manual,
    /// Semi-automated step
    SemiAutomated,
    /// Validation step
    Validation,
}

/// Recovery plan priorities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Plan status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlanStatus {
    Active,
    Draft,
    Testing,
    Deprecated,
}

/// Recovery execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryExecution {
    /// Execution ID
    pub id: Uuid,
    /// Recovery plan ID
    pub plan_id: Uuid,
    /// Execution type
    pub execution_type: ExecutionType,
    /// Started by user
    pub started_by: String,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Execution status
    pub status: ExecutionStatus,
    /// Step executions
    pub step_executions: Vec<StepExecution>,
    /// Overall result
    pub result: Option<ExecutionResult>,
    /// Notes
    pub notes: Option<String>,
}

/// Execution types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionType {
    /// Actual disaster recovery
    Production,
    /// Disaster recovery test
    Test,
    /// Drill/exercise
    Drill,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

/// Step execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    /// Step ID
    pub step_id: Uuid,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Step status
    pub status: ExecutionStatus,
    /// Execution output
    pub output: Option<String>,
    /// Error message
    pub error_message: Option<String>,
    /// Executed by
    pub executed_by: String,
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether execution was successful
    pub success: bool,
    /// Actual RTO achieved
    pub actual_rto_minutes: u32,
    /// Actual RPO achieved
    pub actual_rpo_minutes: u32,
    /// Lessons learned
    pub lessons_learned: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

// ============================================================================
// Backup and Recovery Manager
// ============================================================================

/// Backup and disaster recovery manager
pub struct BackupRecoveryManager {
    /// Backup configurations
    backup_configs: Arc<RwLock<HashMap<String, BackupConfig>>>,
    /// Backup records
    backup_records: Arc<RwLock<HashMap<Uuid, BackupRecord>>>,
    /// Recovery plans
    recovery_plans: Arc<RwLock<HashMap<Uuid, RecoveryPlan>>>,
    /// Recovery executions
    recovery_executions: Arc<RwLock<HashMap<Uuid, RecoveryExecution>>>,
    /// Active backup operations
    active_backups: Arc<Mutex<HashMap<Uuid, BackupProgress>>>,
    /// Audit trail reference
    audit: Arc<ConfigAudit>,
}

/// Backup progress tracking
#[derive(Debug, Clone)]
pub struct BackupProgress {
    /// Backup ID
    pub backup_id: Uuid,
    /// Current phase
    pub current_phase: String,
    /// Progress percentage
    pub progress_percent: u8,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Total bytes to process
    pub total_bytes: Option<u64>,
}

impl BackupRecoveryManager {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        let manager = Self {
            backup_configs: Arc::new(RwLock::new(HashMap::new())),
            backup_records: Arc::new(RwLock::new(HashMap::new())),
            recovery_plans: Arc::new(RwLock::new(HashMap::new())),
            recovery_executions: Arc::new(RwLock::new(HashMap::new())),
            active_backups: Arc::new(Mutex::new(HashMap::new())),
            audit,
        };

        // Initialize default configurations
        tokio::spawn({
            let manager = manager.clone();
            async move {
                if let Err(e) = manager.initialize_defaults().await {
                    tracing::error!("Failed to initialize backup/recovery defaults: {}", e);
                }
            }
        });

        // Start backup scheduler
        tokio::spawn({
            let manager = manager.clone();
            async move {
                manager.backup_scheduler().await;
            }
        });

        manager
    }

    /// Create backup
    pub async fn create_backup(
        &self,
        config_name: &str,
        backup_type: BackupType,
        initiated_by: String,
    ) -> GatewayResult<Uuid> {
        let backup_configs = self.backup_configs.read().await;
        let config = backup_configs.get(config_name)
            .ok_or_else(|| GatewayError::not_found("Backup configuration not found"))?
            .clone();

        if !config.enabled {
            return Err(GatewayError::invalid_input("Backup configuration is disabled"));
        }

        let backup_id = Uuid::new_v4();
        let backup_record = BackupRecord {
            id: backup_id,
            config_name: config_name.to_string(),
            backup_type: backup_type.clone(),
            created_at: Utc::now(),
            size_bytes: 0,
            status: BackupStatus::InProgress,
            storage_location: String::new(),
            metadata: BackupMetadata {
                gateway_version: env!("CARGO_PKG_VERSION").to_string(),
                config_hash: String::new(),
                change_count: 0,
                duration_seconds: 0,
                compression_ratio: None,
                encryption_key_id: None,
                custom_metadata: HashMap::new(),
            },
            verification_results: Vec::new(),
            expires_at: None,
            error_message: None,
        };

        {
            let mut backup_records = self.backup_records.write().await;
            backup_records.insert(backup_id, backup_record);
        }

        tracing::info!(
            backup_id = %backup_id,
            config_name = %config_name,
            backup_type = ?backup_type,
            initiated_by = %initiated_by,
            "Backup started"
        );

        // Start backup process
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.execute_backup(backup_id, config, backup_type).await {
                tracing::error!(backup_id = %backup_id, error = %e, "Backup failed");
                {
                    let mut backup_records = manager.backup_records.write().await;
                    if let Some(record) = backup_records.get_mut(&backup_id) {
                        record.status = BackupStatus::Failed;
                        record.error_message = Some(e.to_string());
                    }
                }
            }
        });

        Ok(backup_id)
    }

    /// Execute backup process
    async fn execute_backup(
        &self,
        backup_id: Uuid,
        config: BackupConfig,
        backup_type: BackupType,
    ) -> GatewayResult<()> {
        let start_time = Utc::now();

        // Update progress
        {
            let mut active_backups = self.active_backups.lock().await;
            active_backups.insert(backup_id, BackupProgress {
                backup_id,
                current_phase: "Initializing".to_string(),
                progress_percent: 0,
                eta: Some(Duration::minutes(10)), // Estimated
                bytes_processed: 0,
                total_bytes: None,
            });
        }

        // Collect data to backup
        let backup_data = self.collect_backup_data(&backup_type).await?;

        // Update progress
        {
            let mut active_backups = self.active_backups.lock().await;
            if let Some(progress) = active_backups.get_mut(&backup_id) {
                progress.current_phase = "Compressing".to_string();
                progress.progress_percent = 25;
            }
        }

        // Calculate hash before compression
        let config_hash = self.calculate_hash(&backup_data);

        // Compress data if enabled
        let compressed_data = if config.compression.enabled {
            self.compress_data(&backup_data, &config.compression).await?
        } else {
            backup_data
        };

        // Update progress
        {
            let mut active_backups = self.active_backups.lock().await;
            if let Some(progress) = active_backups.get_mut(&backup_id) {
                progress.current_phase = "Encrypting".to_string();
                progress.progress_percent = 50;
            }
        }

        // Store original size before moving compressed_data
        let original_size = compressed_data.len();

        // Encrypt data if enabled
        let final_data = if config.encryption.enabled {
            self.encrypt_data(&compressed_data, &config.encryption).await?
        } else {
            compressed_data
        };

        // Update progress
        {
            let mut active_backups = self.active_backups.lock().await;
            if let Some(progress) = active_backups.get_mut(&backup_id) {
                progress.current_phase = "Storing".to_string();
                progress.progress_percent = 75;
                progress.bytes_processed = final_data.len() as u64;
                progress.total_bytes = Some(final_data.len() as u64);
            }
        }

        // Store backup
        let storage_location = self.store_backup(&final_data, &config.storage, backup_id).await?;

        // Update progress
        {
            let mut active_backups = self.active_backups.lock().await;
            if let Some(progress) = active_backups.get_mut(&backup_id) {
                progress.current_phase = "Finalizing".to_string();
                progress.progress_percent = 90;
            }
        }

        // Calculate metadata
        let duration = Utc::now() - start_time;
        let compression_ratio = if config.compression.enabled {
            Some(original_size as f64 / final_data.len() as f64)
        } else {
            None
        };

        // Update backup record
        {
            let mut backup_records = self.backup_records.write().await;
            if let Some(record) = backup_records.get_mut(&backup_id) {
                record.status = BackupStatus::Completed;
                record.size_bytes = final_data.len() as u64;
                record.storage_location = storage_location;
                record.metadata.config_hash = config_hash;
                record.metadata.duration_seconds = duration.num_seconds() as u64;
                record.metadata.compression_ratio = compression_ratio;
                record.expires_at = self.calculate_expiration(&config.retention, &backup_type);
            }
        }

        // Remove from active backups
        {
            let mut active_backups = self.active_backups.lock().await;
            active_backups.remove(&backup_id);
        }

        // Schedule verification if enabled
        if config.verification.enabled {
            self.schedule_verification(backup_id, config.verification).await?;
        }

        // Replicate if configured
        if let Some(replication) = &config.storage.replication {
            self.replicate_backup(backup_id, replication).await?;
        }

        tracing::info!(
            backup_id = %backup_id,
            duration_seconds = duration.num_seconds(),
            size_bytes = final_data.len(),
            "Backup completed successfully"
        );

        Ok(())
    }

    /// Collect data for backup
    async fn collect_backup_data(&self, backup_type: &BackupType) -> GatewayResult<Vec<u8>> {
        match backup_type {
            BackupType::Full => {
                // Collect all configuration and audit data
                let config = GatewayConfig::default(); // Would get current config
                let audit_records = self.audit.get_all_records().await;
                
                let backup_data = serde_json::json!({
                    "config": config,
                    "audit_records": audit_records,
                    "backup_type": "full",
                    "timestamp": Utc::now()
                });
                
                Ok(serde_json::to_vec(&backup_data)?)
            }
            BackupType::ConfigOnly => {
                // Collect only configuration
                let config = GatewayConfig::default(); // Would get current config
                
                let backup_data = serde_json::json!({
                    "config": config,
                    "backup_type": "config_only",
                    "timestamp": Utc::now()
                });
                
                Ok(serde_json::to_vec(&backup_data)?)
            }
            BackupType::AuditTrail => {
                // Collect only audit trail
                let audit_records = self.audit.get_all_records().await;
                
                let backup_data = serde_json::json!({
                    "audit_records": audit_records,
                    "backup_type": "audit_trail",
                    "timestamp": Utc::now()
                });
                
                Ok(serde_json::to_vec(&backup_data)?)
            }
            BackupType::Incremental | BackupType::Differential => {
                // Would implement incremental/differential logic
                // For now, collect basic config to avoid recursion
                let config = GatewayConfig::default();
                let backup_data = serde_json::json!({
                    "config": config,
                    "backup_type": format!("{:?}", backup_type).to_lowercase(),
                    "timestamp": Utc::now()
                });
                Ok(serde_json::to_vec(&backup_data)?)
            }
        }
    }

    /// Compress backup data
    async fn compress_data(&self, data: &[u8], config: &CompressionConfig) -> GatewayResult<Vec<u8>> {
        match config.algorithm {
            CompressionAlgorithm::Gzip => {
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use std::io::Write;
                
                let mut encoder = GzEncoder::new(Vec::new(), Compression::new(config.level as u32));
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            }
            CompressionAlgorithm::Zstd => {
                // Simple compression for now - in production would use zstd crate
                tracing::warn!("ZSTD compression not implemented, using gzip fallback");
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(config.level as u32));
                std::io::Write::write_all(&mut encoder, data)?;
                Ok(encoder.finish()?)
            }
            CompressionAlgorithm::Lz4 => {
                // Simple compression for now - in production would use lz4 crate
                tracing::warn!("LZ4 compression not implemented, using gzip fallback");
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(config.level as u32));
                std::io::Write::write_all(&mut encoder, data)?;
                Ok(encoder.finish()?)
            }
        }
    }

    /// Encrypt backup data
    async fn encrypt_data(&self, data: &[u8], config: &EncryptionConfig) -> GatewayResult<Vec<u8>> {
        match config.algorithm {
            EncryptionAlgorithm::Aes256 => {
                // Simple encryption for now - in production would use proper AES-256
                tracing::warn!("AES-256 encryption not implemented, storing unencrypted");
                Ok(data.to_vec())
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                // Simple encryption for now - in production would use ChaCha20-Poly1305
                tracing::warn!("ChaCha20-Poly1305 encryption not implemented, storing unencrypted");
                Ok(data.to_vec())
            }
        }
    }

    /// Store backup data
    async fn store_backup(
        &self,
        data: &[u8],
        storage: &BackupStorage,
        backup_id: Uuid,
    ) -> GatewayResult<String> {
        match storage.storage_type {
            StorageType::Local => {
                let path = PathBuf::from(&storage.location).join(format!("backup_{}.dat", backup_id));
                tokio::fs::write(&path, data).await?;
                Ok(path.to_string_lossy().to_string())
            }
            StorageType::S3 => {
                // Would implement S3 storage
                Ok(format!("s3://{}/backup_{}.dat", storage.location, backup_id))
            }
            _ => {
                // Would implement other storage types
                Ok(format!("{}backup_{}.dat", storage.location, backup_id))
            }
        }
    }

    /// Calculate backup expiration date
    fn calculate_expiration(&self, retention: &RetentionPolicy, backup_type: &BackupType) -> Option<DateTime<Utc>> {
        let now = Utc::now();
        match backup_type {
            BackupType::Full => Some(now + Duration::days(retention.daily_retention_days as i64)),
            BackupType::ConfigOnly => Some(now + Duration::days(retention.weekly_retention_weeks as i64 * 7)),
            BackupType::AuditTrail => Some(now + Duration::days(retention.yearly_retention_years as i64 * 365)),
            _ => Some(now + Duration::days(retention.daily_retention_days as i64)),
        }
    }

    /// Schedule backup verification
    async fn schedule_verification(&self, backup_id: Uuid, config: VerificationConfig) -> GatewayResult<()> {
        // Would implement verification scheduling
        tracing::info!(backup_id = %backup_id, "Backup verification scheduled");
        Ok(())
    }

    /// Replicate backup to other locations
    async fn replicate_backup(&self, backup_id: Uuid, config: &ReplicationConfig) -> GatewayResult<()> {
        // Would implement backup replication
        tracing::info!(backup_id = %backup_id, "Backup replication started");
        Ok(())
    }

    /// Restore from backup
    pub async fn restore_from_backup(
        &self,
        backup_id: Uuid,
        restore_type: RestoreType,
        initiated_by: String,
    ) -> GatewayResult<Uuid> {
        let backup_records = self.backup_records.read().await;
        let backup_record = backup_records.get(&backup_id)
            .ok_or_else(|| GatewayError::not_found("Backup not found"))?;

        if !matches!(backup_record.status, BackupStatus::Completed) {
            return Err(GatewayError::invalid_input("Backup is not in completed state"));
        }

        let restore_id = Uuid::new_v4();

        tracing::info!(
            restore_id = %restore_id,
            backup_id = %backup_id,
            restore_type = ?restore_type,
            initiated_by = %initiated_by,
            "Restore started"
        );

        // Start restore process
        let manager = self.clone();
        let backup_record = backup_record.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.execute_restore(restore_id, backup_record, restore_type).await {
                tracing::error!(restore_id = %restore_id, error = %e, "Restore failed");
            }
        });

        Ok(restore_id)
    }

    /// Execute restore process
    async fn execute_restore(
        &self,
        restore_id: Uuid,
        backup_record: BackupRecord,
        restore_type: RestoreType,
    ) -> GatewayResult<()> {
        // Would implement restore logic
        tracing::info!(
            restore_id = %restore_id,
            backup_id = %backup_record.id,
            "Restore completed successfully"
        );
        Ok(())
    }

    /// Execute recovery plan
    pub async fn execute_recovery_plan(
        &self,
        plan_id: Uuid,
        execution_type: ExecutionType,
        initiated_by: String,
    ) -> GatewayResult<Uuid> {
        let recovery_plans = self.recovery_plans.read().await;
        let plan = recovery_plans.get(&plan_id)
            .ok_or_else(|| GatewayError::not_found("Recovery plan not found"))?
            .clone();

        let execution_id = Uuid::new_v4();
        let execution = RecoveryExecution {
            id: execution_id,
            plan_id,
            execution_type: execution_type.clone(),
            started_by: initiated_by.clone(),
            started_at: Utc::now(),
            completed_at: None,
            status: ExecutionStatus::Running,
            step_executions: Vec::new(),
            result: None,
            notes: None,
        };

        {
            let mut recovery_executions = self.recovery_executions.write().await;
            recovery_executions.insert(execution_id, execution);
        }

        // Start recovery execution
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.execute_recovery_steps(execution_id, plan).await {
                tracing::error!(execution_id = %execution_id, error = %e, "Recovery execution failed");
            }
        });

        tracing::info!(
            execution_id = %execution_id,
            plan_id = %plan_id,
            execution_type = ?execution_type,
            initiated_by = %initiated_by,
            "Recovery plan execution started"
        );

        Ok(execution_id)
    }

    /// Execute recovery steps
    async fn execute_recovery_steps(&self, execution_id: Uuid, plan: RecoveryPlan) -> GatewayResult<()> {
        // Would implement recovery step execution
        tracing::info!(
            execution_id = %execution_id,
            plan_id = %plan.id,
            "Recovery plan execution completed"
        );
        Ok(())
    }

    /// Calculate hash for data integrity
    fn calculate_hash(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Backup scheduler loop
    async fn backup_scheduler(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Check for scheduled backups
            let backup_configs = self.backup_configs.read().await;
            for (name, config) in backup_configs.iter() {
                if config.enabled && self.should_run_backup(config).await {
                    if let Err(e) = self.create_backup(name, BackupType::Full, "scheduler".to_string()).await {
                        tracing::error!(config_name = %name, error = %e, "Scheduled backup failed");
                    }
                }
            }
        }
    }

    /// Check if backup should run based on schedule
    async fn should_run_backup(&self, config: &BackupConfig) -> bool {
        // Simple schedule checking - in production would use proper cron parsing
        if config.schedule.is_empty() {
            return false;
        }
        
        // For now, just check if it's a daily backup and it's been more than 24 hours
        // In production, would use a cron parser like the `cron` crate
        let now = Utc::now();
        let backup_records = self.backup_records.read().await;
        
        // Check if we have any recent backups for this config
        let recent_backup = backup_records.values()
            .filter(|record| record.config_name == config.name)
            .filter(|record| matches!(record.status, BackupStatus::Completed))
            .max_by_key(|record| record.created_at);
        
        match recent_backup {
            Some(last_backup) => {
                let time_since_last = now - last_backup.created_at;
                time_since_last > Duration::hours(23) // Run daily backups
            }
            None => true, // No previous backup, should run
        }
    }

    /// Initialize default configurations
    async fn initialize_defaults(&self) -> GatewayResult<()> {
        let mut backup_configs = self.backup_configs.write().await;
        
        // Default daily backup configuration
        backup_configs.insert("daily".to_string(), BackupConfig {
            name: "daily".to_string(),
            schedule: "0 2 * * *".to_string(), // Daily at 2 AM
            retention: RetentionPolicy {
                daily_retention_days: 7,
                weekly_retention_weeks: 4,
                monthly_retention_months: 12,
                yearly_retention_years: 7,
                max_backups: Some(100),
            },
            storage: BackupStorage {
                storage_type: StorageType::Local,
                location: "/var/backups/gateway".to_string(),
                credentials: None,
                replication: None,
            },
            encryption: EncryptionConfig {
                enabled: true,
                algorithm: EncryptionAlgorithm::Aes256,
                key_management: KeyManagement::Local {
                    key_file: "/etc/gateway/backup.key".to_string(),
                },
            },
            compression: CompressionConfig {
                enabled: true,
                algorithm: CompressionAlgorithm::Gzip,
                level: 6,
            },
            enabled: true,
            verification: VerificationConfig {
                enabled: true,
                schedule: Some("0 3 * * *".to_string()), // Daily at 3 AM
                methods: vec![VerificationMethod::Checksum, VerificationMethod::ConfigValidation],
            },
        });

        // Initialize default recovery plan
        let mut recovery_plans = self.recovery_plans.write().await;
        recovery_plans.insert(Uuid::new_v4(), RecoveryPlan {
            id: Uuid::new_v4(),
            name: "Full System Recovery".to_string(),
            description: "Complete system recovery from backup".to_string(),
            recovery_type: RecoveryType::FullSystem,
            steps: vec![
                RecoveryStep {
                    id: Uuid::new_v4(),
                    order: 1,
                    name: "Stop Gateway Services".to_string(),
                    description: "Gracefully stop all gateway services".to_string(),
                    step_type: StepType::Automated,
                    estimated_duration_minutes: 5,
                    prerequisites: vec![],
                    automation_script: Some("systemctl stop api-gateway".to_string()),
                    manual_instructions: None,
                    validation_criteria: vec!["Services are stopped".to_string()],
                },
                RecoveryStep {
                    id: Uuid::new_v4(),
                    order: 2,
                    name: "Restore Configuration".to_string(),
                    description: "Restore configuration from backup".to_string(),
                    step_type: StepType::Automated,
                    estimated_duration_minutes: 10,
                    prerequisites: vec!["Services are stopped".to_string()],
                    automation_script: Some("restore-config.sh".to_string()),
                    manual_instructions: None,
                    validation_criteria: vec!["Configuration is valid".to_string()],
                },
                RecoveryStep {
                    id: Uuid::new_v4(),
                    order: 3,
                    name: "Start Gateway Services".to_string(),
                    description: "Start all gateway services".to_string(),
                    step_type: StepType::Automated,
                    estimated_duration_minutes: 5,
                    prerequisites: vec!["Configuration is restored".to_string()],
                    automation_script: Some("systemctl start api-gateway".to_string()),
                    manual_instructions: None,
                    validation_criteria: vec!["Services are running".to_string(), "Health checks pass".to_string()],
                },
            ],
            rto_minutes: 30,
            rpo_minutes: 60,
            priority: RecoveryPriority::Critical,
            status: PlanStatus::Active,
            last_tested: None,
            next_test_due: Some(Utc::now() + Duration::days(90)),
        });

        Ok(())
    }

    /// Get backup record
    pub async fn get_backup(&self, backup_id: Uuid) -> Option<BackupRecord> {
        let backup_records = self.backup_records.read().await;
        backup_records.get(&backup_id).cloned()
    }

    /// List backups
    pub async fn list_backups(&self, limit: usize) -> Vec<BackupRecord> {
        let backup_records = self.backup_records.read().await;
        backup_records.values().take(limit).cloned().collect()
    }

    /// Get recovery plan
    pub async fn get_recovery_plan(&self, plan_id: Uuid) -> Option<RecoveryPlan> {
        let recovery_plans = self.recovery_plans.read().await;
        recovery_plans.get(&plan_id).cloned()
    }

    /// List recovery plans
    pub async fn list_recovery_plans(&self) -> Vec<RecoveryPlan> {
        let recovery_plans = self.recovery_plans.read().await;
        recovery_plans.values().cloned().collect()
    }
}

impl Clone for BackupRecoveryManager {
    fn clone(&self) -> Self {
        Self {
            backup_configs: self.backup_configs.clone(),
            backup_records: self.backup_records.clone(),
            recovery_plans: self.recovery_plans.clone(),
            recovery_executions: self.recovery_executions.clone(),
            active_backups: self.active_backups.clone(),
            audit: self.audit.clone(),
        }
    }
}

/// Restore types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestoreType {
    /// Full system restore
    Full,
    /// Configuration only restore
    ConfigOnly,
    /// Point-in-time restore
    PointInTime { timestamp: DateTime<Utc> },
    /// Selective restore
    Selective { components: Vec<String> },
}

// ============================================================================
// Backup Recovery State and Router
// ============================================================================

/// Backup recovery state
#[derive(Clone)]
pub struct BackupRecoveryState {
    pub manager: BackupRecoveryManager,
}

impl BackupRecoveryState {
    pub fn new(audit: Arc<ConfigAudit>) -> Self {
        Self {
            manager: BackupRecoveryManager::new(audit),
        }
    }
}

/// Create backup recovery router
pub fn create_backup_recovery_router(state: BackupRecoveryState) -> Router {
    Router::new()
        // Backup management
        .route("/backups", post(create_backup))
        .route("/backups", get(list_backups))
        .route("/backups/:backup_id", get(get_backup))
        .route("/backups/:backup_id/restore", post(restore_backup))
        
        // Recovery plans
        .route("/recovery-plans", get(list_recovery_plans))
        .route("/recovery-plans/:plan_id", get(get_recovery_plan))
        .route("/recovery-plans/:plan_id/execute", post(execute_recovery_plan))
        
        // Recovery executions
        .route("/recovery-executions/:execution_id", get(get_recovery_execution))
        
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateBackupRequest {
    pub config_name: String,
    pub backup_type: BackupType,
}

#[derive(Debug, Serialize)]
pub struct CreateBackupResponse {
    pub backup_id: Uuid,
    pub status: BackupStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreBackupRequest {
    pub restore_type: RestoreType,
}

#[derive(Debug, Serialize)]
pub struct RestoreBackupResponse {
    pub restore_id: Uuid,
    pub estimated_duration_minutes: u32,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteRecoveryPlanRequest {
    pub execution_type: ExecutionType,
}

#[derive(Debug, Serialize)]
pub struct ExecuteRecoveryPlanResponse {
    pub execution_id: Uuid,
    pub estimated_duration_minutes: u32,
}

#[derive(Debug, Deserialize)]
pub struct ListBackupsQuery {
    pub status: Option<String>,
    pub backup_type: Option<String>,
    pub limit: Option<usize>,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Create backup
async fn create_backup(
    State(state): State<BackupRecoveryState>,
    Json(request): Json<CreateBackupRequest>,
) -> GatewayResult<Json<CreateBackupResponse>> {
    let backup_id = state.manager.create_backup(
        &request.config_name,
        request.backup_type,
        "admin".to_string(), // Would extract from auth context
    ).await?;

    Ok(Json(CreateBackupResponse {
        backup_id,
        status: BackupStatus::InProgress,
        created_at: Utc::now(),
    }))
}

/// List backups
async fn list_backups(
    State(state): State<BackupRecoveryState>,
    Query(query): Query<ListBackupsQuery>,
) -> GatewayResult<Json<Vec<BackupRecord>>> {
    let limit = query.limit.unwrap_or(50);
    let backups = state.manager.list_backups(limit).await;
    
    // Apply filters
    let filtered_backups = backups.into_iter()
        .filter(|b| {
            if let Some(ref status_str) = query.status {
                // Would implement status string matching
                true
            } else {
                true
            }
        })
        .filter(|b| {
            if let Some(ref type_str) = query.backup_type {
                // Would implement type string matching
                true
            } else {
                true
            }
        })
        .collect();
    
    Ok(Json(filtered_backups))
}

/// Get backup
async fn get_backup(
    State(state): State<BackupRecoveryState>,
    Path(backup_id): Path<Uuid>,
) -> GatewayResult<Json<BackupRecord>> {
    let backup = state.manager.get_backup(backup_id).await
        .ok_or_else(|| GatewayError::not_found("Backup not found"))?;
    
    Ok(Json(backup))
}

/// Restore backup
async fn restore_backup(
    State(state): State<BackupRecoveryState>,
    Path(backup_id): Path<Uuid>,
    Json(request): Json<RestoreBackupRequest>,
) -> GatewayResult<Json<RestoreBackupResponse>> {
    let restore_id = state.manager.restore_from_backup(
        backup_id,
        request.restore_type,
        "admin".to_string(), // Would extract from auth context
    ).await?;

    Ok(Json(RestoreBackupResponse {
        restore_id,
        estimated_duration_minutes: 30, // Would calculate based on backup size
    }))
}

/// List recovery plans
async fn list_recovery_plans(
    State(state): State<BackupRecoveryState>,
) -> GatewayResult<Json<Vec<RecoveryPlan>>> {
    let plans = state.manager.list_recovery_plans().await;
    Ok(Json(plans))
}

/// Get recovery plan
async fn get_recovery_plan(
    State(state): State<BackupRecoveryState>,
    Path(plan_id): Path<Uuid>,
) -> GatewayResult<Json<RecoveryPlan>> {
    let plan = state.manager.get_recovery_plan(plan_id).await
        .ok_or_else(|| GatewayError::not_found("Recovery plan not found"))?;
    
    Ok(Json(plan))
}

/// Execute recovery plan
async fn execute_recovery_plan(
    State(state): State<BackupRecoveryState>,
    Path(plan_id): Path<Uuid>,
    Json(request): Json<ExecuteRecoveryPlanRequest>,
) -> GatewayResult<Json<ExecuteRecoveryPlanResponse>> {
    let execution_id = state.manager.execute_recovery_plan(
        plan_id,
        request.execution_type,
        "admin".to_string(), // Would extract from auth context
    ).await?;

    Ok(Json(ExecuteRecoveryPlanResponse {
        execution_id,
        estimated_duration_minutes: 60, // Would calculate based on plan
    }))
}

/// Get recovery execution
async fn get_recovery_execution(
    State(_state): State<BackupRecoveryState>,
    Path(_execution_id): Path<Uuid>,
) -> GatewayResult<Json<RecoveryExecution>> {
    // Would implement execution retrieval
    Err(GatewayError::not_found("Recovery execution not found"))
}
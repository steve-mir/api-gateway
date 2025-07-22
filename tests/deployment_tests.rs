//! # Deployment Management Tests
//!
//! This module contains comprehensive tests for the deployment management functionality
//! including service version management, blue-green deployments, feature flags,
//! service mesh integration, and multi-tenant configuration.

use api_gateway::admin::deployment::{
    DeploymentState, ServiceVersionManager, BlueGreenDeploymentManager,
    FeatureFlagManager, ServiceMeshIntegration, TenantConfigManager,
    ServiceVersion, BlueGreenDeployment, FeatureFlag, ServiceMeshConfig,
    Tenant, EvaluationContext, VersionStatus, DeploymentStatus, ServiceMeshType, TenantConfig
};
use api_gateway::core::types::{ServiceInstance, Protocol};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_service_version_manager() {
    let version_manager = ServiceVersionManager::new();
    
    // Create a test service version
    let service_version = ServiceVersion {
        id: "v1.0.0".to_string(),
        service_name: "test-service".to_string(),
        version: "1.0.0".to_string(),
        instances: vec![
            ServiceInstance::new(
                "instance-1".to_string(),
                "test-service".to_string(),
                "127.0.0.1:8080".parse().unwrap(),
                Protocol::Http,
            )
        ],
        traffic_weight: 100,
        status: VersionStatus::Active,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: HashMap::new(),
    };

    // Test version creation
    version_manager.create_version(service_version.clone()).await.unwrap();
    
    // Test version retrieval
    let retrieved_version = version_manager.get_version("v1.0.0").await;
    assert!(retrieved_version.is_some());
    assert_eq!(retrieved_version.unwrap().service_name, "test-service");
    
    // Test listing versions for a service
    let versions = version_manager.list_service_versions("test-service").await;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version, "1.0.0");
}

#[tokio::test]
async fn test_blue_green_deployment_manager() {
    let deployment_manager = BlueGreenDeploymentManager::new();
    
    // Create a test blue-green deployment
    let deployment = BlueGreenDeployment {
        id: "deployment-1".to_string(),
        service_name: "test-service".to_string(),
        blue_version: "1.0.0".to_string(),
        green_version: "1.1.0".to_string(),
        blue_instances: vec![
            ServiceInstance::new(
                "blue-1".to_string(),
                "test-service".to_string(),
                "127.0.0.1:8080".parse().unwrap(),
                Protocol::Http,
            )
        ],
        green_instances: vec![
            ServiceInstance::new(
                "green-1".to_string(),
                "test-service".to_string(),
                "127.0.0.1:8081".parse().unwrap(),
                Protocol::Http,
            )
        ],
        blue_traffic_percentage: 100,
        green_traffic_percentage: 0,
        status: DeploymentStatus::Created,
        created_at: Utc::now(),
        metadata: HashMap::new(),
    };

    // Test deployment creation
    deployment_manager.create_deployment(deployment.clone()).await.unwrap();
    
    // Test deployment retrieval
    let retrieved_deployment = deployment_manager.get_deployment("deployment-1").await;
    assert!(retrieved_deployment.is_some());
    assert_eq!(retrieved_deployment.unwrap().service_name, "test-service");
    
    // Test listing deployments
    let deployments = deployment_manager.list_deployments().await;
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0].blue_version, "1.0.0");
}

#[tokio::test]
async fn test_feature_flag_manager() {
    let flag_manager = FeatureFlagManager::new();
    
    // Create a test feature flag
    let feature_flag = FeatureFlag {
        id: "flag-1".to_string(),
        name: "Test Flag".to_string(),
        description: "A test feature flag".to_string(),
        enabled: true,
        default_enabled: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: HashMap::new(),
    };

    // Test flag creation
    flag_manager.create_flag(feature_flag.clone()).await.unwrap();
    
    // Test flag retrieval
    let retrieved_flag = flag_manager.get_flag("flag-1").await;
    assert!(retrieved_flag.is_some());
    assert_eq!(retrieved_flag.unwrap().name, "Test Flag");
    
    // Test flag toggling
    let enabled = flag_manager.toggle_flag("flag-1").await.unwrap();
    assert!(!enabled); // Should be disabled after toggle
    
    // Test listing flags
    let flags = flag_manager.list_flags().await;
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].name, "Test Flag");
}

#[tokio::test]
async fn test_service_mesh_integration() {
    let service_mesh = ServiceMeshIntegration::new();
    
    // Test getting default configuration
    let config = service_mesh.get_config().await;
    assert!(!config.enabled);
    assert!(config.mtls_enabled);
    
    // Test updating configuration
    let new_config = ServiceMeshConfig {
        enabled: true,
        mesh_type: ServiceMeshType::Istio,
        mtls_enabled: false,
    };
    
    service_mesh.update_config(new_config.clone()).await;
    
    let updated_config = service_mesh.get_config().await;
    assert!(updated_config.enabled);
    assert!(!updated_config.mtls_enabled);
}

#[tokio::test]
async fn test_tenant_config_manager() {
    let tenant_manager = TenantConfigManager::new();
    
    // Create a test tenant
    let tenant = Tenant {
        id: "tenant-1".to_string(),
        name: "Test Tenant".to_string(),
        description: "A test tenant".to_string(),
        config: TenantConfig {
            rate_limits: HashMap::new(),
            allowed_protocols: vec![Protocol::Http, Protocol::Grpc],
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: HashMap::new(),
    };

    // Test tenant creation
    tenant_manager.create_tenant(tenant.clone()).await.unwrap();
    
    // Test tenant retrieval
    let retrieved_tenant = tenant_manager.get_tenant("tenant-1").await;
    assert!(retrieved_tenant.is_some());
    assert_eq!(retrieved_tenant.unwrap().name, "Test Tenant");
    
    // Test listing tenants
    let tenants = tenant_manager.list_tenants().await;
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0].name, "Test Tenant");
}

#[tokio::test]
async fn test_deployment_state_creation() {
    // Test creating the deployment state with all managers
    let deployment_state = DeploymentState {
        version_manager: Arc::new(ServiceVersionManager::new()),
        deployment_manager: Arc::new(BlueGreenDeploymentManager::new()),
        feature_flags: Arc::new(FeatureFlagManager::new()),
        service_mesh: Arc::new(ServiceMeshIntegration::new()),
        tenant_manager: Arc::new(TenantConfigManager::new()),
    };

    // Verify all managers are properly initialized
    assert!(deployment_state.version_manager.list_service_versions("test").await.is_empty());
    assert!(deployment_state.deployment_manager.list_deployments().await.is_empty());
    assert!(deployment_state.feature_flags.list_flags().await.is_empty());
    assert!(!deployment_state.service_mesh.get_config().await.enabled);
    assert!(deployment_state.tenant_manager.list_tenants().await.is_empty());
}

#[tokio::test]
async fn test_feature_flag_evaluation_context() {
    // Test creating evaluation context
    let mut context = EvaluationContext {
        user_id: Some("user-123".to_string()),
        tenant_id: Some("tenant-1".to_string()),
        user_role: Some("admin".to_string()),
        custom_attributes: HashMap::new(),
    };
    
    context.custom_attributes.insert("region".to_string(), "us-west-2".to_string());
    context.custom_attributes.insert("environment".to_string(), "production".to_string());
    
    // Verify context properties
    assert_eq!(context.user_id, Some("user-123".to_string()));
    assert_eq!(context.tenant_id, Some("tenant-1".to_string()));
    assert_eq!(context.user_role, Some("admin".to_string()));
    assert_eq!(context.custom_attributes.get("region"), Some(&"us-west-2".to_string()));
    assert_eq!(context.custom_attributes.get("environment"), Some(&"production".to_string()));
}

#[tokio::test]
async fn test_service_version_status_transitions() {
    let version_manager = ServiceVersionManager::new();
    
    // Create a service version in Inactive status
    let mut service_version = ServiceVersion {
        id: "v1.0.0".to_string(),
        service_name: "test-service".to_string(),
        version: "1.0.0".to_string(),
        instances: vec![],
        traffic_weight: 0,
        status: VersionStatus::Inactive,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: HashMap::new(),
    };

    version_manager.create_version(service_version.clone()).await.unwrap();
    
    // Test different status values
    service_version.status = VersionStatus::Deploying;
    version_manager.create_version(service_version.clone()).await.unwrap();
    
    service_version.status = VersionStatus::Active;
    version_manager.create_version(service_version.clone()).await.unwrap();
    
    service_version.status = VersionStatus::Failed;
    version_manager.create_version(service_version.clone()).await.unwrap();
    
    service_version.status = VersionStatus::Deprecated;
    version_manager.create_version(service_version.clone()).await.unwrap();
    
    // All status transitions should work without errors
    let retrieved = version_manager.get_version("v1.0.0").await;
    assert!(retrieved.is_some());
}

#[tokio::test]
async fn test_deployment_status_transitions() {
    let deployment_manager = BlueGreenDeploymentManager::new();
    
    // Test different deployment statuses
    let statuses = vec![
        DeploymentStatus::Created,
        DeploymentStatus::InProgress,
        DeploymentStatus::Completed,
        DeploymentStatus::Failed,
        DeploymentStatus::RolledBack,
        DeploymentStatus::Aborted,
    ];
    
    for (i, status) in statuses.into_iter().enumerate() {
        let deployment = BlueGreenDeployment {
            id: format!("deployment-{}", i),
            service_name: "test-service".to_string(),
            blue_version: "1.0.0".to_string(),
            green_version: "1.1.0".to_string(),
            blue_instances: vec![],
            green_instances: vec![],
            blue_traffic_percentage: 100,
            green_traffic_percentage: 0,
            status,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        
        deployment_manager.create_deployment(deployment).await.unwrap();
    }
    
    // All deployments should be created successfully
    let deployments = deployment_manager.list_deployments().await;
    assert_eq!(deployments.len(), 6);
}
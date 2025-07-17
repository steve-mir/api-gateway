//! # Service Discovery Module
//!
//! This module provides service discovery integrations for multiple platforms including
//! Kubernetes, Consul, and NATS. It implements a unified interface for service registration,
//! discovery, and health monitoring with real-time change notifications.
//!
//! ## Rust Concepts Used
//!
//! - `Arc<T>` for shared ownership of service instances across threads
//! - `DashMap` for thread-safe concurrent access to service registry
//! - `tokio::sync::broadcast` for event notification system
//! - `async_trait` for async methods in traits
//! - `Clone` trait for efficient copying of service data

use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{HealthStatus, Protocol, ServiceInstance};

/// Service discovery trait that all discovery implementations must implement
///
/// This trait provides a unified interface for different service discovery backends.
/// Implementations can be for Kubernetes, Consul, NATS, or any other service registry.
#[async_trait]
pub trait ServiceDiscovery: Send + Sync {
    /// Discover all available services
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>>;
    
    /// Register a service instance
    async fn register_service(&self, service: ServiceInstance) -> GatewayResult<()>;
    
    /// Deregister a service instance
    async fn deregister_service(&self, service_id: &str) -> GatewayResult<()>;
    
    /// Watch for service changes (returns a stream of change events)
    async fn watch_changes(&self) -> GatewayResult<ServiceChangeReceiver>;
    
    /// Get health status of a specific service instance
    async fn get_service_health(&self, service_id: &str) -> GatewayResult<HealthStatus>;
    
    /// Update health status of a service instance
    async fn update_service_health(&self, service_id: &str, status: HealthStatus) -> GatewayResult<()>;
}

/// Service change event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceChangeEvent {
    /// A new service instance was registered
    ServiceRegistered(ServiceInstance),
    /// A service instance was deregistered
    ServiceDeregistered(String), // service_id
    /// A service instance health status changed
    HealthChanged {
        service_id: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
    },
    /// Service metadata was updated
    MetadataUpdated {
        service_id: String,
        metadata: HashMap<String, String>,
    },
}

/// Type alias for service change event receiver
pub type ServiceChangeReceiver = broadcast::Receiver<ServiceChangeEvent>;

/// Type alias for service change event sender
pub type ServiceChangeSender = broadcast::Sender<ServiceChangeEvent>;

/// Configuration for service discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// Type of service discovery to use
    pub discovery_type: DiscoveryType,
    /// Kubernetes-specific configuration
    pub kubernetes: Option<KubernetesConfig>,
    /// Consul-specific configuration
    pub consul: Option<ConsulConfig>,
    /// NATS-specific configuration
    pub nats: Option<NatsConfig>,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Service registration TTL
    pub registration_ttl: Duration,
}

/// Supported service discovery types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryType {
    Kubernetes,
    Consul,
    Nats,
    Static, // For testing and simple deployments
}

/// Kubernetes service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Namespace to watch for services
    pub namespace: Option<String>,
    /// Service label selector
    pub label_selector: Option<String>,
    /// Kubeconfig path (if not using in-cluster config)
    pub kubeconfig_path: Option<String>,
}

/// Consul service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul server address
    pub address: String,
    /// Consul datacenter
    pub datacenter: Option<String>,
    /// Authentication token
    pub token: Option<String>,
    /// Service tags to filter by
    pub tags: Vec<String>,
}

/// NATS service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URLs
    pub servers: Vec<String>,
    /// Subject prefix for service discovery
    pub subject_prefix: String,
    /// Authentication credentials
    pub credentials: Option<String>,
}

/// Kubernetes service discovery implementation
pub struct KubernetesDiscovery {
    client: kube::Client,
    namespace: Option<String>,
    label_selector: Option<String>,
    change_sender: ServiceChangeSender,
}

impl KubernetesDiscovery {
    /// Create a new Kubernetes service discovery instance
    pub async fn new(config: KubernetesConfig) -> GatewayResult<Self> {
        let client = if let Some(kubeconfig_path) = &config.kubeconfig_path {
            let kubeconfig = kube::config::Kubeconfig::read_from(kubeconfig_path)
                .map_err(|e| GatewayError::config(format!("Failed to read kubeconfig: {}", e)))?;
            let config = kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default())
                .await
                .map_err(|e| GatewayError::config(format!("Failed to create kube config: {}", e)))?;
            kube::Client::try_from(config)
                .map_err(|e| GatewayError::config(format!("Failed to create kube client: {}", e)))?
        } else {
            kube::Client::try_default()
                .await
                .map_err(|e| GatewayError::config(format!("Failed to create default kube client: {}", e)))?
        };

        let (change_sender, _) = broadcast::channel(1000);

        Ok(Self {
            client,
            namespace: config.namespace,
            label_selector: config.label_selector,
            change_sender,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for KubernetesDiscovery {
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>> {
        use k8s_openapi::api::core::v1::Service;
        use kube::api::{Api, ListParams};

        let services: Api<Service> = if let Some(namespace) = &self.namespace {
            Api::namespaced(self.client.clone(), namespace)
        } else {
            Api::all(self.client.clone())
        };

        let mut list_params = ListParams::default();
        if let Some(selector) = &self.label_selector {
            list_params = list_params.labels(selector);
        }

        let service_list = services
            .list(&list_params)
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to list services: {}", e)))?;

        let mut instances = Vec::new();

        for service in service_list.items {
            if let Some(spec) = service.spec {
                if let Some(ports) = spec.ports {
                    for port in ports {
                        let port_number = port.port;
                        // Use cluster IP if available, otherwise use service name
                        let address = if let Some(cluster_ip) = &spec.cluster_ip {
                            format!("{}:{}", cluster_ip, port_number)
                        } else if let Some(name) = &service.metadata.name {
                            format!("{}:{}", name, port_number)
                        } else {
                            continue;
                        };

                        let socket_addr: SocketAddr = address
                            .parse()
                            .map_err(|e| GatewayError::service_discovery(format!("Invalid address {}: {}", address, e)))?;

                        let protocol = match port.name.as_deref() {
                            Some("grpc") | Some("grpc-web") => Protocol::Grpc,
                            Some("ws") | Some("websocket") => Protocol::WebSocket,
                            _ => Protocol::Http,
                        };

                        let mut metadata = HashMap::new();
                        if let Some(labels) = &service.metadata.labels {
                            for (k, v) in labels {
                                metadata.insert(k.clone(), v.clone());
                            }
                        }

                        let instance = ServiceInstance {
                            id: format!("{}:{}", service.metadata.name.as_deref().unwrap_or("unknown"), port_number),
                            name: service.metadata.name.clone().unwrap_or_else(|| "unknown".to_string()),
                            address: socket_addr,
                            metadata,
                            health_status: HealthStatus::Unknown,
                            protocol,
                            weight: 1,
                            last_health_check: None,
                        };

                        instances.push(instance);
                    }
                }
            }
        }

        debug!("Discovered {} service instances from Kubernetes", instances.len());
        Ok(instances)
    }

    async fn register_service(&self, _service: ServiceInstance) -> GatewayResult<()> {
        // Kubernetes services are typically managed by deployments/pods
        // This would be used for self-registration scenarios
        warn!("Service registration not implemented for Kubernetes discovery");
        Ok(())
    }

    async fn deregister_service(&self, _service_id: &str) -> GatewayResult<()> {
        warn!("Service deregistration not implemented for Kubernetes discovery");
        Ok(())
    }

    async fn watch_changes(&self) -> GatewayResult<ServiceChangeReceiver> {
        Ok(self.change_sender.subscribe())
    }

    async fn get_service_health(&self, _service_id: &str) -> GatewayResult<HealthStatus> {
        // Health status would be determined by Kubernetes readiness probes
        Ok(HealthStatus::Unknown)
    }

    async fn update_service_health(&self, _service_id: &str, _status: HealthStatus) -> GatewayResult<()> {
        // Health status updates would be handled by Kubernetes
        Ok(())
    }
}

/// Consul service discovery implementation
pub struct ConsulDiscovery {
    client: consul::Client,
    datacenter: Option<String>,
    tags: Vec<String>,
    change_sender: ServiceChangeSender,
}

impl ConsulDiscovery {
    /// Create a new Consul service discovery instance
    pub fn new(config: ConsulConfig) -> GatewayResult<Self> {
        let client_config = consul::Config::new()
            .map_err(|e| GatewayError::config(format!("Failed to create Consul config: {}", e)))?;
        
        let client = consul::Client::new(client_config);

        let (change_sender, _) = broadcast::channel(1000);

        Ok(Self {
            client,
            datacenter: config.datacenter,
            tags: config.tags,
            change_sender,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for ConsulDiscovery {
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>> {
        // For now, return empty list as Consul API has changed significantly
        // This would need to be implemented based on the actual consul crate version
        warn!("Consul service discovery not fully implemented - returning empty list");
        Ok(Vec::new())
    }

    async fn register_service(&self, _service: ServiceInstance) -> GatewayResult<()> {
        // Consul API has changed significantly, placeholder implementation
        warn!("Consul service registration not fully implemented");
        Ok(())
    }

    async fn deregister_service(&self, _service_id: &str) -> GatewayResult<()> {
        // Consul API has changed significantly, placeholder implementation
        warn!("Consul service deregistration not fully implemented");
        Ok(())
    }

    async fn watch_changes(&self) -> GatewayResult<ServiceChangeReceiver> {
        Ok(self.change_sender.subscribe())
    }

    async fn get_service_health(&self, _service_id: &str) -> GatewayResult<HealthStatus> {
        // Consul API has changed significantly, placeholder implementation
        Ok(HealthStatus::Unknown)
    }

    async fn update_service_health(&self, _service_id: &str, _status: HealthStatus) -> GatewayResult<()> {
        // Consul API has changed significantly, placeholder implementation
        Ok(())
    }
}

/// NATS-based service discovery implementation
pub struct NatsDiscovery {
    connection: async_nats::Client,
    subject_prefix: String,
    change_sender: ServiceChangeSender,
}

impl NatsDiscovery {
    /// Create a new NATS service discovery instance
    pub async fn new(config: NatsConfig) -> GatewayResult<Self> {
        let connection = if config.servers.is_empty() {
            async_nats::connect("nats://localhost:4222").await
        } else {
            async_nats::connect(config.servers.join(",")).await
        }
        .map_err(|e| GatewayError::config(format!("Failed to connect to NATS: {}", e)))?;

        let (change_sender, _) = broadcast::channel(1000);

        Ok(Self {
            connection,
            subject_prefix: config.subject_prefix,
            change_sender,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for NatsDiscovery {
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>> {
        // NATS service discovery would typically use a request-response pattern
        // to query for available services
        let subject = format!("{}.discover", self.subject_prefix);
        
        let response = self.connection
            .request(subject, "".into())
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to discover services via NATS: {}", e)))?;

        let instances: Vec<ServiceInstance> = serde_json::from_slice(&response.payload)
            .map_err(|e| GatewayError::service_discovery(format!("Failed to parse service discovery response: {}", e)))?;

        debug!("Discovered {} service instances from NATS", instances.len());
        Ok(instances)
    }

    async fn register_service(&self, service: ServiceInstance) -> GatewayResult<()> {
        let subject = format!("{}.register", self.subject_prefix);
        let payload = serde_json::to_vec(&service)
            .map_err(|e| GatewayError::service_discovery(format!("Failed to serialize service: {}", e)))?;

        self.connection
            .publish(subject, payload.into())
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to register service via NATS: {}", e)))?;

        info!("Registered service {} with NATS", service.id);
        Ok(())
    }

    async fn deregister_service(&self, service_id: &str) -> GatewayResult<()> {
        let subject = format!("{}.deregister", self.subject_prefix);
        let payload = serde_json::json!({ "service_id": service_id });

        self.connection
            .publish(subject, serde_json::to_vec(&payload).unwrap().into())
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to deregister service via NATS: {}", e)))?;

        info!("Deregistered service {} from NATS", service_id);
        Ok(())
    }

    async fn watch_changes(&self) -> GatewayResult<ServiceChangeReceiver> {
        Ok(self.change_sender.subscribe())
    }

    async fn get_service_health(&self, service_id: &str) -> GatewayResult<HealthStatus> {
        let subject = format!("{}.health.{}", self.subject_prefix, service_id);
        
        let response = self.connection
            .request(subject, "".into())
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to get health status via NATS: {}", e)))?;

        let status: HealthStatus = serde_json::from_slice(&response.payload)
            .map_err(|e| GatewayError::service_discovery(format!("Failed to parse health status: {}", e)))?;

        Ok(status)
    }

    async fn update_service_health(&self, service_id: &str, status: HealthStatus) -> GatewayResult<()> {
        let subject = format!("{}.health.{}.update", self.subject_prefix, service_id);
        let payload = serde_json::to_vec(&status)
            .map_err(|e| GatewayError::service_discovery(format!("Failed to serialize health status: {}", e)))?;

        self.connection
            .publish(subject, payload.into())
            .await
            .map_err(|e| GatewayError::service_discovery(format!("Failed to update health status via NATS: {}", e)))?;

        Ok(())
    }
}

/// Thread-safe service registry with concurrent access using DashMap
///
/// This registry maintains an in-memory cache of service instances with
/// efficient concurrent read/write access. It integrates with service discovery
/// backends to keep the registry up-to-date.
pub struct ServiceRegistry {
    /// Service instances indexed by service name
    services: DashMap<String, Vec<Arc<ServiceInstance>>>,
    /// Service instances indexed by instance ID for quick lookups
    instances: DashMap<String, Arc<ServiceInstance>>,
    /// Service discovery backend
    discovery: Arc<dyn ServiceDiscovery>,
    /// Event sender for service change notifications
    change_sender: ServiceChangeSender,
    /// Configuration
    config: ServiceDiscoveryConfig,
}

impl ServiceRegistry {
    /// Create a new service registry with the specified discovery backend
    pub fn new(discovery: Arc<dyn ServiceDiscovery>, config: ServiceDiscoveryConfig) -> Self {
        let (change_sender, _) = broadcast::channel(1000);
        
        Self {
            services: DashMap::new(),
            instances: DashMap::new(),
            discovery,
            change_sender,
            config,
        }
    }

    /// Get all instances for a service
    pub fn get_service_instances(&self, service_name: &str) -> Vec<Arc<ServiceInstance>> {
        self.services
            .get(service_name)
            .map(|instances| instances.clone())
            .unwrap_or_default()
    }

    /// Get healthy instances for a service
    pub fn get_healthy_instances(&self, service_name: &str) -> Vec<Arc<ServiceInstance>> {
        self.get_service_instances(service_name)
            .into_iter()
            .filter(|instance| instance.is_healthy())
            .collect()
    }

    /// Get a specific service instance by ID
    pub fn get_instance(&self, instance_id: &str) -> Option<Arc<ServiceInstance>> {
        self.instances.get(instance_id).map(|instance| instance.clone())
    }

    /// Add or update a service instance
    pub fn add_instance(&self, instance: ServiceInstance) {
        let instance_arc = Arc::new(instance.clone());
        let service_name = instance.name.clone();
        let instance_id = instance.id.clone();

        // Update instance lookup
        let old_instance = self.instances.insert(instance_id.clone(), instance_arc.clone());

        // Update service instances list
        self.services
            .entry(service_name.clone())
            .or_insert_with(Vec::new)
            .retain(|existing| existing.id != instance_id);
        
        self.services
            .get_mut(&service_name)
            .unwrap()
            .push(instance_arc);

        // Send change event
        let event = if old_instance.is_some() {
            ServiceChangeEvent::MetadataUpdated {
                service_id: instance_id.clone(),
                metadata: instance.metadata,
            }
        } else {
            ServiceChangeEvent::ServiceRegistered(instance)
        };

        if let Err(e) = self.change_sender.send(event) {
            warn!("Failed to send service change event: {}", e);
        }

        debug!("Added/updated service instance: {}", instance_id);
    }

    /// Remove a service instance
    pub fn remove_instance(&self, instance_id: &str) {
        if let Some((_, instance)) = self.instances.remove(instance_id) {
            let service_name = &instance.name;
            
            // Remove from service instances list
            if let Some(mut instances) = self.services.get_mut(service_name) {
                instances.retain(|existing| existing.id != instance_id);
                
                // Remove service entry if no instances left
                if instances.is_empty() {
                    drop(instances);
                    self.services.remove(service_name);
                }
            }

            // Send change event
            let event = ServiceChangeEvent::ServiceDeregistered(instance_id.to_string());
            if let Err(e) = self.change_sender.send(event) {
                warn!("Failed to send service change event: {}", e);
            }

            debug!("Removed service instance: {}", instance_id);
        }
    }

    /// Update health status of a service instance
    pub fn update_instance_health(&self, instance_id: &str, new_status: HealthStatus) {
        if let Some(mut instance_ref) = self.instances.get_mut(instance_id) {
            let old_status = instance_ref.health_status.clone();
            
            // Create a new instance with updated health status
            let mut updated_instance = (**instance_ref).clone();
            updated_instance.health_status = new_status.clone();
            updated_instance.last_health_check = Some(Instant::now());
            
            let updated_arc = Arc::new(updated_instance);
            *instance_ref = updated_arc.clone();

            // Update in services map as well
            if let Some(mut instances) = self.services.get_mut(&instance_ref.name) {
                for instance in instances.iter_mut() {
                    if instance.id == instance_id {
                        *instance = updated_arc.clone();
                        break;
                    }
                }
            }

            // Send change event
            let event = ServiceChangeEvent::HealthChanged {
                service_id: instance_id.to_string(),
                old_status,
                new_status: new_status.clone(),
            };

            if let Err(e) = self.change_sender.send(event) {
                warn!("Failed to send health change event: {}", e);
            }

            debug!("Updated health status for instance {}: {:?}", instance_id, new_status);
        }
    }

    /// Refresh service instances from discovery backend
    pub async fn refresh(&self) -> GatewayResult<()> {
        let discovered_instances = self.discovery.discover_services().await?;
        
        info!("Refreshing service registry with {} discovered instances", discovered_instances.len());

        // Clear existing instances
        self.services.clear();
        self.instances.clear();

        // Add discovered instances
        for instance in discovered_instances {
            self.add_instance(instance);
        }

        Ok(())
    }

    /// Start background tasks for service discovery and health checking
    pub async fn start_background_tasks(self: Arc<Self>) -> GatewayResult<()> {
        // Start service discovery refresh task
        let refresh_registry = self.clone();
        let refresh_interval = self.config.health_check_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(refresh_interval);
            loop {
                interval.tick().await;
                if let Err(e) = refresh_registry.refresh().await {
                    error!("Failed to refresh service registry: {}", e);
                }
            }
        });

        // Start service change watcher
        let watch_registry = self.clone();
        if let Ok(mut change_receiver) = self.discovery.watch_changes().await {
            tokio::spawn(async move {
                while let Ok(event) = change_receiver.recv().await {
                    match event {
                        ServiceChangeEvent::ServiceRegistered(instance) => {
                            watch_registry.add_instance(instance);
                        }
                        ServiceChangeEvent::ServiceDeregistered(instance_id) => {
                            watch_registry.remove_instance(&instance_id);
                        }
                        ServiceChangeEvent::HealthChanged { service_id, new_status, .. } => {
                            watch_registry.update_instance_health(&service_id, new_status);
                        }
                        ServiceChangeEvent::MetadataUpdated { service_id, metadata } => {
                            if let Some(mut instance_ref) = watch_registry.instances.get_mut(&service_id) {
                                let mut updated_instance = (**instance_ref).clone();
                                updated_instance.metadata = metadata;
                                *instance_ref = Arc::new(updated_instance);
                            }
                        }
                    }
                }
            });
        }

        info!("Started service registry background tasks");
        Ok(())
    }

    /// Subscribe to service change events
    pub fn subscribe_to_changes(&self) -> ServiceChangeReceiver {
        self.change_sender.subscribe()
    }

    /// Get all service names
    pub fn get_service_names(&self) -> Vec<String> {
        self.services.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> RegistryStats {
        let total_instances = self.instances.len();
        let total_services = self.services.len();
        let healthy_instances = self.instances
            .iter()
            .filter(|entry| entry.value().is_healthy())
            .count();

        RegistryStats {
            total_services,
            total_instances,
            healthy_instances,
            unhealthy_instances: total_instances - healthy_instances,
        }
    }
}

/// Service registry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStats {
    pub total_services: usize,
    pub total_instances: usize,
    pub healthy_instances: usize,
    pub unhealthy_instances: usize,
}

/// Factory function to create service discovery instances based on configuration
pub async fn create_service_discovery(config: &ServiceDiscoveryConfig) -> GatewayResult<Arc<dyn ServiceDiscovery>> {
    match config.discovery_type {
        DiscoveryType::Kubernetes => {
            let k8s_config = config.kubernetes.as_ref()
                .ok_or_else(|| GatewayError::config("Kubernetes config required"))?;
            let discovery = KubernetesDiscovery::new(k8s_config.clone()).await?;
            Ok(Arc::new(discovery))
        }
        DiscoveryType::Consul => {
            let consul_config = config.consul.as_ref()
                .ok_or_else(|| GatewayError::config("Consul config required"))?;
            let discovery = ConsulDiscovery::new(consul_config.clone())?;
            Ok(Arc::new(discovery))
        }
        DiscoveryType::Nats => {
            let nats_config = config.nats.as_ref()
                .ok_or_else(|| GatewayError::config("NATS config required"))?;
            let discovery = NatsDiscovery::new(nats_config.clone()).await?;
            Ok(Arc::new(discovery))
        }
        DiscoveryType::Static => {
            // For testing - return a simple in-memory implementation
            Ok(Arc::new(StaticDiscovery::new()))
        }
    }
}

/// Static service discovery for testing and simple deployments
pub struct StaticDiscovery {
    instances: DashMap<String, ServiceInstance>,
    change_sender: ServiceChangeSender,
}

impl StaticDiscovery {
    pub fn new() -> Self {
        let (change_sender, _) = broadcast::channel(100);
        Self {
            instances: DashMap::new(),
            change_sender,
        }
    }

    pub fn add_static_instance(&self, instance: ServiceInstance) {
        self.instances.insert(instance.id.clone(), instance.clone());
        let _ = self.change_sender.send(ServiceChangeEvent::ServiceRegistered(instance));
    }
}

#[async_trait]
impl ServiceDiscovery for StaticDiscovery {
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>> {
        Ok(self.instances.iter().map(|entry| entry.value().clone()).collect())
    }

    async fn register_service(&self, service: ServiceInstance) -> GatewayResult<()> {
        self.add_static_instance(service);
        Ok(())
    }

    async fn deregister_service(&self, service_id: &str) -> GatewayResult<()> {
        self.instances.remove(service_id);
        let _ = self.change_sender.send(ServiceChangeEvent::ServiceDeregistered(service_id.to_string()));
        Ok(())
    }

    async fn watch_changes(&self) -> GatewayResult<ServiceChangeReceiver> {
        Ok(self.change_sender.subscribe())
    }

    async fn get_service_health(&self, service_id: &str) -> GatewayResult<HealthStatus> {
        Ok(self.instances
            .get(service_id)
            .map(|instance| instance.health_status.clone())
            .unwrap_or(HealthStatus::Unknown))
    }

    async fn update_service_health(&self, service_id: &str, status: HealthStatus) -> GatewayResult<()> {
        if let Some(mut instance) = self.instances.get_mut(service_id) {
            let old_status = instance.health_status.clone();
            instance.health_status = status.clone();
            instance.last_health_check = Some(Instant::now());
            
            let _ = self.change_sender.send(ServiceChangeEvent::HealthChanged {
                service_id: service_id.to_string(),
                old_status,
                new_status: status,
            });
        }
        Ok(())
    }
}
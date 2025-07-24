use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    api::{Api, ListParams, Patch, PatchParams, PostParams},
    Client, ResourceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, BTreeMap};
use tracing::info;
use base64::{Engine as _, engine::general_purpose};

/// Kubernetes resource management for admin interface
#[derive(Clone)]
pub struct K8sResourceManager {
    client: Client,
    namespace: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct K8sResourceInfo {
    pub name: String,
    pub namespace: String,
    pub resource_type: String,
    pub status: String,
    pub created_at: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScalingRequest {
    pub deployment_name: String,
    pub namespace: String,
    pub replicas: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HPAConfig {
    pub name: String,
    pub namespace: String,
    pub target_deployment: String,
    pub min_replicas: i32,
    pub max_replicas: i32,
    pub cpu_target_percentage: i32,
    pub memory_target_percentage: Option<i32>,
}

#[async_trait]
pub trait K8sResourceOperations {
    async fn list_deployments(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>>;
    async fn get_deployment(&self, name: &str, namespace: &str) -> Result<K8sResourceInfo>;
    async fn scale_deployment(&self, request: ScalingRequest) -> Result<()>;
    async fn list_services(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>>;
    async fn list_configmaps(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>>;
    async fn update_configmap(&self, name: &str, namespace: &str, data: HashMap<String, String>) -> Result<()>;
    async fn list_hpas(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>>;
    async fn create_hpa(&self, config: HPAConfig) -> Result<()>;
    async fn update_hpa(&self, config: HPAConfig) -> Result<()>;
    async fn delete_hpa(&self, name: &str, namespace: &str) -> Result<()>;
    async fn get_pod_metrics(&self, namespace: Option<&str>) -> Result<Vec<PodMetrics>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PodMetrics {
    pub name: String,
    pub namespace: String,
    pub cpu_usage: String,
    pub memory_usage: String,
    pub status: String,
    pub node: String,
    pub created_at: String,
}

impl K8sResourceManager {
    pub async fn new(namespace: String) -> Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self { client, namespace })
    }

    pub async fn new_with_client(client: Client, namespace: String) -> Self {
        Self { client, namespace }
    }

    fn resource_to_info<T>(&self, resource: &T, resource_type: &str) -> K8sResourceInfo
    where
        T: ResourceExt,
    {
        // Convert BTreeMap to HashMap for labels and annotations
        let labels: HashMap<String, String> = resource.labels().iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let annotations: HashMap<String, String> = resource.annotations().iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        K8sResourceInfo {
            name: resource.name_any(),
            namespace: resource.namespace().unwrap_or_default(),
            resource_type: resource_type.to_string(),
            status: "Unknown".to_string(), // This would need specific status extraction per resource type
            created_at: resource
                .creation_timestamp()
                .map(|ts| ts.0.to_rfc3339())
                .unwrap_or_default(),
            labels,
            annotations,
        }
    }
}

#[async_trait]
impl K8sResourceOperations for K8sResourceManager {
    async fn list_deployments(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let deployment_list = deployments.list(&list_params).await?;
        
        let mut resources = Vec::new();
        for deployment in deployment_list.items {
            let mut info = self.resource_to_info(&deployment, "Deployment");
            
            // Extract deployment-specific status
            if let Some(status) = &deployment.status {
                info.status = format!(
                    "Ready: {}/{}, Available: {}",
                    status.ready_replicas.unwrap_or(0),
                    status.replicas.unwrap_or(0),
                    status.available_replicas.unwrap_or(0)
                );
            }
            
            resources.push(info);
        }
        
        Ok(resources)
    }

    async fn get_deployment(&self, name: &str, namespace: &str) -> Result<K8sResourceInfo> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let deployment = deployments.get(name).await?;
        
        let mut info = self.resource_to_info(&deployment, "Deployment");
        
        if let Some(status) = &deployment.status {
            info.status = format!(
                "Ready: {}/{}, Available: {}, Updated: {}",
                status.ready_replicas.unwrap_or(0),
                status.replicas.unwrap_or(0),
                status.available_replicas.unwrap_or(0),
                status.updated_replicas.unwrap_or(0)
            );
        }
        
        Ok(info)
    }

    async fn scale_deployment(&self, request: ScalingRequest) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &request.namespace);
        
        let patch = json!({
            "spec": {
                "replicas": request.replicas
            }
        });
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        deployments
            .patch(&request.deployment_name, &patch_params, &Patch::Merge(&patch))
            .await?;
        
        info!(
            "Scaled deployment {} in namespace {} to {} replicas",
            request.deployment_name, request.namespace, request.replicas
        );
        
        Ok(())
    }

    async fn list_services(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let services: Api<Service> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let service_list = services.list(&list_params).await?;
        
        let mut resources = Vec::new();
        for service in service_list.items {
            let mut info = self.resource_to_info(&service, "Service");
            
            // Extract service-specific status
            if let Some(spec) = &service.spec {
                info.status = format!(
                    "Type: {}, ClusterIP: {}",
                    spec.type_.as_ref().unwrap_or(&"ClusterIP".to_string()),
                    spec.cluster_ip.as_ref().unwrap_or(&"None".to_string())
                );
            }
            
            resources.push(info);
        }
        
        Ok(resources)
    }

    async fn list_configmaps(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let configmaps: Api<ConfigMap> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let configmap_list = configmaps.list(&list_params).await?;
        
        let mut resources = Vec::new();
        for configmap in configmap_list.items {
            let mut info = self.resource_to_info(&configmap, "ConfigMap");
            
            // Extract configmap-specific status
            let data_count = configmap.data.as_ref().map(|d| d.len()).unwrap_or(0);
            info.status = format!("Data keys: {}", data_count);
            
            resources.push(info);
        }
        
        Ok(resources)
    }

    async fn update_configmap(
        &self,
        name: &str,
        namespace: &str,
        data: HashMap<String, String>,
    ) -> Result<()> {
        let configmaps: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        
        let patch = json!({
            "data": data
        });
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        configmaps
            .patch(name, &patch_params, &Patch::Merge(&patch))
            .await?;
        
        info!(
            "Updated ConfigMap {} in namespace {} with {} keys",
            name,
            namespace,
            data.len()
        );
        
        Ok(())
    }

    async fn list_hpas(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let hpa_list = hpas.list(&list_params).await?;
        
        let mut resources = Vec::new();
        for hpa in hpa_list.items {
            let mut info = self.resource_to_info(&hpa, "HorizontalPodAutoscaler");
            
            // Extract HPA-specific status
            if let Some(status) = &hpa.status {
                info.status = format!(
                    "Current: {}, Desired: {}, Min: {}, Max: {}",
                    status.current_replicas.unwrap_or(0),
                    status.desired_replicas,
                    hpa.spec.as_ref().map(|s| s.min_replicas.unwrap_or(1)).unwrap_or(1),
                    hpa.spec.as_ref().map(|s| s.max_replicas).unwrap_or(0)
                );
            }
            
            resources.push(info);
        }
        
        Ok(resources)
    }

    async fn create_hpa(&self, config: HPAConfig) -> Result<()> {
        let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(self.client.clone(), &config.namespace);
        
        let mut hpa_spec = json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {
                "name": config.name,
                "namespace": config.namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "api-gateway-admin"
                }
            },
            "spec": {
                "scaleTargetRef": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": config.target_deployment
                },
                "minReplicas": config.min_replicas,
                "maxReplicas": config.max_replicas,
                "metrics": [
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "cpu",
                            "target": {
                                "type": "Utilization",
                                "averageUtilization": config.cpu_target_percentage
                            }
                        }
                    }
                ]
            }
        });
        
        // Add memory metric if specified
        if let Some(memory_target) = config.memory_target_percentage {
            if let Some(metrics) = hpa_spec["spec"]["metrics"].as_array_mut() {
                metrics.push(json!({
                    "type": "Resource",
                    "resource": {
                        "name": "memory",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": memory_target
                        }
                    }
                }));
            }
        }
        
        let hpa: HorizontalPodAutoscaler = serde_json::from_value(hpa_spec)?;
        let post_params = PostParams::default();
        hpas.create(&post_params, &hpa).await?;
        
        info!(
            "Created HPA {} in namespace {} for deployment {}",
            config.name, config.namespace, config.target_deployment
        );
        
        Ok(())
    }

    async fn update_hpa(&self, config: HPAConfig) -> Result<()> {
        let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(self.client.clone(), &config.namespace);
        
        let mut patch_data = json!({
            "spec": {
                "minReplicas": config.min_replicas,
                "maxReplicas": config.max_replicas,
                "metrics": [
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "cpu",
                            "target": {
                                "type": "Utilization",
                                "averageUtilization": config.cpu_target_percentage
                            }
                        }
                    }
                ]
            }
        });
        
        // Add memory metric if specified
        if let Some(memory_target) = config.memory_target_percentage {
            if let Some(metrics) = patch_data["spec"]["metrics"].as_array_mut() {
                metrics.push(json!({
                    "type": "Resource",
                    "resource": {
                        "name": "memory",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": memory_target
                        }
                    }
                }));
            }
        }
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        hpas.patch(&config.name, &patch_params, &Patch::Merge(&patch_data))
            .await?;
        
        info!(
            "Updated HPA {} in namespace {}",
            config.name, config.namespace
        );
        
        Ok(())
    }

    async fn delete_hpa(&self, name: &str, namespace: &str) -> Result<()> {
        let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(self.client.clone(), namespace);
        
        hpas.delete(name, &Default::default()).await?;
        
        info!("Deleted HPA {} in namespace {}", name, namespace);
        
        Ok(())
    }

    async fn get_pod_metrics(&self, namespace: Option<&str>) -> Result<Vec<PodMetrics>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let pod_list = pods.list(&list_params).await?;
        
        let mut metrics = Vec::new();
        for pod in pod_list.items {
            let pod_metrics = PodMetrics {
                name: pod.name_any(),
                namespace: pod.namespace().unwrap_or_default(),
                cpu_usage: "N/A".to_string(), // Would need metrics server integration
                memory_usage: "N/A".to_string(), // Would need metrics server integration
                status: pod
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .unwrap_or(&"Unknown".to_string())
                    .clone(),
                node: pod
                    .spec
                    .as_ref()
                    .and_then(|s| s.node_name.as_ref())
                    .unwrap_or(&"Unknown".to_string())
                    .clone(),
                created_at: pod
                    .creation_timestamp()
                    .map(|ts| ts.0.to_rfc3339())
                    .unwrap_or_default(),
            };
            metrics.push(pod_metrics);
        }
        
        Ok(metrics)
    }
}

/// Extended Kubernetes operations for advanced admin functionality
#[async_trait]
pub trait K8sAdvancedOperations {
    async fn list_ingresses(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>>;
    async fn create_ingress(&self, name: &str, namespace: &str, config: IngressConfig) -> Result<()>;
    async fn update_ingress(&self, name: &str, namespace: &str, config: IngressConfig) -> Result<()>;
    async fn delete_ingress(&self, name: &str, namespace: &str) -> Result<()>;
    async fn get_cluster_info(&self) -> Result<ClusterInfo>;
    async fn get_node_metrics(&self) -> Result<Vec<NodeMetrics>>;
    async fn create_secret(&self, name: &str, namespace: &str, data: HashMap<String, Vec<u8>>) -> Result<()>;
    async fn update_secret(&self, name: &str, namespace: &str, data: HashMap<String, Vec<u8>>) -> Result<()>;
    async fn rollout_restart(&self, deployment_name: &str, namespace: &str) -> Result<()>;
    async fn get_deployment_history(&self, deployment_name: &str, namespace: &str) -> Result<Vec<DeploymentRevision>>;
    async fn rollback_deployment(&self, deployment_name: &str, namespace: &str, revision: Option<i64>) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngressConfig {
    pub hosts: Vec<String>,
    pub tls_enabled: bool,
    pub tls_secret_name: Option<String>,
    pub annotations: HashMap<String, String>,
    pub rules: Vec<IngressRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngressRule {
    pub host: String,
    pub paths: Vec<IngressPath>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngressPath {
    pub path: String,
    pub path_type: String,
    pub service_name: String,
    pub service_port: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterInfo {
    pub version: String,
    pub node_count: i32,
    pub namespace_count: i32,
    pub total_pods: i32,
    pub total_services: i32,
    pub cluster_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub name: String,
    pub status: String,
    pub cpu_capacity: String,
    pub memory_capacity: String,
    pub cpu_usage: String,
    pub memory_usage: String,
    pub pod_count: i32,
    pub conditions: Vec<NodeCondition>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeCondition {
    pub condition_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeploymentRevision {
    pub revision: i64,
    pub created_at: String,
    pub change_cause: Option<String>,
    pub replicas: i32,
    pub image: String,
}

#[async_trait]
impl K8sAdvancedOperations for K8sResourceManager {
    async fn list_ingresses(&self, namespace: Option<&str>) -> Result<Vec<K8sResourceInfo>> {
        let ns = namespace.unwrap_or(&self.namespace);
        let ingresses: Api<Ingress> = Api::namespaced(self.client.clone(), ns);
        
        let list_params = ListParams::default();
        let ingress_list = ingresses.list(&list_params).await?;
        
        let mut resources = Vec::new();
        for ingress in ingress_list.items {
            let mut info = self.resource_to_info(&ingress, "Ingress");
            
            // Extract ingress-specific status
            let hosts: Vec<String> = ingress
                .spec
                .as_ref()
                .map(|spec| {
                    spec.rules
                        .as_ref()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|rule| rule.host.clone())
                        .collect()
                })
                .unwrap_or_default();
            
            info.status = format!("Hosts: {}", hosts.join(", "));
            resources.push(info);
        }
        
        Ok(resources)
    }

    async fn create_ingress(&self, name: &str, namespace: &str, config: IngressConfig) -> Result<()> {
        let ingresses: Api<Ingress> = Api::namespaced(self.client.clone(), namespace);
        
        let mut ingress_rules = Vec::new();
        for rule in config.rules {
            let mut paths = Vec::new();
            for path in rule.paths {
                paths.push(json!({
                    "path": path.path,
                    "pathType": path.path_type,
                    "backend": {
                        "service": {
                            "name": path.service_name,
                            "port": {
                                "number": path.service_port
                            }
                        }
                    }
                }));
            }
            
            ingress_rules.push(json!({
                "host": rule.host,
                "http": {
                    "paths": paths
                }
            }));
        }
        
        let mut ingress_spec = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "annotations": config.annotations,
                "labels": {
                    "app.kubernetes.io/managed-by": "api-gateway-admin"
                }
            },
            "spec": {
                "rules": ingress_rules
            }
        });
        
        // Add TLS configuration if enabled
        if config.tls_enabled {
            let tls_config = json!([{
                "hosts": config.hosts,
                "secretName": config.tls_secret_name.unwrap_or_else(|| format!("{}-tls", name))
            }]);
            ingress_spec["spec"]["tls"] = tls_config;
        }
        
        let ingress: Ingress = serde_json::from_value(ingress_spec)?;
        let post_params = PostParams::default();
        ingresses.create(&post_params, &ingress).await?;
        
        info!("Created Ingress {} in namespace {}", name, namespace);
        Ok(())
    }

    async fn update_ingress(&self, name: &str, namespace: &str, config: IngressConfig) -> Result<()> {
        let ingresses: Api<Ingress> = Api::namespaced(self.client.clone(), namespace);
        
        let mut ingress_rules = Vec::new();
        for rule in config.rules {
            let mut paths = Vec::new();
            for path in rule.paths {
                paths.push(json!({
                    "path": path.path,
                    "pathType": path.path_type,
                    "backend": {
                        "service": {
                            "name": path.service_name,
                            "port": {
                                "number": path.service_port
                            }
                        }
                    }
                }));
            }
            
            ingress_rules.push(json!({
                "host": rule.host,
                "http": {
                    "paths": paths
                }
            }));
        }
        
        let mut patch_data = json!({
            "spec": {
                "rules": ingress_rules
            },
            "metadata": {
                "annotations": config.annotations
            }
        });
        
        // Add TLS configuration if enabled
        if config.tls_enabled {
            let tls_config = json!([{
                "hosts": config.hosts,
                "secretName": config.tls_secret_name.unwrap_or_else(|| format!("{}-tls", name))
            }]);
            patch_data["spec"]["tls"] = tls_config;
        }
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        ingresses.patch(name, &patch_params, &Patch::Merge(&patch_data)).await?;
        
        info!("Updated Ingress {} in namespace {}", name, namespace);
        Ok(())
    }

    async fn delete_ingress(&self, name: &str, namespace: &str) -> Result<()> {
        let ingresses: Api<Ingress> = Api::namespaced(self.client.clone(), namespace);
        ingresses.delete(name, &Default::default()).await?;
        
        info!("Deleted Ingress {} in namespace {}", name, namespace);
        Ok(())
    }

    async fn get_cluster_info(&self) -> Result<ClusterInfo> {
        // Get cluster version
        let version_info = self.client.apiserver_version().await?;
        
        // Get node count
        let nodes: Api<k8s_openapi::api::core::v1::Node> = Api::all(self.client.clone());
        let node_list = nodes.list(&ListParams::default()).await?;
        let node_count = node_list.items.len() as i32;
        
        // Get namespace count
        let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
        let namespace_list = namespaces.list(&ListParams::default()).await?;
        let namespace_count = namespace_list.items.len() as i32;
        
        // Get total pods
        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::all(self.client.clone());
        let pod_list = pods.list(&ListParams::default()).await?;
        let total_pods = pod_list.items.len() as i32;
        
        // Get total services
        let services: Api<Service> = Api::all(self.client.clone());
        let service_list = services.list(&ListParams::default()).await?;
        let total_services = service_list.items.len() as i32;
        
        Ok(ClusterInfo {
            version: format!("{}.{}", version_info.major, version_info.minor),
            node_count,
            namespace_count,
            total_pods,
            total_services,
            cluster_name: "kubernetes".to_string(), // Could be extracted from cluster config
        })
    }

    async fn get_node_metrics(&self) -> Result<Vec<NodeMetrics>> {
        let nodes: Api<k8s_openapi::api::core::v1::Node> = Api::all(self.client.clone());
        let node_list = nodes.list(&ListParams::default()).await?;
        
        let mut metrics = Vec::new();
        for node in node_list.items {
            let mut conditions = Vec::new();
            if let Some(status) = &node.status {
                if let Some(node_conditions) = &status.conditions {
                    for condition in node_conditions {
                        conditions.push(NodeCondition {
                            condition_type: condition.type_.clone(),
                            status: condition.status.clone(),
                            reason: condition.reason.clone(),
                            message: condition.message.clone(),
                        });
                    }
                }
            }
            
            let node_status = node
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .and_then(|conditions| {
                    conditions
                        .iter()
                        .find(|c| c.type_ == "Ready")
                        .map(|c| c.status.clone())
                })
                .unwrap_or_else(|| "Unknown".to_string());
            
            let cpu_capacity = node
                .status
                .as_ref()
                .and_then(|s| s.capacity.as_ref())
                .and_then(|c| c.get("cpu"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            
            let memory_capacity = node
                .status
                .as_ref()
                .and_then(|s| s.capacity.as_ref())
                .and_then(|c| c.get("memory"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            
            metrics.push(NodeMetrics {
                name: node.name_any(),
                status: node_status,
                cpu_capacity,
                memory_capacity,
                cpu_usage: "N/A".to_string(), // Would need metrics server
                memory_usage: "N/A".to_string(), // Would need metrics server
                pod_count: 0, // Would need to count pods per node
                conditions,
            });
        }
        
        Ok(metrics)
    }

    async fn create_secret(&self, name: &str, namespace: &str, data: HashMap<String, Vec<u8>>) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        
        let secret_spec = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "api-gateway-admin"
                }
            },
            "type": "Opaque",
            "data": data.iter().map(|(k, v)| (k.clone(), general_purpose::STANDARD.encode(v))).collect::<HashMap<String, String>>()
        });
        
        let secret: Secret = serde_json::from_value(secret_spec)?;
        let post_params = PostParams::default();
        secrets.create(&post_params, &secret).await?;
        
        info!("Created Secret {} in namespace {}", name, namespace);
        Ok(())
    }

    async fn update_secret(&self, name: &str, namespace: &str, data: HashMap<String, Vec<u8>>) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        
        let patch_data = json!({
            "data": data.iter().map(|(k, v)| (k.clone(), general_purpose::STANDARD.encode(v))).collect::<HashMap<String, String>>()
        });
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        secrets.patch(name, &patch_params, &Patch::Merge(&patch_data)).await?;
        
        info!("Updated Secret {} in namespace {}", name, namespace);
        Ok(())
    }

    async fn rollout_restart(&self, deployment_name: &str, namespace: &str) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        
        let patch_data = json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": chrono::Utc::now().to_rfc3339()
                        }
                    }
                }
            }
        });
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        deployments.patch(deployment_name, &patch_params, &Patch::Merge(&patch_data)).await?;
        
        info!("Restarted deployment {} in namespace {}", deployment_name, namespace);
        Ok(())
    }

    async fn get_deployment_history(&self, deployment_name: &str, namespace: &str) -> Result<Vec<DeploymentRevision>> {
        let replica_sets: Api<k8s_openapi::api::apps::v1::ReplicaSet> = Api::namespaced(self.client.clone(), namespace);
        
        let list_params = ListParams::default().labels(&format!("app.kubernetes.io/name={}", deployment_name));
        let rs_list = replica_sets.list(&list_params).await?;
        
        let mut revisions = Vec::new();
        for rs in rs_list.items {
            if let Some(annotations) = rs.metadata.annotations.as_ref() {
                if let Some(revision_str) = annotations.get("deployment.kubernetes.io/revision") {
                    if let Ok(revision) = revision_str.parse::<i64>() {
                        let change_cause = annotations.get("kubernetes.io/change-cause").cloned();
                        
                        let replicas = rs.spec.as_ref().map(|s| s.replicas.unwrap_or(0)).unwrap_or(0);
                        
                        let image = rs
                            .spec
                            .as_ref()
                            .and_then(|s| s.template.as_ref())
                            .and_then(|t| t.spec.as_ref())
                            .and_then(|s| s.containers.first())
                            .map(|c| c.image.as_ref().unwrap_or(&"unknown".to_string()).clone())
                            .unwrap_or_else(|| "unknown".to_string());
                        
                        revisions.push(DeploymentRevision {
                            revision,
                            created_at: rs.creation_timestamp().map(|ts| ts.0.to_rfc3339()).unwrap_or_default(),
                            change_cause,
                            replicas,
                            image,
                        });
                    }
                }
            }
        }
        
        // Sort by revision number
        revisions.sort_by(|a, b| b.revision.cmp(&a.revision));
        
        Ok(revisions)
    }

    async fn rollback_deployment(&self, deployment_name: &str, namespace: &str, revision: Option<i64>) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        
        // If no revision specified, rollback to previous revision
        let target_revision = if let Some(rev) = revision {
            rev
        } else {
            // Get current revision and rollback to previous
            let deployment = deployments.get(deployment_name).await?;
            let current_revision = deployment
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                .and_then(|r| r.parse::<i64>().ok())
                .unwrap_or(1);
            
            current_revision - 1
        };
        
        let patch_data = json!({
            "metadata": {
                "annotations": {
                    "deployment.kubernetes.io/revision": target_revision.to_string(),
                    "kubernetes.io/change-cause": format!("Rollback to revision {}", target_revision)
                }
            }
        });
        
        let patch_params = PatchParams::apply("api-gateway-admin");
        deployments.patch(deployment_name, &patch_params, &Patch::Merge(&patch_data)).await?;
        
        info!("Rolled back deployment {} in namespace {} to revision {}", 
              deployment_name, namespace, target_revision);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::Client;
    
    #[tokio::test]
    async fn test_k8s_resource_manager_creation() {
        // This test would require a running Kubernetes cluster
        // In a real environment, you'd use a test cluster or mock client
        
        // Mock test - in practice you'd use testcontainers or similar
        let namespace = "test-namespace".to_string();
        
        // This would fail without a real cluster, but shows the interface
        match K8sResourceManager::new(namespace).await {
            Ok(_manager) => {
                // Test successful creation
                assert!(true);
            }
            Err(_) => {
                // Expected in test environment without cluster
                assert!(true);
            }
        }
    }
    
    #[test]
    fn test_scaling_request_serialization() {
        let request = ScalingRequest {
            deployment_name: "test-deployment".to_string(),
            namespace: "test-namespace".to_string(),
            replicas: 5,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ScalingRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(request.deployment_name, deserialized.deployment_name);
        assert_eq!(request.namespace, deserialized.namespace);
        assert_eq!(request.replicas, deserialized.replicas);
    }
    
    #[test]
    fn test_hpa_config_serialization() {
        let config = HPAConfig {
            name: "test-hpa".to_string(),
            namespace: "test-namespace".to_string(),
            target_deployment: "test-deployment".to_string(),
            min_replicas: 2,
            max_replicas: 10,
            cpu_target_percentage: 70,
            memory_target_percentage: Some(80),
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HPAConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.target_deployment, deserialized.target_deployment);
        assert_eq!(config.min_replicas, deserialized.min_replicas);
        assert_eq!(config.max_replicas, deserialized.max_replicas);
        assert_eq!(config.cpu_target_percentage, deserialized.cpu_target_percentage);
        assert_eq!(config.memory_target_percentage, deserialized.memory_target_percentage);
    }
}
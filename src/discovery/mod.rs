pub mod service_discovery;

pub use service_discovery::{
    ServiceDiscovery, ServiceRegistry, ServiceChangeEvent, ServiceChangeReceiver,
    ServiceDiscoveryConfig, DiscoveryType, KubernetesConfig, ConsulConfig, NatsConfig,
    KubernetesDiscovery, ConsulDiscovery, NatsDiscovery, StaticDiscovery,
    RegistryStats, create_service_discovery,
};
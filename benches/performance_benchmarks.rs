//! # Performance Benchmarks
//!
//! This module contains comprehensive performance benchmarks for the API Gateway
//! using the criterion benchmarking framework. These benchmarks help identify
//! performance regressions and optimize hot paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// Import gateway modules
use api_gateway::core::types::{ServiceInstance, IncomingRequest, HealthStatus, Protocol};
use api_gateway::core::connection_pool::{ConnectionPoolManager, ConnectionPoolConfig};
use api_gateway::core::memory_optimization::{MemoryOptimizer, StringInterner, ZeroCopyBuffer};
use api_gateway::core::zero_copy::{ZeroCopyHeaderMap, ZeroCopyPath, ZeroCopyQueryParams, string_pool};
use api_gateway::load_balancing::balancer::{
    LoadBalancer, RoundRobinBalancer, LeastConnectionsBalancer, 
    WeightedBalancer, ConsistentHashBalancer
};
use api_gateway::routing::router::RouterBuilder;

/// Create a test service instance
fn create_test_service(id: &str, port: u16) -> ServiceInstance {
    ServiceInstance {
        id: id.to_string(),
        name: "test-service".to_string(),
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        metadata: HashMap::new(),
        health_status: HealthStatus::Healthy,
        protocol: Protocol::Http,
        weight: 1,
        last_health_check: None,
    }
}

/// Create a test request
fn create_test_request(path: &str) -> IncomingRequest {
    use http::{Method, Uri, Version, HeaderMap};
    
    let uri: Uri = path.parse().unwrap();
    IncomingRequest::new(
        Protocol::Http,
        Method::GET,
        uri,
        Version::HTTP_11,
        HeaderMap::new(),
        Vec::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
    )
}

/// Benchmark route matching performance
fn benchmark_route_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_matching");
    
    // Create router with different numbers of routes
    let route_counts = [10, 100, 1000, 5000];
    
    for &route_count in &route_counts {
        let mut router_builder = RouterBuilder::new();
        
        // Add routes with different patterns
        for i in 0..route_count {
            let path = format!("/api/service{}/endpoint", i);
            router_builder = router_builder.get(&path, &format!("service-{}", i));
        }
        
        // Add some parameterized routes
        for i in 0..route_count / 10 {
            let path = format!("/api/service{}/{{id}}", i);
            router_builder = router_builder.get(&path, &format!("param-service-{}", i));
        }
        
        let router = router_builder.build();
        
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("exact_match", route_count),
            &route_count,
            |b, &_route_count| {
                let request = create_test_request("/api/service500/endpoint");
                b.iter(|| {
                    black_box(router.match_route(black_box(&request)))
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("param_match", route_count),
            &route_count,
            |b, &_route_count| {
                let request = create_test_request("/api/service50/12345");
                b.iter(|| {
                    black_box(router.match_route(black_box(&request)))
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("no_match", route_count),
            &route_count,
            |b, &_route_count| {
                let request = create_test_request("/api/nonexistent/path");
                b.iter(|| {
                    black_box(router.match_route(black_box(&request)))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark load balancing algorithms
fn benchmark_load_balancing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("load_balancing");
    
    // Create test instances
    let instance_counts = [5, 50, 500];
    
    for &instance_count in &instance_counts {
        let instances: Vec<ServiceInstance> = (0..instance_count)
            .map(|i| create_test_service(&format!("service-{}", i), 8080 + i as u16))
            .collect();
        
        let request = create_test_request("/api/test");
        
        // Benchmark Round Robin
        group.bench_with_input(
            BenchmarkId::new("round_robin", instance_count),
            &instance_count,
            |b, &_instance_count| {
                let balancer = RoundRobinBalancer::new();
                b.to_async(&rt).iter(|| async {
                    black_box(balancer.select_instance(black_box(&instances), black_box(&request)).await)
                });
            },
        );
        
        // Benchmark Least Connections
        group.bench_with_input(
            BenchmarkId::new("least_connections", instance_count),
            &instance_count,
            |b, &_instance_count| {
                let balancer = LeastConnectionsBalancer::new();
                b.to_async(&rt).iter(|| async {
                    black_box(balancer.select_instance(black_box(&instances), black_box(&request)).await)
                });
            },
        );
        
        // Benchmark Weighted
        group.bench_with_input(
            BenchmarkId::new("weighted", instance_count),
            &instance_count,
            |b, &_instance_count| {
                let balancer = WeightedBalancer::new();
                b.to_async(&rt).iter(|| async {
                    black_box(balancer.select_instance(black_box(&instances), black_box(&request)).await)
                });
            },
        );
        
        // Benchmark Consistent Hash
        group.bench_with_input(
            BenchmarkId::new("consistent_hash", instance_count),
            &instance_count,
            |b, &_instance_count| {
                let balancer = ConsistentHashBalancer::new(None);
                b.to_async(&rt).iter(|| async {
                    black_box(balancer.select_instance(black_box(&instances), black_box(&request)).await)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark connection pool performance
fn benchmark_connection_pool(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("connection_pool");
    
    let config = ConnectionPoolConfig {
        max_connections_per_service: 100,
        max_idle_time: Duration::from_secs(60),
        connection_timeout: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(90),
        enable_http2: true,
        cleanup_interval: Duration::from_secs(30),
    };
    
    let pool_manager = Arc::new(ConnectionPoolManager::new(config));
    let service = create_test_service("benchmark-service", 8080);
    
    group.bench_function("get_connection", |b| {
        b.to_async(&rt).iter(|| async {
            let pool_manager = pool_manager.clone();
            let service = service.clone();
            // Note: This will fail in benchmarks since we don't have a real server
            // but it measures the pool lookup and creation overhead
            let _ = black_box(pool_manager.get_or_create_pool(&service));
        });
    });
    
    group.bench_function("pool_stats", |b| {
        b.to_async(&rt).iter(|| async {
            let pool_manager = pool_manager.clone();
            black_box(pool_manager.get_global_stats().await)
        });
    });
    
    group.finish();
}

/// Benchmark caching performance
fn benchmark_caching(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("caching");
    
    let config = CacheConfig {
        in_memory_enabled: true,
        in_memory: InMemoryCacheConfig {
            max_entries: 10000,
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            cleanup_interval: Duration::from_secs(60),
        },
        redis_enabled: false,
        redis: RedisCacheConfig {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout: Duration::from_secs(5),
            key_prefix: "gateway:".to_string(),
            cluster_mode: false,
        },
        default_ttl: Duration::from_secs(300),
        max_key_length: 250,
        operation_timeout: Duration::from_secs(1),
        enable_stats: true,
    };
    
    group.bench_function("cache_creation", |b| {
        b.to_async(&rt).iter(|| async {
            let config = config.clone();
            black_box(CacheManager::new(config).await)
        });
    });
    
    // Benchmark cache operations with an actual cache instance
    let cache_manager = rt.block_on(async {
        CacheManager::new(config.clone()).await.unwrap()
    });
    
    group.bench_function("cache_set", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("benchmark_key_{}", fastrand::u64(..));
            let value = b"benchmark_value".to_vec();
            let ttl = Duration::from_secs(60);
            let _ = black_box(cache_manager.set(&key, value, Some(ttl)).await);
        });
    });
    
    // Pre-populate cache for get benchmarks
    rt.block_on(async {
        for i in 0..1000 {
            let key = format!("get_benchmark_key_{}", i);
            let value = format!("benchmark_value_{}", i).into_bytes();
            let _ = cache_manager.set(&key, value, Some(Duration::from_secs(300))).await;
        }
    });
    
    group.bench_function("cache_get_hit", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("get_benchmark_key_{}", fastrand::usize(0..1000));
            black_box(cache_manager.get(&key).await)
        });
    });
    
    group.bench_function("cache_get_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("miss_key_{}", fastrand::u64(..));
            black_box(cache_manager.get(&key).await)
        });
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    
    // Benchmark Arc vs Rc (Arc should be used for thread safety)
    group.bench_function("arc_clone", |b| {
        let data = Arc::new(vec![1u8; 1024]);
        b.iter(|| {
            let _cloned = black_box(data.clone());
        });
    });
    
    // Benchmark HashMap vs DashMap for concurrent access
    group.bench_function("hashmap_insert", |b| {
        let mut map = HashMap::new();
        b.iter(|| {
            let key = fastrand::u64(..).to_string();
            let value = fastrand::u64(..);
            black_box(map.insert(key, value));
        });
    });
    
    group.bench_function("dashmap_insert", |b| {
        let map = dashmap::DashMap::new();
        b.iter(|| {
            let key = fastrand::u64(..).to_string();
            let value = fastrand::u64(..);
            black_box(map.insert(key, value));
        });
    });
    
    // Benchmark string operations
    group.bench_function("string_format", |b| {
        b.iter(|| {
            let id = fastrand::u64(..);
            let name = "service";
            black_box(format!("{}:{}", name, id));
        });
    });
    
    group.bench_function("string_concat", |b| {
        b.iter(|| {
            let id = fastrand::u64(..).to_string();
            let name = "service";
            let mut result = String::with_capacity(name.len() + 1 + id.len());
            result.push_str(name);
            result.push(':');
            result.push_str(&id);
            black_box(result);
        });
    });
    
    group.finish();
}

/// Benchmark serialization performance
fn benchmark_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");
    
    let service = create_test_service("benchmark-service", 8080);
    let services: Vec<ServiceInstance> = (0..100)
        .map(|i| create_test_service(&format!("service-{}", i), 8080 + i as u16))
        .collect();
    
    group.bench_function("json_serialize_single", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(&service).unwrap())
        });
    });
    
    group.bench_function("json_serialize_vec", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(&services).unwrap())
        });
    });
    
    let json_single = serde_json::to_string(&service).unwrap();
    let json_vec = serde_json::to_string(&services).unwrap();
    
    group.bench_function("json_deserialize_single", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<ServiceInstance>(&json_single).unwrap())
        });
    });
    
    group.bench_function("json_deserialize_vec", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<Vec<ServiceInstance>>(&json_vec).unwrap())
        });
    });
    
    group.finish();
}

/// Benchmark concurrent operations
fn benchmark_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_operations");
    
    // Benchmark concurrent load balancer access
    group.bench_function("concurrent_load_balancing", |b| {
        let balancer = Arc::new(RoundRobinBalancer::new());
        let instances: Arc<Vec<ServiceInstance>> = Arc::new(
            (0..50)
                .map(|i| create_test_service(&format!("service-{}", i), 8080 + i as u16))
                .collect()
        );
        
        b.to_async(&rt).iter(|| async {
            let handles: Vec<_> = (0..10).map(|_| {
                let balancer = balancer.clone();
                let instances = instances.clone();
                tokio::spawn(async move {
                    let request = create_test_request("/api/test");
                    balancer.select_instance(&instances, &request).await
                })
            }).collect();
            
            for handle in handles {
                let _ = black_box(handle.await);
            }
        });
    });
    
    // Benchmark concurrent cache access
    let cache_config = CacheConfig {
        in_memory_enabled: true,
        in_memory: InMemoryCacheConfig {
            max_entries: 10000,
            max_memory_bytes: 100 * 1024 * 1024,
            cleanup_interval: Duration::from_secs(60),
        },
        redis_enabled: false,
        redis: RedisCacheConfig {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout: Duration::from_secs(5),
            key_prefix: "gateway:".to_string(),
            cluster_mode: false,
        },
        default_ttl: Duration::from_secs(300),
        max_key_length: 250,
        operation_timeout: Duration::from_secs(1),
        enable_stats: true,
    };
    
    let cache_manager = rt.block_on(async {
        Arc::new(CacheManager::new(cache_config).await.unwrap())
    });
    
    group.bench_function("concurrent_cache_operations", |b| {
        b.to_async(&rt).iter(|| async {
            let handles: Vec<_> = (0..10).map(|i| {
                let cache = cache_manager.clone();
                tokio::spawn(async move {
                    let key = format!("concurrent_key_{}", i);
                    let value = format!("value_{}", i).into_bytes();
                    let _ = cache.set(&key, value, Some(Duration::from_secs(60))).await;
                    let _ = cache.get(&key).await;
                })
            }).collect();
            
            for handle in handles {
                let _ = black_box(handle.await);
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_route_matching,
    benchmark_load_balancing,
    benchmark_connection_pool,
    benchmark_caching,
    benchmark_memory_allocation,
    benchmark_serialization,
    benchmark_concurrent_operations
);

criterion_main!(benches);
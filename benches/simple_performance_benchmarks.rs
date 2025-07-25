//! # Simple Performance Benchmarks
//!
//! This module contains synchronous performance benchmarks for the API Gateway
//! focusing on memory optimization and zero-copy operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;

// Import gateway modules
use api_gateway::core::types::{ServiceInstance, HealthStatus, Protocol};
use api_gateway::core::memory_optimization::{MemoryOptimizer, StringInterner, ZeroCopyBuffer};
use api_gateway::core::zero_copy::{ZeroCopyHeaderMap, ZeroCopyPath, ZeroCopyQueryParams, ZeroCopyHeaderValue, string_pool};
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

/// Benchmark route matching performance
fn benchmark_route_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_matching");
    
    // Create router with different numbers of routes
    let route_counts = [10, 100, 1000];
    
    for &route_count in &route_counts {
        let mut router_builder = RouterBuilder::new();
        
        // Add routes with different patterns
        for i in 0..route_count {
            let path = format!("/api/service{}/endpoint", i);
            router_builder = router_builder.get(&path, &format!("service-{}", i));
        }
        
        let router = router_builder.build();
        
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("exact_match", route_count),
            &route_count,
            |b, &_route_count| {
                b.iter(|| {
                    // Create a minimal request for benchmarking
                    use http::{Method, Uri, Version, HeaderMap};
                    let uri: Uri = "/api/service500/endpoint".parse().unwrap();
                    let request = api_gateway::core::types::IncomingRequest::new(
                        Protocol::Http,
                        Method::GET,
                        uri,
                        Version::HTTP_11,
                        HeaderMap::new(),
                        Vec::new(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                    );
                    black_box(router.match_route(black_box(&request)))
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("no_match", route_count),
            &route_count,
            |b, &_route_count| {
                b.iter(|| {
                    // Create a minimal request for benchmarking
                    use http::{Method, Uri, Version, HeaderMap};
                    let uri: Uri = "/api/nonexistent/path".parse().unwrap();
                    let request = api_gateway::core::types::IncomingRequest::new(
                        Protocol::Http,
                        Method::GET,
                        uri,
                        Version::HTTP_11,
                        HeaderMap::new(),
                        Vec::new(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                    );
                    black_box(router.match_route(black_box(&request)))
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark memory optimization features
fn benchmark_memory_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_optimization");
    
    // Benchmark string interning
    group.bench_function("string_interning", |b| {
        let interner = StringInterner::new(10000);
        let strings = [
            "content-type", "application/json", "authorization", "bearer",
            "x-request-id", "x-correlation-id", "user-agent", "mozilla",
        ];
        
        b.iter(|| {
            for s in &strings {
                let _interned = black_box(interner.intern(s));
            }
        });
    });
    
    // Benchmark zero-copy buffer operations
    group.bench_function("zero_copy_buffer", |b| {
        let data = vec![1u8; 1024];
        
        b.iter(|| {
            let buffer = ZeroCopyBuffer::from_vec(black_box(data.clone()));
            let (left, right) = buffer.split_at(512);
            black_box((left, right));
        });
    });
    
    // Benchmark Arc vs direct allocation
    group.bench_function("arc_clone", |b| {
        let data = Arc::new(vec![1u8; 1024]);
        b.iter(|| {
            let _cloned = black_box(data.clone());
        });
    });
    
    group.bench_function("vec_clone", |b| {
        let data = vec![1u8; 1024];
        b.iter(|| {
            let _cloned = black_box(data.clone());
        });
    });
    
    group.finish();
}

/// Benchmark zero-copy operations
fn benchmark_zero_copy_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy");
    
    // Benchmark path parsing
    group.bench_function("path_parsing", |b| {
        let path_bytes = Bytes::from("/api/users/123/posts/456?name=john&age=30");
        
        b.iter(|| {
            let path = ZeroCopyPath::parse(black_box(path_bytes.clone()));
            black_box(path);
        });
    });
    
    // Benchmark query parameter parsing
    group.bench_function("query_param_parsing", |b| {
        let query_bytes = Bytes::from("name=john&age=30&city=new_york&active=true");
        
        b.iter(|| {
            let params = ZeroCopyQueryParams::parse(black_box(query_bytes.clone()));
            black_box(params);
        });
    });
    
    // Benchmark header map operations
    group.bench_function("header_map_operations", |b| {
        let mut headers = ZeroCopyHeaderMap::new();
        
        b.iter(|| {
            let name = Bytes::from_static(b"content-type");
            let value = ZeroCopyHeaderValue::from_static("application/json");
            headers.insert(black_box(name), black_box(value));
            
            let retrieved = headers.get(b"content-type");
            black_box(retrieved);
        });
    });
    
    // Benchmark string pool access
    group.bench_function("string_pool_access", |b| {
        let pool = string_pool();
        
        b.iter(|| {
            let method = &pool.get;
            let content_type = &pool.json_content_type;
            black_box((method, content_type));
        });
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    
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
    
    // Benchmark bytes vs string operations
    group.bench_function("bytes_clone", |b| {
        let data = Bytes::from_static(b"hello world this is a test string");
        b.iter(|| {
            let _cloned = black_box(data.clone());
        });
    });
    
    group.bench_function("string_clone", |b| {
        let data = "hello world this is a test string".to_string();
        b.iter(|| {
            let _cloned = black_box(data.clone());
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

criterion_group!(
    benches,
    benchmark_route_matching,
    benchmark_memory_optimization,
    benchmark_zero_copy_operations,
    benchmark_memory_allocation,
    benchmark_serialization
);

criterion_main!(benches);
//! # Hot Path Benchmarks
//!
//! Benchmarks for identifying and optimizing hot paths in the API Gateway.
//! These benchmarks focus on the most performance-critical code paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use bytes::Bytes;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;

// Import gateway modules
use api_gateway::core::profiler::{PerformanceProfiler, ProfilerConfig};
use api_gateway::core::connection_pool::{ConnectionPoolManager, ConnectionPoolConfig};
use api_gateway::core::memory_optimization::{MemoryOptimizer, MemoryConfig, OptimizedArc};
use api_gateway::core::zero_copy::{ZeroCopyBytes, ZeroCopyBuilder, ZeroCopyUtils, ZeroCopyConfig};
use api_gateway::core::types::{ServiceInstance, HealthStatus, Protocol};

/// Create a test service instance
fn create_test_service(id: &str, port: u16) -> ServiceInstance {
    ServiceInstance {
        id: id.to_string(),
        name: format!("test-service-{}", id),
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        metadata: HashMap::new(),
        health_status: HealthStatus::Healthy,
        protocol: Protocol::Http,
        weight: 1,
        last_health_check: None,
    }
}

/// Benchmark request routing hot path
fn benchmark_request_routing_hot_path(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hot_path_routing");
    
    // Test different request sizes
    for request_size in [1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*request_size as u64));
        
        let request_data = vec![0u8; *request_size];
        let zero_copy_data = ZeroCopyBytes::from_slice(&request_data);
        
        group.bench_with_input(
            BenchmarkId::new("zero_copy_routing", request_size),
            request_size,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        // Simulate hot path: request parsing and routing
                        let _parsed_request = black_box(zero_copy_data.clone());
                        
                        // Simulate path matching (hot path)
                        let path = "/api/v1/users/123/profile";
                        let _matched = black_box(path.starts_with("/api/v1"));
                        
                        // Simulate header processing (hot path)
                        let headers = vec![
                            ("content-type", "application/json"),
                            ("authorization", "Bearer token123"),
                            ("x-request-id", "req-456"),
                        ];
                        let _processed_headers = black_box(headers.len());
                    })
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark connection pool hot path
fn benchmark_connection_pool_hot_path(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hot_path_connection_pool");
    
    let config = ConnectionPoolConfig::default();
    let pool_manager = Arc::new(ConnectionPoolManager::new(config));
    let service = create_test_service("hot-path-test", 8080);
    
    // Pre-warm the pool
    rt.block_on(async {
        for _ in 0..10 {
            let conn = pool_manager.get_connection(&service).await.unwrap();
            pool_manager.return_connection(&service, conn).await;
        }
    });
    
    group.bench_function("get_return_connection", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Hot path: get connection from pool
                let connection = black_box(pool_manager.get_connection(&service).await.unwrap());
                
                // Simulate using connection (hot path)
                let _connection_id = black_box(&connection.connection_id);
                
                // Hot path: return connection to pool
                pool_manager.return_connection(&service, connection).await;
            })
        })
    });
    
    group.finish();
}

/// Benchmark memory allocation hot path
fn benchmark_memory_allocation_hot_path(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hot_path_memory");
    
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    // Test different allocation sizes
    for size in [1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("buffer_allocation", size),
            size,
            |b, &size| {
                b.iter(|| {
                    rt.block_on(async {
                        // Hot path: buffer allocation
                        let buffer = black_box(memory_optimizer.buffer_manager.get_buffer(size));
                        
                        // Simulate buffer usage (hot path)
                        let _capacity = black_box(buffer.capacity());
                        
                        // Hot path: buffer return
                        memory_optimizer.buffer_manager.return_buffer(buffer);
                    })
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark zero-copy operations hot path
fn benchmark_zero_copy_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path_zero_copy");
    
    // Test different data sizes
    for size in [1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let data = vec![0u8; *size];
        let zero_copy_data = ZeroCopyBytes::from_slice(&data);
        
        group.bench_with_input(
            BenchmarkId::new("slice_operations", size),
            size,
            |b, &size| {
                b.iter(|| {
                    // Hot path: zero-copy slicing
                    let mid = size / 2;
                    let _left = black_box(zero_copy_data.slice(0, mid).unwrap());
                    let _right = black_box(zero_copy_data.slice(mid, size).unwrap());
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("builder_operations", size),
            size,
            |b, &size| {
                b.iter(|| {
                    // Hot path: zero-copy building
                    let mut builder = ZeroCopyBuilder::new();
                    let chunk_size = size / 4;
                    
                    for i in 0..4 {
                        let start = i * chunk_size;
                        let end = if i == 3 { size } else { (i + 1) * chunk_size };
                        let chunk = zero_copy_data.slice(start, end).unwrap();
                        builder.push(chunk);
                    }
                    
                    let _result = black_box(builder.build());
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark Arc optimization hot path
fn benchmark_arc_optimization_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path_arc_optimization");
    
    // Test different data types
    let string_data = "Hello, World! This is a test string for Arc optimization.".to_string();
    let vec_data = vec![1u32; 1000];
    let bytes_data = Bytes::from_static(b"Static bytes data for testing Arc optimization performance");
    
    group.bench_function("optimized_arc_string", |b| {
        b.iter(|| {
            // Hot path: OptimizedArc creation and cloning
            let arc1 = black_box(OptimizedArc::new(string_data.clone()));
            let arc2 = black_box(arc1.clone());
            let arc3 = black_box(arc2.clone());
            
            // Hot path: reference counting checks
            let _ref_count = black_box(arc1.ref_count());
            let _is_unique = black_box(arc3.is_unique());
        })
    });
    
    group.bench_function("optimized_arc_vec", |b| {
        b.iter(|| {
            // Hot path: OptimizedArc with Vec
            let arc1 = black_box(OptimizedArc::new(vec_data.clone()));
            let arc2 = black_box(arc1.clone());
            
            // Hot path: accessing data
            let _len = black_box(arc1.len());
            let _first = black_box(arc2.get(0));
        })
    });
    
    group.bench_function("optimized_arc_bytes", |b| {
        b.iter(|| {
            // Hot path: OptimizedArc with Bytes
            let arc1 = black_box(OptimizedArc::new(bytes_data.clone()));
            let arc2 = black_box(arc1.clone());
            
            // Hot path: bytes operations
            let _len = black_box(arc1.len());
            let _slice = black_box(arc2.slice(0..10));
        })
    });
    
    group.finish();
}

/// Benchmark profiler overhead
fn benchmark_profiler_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hot_path_profiler_overhead");
    
    let profiler = Arc::new(PerformanceProfiler::default());
    
    // Benchmark without profiling
    group.bench_function("without_profiling", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate some work
                let data = black_box(vec![1u32; 100]);
                let _sum: u32 = black_box(data.iter().sum());
            })
        })
    });
    
    // Benchmark with profiling
    group.bench_function("with_profiling", |b| {
        b.iter(|| {
            rt.block_on(async {
                let start = std::time::Instant::now();
                
                // Simulate some work
                let data = black_box(vec![1u32; 100]);
                let _sum: u32 = black_box(data.iter().sum());
                
                let duration = start.elapsed();
                profiler.record_execution("test_function".to_string(), duration).await;
            })
        })
    });
    
    group.finish();
}

/// Benchmark request processing pipeline hot path
fn benchmark_request_pipeline_hot_path(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hot_path_request_pipeline");
    
    // Setup components
    let connection_pool = Arc::new(ConnectionPoolManager::new(ConnectionPoolConfig::default()));
    let memory_optimizer = Arc::new(MemoryOptimizer::new(MemoryConfig::default()));
    let service = create_test_service("pipeline-test", 8080);
    
    group.bench_function("full_request_pipeline", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Hot path: request parsing
                let request_data = black_box(b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n");
                let zero_copy_request = black_box(ZeroCopyBytes::from_slice(request_data));
                
                // Hot path: header parsing
                let _headers = black_box(parse_headers(&zero_copy_request));
                
                // Hot path: route matching
                let path = "/api/v1/users";
                let _route_matched = black_box(path.starts_with("/api/v1"));
                
                // Hot path: get buffer for response
                let response_buffer = memory_optimizer.buffer_manager.get_buffer(4096);
                
                // Hot path: get connection
                let service = create_test_service("pipeline", 8080);
                let connection = connection_pool.get_connection(&service).await.unwrap();
                
                // Simulate processing
                tokio::time::sleep(Duration::from_nanos(1)).await;
                
                // Hot path: return resources
                connection_pool.return_connection(&service, connection).await;
                memory_optimizer.buffer_manager.return_buffer(response_buffer);
            })
        })
    });
    
    group.finish();
}

/// Simple header parsing for benchmarking
fn parse_headers(data: &ZeroCopyBytes) -> Vec<(&str, &str)> {
    // Simplified header parsing for benchmarking
    vec![
        ("host", "example.com"),
        ("user-agent", "test-client"),
        ("accept", "application/json"),
    ]
}

criterion_group!(
    benches,
    benchmark_request_routing_hot_path,
    benchmark_connection_pool_hot_path,
    benchmark_memory_allocation_hot_path,
    benchmark_zero_copy_hot_path,
    benchmark_arc_optimization_hot_path,
    benchmark_profiler_overhead,
    benchmark_request_pipeline_hot_path,
);
criterion_main!(benches);
//! # Performance Optimization Benchmarks
//!
//! Comprehensive benchmarks for measuring the performance impact of various
//! optimizations in the API Gateway including connection pooling, memory
//! optimization, and zero-copy operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use bytes::{Bytes, BytesMut};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;

// Import gateway modules
use api_gateway::core::connection_pool::{ConnectionPoolManager, ConnectionPoolConfig};
use api_gateway::core::memory_optimization::{
    MemoryOptimizer, MemoryConfig, OptimizedArc, ZeroCopyBuffer, BufferManager, BufferReuseConfig
};
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

/// Benchmark connection pool performance
fn benchmark_connection_pool(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("connection_pool");
    
    // Test different pool sizes
    for pool_size in [10, 50, 100, 200].iter() {
        let config = ConnectionPoolConfig {
            max_connections_per_service: *pool_size,
            max_idle_time: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(90),
            enable_http2: true,
            cleanup_interval: Duration::from_secs(30),
        };
        
        let pool_manager = Arc::new(ConnectionPoolManager::new(config));
        let service = create_test_service("bench", 8080);
        
        group.bench_with_input(
            BenchmarkId::new("get_connection", pool_size),
            pool_size,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        let connection = pool_manager.get_connection(&service).await.unwrap();
                        pool_manager.return_connection(&service, connection).await;
                    })
                });
            },
        );
    }
    
    // Benchmark concurrent connection access
    group.bench_function("concurrent_access", |b| {
        let config = ConnectionPoolConfig::default();
        let pool_manager = Arc::new(ConnectionPoolManager::new(config));
        let service = create_test_service("concurrent", 8080);
        
        b.iter(|| {
            rt.block_on(async {
                let handles: Vec<_> = (0..10).map(|_| {
                    let pool = pool_manager.clone();
                    let svc = service.clone();
                    tokio::spawn(async move {
                        let connection = pool.get_connection(&svc).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        pool.return_connection(&svc, connection).await;
                    })
                }).collect();
                
                for handle in handles {
                    handle.await.unwrap();
                }
            })
        });
    });
    
    group.finish();
}

/// Benchmark memory optimization features
fn benchmark_memory_optimization(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("memory_optimization");
    
    // Benchmark OptimizedArc vs regular Arc
    group.bench_function("optimized_arc_creation", |b| {
        b.iter(|| {
            let data = vec![0u8; 1024];
            let _arc = OptimizedArc::new(black_box(data));
        });
    });
    
    group.bench_function("regular_arc_creation", |b| {
        b.iter(|| {
            let data = vec![0u8; 1024];
            let _arc = Arc::new(black_box(data));
        });
    });
    
    // Benchmark buffer manager
    let config = BufferReuseConfig::default();
    let buffer_manager = Arc::new(BufferManager::new(config));
    
    group.bench_function("buffer_manager_get_return", |b| {
        b.iter(|| {
            let buffer = buffer_manager.get_buffer(4096);
            buffer_manager.return_buffer(buffer);
        });
    });
    
    group.bench_function("direct_buffer_allocation", |b| {
        b.iter(|| {
            let _buffer = BytesMut::with_capacity(black_box(4096));
        });
    });
    
    // Benchmark zero-copy buffer operations
    let test_data = vec![0u8; 8192];
    let zero_copy_buffer = ZeroCopyBuffer::from_slice(&test_data);
    
    group.bench_function("zero_copy_slice", |b| {
        b.iter(|| {
            let _slice = zero_copy_buffer.slice(black_box(1024), black_box(2048)).unwrap();
        });
    });
    
    group.bench_function("regular_slice_copy", |b| {
        b.iter(|| {
            let start = black_box(1024);
            let end = black_box(2048);
            let _slice = test_data[start..end].to_vec();
        });
    });
    
    group.finish();
}

/// Benchmark zero-copy operations
fn benchmark_zero_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy");
    
    // Test different data sizes
    for size in [1024, 4096, 16384, 65536].iter() {
        let test_data = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Benchmark zero-copy bytes creation
        group.bench_with_input(
            BenchmarkId::new("zero_copy_from_slice", size),
            size,
            |b, _| {
                b.iter(|| {
                    let _bytes = ZeroCopyBytes::from_slice(black_box(&test_data));
                });
            },
        );
        
        // Benchmark regular bytes creation
        group.bench_with_input(
            BenchmarkId::new("regular_bytes_copy", size),
            size,
            |b, _| {
                b.iter(|| {
                    let _bytes = Bytes::copy_from_slice(black_box(&test_data));
                });
            },
        );
        
        // Benchmark zero-copy slicing
        let zero_copy_bytes = ZeroCopyBytes::from_slice(&test_data);
        group.bench_with_input(
            BenchmarkId::new("zero_copy_slice", size),
            size,
            |b, _| {
                b.iter(|| {
                    let mid = size / 2;
                    let _slice = zero_copy_bytes.slice(black_box(0), black_box(mid)).unwrap();
                });
            },
        );
    }
    
    // Benchmark zero-copy builder
    group.bench_function("zero_copy_builder", |b| {
        let chunks: Vec<_> = (0..10).map(|i| {
            ZeroCopyBytes::from_slice(&vec![i as u8; 1024])
        }).collect();
        
        b.iter(|| {
            let mut builder = ZeroCopyBuilder::new();
            for chunk in &chunks {
                builder.push(black_box(chunk.clone()));
            }
            let _result = builder.build();
        });
    });
    
    // Benchmark zero-copy concatenation
    group.bench_function("zero_copy_concat", |b| {
        let bytes1 = ZeroCopyBytes::from_slice(&vec![1u8; 4096]);
        let bytes2 = ZeroCopyBytes::from_slice(&vec![2u8; 4096]);
        
        b.iter(|| {
            let _result = bytes1.concat(black_box(&bytes2));
        });
    });
    
    // Benchmark zero-copy utilities
    let large_data = ZeroCopyBytes::from_slice(&vec![0u8; 32768]);
    group.bench_function("zero_copy_chunking", |b| {
        b.iter(|| {
            let _chunks = ZeroCopyUtils::chunk_data(black_box(large_data.clone()), black_box(4096));
        });
    });
    
    group.finish();
}

/// Benchmark request processing pipeline with optimizations
fn benchmark_request_pipeline(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("request_pipeline");
    
    // Setup optimized components
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    let pool_config = ConnectionPoolConfig::default();
    let connection_pool = Arc::new(ConnectionPoolManager::new(pool_config));
    
    let zero_copy_config = ZeroCopyConfig::default();
    
    // Benchmark optimized vs non-optimized request processing
    group.bench_function("optimized_request_processing", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate request processing with optimizations
                let request_data = vec![0u8; 4096];
                
                // Use zero-copy for request data
                let zero_copy_request = ZeroCopyBytes::from_slice(&request_data);
                
                // Use buffer manager for response
                let response_buffer = memory_optimizer.buffer_manager.get_buffer(4096);
                
                // Use connection pool
                let service = create_test_service("pipeline", 8080);
                let connection = connection_pool.get_connection(&service).await.unwrap();
                
                // Simulate processing
                tokio::time::sleep(Duration::from_micros(100)).await;
                
                // Return resources
                connection_pool.return_connection(&service, connection).await;
                memory_optimizer.buffer_manager.return_buffer(response_buffer);
                
                black_box(zero_copy_request);
            })
        });
    });
    
    group.bench_function("non_optimized_request_processing", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate request processing without optimizations
                let request_data = vec![0u8; 4096];
                
                // Regular copy for request data
                let _request_copy = request_data.clone();
                
                // Direct buffer allocation for response
                let _response_buffer = BytesMut::with_capacity(4096);
                
                // Simulate processing
                tokio::time::sleep(Duration::from_micros(100)).await;
                
                black_box(request_data);
            })
        });
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");
    
    // Benchmark different allocation strategies
    group.bench_function("frequent_small_allocations", |b| {
        b.iter(|| {
            let mut buffers = Vec::new();
            for _ in 0..100 {
                buffers.push(vec![0u8; black_box(64)]);
            }
            black_box(buffers);
        });
    });
    
    group.bench_function("pooled_small_allocations", |b| {
        let config = BufferReuseConfig::default();
        let buffer_manager = BufferManager::new(config);
        
        b.iter(|| {
            let mut buffers = Vec::new();
            for _ in 0..100 {
                let buffer = buffer_manager.get_buffer(black_box(64));
                buffers.push(buffer);
            }
            // Buffers are returned to pool when dropped
            black_box(buffers);
        });
    });
    
    // Benchmark Arc vs OptimizedArc for shared data
    group.bench_function("arc_cloning", |b| {
        let data = Arc::new(vec![0u8; 1024]);
        b.iter(|| {
            let mut clones = Vec::new();
            for _ in 0..10 {
                clones.push(data.clone());
            }
            black_box(clones);
        });
    });
    
    group.bench_function("optimized_arc_cloning", |b| {
        let data = OptimizedArc::new(vec![0u8; 1024]);
        b.iter(|| {
            let mut clones = Vec::new();
            for _ in 0..10 {
                clones.push(data.clone_or_arc());
            }
            black_box(clones);
        });
    });
    
    group.finish();
}

/// Benchmark hot path operations
fn benchmark_hot_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_paths");
    
    // Benchmark header parsing (common hot path)
    group.bench_function("header_parsing_optimized", |b| {
        let headers_data = b"Content-Type: application/json\r\nContent-Length: 1024\r\nAuthorization: Bearer token123\r\n\r\n";
        let zero_copy_headers = ZeroCopyBytes::from_slice(headers_data);
        
        b.iter(|| {
            // Simulate optimized header parsing using zero-copy
            let mut headers = HashMap::new();
            let header_str = std::str::from_utf8(zero_copy_headers.as_slice()).unwrap();
            
            for line in header_str.lines() {
                if let Some((key, value)) = line.split_once(": ") {
                    headers.insert(key, value);
                }
            }
            
            black_box(headers);
        });
    });
    
    group.bench_function("header_parsing_regular", |b| {
        let headers_data = b"Content-Type: application/json\r\nContent-Length: 1024\r\nAuthorization: Bearer token123\r\n\r\n";
        
        b.iter(|| {
            // Simulate regular header parsing with copying
            let mut headers = HashMap::new();
            let header_str = String::from_utf8(headers_data.to_vec()).unwrap();
            
            for line in header_str.lines() {
                if let Some((key, value)) = line.split_once(": ") {
                    headers.insert(key.to_string(), value.to_string());
                }
            }
            
            black_box(headers);
        });
    });
    
    // Benchmark route matching (another hot path)
    group.bench_function("route_matching", |b| {
        let routes = vec![
            "/api/v1/users",
            "/api/v1/users/{id}",
            "/api/v1/posts",
            "/api/v1/posts/{id}",
            "/api/v1/comments",
            "/health",
            "/metrics",
            "/admin/config",
        ];
        
        let test_path = "/api/v1/users/123";
        
        b.iter(|| {
            // Simulate route matching
            let mut matched = false;
            for route in &routes {
                if route.contains("{id}") {
                    let pattern = route.replace("{id}", "123");
                    if pattern == test_path {
                        matched = true;
                        break;
                    }
                } else if *route == test_path {
                    matched = true;
                    break;
                }
            }
            black_box(matched);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_connection_pool,
    benchmark_memory_optimization,
    benchmark_zero_copy,
    benchmark_request_pipeline,
    benchmark_memory_patterns,
    benchmark_hot_paths
);

criterion_main!(benches);
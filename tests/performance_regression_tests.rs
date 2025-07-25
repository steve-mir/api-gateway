//! # Performance Regression Tests
//!
//! These tests ensure that performance optimizations don't regress over time
//! and that the gateway maintains acceptable performance characteristics.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::time::timeout;

use api_gateway::core::connection_pool::{ConnectionPoolManager, ConnectionPoolConfig};
use api_gateway::core::memory_optimization::{
    MemoryOptimizer, MemoryConfig, OptimizedArc, BufferManager, BufferReuseConfig
};
use api_gateway::core::zero_copy::{ZeroCopyBytes, ZeroCopyBuilder, ZeroCopyUtils, ZeroCopyConfig};
use api_gateway::core::types::{ServiceInstance, HealthStatus, Protocol};

/// Performance test configuration
struct PerformanceTestConfig {
    /// Maximum acceptable duration for operations
    max_duration: Duration,
    /// Number of iterations for performance tests
    iterations: usize,
    /// Concurrency level for concurrent tests
    concurrency: usize,
    /// Memory usage tolerance (bytes)
    memory_tolerance: usize,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_millis(100),
            iterations: 1000,
            concurrency: 10,
            memory_tolerance: 1024 * 1024, // 1MB
        }
    }
}

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

/// Test connection pool performance doesn't regress
#[tokio::test]
async fn test_connection_pool_performance_regression() {
    let config = PerformanceTestConfig::default();
    
    let pool_config = ConnectionPoolConfig {
        max_connections_per_service: 50,
        max_idle_time: Duration::from_secs(60),
        connection_timeout: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(90),
        enable_http2: true,
        cleanup_interval: Duration::from_secs(30),
    };
    
    let pool_manager = Arc::new(ConnectionPoolManager::new(pool_config));
    let service = create_test_service("perf-test", 8080);
    
    // Test single-threaded performance
    let start_time = Instant::now();
    for _ in 0..config.iterations {
        let connection = pool_manager.get_connection(&service).await.unwrap();
        pool_manager.return_connection(&service, connection).await;
    }
    let single_threaded_duration = start_time.elapsed();
    
    println!("Connection pool single-threaded: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             single_threaded_duration,
             config.iterations as f64 / single_threaded_duration.as_secs_f64());
    
    // Performance regression check
    let max_acceptable_duration = Duration::from_millis(config.iterations as u64 * 2); // 2ms per operation
    assert!(single_threaded_duration < max_acceptable_duration, 
            "Connection pool performance regression: took {:?}, expected < {:?}", 
            single_threaded_duration, max_acceptable_duration);
    
    // Test concurrent performance
    let start_time = Instant::now();
    let handles: Vec<_> = (0..config.concurrency).map(|_| {
        let pool = pool_manager.clone();
        let svc = service.clone();
        let iterations = config.iterations / config.concurrency;
        
        tokio::spawn(async move {
            for _ in 0..iterations {
                let connection = pool.get_connection(&svc).await.unwrap();
                pool.return_connection(&svc, connection).await;
            }
        })
    }).collect();
    
    for handle in handles {
        handle.await.unwrap();
    }
    let concurrent_duration = start_time.elapsed();
    
    println!("Connection pool concurrent: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             concurrent_duration,
             config.iterations as f64 / concurrent_duration.as_secs_f64());
    
    // Concurrent performance should be better than single-threaded
    assert!(concurrent_duration < single_threaded_duration * 2, 
            "Concurrent performance regression: took {:?}, single-threaded took {:?}", 
            concurrent_duration, single_threaded_duration);
}

/// Test memory optimization performance doesn't regress
#[tokio::test]
async fn test_memory_optimization_performance_regression() {
    let config = PerformanceTestConfig::default();
    
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    // Test buffer manager performance
    let start_time = Instant::now();
    for _ in 0..config.iterations {
        let buffer = memory_optimizer.buffer_manager.get_buffer(4096);
        memory_optimizer.buffer_manager.return_buffer(buffer);
    }
    let buffer_duration = start_time.elapsed();
    
    println!("Buffer manager: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             buffer_duration,
             config.iterations as f64 / buffer_duration.as_secs_f64());
    
    // Buffer operations should be very fast
    let max_buffer_duration = Duration::from_millis(config.iterations as u64 / 10); // 0.1ms per operation
    assert!(buffer_duration < max_buffer_duration, 
            "Buffer manager performance regression: took {:?}, expected < {:?}", 
            buffer_duration, max_buffer_duration);
    
    // Test OptimizedArc performance
    let start_time = Instant::now();
    for _ in 0..config.iterations {
        let data = vec![0u8; 1024];
        let arc = OptimizedArc::new(data);
        let _cloned = arc.clone_or_arc();
    }
    let arc_duration = start_time.elapsed();
    
    println!("OptimizedArc: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             arc_duration,
             config.iterations as f64 / arc_duration.as_secs_f64());
    
    // Arc operations should be fast
    let max_arc_duration = Duration::from_millis(config.iterations as u64); // 1ms per operation
    assert!(arc_duration < max_arc_duration, 
            "OptimizedArc performance regression: took {:?}, expected < {:?}", 
            arc_duration, max_arc_duration);
}

/// Test zero-copy operations performance doesn't regress
#[tokio::test]
async fn test_zero_copy_performance_regression() {
    let config = PerformanceTestConfig::default();
    
    let test_data = vec![0u8; 8192];
    
    // Test zero-copy bytes creation
    let start_time = Instant::now();
    for _ in 0..config.iterations {
        let _bytes = ZeroCopyBytes::from_slice(&test_data);
    }
    let creation_duration = start_time.elapsed();
    
    println!("ZeroCopyBytes creation: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             creation_duration,
             config.iterations as f64 / creation_duration.as_secs_f64());
    
    // Zero-copy creation should be very fast
    let max_creation_duration = Duration::from_millis(config.iterations as u64 / 100); // 0.01ms per operation
    assert!(creation_duration < max_creation_duration, 
            "ZeroCopyBytes creation performance regression: took {:?}, expected < {:?}", 
            creation_duration, max_creation_duration);
    
    // Test zero-copy slicing
    let zero_copy_bytes = ZeroCopyBytes::from_slice(&test_data);
    let start_time = Instant::now();
    for i in 0..config.iterations {
        let start = i % 4096;
        let end = start + 1024;
        let _slice = zero_copy_bytes.slice(start, end).unwrap();
    }
    let slicing_duration = start_time.elapsed();
    
    println!("ZeroCopyBytes slicing: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             slicing_duration,
             config.iterations as f64 / slicing_duration.as_secs_f64());
    
    // Slicing should be very fast (no data copying)
    let max_slicing_duration = Duration::from_millis(config.iterations as u64 / 50); // 0.02ms per operation
    assert!(slicing_duration < max_slicing_duration, 
            "ZeroCopyBytes slicing performance regression: took {:?}, expected < {:?}", 
            slicing_duration, max_slicing_duration);
    
    // Test zero-copy builder
    let chunks: Vec<_> = (0..10).map(|i| {
        ZeroCopyBytes::from_slice(&vec![i as u8; 1024])
    }).collect();
    
    let start_time = Instant::now();
    for _ in 0..config.iterations / 10 { // Fewer iterations for builder test
        let mut builder = ZeroCopyBuilder::new();
        for chunk in &chunks {
            builder.push(chunk.clone());
        }
        let _result = builder.build();
    }
    let builder_duration = start_time.elapsed();
    
    println!("ZeroCopyBuilder: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations / 10, 
             builder_duration,
             (config.iterations / 10) as f64 / builder_duration.as_secs_f64());
    
    // Builder operations should be reasonably fast
    let max_builder_duration = Duration::from_millis(config.iterations as u64 / 5); // 0.2ms per operation
    assert!(builder_duration < max_builder_duration, 
            "ZeroCopyBuilder performance regression: took {:?}, expected < {:?}", 
            builder_duration, max_builder_duration);
}

/// Test memory usage doesn't grow excessively
#[tokio::test]
async fn test_memory_usage_regression() {
    let config = PerformanceTestConfig::default();
    
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    // Record initial memory usage
    let initial_stats = memory_optimizer.get_stats();
    let initial_usage = initial_stats.memory_usage.current_usage;
    
    // Perform many operations that should not leak memory
    for _ in 0..config.iterations {
        // Buffer operations
        let buffer = memory_optimizer.buffer_manager.get_buffer(4096);
        memory_optimizer.buffer_manager.return_buffer(buffer);
        
        // Zero-copy operations
        let data = vec![0u8; 1024];
        let zero_copy = ZeroCopyBytes::from_slice(&data);
        let _slice = zero_copy.slice(0, 512).unwrap();
        
        // Arc operations
        let arc_data = OptimizedArc::new(vec![0u8; 512]);
        let _cloned = arc_data.clone_or_arc();
    }
    
    // Check final memory usage
    let final_stats = memory_optimizer.get_stats();
    let final_usage = final_stats.memory_usage.current_usage;
    let memory_growth = final_usage.saturating_sub(initial_usage);
    
    println!("Memory usage: initial={}, final={}, growth={}", 
             initial_usage, final_usage, memory_growth);
    
    // Memory growth should be within tolerance
    assert!(memory_growth < config.memory_tolerance, 
            "Memory usage regression: grew by {} bytes, tolerance is {} bytes", 
            memory_growth, config.memory_tolerance);
}

/// Test concurrent performance under load
#[tokio::test]
async fn test_concurrent_performance_regression() {
    let config = PerformanceTestConfig {
        iterations: 10000,
        concurrency: 50,
        ..Default::default()
    };
    
    let pool_config = ConnectionPoolConfig::default();
    let pool_manager = Arc::new(ConnectionPoolManager::new(pool_config));
    
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    let service = create_test_service("concurrent-test", 8080);
    
    // Test concurrent mixed operations
    let start_time = Instant::now();
    let handles: Vec<_> = (0..config.concurrency).map(|i| {
        let pool = pool_manager.clone();
        let memory = memory_optimizer.clone();
        let svc = service.clone();
        let iterations = config.iterations / config.concurrency;
        
        tokio::spawn(async move {
            for j in 0..iterations {
                // Mix of operations
                match j % 3 {
                    0 => {
                        // Connection pool operation
                        if let Ok(connection) = pool.get_connection(&svc).await {
                            pool.return_connection(&svc, connection).await;
                        }
                    }
                    1 => {
                        // Buffer operation
                        let buffer = memory.buffer_manager.get_buffer(4096);
                        memory.buffer_manager.return_buffer(buffer);
                    }
                    2 => {
                        // Zero-copy operation
                        let data = vec![(i + j) as u8; 1024];
                        let zero_copy = ZeroCopyBytes::from_slice(&data);
                        let _slice = zero_copy.slice(0, 512).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        })
    }).collect();
    
    // Wait for all tasks with timeout
    let result = timeout(Duration::from_secs(30), async {
        for handle in handles {
            handle.await.unwrap();
        }
    }).await;
    
    assert!(result.is_ok(), "Concurrent performance test timed out");
    
    let total_duration = start_time.elapsed();
    
    println!("Concurrent mixed operations: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             total_duration,
             config.iterations as f64 / total_duration.as_secs_f64());
    
    // Should complete within reasonable time
    let max_duration = Duration::from_secs(10);
    assert!(total_duration < max_duration, 
            "Concurrent performance regression: took {:?}, expected < {:?}", 
            total_duration, max_duration);
}

/// Test that optimizations provide measurable benefits
#[tokio::test]
async fn test_optimization_benefits() {
    let iterations = 1000;
    
    // Test buffer pooling vs direct allocation
    let buffer_config = BufferReuseConfig::default();
    let buffer_manager = BufferManager::new(buffer_config);
    
    // Measure pooled allocation
    let start_time = Instant::now();
    for _ in 0..iterations {
        let buffer = buffer_manager.get_buffer(4096);
        buffer_manager.return_buffer(buffer);
    }
    let pooled_duration = start_time.elapsed();
    
    // Measure direct allocation
    let start_time = Instant::now();
    for _ in 0..iterations {
        let _buffer = bytes::BytesMut::with_capacity(4096);
    }
    let direct_duration = start_time.elapsed();
    
    println!("Buffer allocation - Pooled: {:?}, Direct: {:?}, Ratio: {:.2}x", 
             pooled_duration, direct_duration, 
             pooled_duration.as_secs_f64() / direct_duration.as_secs_f64());
    
    // Pooled allocation should eventually be faster (after warmup)
    // For this test, we just ensure it's not significantly slower
    assert!(pooled_duration < direct_duration * 3, 
            "Buffer pooling is too slow compared to direct allocation");
    
    // Test zero-copy vs regular copy
    let test_data = vec![0u8; 8192];
    
    // Measure zero-copy slicing
    let zero_copy_bytes = ZeroCopyBytes::from_slice(&test_data);
    let start_time = Instant::now();
    for i in 0..iterations {
        let start = i % 4096;
        let end = start + 1024;
        let _slice = zero_copy_bytes.slice(start, end).unwrap();
    }
    let zero_copy_duration = start_time.elapsed();
    
    // Measure regular copying
    let start_time = Instant::now();
    for i in 0..iterations {
        let start = i % 4096;
        let end = start + 1024;
        let _slice = test_data[start..end].to_vec();
    }
    let copy_duration = start_time.elapsed();
    
    println!("Data slicing - Zero-copy: {:?}, Copy: {:?}, Ratio: {:.2}x", 
             zero_copy_duration, copy_duration, 
             copy_duration.as_secs_f64() / zero_copy_duration.as_secs_f64());
    
    // Zero-copy should be significantly faster
    assert!(zero_copy_duration < copy_duration, 
            "Zero-copy slicing should be faster than copying");
}

/// Test performance under memory pressure
#[tokio::test]
async fn test_performance_under_memory_pressure() {
    let config = PerformanceTestConfig {
        iterations: 5000,
        concurrency: 20,
        ..Default::default()
    };
    
    let memory_config = MemoryConfig::default();
    let memory_optimizer = Arc::new(MemoryOptimizer::new(memory_config));
    
    // Create memory pressure by allocating large objects
    let _large_objects: Vec<_> = (0..100).map(|_| vec![0u8; 1024 * 1024]).collect(); // 100MB
    
    // Test performance under memory pressure
    let start_time = Instant::now();
    let handles: Vec<_> = (0..config.concurrency).map(|_| {
        let memory = memory_optimizer.clone();
        let iterations = config.iterations / config.concurrency;
        
        tokio::spawn(async move {
            for _ in 0..iterations {
                let buffer = memory.buffer_manager.get_buffer(4096);
                
                // Simulate some work
                tokio::task::yield_now().await;
                
                memory.buffer_manager.return_buffer(buffer);
            }
        })
    }).collect();
    
    for handle in handles {
        handle.await.unwrap();
    }
    let pressure_duration = start_time.elapsed();
    
    println!("Performance under memory pressure: {} ops in {:?} ({:.2} ops/sec)", 
             config.iterations, 
             pressure_duration,
             config.iterations as f64 / pressure_duration.as_secs_f64());
    
    // Should still complete within reasonable time even under memory pressure
    let max_duration = Duration::from_secs(15);
    assert!(pressure_duration < max_duration, 
            "Performance degraded too much under memory pressure: took {:?}, expected < {:?}", 
            pressure_duration, max_duration);
}

/// Test that cleanup operations don't impact performance significantly
#[tokio::test]
async fn test_cleanup_performance_impact() {
    let pool_config = ConnectionPoolConfig {
        cleanup_interval: Duration::from_millis(100), // Frequent cleanup for testing
        ..Default::default()
    };
    let pool_manager = Arc::new(ConnectionPoolManager::new(pool_config));
    
    // Start cleanup task
    pool_manager.clone().start_cleanup_task();
    
    let service = create_test_service("cleanup-test", 8080);
    let iterations = 1000;
    
    // Measure performance with cleanup running
    let start_time = Instant::now();
    for _ in 0..iterations {
        let connection = pool_manager.get_connection(&service).await.unwrap();
        pool_manager.return_connection(&service, connection).await;
        
        // Occasionally sleep to let cleanup run
        if rand::random::<u8>() % 100 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    let with_cleanup_duration = start_time.elapsed();
    
    println!("Performance with cleanup: {} ops in {:?} ({:.2} ops/sec)", 
             iterations, 
             with_cleanup_duration,
             iterations as f64 / with_cleanup_duration.as_secs_f64());
    
    // Cleanup should not significantly impact performance
    let max_duration = Duration::from_secs(5);
    assert!(with_cleanup_duration < max_duration, 
            "Cleanup operations impacted performance too much: took {:?}, expected < {:?}", 
            with_cleanup_duration, max_duration);
}
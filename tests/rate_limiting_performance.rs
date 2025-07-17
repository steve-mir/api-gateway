//! # Rate Limiting Performance Tests
//!
//! This module contains comprehensive performance tests for the rate limiting system.
//! It tests various scenarios including:
//! - High concurrent load testing
//! - Different algorithm performance comparison
//! - Memory usage under load
//! - Distributed vs in-memory performance
//! - Burst handling capabilities
//!
//! ## Running Tests
//! ```bash
//! cargo test --release --test rate_limiting_performance
//! ```
//!
//! ## Benchmarking
//! ```bash
//! cargo bench --bench rate_limiting_bench
//! ```

use api_gateway::middleware::rate_limiting::{
    InMemoryStorage, RateLimitAlgorithmType, RateLimitConfig, RateLimitGranularity,
    RateLimitMiddleware, RedisStorage, TokenBucketAlgorithm, SlidingWindowAlgorithm,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

/// Test configuration for performance tests
struct PerformanceTestConfig {
    pub concurrent_requests: usize,
    pub requests_per_client: usize,
    pub rate_limit: u32,
    pub window_duration: Duration,
    pub test_duration: Duration,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            concurrent_requests: 100,
            requests_per_client: 1000,
            rate_limit: 1000,
            window_duration: Duration::from_secs(60),
            test_duration: Duration::from_secs(30),
        }
    }
}

/// Performance test results
#[derive(Debug)]
struct PerformanceTestResult {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub requests_per_second: f64,
    pub average_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub test_duration: Duration,
}

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();
}

/// Create a test rate limiter with specified configuration
async fn create_test_rate_limiter(
    algorithm: RateLimitAlgorithmType,
    distributed: bool,
) -> Arc<RateLimitMiddleware> {
    let config = RateLimitConfig {
        algorithm,
        requests_per_window: 1000,
        window_duration: Duration::from_secs(60),
        burst_size: Some(100),
        granularity: RateLimitGranularity::PerUser,
        distributed,
        redis_url: if distributed {
            Some("redis://localhost:6379".to_string())
        } else {
            None
        },
        key_prefix: "test".to_string(),
        admin_exemptions: vec![],
        endpoint_rules: Default::default(),
    };

    Arc::new(RateLimitMiddleware::new(config).await.unwrap())
}

/// Run a single performance test
async fn run_performance_test(
    rate_limiter: Arc<RateLimitMiddleware>,
    config: PerformanceTestConfig,
    test_name: &str,
) -> PerformanceTestResult {
    info!("Starting performance test: {}", test_name);
    
    let start_time = Instant::now();
    let mut join_set = JoinSet::new();
    let semaphore = Arc::new(Semaphore::new(config.concurrent_requests));
    
    let mut latencies = Vec::new();
    let mut total_requests = 0u64;
    let mut successful_requests = 0u64;
    
    // Spawn concurrent tasks
    for client_id in 0..config.concurrent_requests {
        let rate_limiter = rate_limiter.clone();
        let semaphore = semaphore.clone();
        let requests_per_client = config.requests_per_client;
        
        join_set.spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut client_latencies = Vec::new();
            let mut client_successful = 0u64;
            let mut client_total = 0u64;
            
            for request_id in 0..requests_per_client {
                let request_start = Instant::now();
                
                let result = rate_limiter
                    .check_rate_limit(
                        Some(&format!("user_{}", client_id)),
                        Some("test_service"),
                        Some("/api/test"),
                        "/api/test",
                    )
                    .await;
                
                let latency = request_start.elapsed();
                client_latencies.push(latency.as_micros() as f64 / 1000.0); // Convert to ms
                client_total += 1;
                
                if result.is_ok() && result.unwrap().allowed {
                    client_successful += 1;
                }
                
                // Small delay to simulate realistic request patterns
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
            
            (client_latencies, client_successful, client_total)
        });
    }
    
    // Collect results from all tasks
    while let Some(result) = join_set.join_next().await {
        if let Ok((client_latencies, client_successful, client_total)) = result {
            latencies.extend(client_latencies);
            successful_requests += client_successful;
            total_requests += client_total;
        }
    }
    
    let test_duration = start_time.elapsed();
    
    // Calculate statistics
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let average_latency_ms = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let p95_index = (latencies.len() as f64 * 0.95) as usize;
    let p99_index = (latencies.len() as f64 * 0.99) as usize;
    let p95_latency_ms = latencies.get(p95_index).copied().unwrap_or(0.0);
    let p99_latency_ms = latencies.get(p99_index).copied().unwrap_or(0.0);
    
    let requests_per_second = total_requests as f64 / test_duration.as_secs_f64();
    let failed_requests = total_requests - successful_requests;
    
    let result = PerformanceTestResult {
        total_requests,
        successful_requests,
        failed_requests,
        requests_per_second,
        average_latency_ms,
        p95_latency_ms,
        p99_latency_ms,
        test_duration,
    };
    
    info!(
        "Performance test '{}' completed: {} req/s, {:.2}ms avg latency, {:.2}% success rate",
        test_name,
        result.requests_per_second,
        result.average_latency_ms,
        (result.successful_requests as f64 / result.total_requests as f64) * 100.0
    );
    
    result
}

#[tokio::test]
async fn test_token_bucket_performance_in_memory() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    let config = PerformanceTestConfig::default();
    
    let result = run_performance_test(
        rate_limiter,
        config,
        "Token Bucket (In-Memory)"
    ).await;
    
    // Assertions for performance benchmarks
    assert!(result.requests_per_second > 1000.0, "Should handle at least 1000 req/s");
    assert!(result.average_latency_ms < 10.0, "Average latency should be under 10ms");
    assert!(result.p95_latency_ms < 50.0, "P95 latency should be under 50ms");
    assert!(result.successful_requests > 0, "Should have some successful requests");
}

#[tokio::test]
async fn test_sliding_window_performance_in_memory() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::SlidingWindow, false).await;
    let config = PerformanceTestConfig::default();
    
    let result = run_performance_test(
        rate_limiter,
        config,
        "Sliding Window (In-Memory)"
    ).await;
    
    // Assertions for performance benchmarks
    assert!(result.requests_per_second > 800.0, "Should handle at least 800 req/s");
    assert!(result.average_latency_ms < 15.0, "Average latency should be under 15ms");
    assert!(result.p95_latency_ms < 75.0, "P95 latency should be under 75ms");
    assert!(result.successful_requests > 0, "Should have some successful requests");
}

#[tokio::test]
#[ignore] // Requires Redis server
async fn test_token_bucket_performance_redis() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, true).await;
    let config = PerformanceTestConfig {
        concurrent_requests: 50, // Reduce concurrency for Redis
        requests_per_client: 500,
        ..Default::default()
    };
    
    let result = run_performance_test(
        rate_limiter,
        config,
        "Token Bucket (Redis)"
    ).await;
    
    // Redis will be slower but should still be reasonable
    assert!(result.requests_per_second > 200.0, "Should handle at least 200 req/s with Redis");
    assert!(result.average_latency_ms < 50.0, "Average latency should be under 50ms with Redis");
    assert!(result.successful_requests > 0, "Should have some successful requests");
}

#[tokio::test]
async fn test_burst_handling_performance() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    
    // Test burst scenario - many requests in a short time
    let config = PerformanceTestConfig {
        concurrent_requests: 200,
        requests_per_client: 100,
        rate_limit: 500,
        window_duration: Duration::from_secs(60),
        test_duration: Duration::from_secs(5), // Short burst
    };
    
    let result = run_performance_test(
        rate_limiter,
        config,
        "Burst Handling"
    ).await;
    
    // In burst scenarios, we expect some requests to be denied
    assert!(result.total_requests > 10000, "Should generate significant load");
    assert!(result.failed_requests > 0, "Should have some rate limited requests");
    assert!(result.requests_per_second > 2000.0, "Should handle high burst rate");
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    
    // Test with many different users to stress memory usage
    let start_time = Instant::now();
    let mut join_set = JoinSet::new();
    
    // Create 1000 different users making requests
    for user_id in 0..1000 {
        let rate_limiter = rate_limiter.clone();
        
        join_set.spawn(async move {
            for _ in 0..10 {
                let _ = rate_limiter
                    .check_rate_limit(
                        Some(&format!("user_{}", user_id)),
                        Some("test_service"),
                        Some("/api/test"),
                        "/api/test",
                    )
                    .await;
                
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
    
    // Wait for all tasks to complete
    while let Some(_) = join_set.join_next().await {}
    
    let duration = start_time.elapsed();
    
    info!("Memory stress test completed in {:?}", duration);
    
    // Test should complete in reasonable time even with many users
    assert!(duration < Duration::from_secs(30), "Should complete within 30 seconds");
}

#[tokio::test]
async fn test_algorithm_comparison() {
    init_tracing();
    
    let test_config = PerformanceTestConfig {
        concurrent_requests: 50,
        requests_per_client: 200,
        ..Default::default()
    };
    
    // Test Token Bucket
    let token_bucket_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    let token_bucket_result = run_performance_test(
        token_bucket_limiter,
        test_config.clone(),
        "Token Bucket Comparison"
    ).await;
    
    // Test Sliding Window
    let sliding_window_limiter = create_test_rate_limiter(RateLimitAlgorithmType::SlidingWindow, false).await;
    let sliding_window_result = run_performance_test(
        sliding_window_limiter,
        test_config,
        "Sliding Window Comparison"
    ).await;
    
    info!(
        "Algorithm Comparison Results:\n\
         Token Bucket: {:.2} req/s, {:.2}ms avg latency\n\
         Sliding Window: {:.2} req/s, {:.2}ms avg latency",
        token_bucket_result.requests_per_second,
        token_bucket_result.average_latency_ms,
        sliding_window_result.requests_per_second,
        sliding_window_result.average_latency_ms
    );
    
    // Both algorithms should perform reasonably well
    assert!(token_bucket_result.requests_per_second > 500.0);
    assert!(sliding_window_result.requests_per_second > 400.0);
    
    // Token bucket should generally be faster due to simpler logic
    assert!(
        token_bucket_result.average_latency_ms <= sliding_window_result.average_latency_ms * 1.5,
        "Token bucket should not be significantly slower than sliding window"
    );
}

#[tokio::test]
async fn test_granularity_performance_impact() {
    init_tracing();
    
    // Test different granularity levels to see performance impact
    let granularities = vec![
        RateLimitGranularity::Global,
        RateLimitGranularity::PerUser,
        RateLimitGranularity::PerService,
        RateLimitGranularity::PerUserPerService,
    ];
    
    for granularity in granularities {
        let config = RateLimitConfig {
            algorithm: RateLimitAlgorithmType::TokenBucket,
            requests_per_window: 1000,
            window_duration: Duration::from_secs(60),
            burst_size: Some(100),
            granularity: granularity.clone(),
            distributed: false,
            redis_url: None,
            key_prefix: "test".to_string(),
            admin_exemptions: vec![],
            endpoint_rules: Default::default(),
        };
        
        let rate_limiter = Arc::new(RateLimitMiddleware::new(config).await.unwrap());
        
        let test_config = PerformanceTestConfig {
            concurrent_requests: 20,
            requests_per_client: 100,
            ..Default::default()
        };
        
        let result = run_performance_test(
            rate_limiter,
            test_config,
            &format!("Granularity {:?}", granularity)
        ).await;
        
        // All granularity levels should perform reasonably
        assert!(result.requests_per_second > 200.0, 
                "Granularity {:?} should handle at least 200 req/s", granularity);
        assert!(result.average_latency_ms < 25.0,
                "Granularity {:?} should have latency under 25ms", granularity);
    }
}

#[tokio::test]
async fn test_concurrent_configuration_updates() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    let mut join_set = JoinSet::new();
    
    // Spawn tasks that continuously make requests
    for client_id in 0..10 {
        let rate_limiter = rate_limiter.clone();
        
        join_set.spawn(async move {
            for _ in 0..100 {
                let _ = rate_limiter
                    .check_rate_limit(
                        Some(&format!("user_{}", client_id)),
                        Some("test_service"),
                        Some("/api/test"),
                        "/api/test",
                    )
                    .await;
                
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }
    
    // Spawn task that updates configuration
    let rate_limiter_config = rate_limiter.clone();
    join_set.spawn(async move {
        for i in 0..5 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            
            let new_config = RateLimitConfig {
                algorithm: RateLimitAlgorithmType::TokenBucket,
                requests_per_window: 500 + (i * 100),
                window_duration: Duration::from_secs(60),
                burst_size: Some(50 + (i * 10)),
                granularity: RateLimitGranularity::PerUser,
                distributed: false,
                redis_url: None,
                key_prefix: "test".to_string(),
                admin_exemptions: vec![],
                endpoint_rules: Default::default(),
            };
            
            let _ = rate_limiter_config.update_config(new_config).await;
        }
    });
    
    // Wait for all tasks to complete
    while let Some(_) = join_set.join_next().await {}
    
    info!("Concurrent configuration update test completed successfully");
}

/// Stress test with extreme load
#[tokio::test]
async fn test_extreme_load_stress() {
    init_tracing();
    
    let rate_limiter = create_test_rate_limiter(RateLimitAlgorithmType::TokenBucket, false).await;
    
    let config = PerformanceTestConfig {
        concurrent_requests: 500,
        requests_per_client: 100,
        rate_limit: 10000,
        window_duration: Duration::from_secs(60),
        test_duration: Duration::from_secs(10),
    };
    
    let result = run_performance_test(
        rate_limiter,
        config,
        "Extreme Load Stress Test"
    ).await;
    
    // Under extreme load, system should remain stable
    assert!(result.total_requests > 30000, "Should handle significant load");
    assert!(result.requests_per_second > 3000.0, "Should maintain high throughput");
    assert!(result.p99_latency_ms < 200.0, "P99 latency should remain reasonable");
    
    info!("Extreme load stress test passed - system remained stable under load");
}
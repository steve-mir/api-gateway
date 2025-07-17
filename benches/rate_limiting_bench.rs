//! # Rate Limiting Benchmarks
//!
//! This module contains detailed benchmarks for the rate limiting system
//! using the Criterion benchmarking framework.
//!
//! ## Running Benchmarks
//! ```bash
//! cargo bench --bench rate_limiting_bench
//! ```

use api_gateway::middleware::rate_limiting::{
    InMemoryStorage, RateLimitAlgorithmType, RateLimitConfig, RateLimitGranularity,
    RateLimitMiddleware, TokenBucketAlgorithm, SlidingWindowAlgorithm,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Create a test rate limiter for benchmarking
async fn create_bench_rate_limiter(algorithm: RateLimitAlgorithmType) -> Arc<RateLimitMiddleware> {
    let config = RateLimitConfig {
        algorithm,
        requests_per_window: 1000,
        window_duration: Duration::from_secs(60),
        burst_size: Some(100),
        granularity: RateLimitGranularity::PerUser,
        distributed: false,
        redis_url: None,
        key_prefix: "bench".to_string(),
        admin_exemptions: vec![],
        endpoint_rules: Default::default(),
    };

    Arc::new(RateLimitMiddleware::new(config).await.unwrap())
}

/// Benchmark single request rate limiting check
fn bench_single_request(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let token_bucket_limiter = rt.block_on(create_bench_rate_limiter(RateLimitAlgorithmType::TokenBucket));
    let sliding_window_limiter = rt.block_on(create_bench_rate_limiter(RateLimitAlgorithmType::SlidingWindow));
    
    let mut group = c.benchmark_group("single_request");
    
    group.bench_function("token_bucket", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                token_bucket_limiter
                    .check_rate_limit(
                        Some("user_123"),
                        Some("service_test"),
                        Some("/api/test"),
                        "/api/test",
                    )
                    .await
            )
        })
    });
    
    group.bench_function("sliding_window", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                sliding_window_limiter
                    .check_rate_limit(
                        Some("user_123"),
                        Some("service_test"),
                        Some("/api/test"),
                        "/api/test",
                    )
                    .await
            )
        })
    });
    
    group.finish();
}

/// Benchmark concurrent requests
fn bench_concurrent_requests(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let token_bucket_limiter = rt.block_on(create_bench_rate_limiter(RateLimitAlgorithmType::TokenBucket));
    
    let mut group = c.benchmark_group("concurrent_requests");
    
    for concurrency in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("token_bucket", concurrency),
            concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();
                    
                    for i in 0..concurrency {
                        let limiter = token_bucket_limiter.clone();
                        let handle = tokio::spawn(async move {
                            limiter
                                .check_rate_limit(
                                    Some(&format!("user_{}", i)),
                                    Some("service_test"),
                                    Some("/api/test"),
                                    "/api/test",
                                )
                                .await
                        });
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        black_box(handle.await.unwrap());
                    }
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark different granularity levels
fn bench_granularity_levels(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let granularities = vec![
        ("global", RateLimitGranularity::Global),
        ("per_user", RateLimitGranularity::PerUser),
        ("per_service", RateLimitGranularity::PerService),
        ("per_endpoint", RateLimitGranularity::PerEndpoint),
        ("per_user_per_service", RateLimitGranularity::PerUserPerService),
        ("per_user_per_endpoint", RateLimitGranularity::PerUserPerEndpoint),
    ];
    
    let mut group = c.benchmark_group("granularity_levels");
    
    for (name, granularity) in granularities {
        let config = RateLimitConfig {
            algorithm: RateLimitAlgorithmType::TokenBucket,
            requests_per_window: 1000,
            window_duration: Duration::from_secs(60),
            burst_size: Some(100),
            granularity,
            distributed: false,
            redis_url: None,
            key_prefix: "bench".to_string(),
            admin_exemptions: vec![],
            endpoint_rules: Default::default(),
        };
        
        let limiter = rt.block_on(async {
            Arc::new(RateLimitMiddleware::new(config).await.unwrap())
        });
        
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                black_box(
                    limiter
                        .check_rate_limit(
                            Some("user_123"),
                            Some("service_test"),
                            Some("/api/test"),
                            "/api/test",
                        )
                        .await
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmark memory usage with many users
fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let limiter = rt.block_on(create_bench_rate_limiter(RateLimitAlgorithmType::TokenBucket));
    
    let mut group = c.benchmark_group("memory_usage");
    
    for user_count in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("many_users", user_count),
            user_count,
            |b, &user_count| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();
                    
                    for i in 0..user_count {
                        let limiter = limiter.clone();
                        let handle = tokio::spawn(async move {
                            limiter
                                .check_rate_limit(
                                    Some(&format!("user_{}", i)),
                                    Some("service_test"),
                                    Some("/api/test"),
                                    "/api/test",
                                )
                                .await
                        });
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        black_box(handle.await.unwrap());
                    }
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark burst handling
fn bench_burst_handling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let limiter = rt.block_on(create_bench_rate_limiter(RateLimitAlgorithmType::TokenBucket));
    
    let mut group = c.benchmark_group("burst_handling");
    
    for burst_size in [10, 50, 100, 200].iter() {
        group.bench_with_input(
            BenchmarkId::new("burst_requests", burst_size),
            burst_size,
            |b, &burst_size| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();
                    
                    // Send burst of requests from same user
                    for _ in 0..burst_size {
                        let limiter = limiter.clone();
                        let handle = tokio::spawn(async move {
                            limiter
                                .check_rate_limit(
                                    Some("burst_user"),
                                    Some("service_test"),
                                    Some("/api/test"),
                                    "/api/test",
                                )
                                .await
                        });
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        black_box(handle.await.unwrap());
                    }
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_single_request,
    bench_concurrent_requests,
    bench_granularity_levels,
    bench_memory_usage,
    bench_burst_handling
);
criterion_main!(benches);
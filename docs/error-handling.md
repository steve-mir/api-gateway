# Error Handling System

The API Gateway includes a comprehensive error handling system that provides error tracking, custom error pages, error recovery mechanisms, and administrative interfaces for error management.

## Components

### 1. Error Tracking (`core::error_tracking`)

The error tracking system collects and analyzes error events to provide insights into system health and identify patterns.

**Features:**
- Real-time error event collection
- Error pattern detection and alerting
- Error statistics and analytics
- Configurable thresholds for alerting

**Usage:**
```rust
use api_gateway::core::error_tracking::{ErrorTracker, ErrorPatternConfig};

let config = ErrorPatternConfig {
    error_rate_threshold: 10.0, // 10 errors per minute
    error_rate_window: 5,        // 5 minute window
    consecutive_error_threshold: 5,
    consecutive_error_window: 2,
    auto_circuit_breaker: true,
    auto_recovery: true,
};

let tracker = ErrorTracker::new(config);

// Track an error
let error_event = ErrorEvent::new(
    &error,
    "/api/users".to_string(),
    "GET".to_string(),
    "192.168.1.1".to_string(),
    Some("Mozilla/5.0".to_string()),
    "req-123".to_string(),
    Some("trace-456".to_string()),
    Some("user-service".to_string()),
);

tracker.track_error(error_event).await;
```

### 2. Custom Error Pages (`core::error_pages`)

The error page system generates custom error responses based on content negotiation and configuration.

**Features:**
- HTML error pages with customizable templates
- JSON error responses for API clients
- Content negotiation based on Accept headers
- Configurable branding and styling

**Usage:**
```rust
use api_gateway::core::error_pages::{ErrorPageGenerator, ErrorPageConfig};

let config = ErrorPageConfig {
    enabled: true,
    brand_name: "My API Gateway".to_string(),
    support_contact: Some("support@example.com".to_string()),
    show_details: false, // Hide details in production
    ..Default::default()
};

let generator = ErrorPageGenerator::new(config)?;

// Generate error response
let response = generator.generate_error_response(
    &error,
    &request_headers,
    Some("/api/users"),
    Some("req-123"),
);
```

### 3. Error Recovery (`core::error_recovery`)

The error recovery system implements various strategies to handle failures gracefully.

**Recovery Strategies:**
- Retry with exponential backoff
- Fallback to alternative services
- Cached response fallback
- Default/static response fallback
- Graceful degradation

**Usage:**
```rust
use api_gateway::core::error_recovery::{ErrorRecoveryManager, RecoveryConfig};

let config = RecoveryConfig {
    enabled: true,
    max_attempts: 3,
    recovery_timeout: Duration::from_secs(10),
    ..Default::default()
};

let recovery_manager = ErrorRecoveryManager::new(config);

// Attempt recovery
let context = RecoveryContext {
    request_path: "/api/users".to_string(),
    request_method: "GET".to_string(),
    // ... other fields
};

let result = recovery_manager.recover_from_error(&error, context).await;
```

### 4. Error Handling Middleware (`middleware::error_handling`)

The error handling middleware integrates all error management systems into the request processing pipeline.

**Usage:**
```rust
use api_gateway::middleware::error_handling::{ErrorHandlingState, create_error_handling_layer};

let state = ErrorHandlingState {
    error_tracker,
    recovery_manager,
    error_page_generator,
};

let app = Router::new()
    .route("/api/users", get(users_handler))
    .layer(create_error_handling_layer(state));
```

### 5. Admin Endpoints (`admin::error_tracking`)

The admin interface provides endpoints for error management and analysis.

**Available Endpoints:**
- `GET /admin/errors` - List recent errors
- `GET /admin/errors/stats` - Error statistics
- `GET /admin/errors/summary` - Error summary
- `GET /admin/errors/dashboard` - Comprehensive dashboard
- `PUT /admin/errors/config` - Update configuration
- `GET /admin/errors/pages/preview/{status_code}` - Preview error pages

## Configuration

### Error Pattern Configuration

```yaml
error_tracking:
  error_rate_threshold: 10.0      # Errors per minute threshold
  error_rate_window: 5            # Time window in minutes
  consecutive_error_threshold: 5   # Consecutive errors threshold
  consecutive_error_window: 2      # Time window for consecutive errors
  auto_circuit_breaker: true       # Enable automatic circuit breaker
  auto_recovery: true              # Enable automatic recovery
```

### Error Page Configuration

```yaml
error_pages:
  enabled: true
  brand_name: "API Gateway"
  support_contact: "support@example.com"
  show_details: false              # Hide details in production
  custom_css: |
    .error-container { background: #f8f9fa; }
  custom_messages:
    404: "The requested resource was not found"
    500: "An internal error occurred"
```

### Recovery Configuration

```yaml
error_recovery:
  enabled: true
  max_attempts: 3
  recovery_timeout: "10s"
  strategies:
    service_unavailable:
      - type: retry_with_backoff
        max_retries: 3
        initial_delay: "100ms"
        max_delay: "5s"
      - type: fallback_service
        fallback_service: "fallback-api"
      - type: cached_response
```

## Error Types and Status Codes

| Error Type | HTTP Status | Retryable | Circuit Breaker |
|------------|-------------|-----------|-----------------|
| Authentication | 401 | No | No |
| Authorization | 403 | No | No |
| RateLimitExceeded | 429 | No | No |
| ServiceUnavailable | 503 | Yes | Yes |
| Timeout | 504 | Yes | Yes |
| CircuitBreakerOpen | 503 | No | No |
| Internal | 500 | No | No |

## Monitoring and Alerting

The error tracking system provides real-time alerts for:

- High error rates
- Consecutive errors from the same service
- Service degradation
- Circuit breaker triggers

Subscribe to alerts:

```rust
let mut alert_receiver = error_tracker.subscribe_to_alerts();

while let Ok(alert) = alert_receiver.recv().await {
    match alert {
        ErrorAlert::HighErrorRate { error_type, rate, .. } => {
            // Handle high error rate alert
        }
        ErrorAlert::ConsecutiveErrors { service, count, .. } => {
            // Handle consecutive errors alert
        }
        // ... other alert types
    }
}
```

## Best Practices

1. **Configure appropriate thresholds** - Set error rate and consecutive error thresholds based on your service requirements.

2. **Use graceful degradation** - Implement fallback responses that provide reduced functionality rather than complete failure.

3. **Monitor error patterns** - Use the admin dashboard to identify and address recurring error patterns.

4. **Customize error pages** - Provide user-friendly error pages that match your application's branding.

5. **Test error scenarios** - Regularly test error handling paths to ensure they work as expected.

6. **Log error context** - Include sufficient context in error logs for debugging and analysis.

## Example Integration

See `examples/error_handling_integration.rs` for a complete example of how to integrate all error handling components into your application.

## Testing

The error handling system includes comprehensive tests:

```bash
# Run error handling tests
cargo test error_handling_tests

# Run integration tests
cargo test --example error_handling_integration
```

## Performance Considerations

- Error tracking uses in-memory circular buffers with configurable limits
- Error recovery has configurable timeouts to prevent hanging requests
- Admin endpoints are rate-limited to prevent abuse
- Error page generation is optimized for common error types

## Security Considerations

- Error details can be hidden in production using `show_details: false`
- Admin endpoints should be protected with authentication
- Error logs should not contain sensitive information
- Custom error pages should be sanitized to prevent XSS
# Traffic Management Admin API

This document describes the REST API endpoints for managing traffic configuration, A/B testing, queue management, priority rules, and graceful shutdown controls.

## Base URL

All traffic management endpoints are available under `/admin/traffic/`

## Authentication

These endpoints require admin authentication and should be protected in production environments.

## Endpoints Overview

### Traffic Configuration
- `GET /admin/traffic/config` - Get current traffic configuration
- `PUT /admin/traffic/config` - Update traffic configuration
- `POST /admin/traffic/config/validate` - Validate configuration

### Queue Management
- `GET /admin/traffic/queue/config` - Get queue configuration
- `PUT /admin/traffic/queue/config` - Update queue configuration
- `GET /admin/traffic/queue/metrics` - Get queue metrics
- `POST /admin/traffic/queue/clear` - Clear the request queue
- `POST /admin/traffic/queue/pause` - Pause queue processing
- `POST /admin/traffic/queue/resume` - Resume queue processing

### Traffic Shaping
- `GET /admin/traffic/shaping/config` - Get shaping configuration
- `PUT /admin/traffic/shaping/config` - Update shaping configuration
- `GET /admin/traffic/shaping/metrics` - Get shaping metrics
- `POST /admin/traffic/shaping/reset` - Reset shaping counters

### Priority Management
- `GET /admin/traffic/priority/config` - Get priority configuration
- `PUT /admin/traffic/priority/config` - Update priority configuration
- `GET /admin/traffic/priority/rules` - Get priority rules
- `POST /admin/traffic/priority/rules` - Add priority rule
- `PUT /admin/traffic/priority/rules/{rule_id}` - Update priority rule
- `DELETE /admin/traffic/priority/rules/{rule_id}` - Delete priority rule

### A/B Testing
- `GET /admin/traffic/ab-tests` - List A/B tests
- `POST /admin/traffic/ab-tests` - Create A/B test
- `GET /admin/traffic/ab-tests/{test_id}` - Get A/B test details
- `PUT /admin/traffic/ab-tests/{test_id}` - Update A/B test
- `DELETE /admin/traffic/ab-tests/{test_id}` - Delete A/B test
- `POST /admin/traffic/ab-tests/{test_id}/start` - Start A/B test
- `POST /admin/traffic/ab-tests/{test_id}/stop` - Stop A/B test
- `GET /admin/traffic/ab-tests/{test_id}/metrics` - Get A/B test metrics

### Traffic Splitting
- `GET /admin/traffic/splits` - List traffic splits
- `POST /admin/traffic/splits` - Create traffic split
- `GET /admin/traffic/splits/{split_id}` - Get traffic split details
- `PUT /admin/traffic/splits/{split_id}` - Update traffic split
- `DELETE /admin/traffic/splits/{split_id}` - Delete traffic split
- `POST /admin/traffic/splits/{split_id}/enable` - Enable traffic split
- `POST /admin/traffic/splits/{split_id}/disable` - Disable traffic split

### Graceful Shutdown
- `GET /admin/traffic/shutdown/config` - Get shutdown configuration
- `PUT /admin/traffic/shutdown/config` - Update shutdown configuration
- `GET /admin/traffic/shutdown/status` - Get shutdown status
- `POST /admin/traffic/shutdown/initiate` - Initiate graceful shutdown
- `POST /admin/traffic/shutdown/cancel` - Cancel graceful shutdown
- `POST /admin/traffic/shutdown/drain` - Drain connections

### Overall Status
- `GET /admin/traffic/status` - Get overall traffic status
- `GET /admin/traffic/metrics` - Get comprehensive traffic metrics
- `GET /admin/traffic/health` - Get traffic health status

## Example Usage

### Get Current Traffic Configuration

```bash
curl -X GET http://localhost:8080/admin/traffic/config \
  -H "Authorization: Bearer <admin-token>"
```

### Update Queue Configuration

```bash
curl -X PUT http://localhost:8080/admin/traffic/queue/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "config": {
      "max_queue_size": 10000,
      "backpressure_threshold": 0.8,
      "timeout": "30s",
      "priority_levels": 3
    },
    "changed_by": "admin-user"
  }'
```

### Create A/B Test

```bash
curl -X POST http://localhost:8080/admin/traffic/ab-tests \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "config": {
      "name": "homepage-redesign",
      "description": "Testing new homepage design",
      "variants": [
        {
          "name": "control",
          "weight": 50,
          "upstream": "homepage-v1"
        },
        {
          "name": "treatment",
          "weight": 50,
          "upstream": "homepage-v2"
        }
      ],
      "traffic_allocation": 100,
      "duration": "7d"
    },
    "changed_by": "product-team"
  }'
```

### Add Priority Rule

```bash
curl -X POST http://localhost:8080/admin/traffic/priority/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "rule": {
      "id": "premium-users",
      "name": "Premium User Priority",
      "condition": "headers.user-tier == \"premium\"",
      "priority": 1,
      "enabled": true
    },
    "changed_by": "admin-user"
  }'
```

### Initiate Graceful Shutdown

```bash
curl -X POST http://localhost:8080/admin/traffic/shutdown/initiate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "timeout": "60s",
    "changed_by": "ops-team",
    "reason": "Planned maintenance"
  }'
```

### Get Traffic Metrics

```bash
curl -X GET "http://localhost:8080/admin/traffic/metrics?start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z&include_historical=true" \
  -H "Authorization: Bearer <admin-token>"
```

## Response Formats

### Success Response
```json
{
  "success": true,
  "change_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Configuration updated successfully"
}
```

### Error Response
```json
{
  "error": "Failed to update configuration",
  "details": "Validation failed: max_queue_size must be greater than 0"
}
```

### Validation Response
```json
{
  "valid": false,
  "errors": [
    "Queue max_queue_size must be greater than 0",
    "Backpressure threshold must be between 0.0 and 1.0"
  ]
}
```

## Configuration Examples

### Complete Traffic Configuration
```json
{
  "queue": {
    "max_queue_size": 10000,
    "backpressure_threshold": 0.8,
    "timeout": "30s",
    "priority_levels": 3
  },
  "shaping": {
    "global_rps_limit": 1000,
    "per_client_rps_limit": 100,
    "burst_size": 50,
    "window_size": "1s"
  },
  "priority": {
    "enabled": true,
    "default_priority": 2,
    "rules": []
  },
  "shutdown": {
    "grace_period": "30s",
    "drain_timeout": "10s",
    "force_timeout": "60s"
  },
  "splitting": []
}
```

### A/B Test Configuration
```json
{
  "name": "checkout-flow-test",
  "description": "Testing simplified checkout flow",
  "variants": [
    {
      "name": "control",
      "weight": 40,
      "upstream": "checkout-v1"
    },
    {
      "name": "simplified",
      "weight": 60,
      "upstream": "checkout-v2"
    }
  ],
  "traffic_allocation": 50,
  "duration": "14d",
  "success_criteria": {
    "conversion_rate": 0.15,
    "min_sample_size": 1000
  }
}
```

## Security Considerations

1. **Authentication**: All endpoints require admin-level authentication
2. **Authorization**: Implement role-based access control for different operations
3. **Audit Logging**: All configuration changes are logged with user attribution
4. **Rate Limiting**: Consider rate limiting admin endpoints to prevent abuse
5. **Input Validation**: All inputs are validated before processing
6. **HTTPS**: Use HTTPS in production environments

## Monitoring and Alerting

- Monitor queue depth and backpressure activation
- Alert on traffic shaping threshold breaches
- Track A/B test performance and statistical significance
- Monitor graceful shutdown progress
- Set up alerts for configuration validation failures
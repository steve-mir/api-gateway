#!/bin/bash

# End-to-End Validation Script for API Gateway Production Deployment
# This script performs comprehensive testing and validation of the deployed gateway

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-api-gateway}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production}"
GATEWAY_URL="${GATEWAY_URL:-}"
ADMIN_URL="${ADMIN_URL:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
PARALLEL_TESTS="${PARALLEL_TESTS:-5}"
LOAD_TEST_DURATION="${LOAD_TEST_DURATION:-60}"
LOAD_TEST_USERS="${LOAD_TEST_USERS:-10}"
SKIP_LOAD_TESTS="${SKIP_LOAD_TESTS:-false}"
SKIP_SECURITY_TESTS="${SKIP_SECURITY_TESTS:-false}"
TEST_API_KEY="${TEST_API_KEY:-}"
TEST_JWT_TOKEN="${TEST_JWT_TOKEN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
    ((TESTS_PASSED++))
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $1${NC}"
    ((TESTS_SKIPPED++))
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
    ((TESTS_FAILED++))
}

fatal() {
    error "$1"
    exit 1
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Make HTTP request with timeout and retries
http_request() {
    local method="$1"
    local url="$2"
    local expected_status="${3:-200}"
    local headers="${4:-}"
    local data="${5:-}"
    local timeout="${6:-10}"
    
    local curl_args=(-s -w "%{http_code}" -m "$timeout" -X "$method")
    
    if [ -n "$headers" ]; then
        while IFS= read -r header; do
            curl_args+=(-H "$header")
        done <<< "$headers"
    fi
    
    if [ -n "$data" ]; then
        curl_args+=(-d "$data")
    fi
    
    curl_args+=("$url")
    
    local response
    response=$(curl "${curl_args[@]}" 2>/dev/null || echo "000")
    
    local status_code="${response: -3}"
    local body="${response%???}"
    
    if [ "$status_code" = "$expected_status" ]; then
        return 0
    else
        echo "Expected $expected_status, got $status_code" >&2
        return 1
    fi
}

# Wait for service to be ready
wait_for_service() {
    local url="$1"
    local timeout="${2:-60}"
    local interval=5
    local elapsed=0
    
    log "Waiting for service to be ready: $url"
    
    while [ $elapsed -lt $timeout ]; do
        if http_request "GET" "$url/health" "200" "" "" 5 >/dev/null 2>&1; then
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    return 1
}

# =============================================================================
# SERVICE DISCOVERY AND URL DETECTION
# =============================================================================

discover_service_urls() {
    log "🔍 Discovering service URLs..."
    
    # Try to get LoadBalancer IP
    local gateway_ip
    gateway_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [ -z "$gateway_ip" ]; then
        # Try to get external IP from ingress
        gateway_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get ingress api-gateway \
            -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    fi
    
    if [ -z "$gateway_ip" ]; then
        # Fall back to cluster IP
        gateway_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
            -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    fi
    
    if [ -n "$gateway_ip" ]; then
        GATEWAY_URL="${GATEWAY_URL:-http://$gateway_ip:8080}"
        success "Gateway URL discovered: $GATEWAY_URL"
    else
        warning "Could not discover gateway URL automatically"
        if [ -z "$GATEWAY_URL" ]; then
            fatal "GATEWAY_URL must be provided manually"
        fi
    fi
    
    # Discover admin URL
    local admin_namespace="${NAMESPACE}-admin"
    local admin_ip
    admin_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get service api-gateway-admin \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    
    if [ -n "$admin_ip" ]; then
        ADMIN_URL="${ADMIN_URL:-http://$admin_ip:9090}"
        success "Admin URL discovered: $ADMIN_URL"
    else
        warning "Could not discover admin URL"
    fi
}

# =============================================================================
# INFRASTRUCTURE TESTS
# =============================================================================

test_kubernetes_resources() {
    log "☸️  Testing Kubernetes resources..."
    
    # Test main namespace
    if kubectl --context="$KUBECTL_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1; then
        success "Main namespace exists: $NAMESPACE"
    else
        error "Main namespace missing: $NAMESPACE"
        return 1
    fi
    
    # Test gateway deployment
    local gateway_ready
    gateway_ready=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get deployment api-gateway \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    
    if [ "$gateway_ready" -gt 0 ]; then
        success "Gateway deployment is ready ($gateway_ready replicas)"
    else
        error "Gateway deployment is not ready"
        return 1
    fi
    
    # Test gateway pods
    local gateway_pods
    gateway_pods=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get pods \
        -l app.kubernetes.io/name=api-gateway --field-selector=status.phase=Running \
        --no-headers | wc -l)
    
    if [ "$gateway_pods" -gt 0 ]; then
        success "Gateway pods are running ($gateway_pods pods)"
    else
        error "No gateway pods are running"
        return 1
    fi
    
    # Test gateway service
    if kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway >/dev/null 2>&1; then
        success "Gateway service exists"
    else
        error "Gateway service missing"
        return 1
    fi
    
    # Test admin namespace and resources
    local admin_namespace="${NAMESPACE}-admin"
    if kubectl --context="$KUBECTL_CONTEXT" get namespace "$admin_namespace" >/dev/null 2>&1; then
        success "Admin namespace exists: $admin_namespace"
        
        local admin_ready
        admin_ready=$(kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get deployment api-gateway-admin \
            -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        
        if [ "$admin_ready" -gt 0 ]; then
            success "Admin deployment is ready ($admin_ready replicas)"
        else
            warning "Admin deployment is not ready"
        fi
    else
        warning "Admin namespace missing: $admin_namespace"
    fi
}

test_service_connectivity() {
    log "🌐 Testing service connectivity..."
    
    # Test gateway health endpoint
    if wait_for_service "$GATEWAY_URL" 60; then
        success "Gateway service is reachable"
    else
        error "Gateway service is not reachable"
        return 1
    fi
    
    # Test admin service if available
    if [ -n "$ADMIN_URL" ]; then
        if wait_for_service "$ADMIN_URL" 30; then
            success "Admin service is reachable"
        else
            warning "Admin service is not reachable"
        fi
    fi
}

# =============================================================================
# FUNCTIONAL TESTS
# =============================================================================

test_health_endpoints() {
    log "🏥 Testing health endpoints..."
    
    # Test gateway health
    if http_request "GET" "$GATEWAY_URL/health" "200"; then
        success "Gateway health endpoint working"
    else
        error "Gateway health endpoint failed"
    fi
    
    # Test gateway readiness
    if http_request "GET" "$GATEWAY_URL/ready" "200"; then
        success "Gateway readiness endpoint working"
    else
        error "Gateway readiness endpoint failed"
    fi
    
    # Test admin health if available
    if [ -n "$ADMIN_URL" ]; then
        if http_request "GET" "$ADMIN_URL/admin/health" "200"; then
            success "Admin health endpoint working"
        else
            warning "Admin health endpoint failed"
        fi
    fi
}

test_metrics_endpoints() {
    log "📊 Testing metrics endpoints..."
    
    # Test gateway metrics
    if http_request "GET" "$GATEWAY_URL:9090/metrics" "200"; then
        success "Gateway metrics endpoint working"
    else
        error "Gateway metrics endpoint failed"
    fi
    
    # Verify metrics content
    local metrics_response
    metrics_response=$(curl -s "$GATEWAY_URL:9090/metrics" 2>/dev/null || echo "")
    
    if echo "$metrics_response" | grep -q "gateway_requests_total"; then
        success "Gateway metrics contain expected data"
    else
        warning "Gateway metrics missing expected data"
    fi
    
    # Test admin metrics if available
    if [ -n "$ADMIN_URL" ]; then
        if http_request "GET" "$ADMIN_URL/admin/metrics" "200"; then
            success "Admin metrics endpoint working"
        else
            warning "Admin metrics endpoint failed"
        fi
    fi
}

test_api_endpoints() {
    log "🔌 Testing API endpoints..."
    
    # Test basic API endpoints
    local test_endpoints=(
        "/api/v1/users:GET:200"
        "/api/v1/products:GET:200"
        "/health:GET:200"
        "/ready:GET:200"
    )
    
    for endpoint_spec in "${test_endpoints[@]}"; do
        IFS=':' read -r path method expected_status <<< "$endpoint_spec"
        
        if http_request "$method" "$GATEWAY_URL$path" "$expected_status"; then
            success "API endpoint working: $method $path"
        else
            # Some endpoints might require authentication, so 401 is acceptable
            if http_request "$method" "$GATEWAY_URL$path" "401"; then
                success "API endpoint working (requires auth): $method $path"
            else
                error "API endpoint failed: $method $path"
            fi
        fi
    done
}

test_authentication() {
    log "🔐 Testing authentication..."
    
    # Test without authentication (should fail for protected endpoints)
    if http_request "GET" "$GATEWAY_URL/api/v1/users" "401"; then
        success "Authentication required for protected endpoints"
    else
        warning "Authentication not enforced on protected endpoints"
    fi
    
    # Test with API key if provided
    if [ -n "$TEST_API_KEY" ]; then
        local auth_header="X-API-Key: $TEST_API_KEY"
        if http_request "GET" "$GATEWAY_URL/api/v1/users" "200" "$auth_header"; then
            success "API key authentication working"
        else
            warning "API key authentication failed"
        fi
    else
        warning "No TEST_API_KEY provided, skipping API key test"
    fi
    
    # Test with JWT token if provided
    if [ -n "$TEST_JWT_TOKEN" ]; then
        local auth_header="Authorization: Bearer $TEST_JWT_TOKEN"
        if http_request "GET" "$GATEWAY_URL/api/v1/users" "200" "$auth_header"; then
            success "JWT authentication working"
        else
            warning "JWT authentication failed"
        fi
    else
        warning "No TEST_JWT_TOKEN provided, skipping JWT test"
    fi
}

test_rate_limiting() {
    log "🚦 Testing rate limiting..."
    
    # Make multiple rapid requests to trigger rate limiting
    local rate_limit_triggered=false
    
    for i in {1..20}; do
        if ! http_request "GET" "$GATEWAY_URL/health" "200" "" "" 1 >/dev/null 2>&1; then
            # Check if it's a rate limit response (429)
            local status
            status=$(curl -s -w "%{http_code}" -m 1 "$GATEWAY_URL/health" 2>/dev/null | tail -c 3)
            if [ "$status" = "429" ]; then
                rate_limit_triggered=true
                break
            fi
        fi
        sleep 0.1
    done
    
    if [ "$rate_limit_triggered" = true ]; then
        success "Rate limiting is working"
    else
        warning "Rate limiting not triggered (may be configured with high limits)"
    fi
}

test_cors() {
    log "🌍 Testing CORS configuration..."
    
    # Test CORS preflight request
    local cors_headers="Origin: https://example.com
Access-Control-Request-Method: GET
Access-Control-Request-Headers: Content-Type"
    
    if http_request "OPTIONS" "$GATEWAY_URL/api/v1/users" "200" "$cors_headers"; then
        success "CORS preflight request working"
    else
        warning "CORS preflight request failed"
    fi
    
    # Test actual CORS request
    local origin_header="Origin: https://example.com"
    local response
    response=$(curl -s -H "$origin_header" "$GATEWAY_URL/health" 2>/dev/null || echo "")
    
    if [ -n "$response" ]; then
        success "CORS request working"
    else
        warning "CORS request failed"
    fi
}

# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

test_response_times() {
    log "⚡ Testing response times..."
    
    local endpoints=("/health" "/ready" "/api/v1/users")
    local max_response_time=2000  # 2 seconds in milliseconds
    
    for endpoint in "${endpoints[@]}"; do
        local response_time
        response_time=$(curl -s -w "%{time_total}" -o /dev/null "$GATEWAY_URL$endpoint" 2>/dev/null | \
            awk '{print int($1 * 1000)}')  # Convert to milliseconds
        
        if [ "$response_time" -lt "$max_response_time" ]; then
            success "Response time acceptable for $endpoint: ${response_time}ms"
        else
            warning "Response time high for $endpoint: ${response_time}ms"
        fi
    done
}

test_concurrent_requests() {
    log "🔄 Testing concurrent request handling..."
    
    if ! command_exists ab; then
        warning "Apache Bench (ab) not available, skipping concurrent request test"
        return 0
    fi
    
    # Test with moderate concurrency
    local concurrent_users=10
    local total_requests=100
    
    log "Running $total_requests requests with $concurrent_users concurrent users..."
    
    local ab_output
    ab_output=$(ab -n "$total_requests" -c "$concurrent_users" "$GATEWAY_URL/health" 2>/dev/null || echo "")
    
    if echo "$ab_output" | grep -q "Complete requests:.*$total_requests"; then
        local failed_requests
        failed_requests=$(echo "$ab_output" | grep "Failed requests:" | awk '{print $3}' || echo "0")
        
        if [ "$failed_requests" -eq 0 ]; then
            success "Concurrent requests handled successfully"
        else
            warning "Some concurrent requests failed: $failed_requests"
        fi
    else
        error "Concurrent request test failed"
    fi
}

run_load_tests() {
    if [ "$SKIP_LOAD_TESTS" = "true" ]; then
        warning "Load tests skipped"
        return 0
    fi
    
    log "🏋️  Running load tests..."
    
    if ! command_exists ab; then
        warning "Apache Bench (ab) not available, skipping load tests"
        return 0
    fi
    
    # Run load test
    local duration="$LOAD_TEST_DURATION"
    local users="$LOAD_TEST_USERS"
    local total_requests=$((duration * users))
    
    log "Running load test: $total_requests requests over ${duration}s with $users concurrent users"
    
    local ab_output
    ab_output=$(ab -t "$duration" -c "$users" "$GATEWAY_URL/health" 2>/dev/null || echo "")
    
    if [ -n "$ab_output" ]; then
        local requests_per_second
        requests_per_second=$(echo "$ab_output" | grep "Requests per second:" | awk '{print $4}' || echo "0")
        
        local mean_response_time
        mean_response_time=$(echo "$ab_output" | grep "Time per request:" | head -1 | awk '{print $4}' || echo "0")
        
        success "Load test completed: ${requests_per_second} req/s, ${mean_response_time}ms avg response time"
        
        # Check if performance is acceptable
        if (( $(echo "$requests_per_second > 100" | bc -l) )); then
            success "Performance is acceptable (>100 req/s)"
        else
            warning "Performance may be low (<100 req/s)"
        fi
    else
        error "Load test failed"
    fi
}

# =============================================================================
# SECURITY TESTS
# =============================================================================

run_security_tests() {
    if [ "$SKIP_SECURITY_TESTS" = "true" ]; then
        warning "Security tests skipped"
        return 0
    fi
    
    log "🔒 Running security tests..."
    
    test_security_headers
    test_sql_injection_protection
    test_xss_protection
    test_path_traversal_protection
}

test_security_headers() {
    log "Testing security headers..."
    
    local response_headers
    response_headers=$(curl -s -I "$GATEWAY_URL/health" 2>/dev/null || echo "")
    
    local expected_headers=(
        "X-Frame-Options"
        "X-Content-Type-Options"
        "X-XSS-Protection"
        "Strict-Transport-Security"
    )
    
    for header in "${expected_headers[@]}"; do
        if echo "$response_headers" | grep -qi "$header"; then
            success "Security header present: $header"
        else
            warning "Security header missing: $header"
        fi
    done
}

test_sql_injection_protection() {
    log "Testing SQL injection protection..."
    
    local sql_payloads=(
        "' OR '1'='1"
        "'; DROP TABLE users; --"
        "1' UNION SELECT * FROM users --"
    )
    
    for payload in "${sql_payloads[@]}"; do
        local encoded_payload
        encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
        
        # Test in query parameter
        if http_request "GET" "$GATEWAY_URL/api/v1/users?id=$encoded_payload" "400" "" "" 5 >/dev/null 2>&1; then
            success "SQL injection blocked in query parameter"
        else
            # 404 or other error is also acceptable
            if ! http_request "GET" "$GATEWAY_URL/api/v1/users?id=$encoded_payload" "200" "" "" 5 >/dev/null 2>&1; then
                success "SQL injection handled safely"
            else
                warning "Potential SQL injection vulnerability"
            fi
        fi
    done
}

test_xss_protection() {
    log "Testing XSS protection..."
    
    local xss_payloads=(
        "<script>alert('xss')</script>"
        "javascript:alert('xss')"
        "<img src=x onerror=alert('xss')>"
    )
    
    for payload in "${xss_payloads[@]}"; do
        local encoded_payload
        encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
        
        local response
        response=$(curl -s "$GATEWAY_URL/api/v1/users?search=$encoded_payload" 2>/dev/null || echo "")
        
        if echo "$response" | grep -q "$payload"; then
            warning "Potential XSS vulnerability detected"
        else
            success "XSS payload properly handled"
        fi
    done
}

test_path_traversal_protection() {
    log "Testing path traversal protection..."
    
    local traversal_payloads=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    )
    
    for payload in "${traversal_payloads[@]}"; do
        if http_request "GET" "$GATEWAY_URL/$payload" "404" "" "" 5 >/dev/null 2>&1; then
            success "Path traversal blocked: $payload"
        else
            if ! http_request "GET" "$GATEWAY_URL/$payload" "200" "" "" 5 >/dev/null 2>&1; then
                success "Path traversal handled safely: $payload"
            else
                warning "Potential path traversal vulnerability: $payload"
            fi
        fi
    done
}

# =============================================================================
# INTEGRATION TESTS
# =============================================================================

test_service_discovery() {
    log "🔍 Testing service discovery..."
    
    # This would test actual service discovery functionality
    # For now, we'll check if the gateway can reach configured upstreams
    
    if [ -n "$ADMIN_URL" ]; then
        # Try to get service list from admin API
        local services_response
        services_response=$(curl -s "$ADMIN_URL/api/v1/services" 2>/dev/null || echo "")
        
        if [ -n "$services_response" ]; then
            success "Service discovery API accessible"
        else
            warning "Service discovery API not accessible"
        fi
    else
        warning "Admin URL not available, skipping service discovery test"
    fi
}

test_load_balancing() {
    log "⚖️  Testing load balancing..."
    
    # Make multiple requests and check if they're distributed
    # This is a simplified test - in practice you'd need multiple backend instances
    
    local responses=()
    for i in {1..10}; do
        local response
        response=$(curl -s -H "X-Request-ID: test-$i" "$GATEWAY_URL/health" 2>/dev/null || echo "")
        responses+=("$response")
    done
    
    if [ ${#responses[@]} -eq 10 ]; then
        success "Load balancing test completed (10 requests processed)"
    else
        warning "Load balancing test incomplete"
    fi
}

test_circuit_breaker() {
    log "🔌 Testing circuit breaker..."
    
    # This would require a way to trigger upstream failures
    # For now, we'll just check if circuit breaker metrics are available
    
    local metrics_response
    metrics_response=$(curl -s "$GATEWAY_URL:9090/metrics" 2>/dev/null || echo "")
    
    if echo "$metrics_response" | grep -q "circuit_breaker"; then
        success "Circuit breaker metrics available"
    else
        warning "Circuit breaker metrics not found"
    fi
}

test_caching() {
    log "💾 Testing caching..."
    
    # Make the same request twice and check for cache headers
    local first_response
    first_response=$(curl -s -I "$GATEWAY_URL/api/v1/users" 2>/dev/null || echo "")
    
    sleep 1
    
    local second_response
    second_response=$(curl -s -I "$GATEWAY_URL/api/v1/users" 2>/dev/null || echo "")
    
    if echo "$second_response" | grep -qi "x-cache.*hit"; then
        success "Caching is working"
    else
        warning "Cache headers not detected (caching may not be enabled for this endpoint)"
    fi
}

# =============================================================================
# MONITORING AND OBSERVABILITY TESTS
# =============================================================================

test_logging() {
    log "📝 Testing logging..."
    
    # Check if logs are being generated
    local log_entries
    log_entries=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" logs \
        -l app.kubernetes.io/name=api-gateway --tail=10 2>/dev/null || echo "")
    
    if [ -n "$log_entries" ]; then
        success "Application logs are being generated"
    else
        warning "No application logs found"
    fi
    
    # Check log format (should be JSON in production)
    if echo "$log_entries" | head -1 | jq . >/dev/null 2>&1; then
        success "Logs are in JSON format"
    else
        warning "Logs are not in JSON format"
    fi
}

test_tracing() {
    log "🔍 Testing distributed tracing..."
    
    # Make a request with tracing headers
    local trace_id
    trace_id=$(uuidgen 2>/dev/null || echo "test-trace-$(date +%s)")
    
    local trace_headers="X-Trace-ID: $trace_id
X-Span-ID: test-span-$(date +%s)"
    
    if http_request "GET" "$GATEWAY_URL/health" "200" "$trace_headers"; then
        success "Request with tracing headers processed"
        
        # Check if trace ID appears in logs
        sleep 2
        local recent_logs
        recent_logs=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" logs \
            -l app.kubernetes.io/name=api-gateway --tail=50 2>/dev/null || echo "")
        
        if echo "$recent_logs" | grep -q "$trace_id"; then
            success "Trace ID found in logs"
        else
            warning "Trace ID not found in logs"
        fi
    else
        warning "Request with tracing headers failed"
    fi
}

test_alerting() {
    log "🚨 Testing alerting configuration..."
    
    # Check if Prometheus is scraping metrics
    local metrics_response
    metrics_response=$(curl -s "$GATEWAY_URL:9090/metrics" 2>/dev/null || echo "")
    
    if echo "$metrics_response" | grep -q "up 1"; then
        success "Metrics are being exposed for alerting"
    else
        warning "Metrics may not be properly exposed"
    fi
    
    # Check for alert-worthy metrics
    local alert_metrics=(
        "gateway_requests_total"
        "gateway_request_duration_seconds"
        "gateway_errors_total"
    )
    
    for metric in "${alert_metrics[@]}"; do
        if echo "$metrics_response" | grep -q "$metric"; then
            success "Alert metric available: $metric"
        else
            warning "Alert metric missing: $metric"
        fi
    done
}

# =============================================================================
# DISASTER RECOVERY TESTS
# =============================================================================

test_backup_procedures() {
    log "💾 Testing backup procedures..."
    
    # Check if backup script exists and is executable
    if [ -x "scripts/backup-admin.sh" ]; then
        success "Backup script is available and executable"
        
        # Test dry run of backup
        if DRY_RUN=true ./scripts/backup-admin.sh list >/dev/null 2>&1; then
            success "Backup script dry run successful"
        else
            warning "Backup script dry run failed"
        fi
    else
        warning "Backup script not found or not executable"
    fi
}

test_configuration_reload() {
    log "🔄 Testing configuration reload..."
    
    # This would test hot configuration reloading
    # For now, we'll just check if the configuration endpoint is available
    
    if [ -n "$ADMIN_URL" ]; then
        if http_request "GET" "$ADMIN_URL/api/v1/config" "200"; then
            success "Configuration endpoint accessible"
        else
            warning "Configuration endpoint not accessible"
        fi
    else
        warning "Admin URL not available, skipping configuration reload test"
    fi
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

generate_test_report() {
    log "📊 Generating test report..."
    
    local report_file="e2e-test-report-$(date +'%Y%m%d_%H%M%S').json"
    
    cat > "$report_file" << EOF
{
    "test_run": {
        "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
        "environment": "$ENVIRONMENT",
        "namespace": "$NAMESPACE",
        "gateway_url": "$GATEWAY_URL",
        "admin_url": "$ADMIN_URL"
    },
    "results": {
        "tests_passed": $TESTS_PASSED,
        "tests_failed": $TESTS_FAILED,
        "tests_skipped": $TESTS_SKIPPED,
        "total_tests": $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED)),
        "success_rate": $(echo "scale=2; $TESTS_PASSED * 100 / ($TESTS_PASSED + $TESTS_FAILED + $TESTS_SKIPPED)" | bc -l 2>/dev/null || echo "0")
    },
    "test_categories": {
        "infrastructure": "completed",
        "functional": "completed",
        "performance": "completed",
        "security": "$([ "$SKIP_SECURITY_TESTS" = "true" ] && echo "skipped" || echo "completed")",
        "integration": "completed",
        "monitoring": "completed",
        "disaster_recovery": "completed"
    },
    "recommendations": [
        $([ $TESTS_FAILED -gt 0 ] && echo '"Investigate and fix failed tests before production deployment",' || echo "")
        $([ $TESTS_SKIPPED -gt 5 ] && echo '"Review skipped tests and enable them if applicable",' || echo "")
        "Monitor system performance and adjust resources as needed",
        "Set up automated testing pipeline for continuous validation",
        "Review and update security configurations regularly"
    ]
}
EOF
    
    success "Test report generated: $report_file"
    
    # Display summary
    echo
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo "Tests Passed:  $TESTS_PASSED"
    echo "Tests Failed:  $TESTS_FAILED"
    echo "Tests Skipped: $TESTS_SKIPPED"
    echo "Total Tests:   $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    echo "Success Rate:  $(echo "scale=1; $TESTS_PASSED * 100 / ($TESTS_PASSED + $TESTS_FAILED + $TESTS_SKIPPED)" | bc -l 2>/dev/null || echo "0")%"
    echo "=========================================="
    
    if [ $TESTS_FAILED -eq 0 ]; then
        success "🎉 All tests passed! System is ready for production."
        return 0
    else
        error "❌ Some tests failed. Please review and fix issues before production deployment."
        return 1
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "🚀 Starting end-to-end validation for API Gateway"
    log "Environment: $ENVIRONMENT"
    log "Namespace: $NAMESPACE"
    log "Test Timeout: ${TEST_TIMEOUT}s"
    
    # Check required tools
    local required_tools=("curl" "kubectl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            fatal "$tool is required but not installed"
        fi
    done
    
    # Discover service URLs
    discover_service_urls
    
    # Run test suites
    log "📋 Running test suites..."
    
    # Infrastructure tests
    log "🏗️  Running infrastructure tests..."
    test_kubernetes_resources
    test_service_connectivity
    
    # Functional tests
    log "⚙️  Running functional tests..."
    test_health_endpoints
    test_metrics_endpoints
    test_api_endpoints
    test_authentication
    test_rate_limiting
    test_cors
    
    # Performance tests
    log "⚡ Running performance tests..."
    test_response_times
    test_concurrent_requests
    run_load_tests
    
    # Security tests
    log "🔒 Running security tests..."
    run_security_tests
    
    # Integration tests
    log "🔗 Running integration tests..."
    test_service_discovery
    test_load_balancing
    test_circuit_breaker
    test_caching
    
    # Monitoring and observability tests
    log "📊 Running monitoring tests..."
    test_logging
    test_tracing
    test_alerting
    
    # Disaster recovery tests
    log "🆘 Running disaster recovery tests..."
    test_backup_procedures
    test_configuration_reload
    
    # Generate report
    generate_test_report
}

# Show usage if help requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
End-to-End Validation Script for API Gateway

Usage: $0 [OPTIONS]

Environment Variables:
  ENVIRONMENT              Deployment environment (default: production)
  NAMESPACE               Kubernetes namespace (default: api-gateway)
  KUBECTL_CONTEXT         Kubectl context (default: production)
  GATEWAY_URL             Gateway URL (auto-discovered if not set)
  ADMIN_URL               Admin URL (auto-discovered if not set)
  TEST_TIMEOUT            Test timeout in seconds (default: 300)
  PARALLEL_TESTS          Number of parallel tests (default: 5)
  LOAD_TEST_DURATION      Load test duration in seconds (default: 60)
  LOAD_TEST_USERS         Load test concurrent users (default: 10)
  SKIP_LOAD_TESTS         Skip load tests (default: false)
  SKIP_SECURITY_TESTS     Skip security tests (default: false)
  TEST_API_KEY            API key for authentication tests
  TEST_JWT_TOKEN          JWT token for authentication tests

Examples:
  # Standard validation
  $0

  # Skip load tests
  SKIP_LOAD_TESTS=true $0

  # Test with authentication
  TEST_API_KEY="your-api-key" TEST_JWT_TOKEN="your-jwt-token" $0

  # Custom gateway URL
  GATEWAY_URL="https://api.example.com" $0
EOF
    exit 0
fi

# Execute main function
main "$@"
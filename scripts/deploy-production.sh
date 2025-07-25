#!/bin/bash

# Production Deployment Script for API Gateway
# This script handles the complete deployment process with safety checks and rollback capabilities

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-api-gateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-your-registry.com}"
IMAGE_NAME="${IMAGE_NAME:-api-gateway}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production}"
HELM_RELEASE_NAME="${HELM_RELEASE_NAME:-api-gateway}"
CONFIG_FILE="${CONFIG_FILE:-config/production.yaml}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
DEPLOYMENT_TIMEOUT="${DEPLOYMENT_TIMEOUT:-600}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
}

fatal() {
    error "$1"
    exit 1
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Wait for deployment to be ready
wait_for_deployment() {
    local deployment_name="$1"
    local timeout="$2"
    
    log "Waiting for deployment $deployment_name to be ready (timeout: ${timeout}s)..."
    
    if kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" wait \
        --for=condition=available \
        --timeout="${timeout}s" \
        deployment/"$deployment_name"; then
        success "Deployment $deployment_name is ready"
        return 0
    else
        error "Deployment $deployment_name failed to become ready within ${timeout}s"
        return 1
    fi
}

# Health check function
health_check() {
    local service_url="$1"
    local timeout="$2"
    local interval=5
    local elapsed=0
    
    log "Performing health check on $service_url (timeout: ${timeout}s)..."
    
    while [ $elapsed -lt $timeout ]; do
        if curl -f -s "$service_url/health" >/dev/null 2>&1; then
            success "Health check passed"
            return 0
        fi
        
        log "Health check failed, retrying in ${interval}s... (${elapsed}/${timeout}s elapsed)"
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    error "Health check failed after ${timeout}s"
    return 1
}

# Rollback function
rollback_deployment() {
    warning "Rolling back deployment..."
    
    if kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" rollout undo deployment/api-gateway; then
        success "Rollback initiated"
        
        if wait_for_deployment "api-gateway" "$DEPLOYMENT_TIMEOUT"; then
            success "Rollback completed successfully"
        else
            fatal "Rollback failed"
        fi
    else
        fatal "Failed to initiate rollback"
    fi
}

# =============================================================================
# PRE-DEPLOYMENT CHECKS
# =============================================================================

pre_deployment_checks() {
    log "🔍 Performing pre-deployment checks..."
    
    # Check required tools
    local required_tools=("kubectl" "docker" "helm" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            fatal "$tool is required but not installed"
        fi
    done
    success "All required tools are available"
    
    # Check kubectl context
    local current_context
    current_context=$(kubectl config current-context)
    if [ "$current_context" != "$KUBECTL_CONTEXT" ]; then
        warning "Current kubectl context is '$current_context', switching to '$KUBECTL_CONTEXT'"
        kubectl config use-context "$KUBECTL_CONTEXT" || fatal "Failed to switch kubectl context"
    fi
    success "kubectl context verified: $KUBECTL_CONTEXT"
    
    # Check namespace exists
    if ! kubectl --context="$KUBECTL_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1; then
        log "Creating namespace $NAMESPACE..."
        kubectl --context="$KUBECTL_CONTEXT" create namespace "$NAMESPACE" || fatal "Failed to create namespace"
    fi
    success "Namespace $NAMESPACE exists"
    
    # Check configuration file
    if [ ! -f "$CONFIG_FILE" ]; then
        fatal "Configuration file $CONFIG_FILE not found"
    fi
    success "Configuration file $CONFIG_FILE exists"
    
    # Validate configuration
    log "Validating configuration..."
    if ! ./target/release/api-gateway --config "$CONFIG_FILE" --validate-config; then
        fatal "Configuration validation failed"
    fi
    success "Configuration validation passed"
    
    # Check Docker registry access
    log "Checking Docker registry access..."
    if ! docker pull "$REGISTRY/$IMAGE_NAME:$IMAGE_TAG" >/dev/null 2>&1; then
        warning "Cannot pull image $REGISTRY/$IMAGE_NAME:$IMAGE_TAG - will build locally"
    else
        success "Docker registry access verified"
    fi
    
    success "Pre-deployment checks completed"
}

# =============================================================================
# BUILD AND PUSH
# =============================================================================

build_and_push() {
    log "🏗️  Building and pushing Docker image..."
    
    # Build the application
    log "Building Rust application..."
    cargo build --release || fatal "Failed to build application"
    success "Application built successfully"
    
    # Build Docker image
    local full_image_name="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    log "Building Docker image: $full_image_name"
    
    docker build \
        --tag "$full_image_name" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse HEAD)" \
        --build-arg VERSION="$IMAGE_TAG" \
        . || fatal "Failed to build Docker image"
    
    success "Docker image built: $full_image_name"
    
    # Push to registry
    if [ "$DRY_RUN" != "true" ]; then
        log "Pushing Docker image to registry..."
        docker push "$full_image_name" || fatal "Failed to push Docker image"
        success "Docker image pushed successfully"
    else
        log "DRY_RUN: Skipping Docker image push"
    fi
}

# =============================================================================
# DEPLOYMENT
# =============================================================================

deploy_application() {
    log "🚀 Deploying application..."
    
    # Create ConfigMap for configuration
    log "Creating configuration ConfigMap..."
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" create configmap api-gateway-config \
        --from-file="$CONFIG_FILE" \
        --dry-run=client -o yaml | \
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" apply -f - || \
        fatal "Failed to create configuration ConfigMap"
    
    # Deploy using Helm or kubectl
    if [ -f "helm/api-gateway/Chart.yaml" ]; then
        deploy_with_helm
    else
        deploy_with_kubectl
    fi
}

deploy_with_helm() {
    log "Deploying with Helm..."
    
    local helm_args=(
        "upgrade" "--install" "$HELM_RELEASE_NAME"
        "helm/api-gateway"
        "--namespace" "$NAMESPACE"
        "--set" "image.repository=$REGISTRY/$IMAGE_NAME"
        "--set" "image.tag=$IMAGE_TAG"
        "--set" "environment=$ENVIRONMENT"
        "--timeout" "${DEPLOYMENT_TIMEOUT}s"
        "--wait"
    )
    
    if [ "$DRY_RUN" = "true" ]; then
        helm_args+=("--dry-run")
    fi
    
    if helm "${helm_args[@]}"; then
        success "Helm deployment completed"
    else
        error "Helm deployment failed"
        if [ "$ROLLBACK_ON_FAILURE" = "true" ] && [ "$DRY_RUN" != "true" ]; then
            rollback_deployment
        fi
        fatal "Deployment failed"
    fi
}

deploy_with_kubectl() {
    log "Deploying with kubectl..."
    
    # Update deployment image
    local full_image_name="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    
    if [ "$DRY_RUN" = "true" ]; then
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" set image \
            deployment/api-gateway api-gateway="$full_image_name" \
            --dry-run=client -o yaml
    else
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" set image \
            deployment/api-gateway api-gateway="$full_image_name" || \
            fatal "Failed to update deployment image"
        
        # Wait for rollout to complete
        if ! kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" rollout status \
            deployment/api-gateway --timeout="${DEPLOYMENT_TIMEOUT}s"; then
            error "Deployment rollout failed"
            if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
                rollback_deployment
            fi
            fatal "Deployment failed"
        fi
        
        success "kubectl deployment completed"
    fi
}

# =============================================================================
# POST-DEPLOYMENT VERIFICATION
# =============================================================================

post_deployment_verification() {
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Skipping post-deployment verification"
        return 0
    fi
    
    log "🔍 Performing post-deployment verification..."
    
    # Wait for pods to be ready
    log "Waiting for pods to be ready..."
    if ! kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" wait \
        --for=condition=ready \
        --timeout="${HEALTH_CHECK_TIMEOUT}s" \
        pod -l app.kubernetes.io/name=api-gateway; then
        error "Pods failed to become ready"
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            rollback_deployment
        fi
        fatal "Post-deployment verification failed"
    fi
    success "All pods are ready"
    
    # Get service URL for health checks
    local service_url
    service_url=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [ -z "$service_url" ]; then
        # Try to get cluster IP if LoadBalancer IP is not available
        service_url=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
            -o jsonpath='{.spec.clusterIP}')
        service_url="http://$service_url:8080"
    else
        service_url="http://$service_url:8080"
    fi
    
    # Perform health checks
    if ! health_check "$service_url" "$HEALTH_CHECK_TIMEOUT"; then
        error "Health check failed"
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            rollback_deployment
        fi
        fatal "Post-deployment verification failed"
    fi
    
    # Run integration tests if not skipped
    if [ "$SKIP_TESTS" != "true" ]; then
        run_integration_tests "$service_url"
    fi
    
    success "Post-deployment verification completed"
}

run_integration_tests() {
    local service_url="$1"
    
    log "🧪 Running integration tests..."
    
    # Basic API tests
    log "Testing basic API endpoints..."
    
    # Test health endpoint
    if ! curl -f -s "$service_url/health" | jq -e '.status == "healthy"' >/dev/null; then
        error "Health endpoint test failed"
        return 1
    fi
    
    # Test readiness endpoint
    if ! curl -f -s "$service_url/ready" | jq -e '.status == "ready"' >/dev/null; then
        error "Readiness endpoint test failed"
        return 1
    fi
    
    # Test metrics endpoint
    if ! curl -f -s "$service_url:9090/metrics" | grep -q "gateway_requests_total"; then
        error "Metrics endpoint test failed"
        return 1
    fi
    
    success "Integration tests passed"
}

# =============================================================================
# CLEANUP
# =============================================================================

cleanup() {
    log "🧹 Performing cleanup..."
    
    # Clean up old Docker images
    log "Cleaning up old Docker images..."
    docker image prune -f >/dev/null 2>&1 || true
    
    # Clean up old ReplicaSets
    log "Cleaning up old ReplicaSets..."
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" delete replicaset \
        --field-selector='status.replicas=0' >/dev/null 2>&1 || true
    
    success "Cleanup completed"
}

# =============================================================================
# MAIN DEPLOYMENT FLOW
# =============================================================================

main() {
    log "🚀 Starting production deployment of API Gateway"
    log "Environment: $ENVIRONMENT"
    log "Namespace: $NAMESPACE"
    log "Image: $REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    log "Dry run: $DRY_RUN"
    
    # Trap to ensure cleanup on exit
    trap cleanup EXIT
    
    # Execute deployment steps
    pre_deployment_checks
    build_and_push
    deploy_application
    post_deployment_verification
    
    success "🎉 Deployment completed successfully!"
    
    # Display deployment information
    log "📊 Deployment Information:"
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get pods -l app.kubernetes.io/name=api-gateway
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get services api-gateway
    
    log "🔗 Access URLs:"
    local service_ip
    service_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || \
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.spec.clusterIP}')
    
    if [ -n "$service_ip" ]; then
        log "  Gateway: http://$service_ip:8080"
        log "  Admin:   http://$service_ip:9090"
        log "  Metrics: http://$service_ip:9090/metrics"
    fi
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Show usage if help requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
Production Deployment Script for API Gateway

Usage: $0 [OPTIONS]

Environment Variables:
  ENVIRONMENT              Deployment environment (default: production)
  NAMESPACE               Kubernetes namespace (default: api-gateway)
  IMAGE_TAG               Docker image tag (default: latest)
  REGISTRY                Docker registry (default: your-registry.com)
  IMAGE_NAME              Docker image name (default: api-gateway)
  KUBECTL_CONTEXT         Kubectl context (default: production)
  HELM_RELEASE_NAME       Helm release name (default: api-gateway)
  CONFIG_FILE             Configuration file (default: config/production.yaml)
  DRY_RUN                 Dry run mode (default: false)
  SKIP_TESTS              Skip integration tests (default: false)
  ROLLBACK_ON_FAILURE     Rollback on failure (default: true)
  HEALTH_CHECK_TIMEOUT    Health check timeout in seconds (default: 300)
  DEPLOYMENT_TIMEOUT      Deployment timeout in seconds (default: 600)

Examples:
  # Standard production deployment
  $0

  # Dry run deployment
  DRY_RUN=true $0

  # Deploy specific version
  IMAGE_TAG=v1.2.3 $0

  # Deploy to staging
  ENVIRONMENT=staging NAMESPACE=api-gateway-staging $0
EOF
    exit 0
fi

# Execute main function
main "$@"
#!/bin/bash

# API Gateway Deployment Script
# This script automates the deployment of the API Gateway to various environments
# with comprehensive validation, rollback capabilities, and monitoring integration

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/gateway-deploy-${TIMESTAMP}.log"

# Default values
ENVIRONMENT="staging"
IMAGE_TAG="latest"
NAMESPACE=""
CONFIG_FILE=""
DRY_RUN=false
SKIP_TESTS=false
ROLLBACK=false
PREVIOUS_VERSION=""
TIMEOUT=600
HEALTH_CHECK_RETRIES=30
HEALTH_CHECK_INTERVAL=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}" | tee -a "$LOG_FILE"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy API Gateway to Kubernetes

OPTIONS:
    -e, --environment ENV       Target environment (staging, production) [default: staging]
    -t, --tag TAG              Docker image tag [default: latest]
    -n, --namespace NAMESPACE  Kubernetes namespace [default: api-gateway-ENV]
    -c, --config CONFIG        Configuration file path
    -d, --dry-run              Perform a dry run without making changes
    -s, --skip-tests           Skip pre-deployment tests
    -r, --rollback VERSION     Rollback to previous version
    --timeout SECONDS          Deployment timeout in seconds [default: 600]
    --health-retries COUNT     Health check retry count [default: 30]
    --health-interval SECONDS  Health check interval [default: 10]
    -h, --help                 Show this help message

EXAMPLES:
    # Deploy to staging
    $0 --environment staging --tag v1.2.0

    # Deploy to production with custom config
    $0 --environment production --tag v1.2.0 --config config/production.yaml

    # Dry run deployment
    $0 --environment production --tag v1.2.0 --dry-run

    # Rollback to previous version
    $0 --environment production --rollback v1.1.0

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -s|--skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -r|--rollback)
                ROLLBACK=true
                PREVIOUS_VERSION="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --health-retries)
                HEALTH_CHECK_RETRIES="$2"
                shift 2
                ;;
            --health-interval)
                HEALTH_CHECK_INTERVAL="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set default namespace if not provided
    if [[ -z "$NAMESPACE" ]]; then
        NAMESPACE="api-gateway-${ENVIRONMENT}"
    fi

    # Set default config file if not provided
    if [[ -z "$CONFIG_FILE" ]]; then
        CONFIG_FILE="${PROJECT_ROOT}/config/${ENVIRONMENT}.yaml"
    fi
}

# Validate prerequisites
validate_prerequisites() {
    log "Validating prerequisites..."

    # Check required tools
    local required_tools=("kubectl" "docker" "helm")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
            exit 1
        fi
    done

    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        warn "Namespace $NAMESPACE does not exist, creating it..."
        if [[ "$DRY_RUN" == "false" ]]; then
            kubectl create namespace "$NAMESPACE"
        fi
    fi

    # Validate configuration file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    # Validate Docker image exists
    if [[ "$DRY_RUN" == "false" ]] && [[ "$ROLLBACK" == "false" ]]; then
        log "Validating Docker image: api-gateway:${IMAGE_TAG}"
        if ! docker manifest inspect "api-gateway:${IMAGE_TAG}" &> /dev/null; then
            error "Docker image api-gateway:${IMAGE_TAG} not found"
            exit 1
        fi
    fi

    success "Prerequisites validation completed"
}

# Run pre-deployment tests
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        warn "Skipping pre-deployment tests"
        return 0
    fi

    log "Running pre-deployment tests..."

    # Configuration validation
    log "Validating configuration..."
    if ! "${PROJECT_ROOT}/target/release/api-gateway" --config "$CONFIG_FILE" --validate-config &> /dev/null; then
        error "Configuration validation failed"
        exit 1
    fi

    # Unit tests
    log "Running unit tests..."
    cd "$PROJECT_ROOT"
    if ! cargo test --release &> /dev/null; then
        error "Unit tests failed"
        exit 1
    fi

    # Integration tests (if available)
    if [[ -f "${PROJECT_ROOT}/scripts/integration-tests.sh" ]]; then
        log "Running integration tests..."
        if ! "${PROJECT_ROOT}/scripts/integration-tests.sh"; then
            error "Integration tests failed"
            exit 1
        fi
    fi

    success "Pre-deployment tests completed"
}

# Create backup of current deployment
create_backup() {
    log "Creating backup of current deployment..."

    local backup_dir="${PROJECT_ROOT}/backups/deployment-${TIMESTAMP}"
    mkdir -p "$backup_dir"

    # Backup current deployment
    kubectl get deployment api-gateway -n "$NAMESPACE" -o yaml > "${backup_dir}/deployment.yaml" 2>/dev/null || true
    kubectl get configmap gateway-config -n "$NAMESPACE" -o yaml > "${backup_dir}/configmap.yaml" 2>/dev/null || true
    kubectl get secret gateway-secrets -n "$NAMESPACE" -o yaml > "${backup_dir}/secrets.yaml" 2>/dev/null || true
    kubectl get service api-gateway -n "$NAMESPACE" -o yaml > "${backup_dir}/service.yaml" 2>/dev/null || true

    # Save current image tag
    local current_image
    current_image=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "none")
    echo "$current_image" > "${backup_dir}/current-image.txt"

    log "Backup created at: $backup_dir"
}

# Update configuration
update_configuration() {
    log "Updating configuration..."

    # Create ConfigMap from configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would create ConfigMap from $CONFIG_FILE"
    else
        kubectl create configmap gateway-config \
            --from-file="$CONFIG_FILE" \
            --namespace="$NAMESPACE" \
            --dry-run=client -o yaml | kubectl apply -f -
    fi

    # Update secrets if they exist
    if [[ -f "${PROJECT_ROOT}/secrets/${ENVIRONMENT}-secrets.yaml" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log "[DRY RUN] Would apply secrets"
        else
            kubectl apply -f "${PROJECT_ROOT}/secrets/${ENVIRONMENT}-secrets.yaml" -n "$NAMESPACE"
        fi
    fi

    success "Configuration updated"
}

# Deploy application
deploy_application() {
    if [[ "$ROLLBACK" == "true" ]]; then
        rollback_deployment
        return
    fi

    log "Deploying API Gateway version $IMAGE_TAG to $ENVIRONMENT..."

    # Update deployment image
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would update deployment image to api-gateway:${IMAGE_TAG}"
    else
        kubectl set image deployment/api-gateway \
            api-gateway="api-gateway:${IMAGE_TAG}" \
            --namespace="$NAMESPACE"
    fi

    # Wait for rollout to complete
    if [[ "$DRY_RUN" == "false" ]]; then
        log "Waiting for deployment rollout to complete..."
        if ! kubectl rollout status deployment/api-gateway \
            --namespace="$NAMESPACE" \
            --timeout="${TIMEOUT}s"; then
            error "Deployment rollout failed"
            return 1
        fi
    fi

    success "Application deployed successfully"
}

# Rollback deployment
rollback_deployment() {
    log "Rolling back to version $PREVIOUS_VERSION..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would rollback to version $PREVIOUS_VERSION"
        return
    fi

    # Rollback using kubectl
    if [[ -n "$PREVIOUS_VERSION" ]]; then
        kubectl set image deployment/api-gateway \
            api-gateway="api-gateway:${PREVIOUS_VERSION}" \
            --namespace="$NAMESPACE"
    else
        kubectl rollout undo deployment/api-gateway --namespace="$NAMESPACE"
    fi

    # Wait for rollback to complete
    log "Waiting for rollback to complete..."
    if ! kubectl rollout status deployment/api-gateway \
        --namespace="$NAMESPACE" \
        --timeout="${TIMEOUT}s"; then
        error "Rollback failed"
        return 1
    fi

    success "Rollback completed successfully"
}

# Perform health checks
health_check() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would perform health checks"
        return 0
    fi

    log "Performing health checks..."

    # Get service endpoint
    local service_ip
    service_ip=$(kubectl get service api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    
    if [[ -z "$service_ip" ]]; then
        error "Could not get service IP"
        return 1
    fi

    # Health check loop
    local retries=0
    while [[ $retries -lt $HEALTH_CHECK_RETRIES ]]; do
        log "Health check attempt $((retries + 1))/$HEALTH_CHECK_RETRIES..."
        
        # Port forward for health check
        kubectl port-forward service/api-gateway 8080:8080 -n "$NAMESPACE" &
        local port_forward_pid=$!
        sleep 2

        # Perform health check
        if curl -f -s "http://localhost:8080/health" > /dev/null; then
            kill $port_forward_pid 2>/dev/null || true
            success "Health check passed"
            return 0
        fi

        kill $port_forward_pid 2>/dev/null || true
        retries=$((retries + 1))
        
        if [[ $retries -lt $HEALTH_CHECK_RETRIES ]]; then
            log "Health check failed, retrying in ${HEALTH_CHECK_INTERVAL}s..."
            sleep "$HEALTH_CHECK_INTERVAL"
        fi
    done

    error "Health checks failed after $HEALTH_CHECK_RETRIES attempts"
    return 1
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would verify deployment"
        return 0
    fi

    # Check pod status
    local ready_pods
    ready_pods=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    local desired_pods
    desired_pods=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')

    if [[ "$ready_pods" != "$desired_pods" ]]; then
        error "Deployment verification failed: $ready_pods/$desired_pods pods ready"
        return 1
    fi

    # Check service endpoints
    local endpoints
    endpoints=$(kubectl get endpoints api-gateway -n "$NAMESPACE" -o jsonpath='{.subsets[0].addresses}')
    if [[ -z "$endpoints" ]]; then
        error "No service endpoints available"
        return 1
    fi

    # Verify image version
    local current_image
    current_image=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
    local expected_image="api-gateway:${IMAGE_TAG}"
    
    if [[ "$ROLLBACK" == "true" ]]; then
        expected_image="api-gateway:${PREVIOUS_VERSION}"
    fi

    if [[ "$current_image" != "$expected_image" ]]; then
        error "Image verification failed: expected $expected_image, got $current_image"
        return 1
    fi

    success "Deployment verification completed"
}

# Send deployment notification
send_notification() {
    local status="$1"
    local message="$2"

    log "Sending deployment notification..."

    # Slack notification (if webhook URL is set)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        local color="good"
        if [[ "$status" == "failed" ]]; then
            color="danger"
        fi

        curl -X POST -H 'Content-type: application/json' \
            --data "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"API Gateway Deployment\",
                    \"fields\": [
                        {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
                        {\"title\": \"Version\", \"value\": \"$IMAGE_TAG\", \"short\": true},
                        {\"title\": \"Status\", \"value\": \"$status\", \"short\": true},
                        {\"title\": \"Message\", \"value\": \"$message\", \"short\": false}
                    ]
                }]
            }" \
            "$SLACK_WEBHOOK_URL" || warn "Failed to send Slack notification"
    fi

    # Email notification (if configured)
    if [[ -n "${EMAIL_RECIPIENTS:-}" ]]; then
        echo "$message" | mail -s "API Gateway Deployment - $status" "$EMAIL_RECIPIENTS" || warn "Failed to send email notification"
    fi
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Remove temporary files
    rm -f /tmp/kubectl-port-forward-* 2>/dev/null || true
}

# Main deployment function
main() {
    log "Starting API Gateway deployment..."
    log "Environment: $ENVIRONMENT"
    log "Image Tag: $IMAGE_TAG"
    log "Namespace: $NAMESPACE"
    log "Config File: $CONFIG_FILE"
    log "Dry Run: $DRY_RUN"

    # Set trap for cleanup
    trap cleanup EXIT

    # Validate prerequisites
    validate_prerequisites

    # Run tests
    run_tests

    # Create backup
    create_backup

    # Update configuration
    update_configuration

    # Deploy application
    if ! deploy_application; then
        error "Deployment failed"
        send_notification "failed" "Deployment to $ENVIRONMENT failed"
        exit 1
    fi

    # Perform health checks
    if ! health_check; then
        error "Health checks failed"
        send_notification "failed" "Health checks failed for $ENVIRONMENT deployment"
        exit 1
    fi

    # Verify deployment
    if ! verify_deployment; then
        error "Deployment verification failed"
        send_notification "failed" "Deployment verification failed for $ENVIRONMENT"
        exit 1
    fi

    # Success
    local action="Deployment"
    if [[ "$ROLLBACK" == "true" ]]; then
        action="Rollback"
    fi

    success "$action completed successfully!"
    send_notification "success" "$action to $ENVIRONMENT completed successfully"

    log "Deployment log saved to: $LOG_FILE"
}

# Parse arguments and run main function
parse_args "$@"
main
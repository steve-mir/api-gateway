#!/bin/bash

# API Gateway Kubernetes Deployment Script
# This script demonstrates the complete deployment process for the API Gateway

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-api-gateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_BUILD="${SKIP_BUILD:-false}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300s}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
API Gateway Kubernetes Deployment Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -n, --namespace NAME    Kubernetes namespace (default: api-gateway)
    -t, --tag TAG          Docker image tag (default: latest)
    -r, --registry URL     Docker registry URL
    -c, --context CONTEXT  Kubectl context to use
    -d, --dry-run          Perform a dry run without applying changes
    -s, --skip-build       Skip Docker image build
    -w, --wait TIMEOUT     Wait timeout for deployments (default: 300s)

Environment Variables:
    NAMESPACE              Kubernetes namespace
    IMAGE_TAG              Docker image tag
    REGISTRY               Docker registry URL
    KUBECTL_CONTEXT        Kubectl context
    DRY_RUN                Perform dry run (true/false)
    SKIP_BUILD             Skip build (true/false)
    WAIT_TIMEOUT           Wait timeout

Examples:
    # Basic deployment
    $0

    # Deploy to specific namespace with custom tag
    $0 --namespace production --tag v1.2.3

    # Dry run deployment
    $0 --dry-run

    # Deploy with custom registry
    $0 --registry my-registry.com --tag v1.2.3
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -c|--context)
            KUBECTL_CONTEXT="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -s|--skip-build)
            SKIP_BUILD="true"
            shift
            ;;
        -w|--wait)
            WAIT_TIMEOUT="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if docker is installed (unless skipping build)
    if [[ "$SKIP_BUILD" != "true" ]] && ! command -v docker &> /dev/null; then
        log_error "docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check kubectl context
    if [[ -n "$KUBECTL_CONTEXT" ]]; then
        if ! kubectl config use-context "$KUBECTL_CONTEXT" &> /dev/null; then
            log_error "Failed to switch to kubectl context: $KUBECTL_CONTEXT"
            exit 1
        fi
        log_info "Using kubectl context: $KUBECTL_CONTEXT"
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build Docker image
build_image() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Skipping Docker image build"
        return
    fi
    
    log_info "Building Docker image..."
    
    local image_name="api-gateway"
    if [[ -n "$REGISTRY" ]]; then
        image_name="${REGISTRY}/api-gateway"
    fi
    
    local full_image_name="${image_name}:${IMAGE_TAG}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would build image: $full_image_name"
        return
    fi
    
    # Build the image
    docker build -t "$full_image_name" .
    
    # Push to registry if specified
    if [[ -n "$REGISTRY" ]]; then
        log_info "Pushing image to registry..."
        docker push "$full_image_name"
    fi
    
    log_success "Docker image built: $full_image_name"
}

# Create namespace if it doesn't exist
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Namespace $NAMESPACE already exists"
        return
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would create namespace: $NAMESPACE"
        return
    fi
    
    kubectl apply -f k8s/namespace.yaml
    log_success "Namespace created: $NAMESPACE"
}

# Apply Kubernetes manifests
apply_manifests() {
    log_info "Applying Kubernetes manifests..."
    
    local kubectl_cmd="kubectl"
    if [[ "$DRY_RUN" == "true" ]]; then
        kubectl_cmd="kubectl --dry-run=client"
        log_info "DRY RUN: Validating manifests..."
    fi
    
    # Apply manifests in order
    local manifests=(
        "k8s/namespace.yaml"
        "k8s/rbac.yaml"
        "k8s/secret.yaml"
        "k8s/configmap.yaml"
        "k8s/service.yaml"
        "k8s/deployment.yaml"
        "k8s/hpa.yaml"
        "k8s/pdb.yaml"
        "k8s/networkpolicy.yaml"
        "k8s/ingress.yaml"
    )
    
    for manifest in "${manifests[@]}"; do
        if [[ -f "$manifest" ]]; then
            log_info "Applying $manifest..."
            
            # Update image tag in deployment manifest
            if [[ "$manifest" == "k8s/deployment.yaml" ]]; then
                local temp_manifest="/tmp/deployment-${RANDOM}.yaml"
                local image_name="api-gateway"
                if [[ -n "$REGISTRY" ]]; then
                    image_name="${REGISTRY}/api-gateway"
                fi
                
                sed "s|image: api-gateway:latest|image: ${image_name}:${IMAGE_TAG}|g" "$manifest" > "$temp_manifest"
                $kubectl_cmd apply -f "$temp_manifest"
                rm -f "$temp_manifest"
            else
                $kubectl_cmd apply -f "$manifest"
            fi
        else
            log_warning "Manifest not found: $manifest"
        fi
    done
    
    if [[ "$DRY_RUN" != "true" ]]; then
        log_success "Kubernetes manifests applied"
    else
        log_success "Manifest validation completed"
    fi
}

# Wait for deployment to be ready
wait_for_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would wait for deployment to be ready"
        return
    fi
    
    log_info "Waiting for deployment to be ready..."
    
    if kubectl wait --for=condition=available --timeout="$WAIT_TIMEOUT" deployment/api-gateway -n "$NAMESPACE"; then
        log_success "Deployment is ready"
    else
        log_error "Deployment failed to become ready within $WAIT_TIMEOUT"
        exit 1
    fi
}

# Verify deployment
verify_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would verify deployment"
        return
    fi
    
    log_info "Verifying deployment..."
    
    # Check deployment status
    local deployment_status
    deployment_status=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}')
    
    if [[ "$deployment_status" == "True" ]]; then
        log_success "Deployment is available"
    else
        log_error "Deployment is not available"
        kubectl describe deployment api-gateway -n "$NAMESPACE"
        exit 1
    fi
    
    # Check pod status
    local ready_pods
    ready_pods=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    local desired_pods
    desired_pods=$(kubectl get deployment api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    
    log_info "Ready pods: $ready_pods/$desired_pods"
    
    if [[ "$ready_pods" == "$desired_pods" ]]; then
        log_success "All pods are ready"
    else
        log_warning "Not all pods are ready"
        kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=api-gateway
    fi
    
    # Check service endpoints
    local endpoints
    endpoints=$(kubectl get endpoints api-gateway -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' | wc -w)
    
    if [[ "$endpoints" -gt 0 ]]; then
        log_success "Service has $endpoints endpoint(s)"
    else
        log_warning "Service has no endpoints"
    fi
    
    # Display service information
    log_info "Service information:"
    kubectl get service api-gateway -n "$NAMESPACE"
    
    # Display ingress information if available
    if kubectl get ingress api-gateway-ingress -n "$NAMESPACE" &> /dev/null; then
        log_info "Ingress information:"
        kubectl get ingress api-gateway-ingress -n "$NAMESPACE"
    fi
}

# Show deployment status
show_status() {
    log_info "Deployment Status Summary:"
    echo "=========================="
    echo "Namespace: $NAMESPACE"
    echo "Image Tag: $IMAGE_TAG"
    if [[ -n "$REGISTRY" ]]; then
        echo "Registry: $REGISTRY"
    fi
    echo ""
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "DRY RUN MODE - No changes were applied"
        return
    fi
    
    # Show deployment status
    echo "Deployments:"
    kubectl get deployments -n "$NAMESPACE" -l app.kubernetes.io/name=api-gateway
    echo ""
    
    # Show pod status
    echo "Pods:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=api-gateway
    echo ""
    
    # Show service status
    echo "Services:"
    kubectl get services -n "$NAMESPACE" -l app.kubernetes.io/name=api-gateway
    echo ""
    
    # Show HPA status
    echo "Horizontal Pod Autoscalers:"
    kubectl get hpa -n "$NAMESPACE" -l app.kubernetes.io/name=api-gateway
    echo ""
    
    # Show ingress status
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        echo "Ingresses:"
        kubectl get ingress -n "$NAMESPACE"
        echo ""
    fi
}

# Cleanup function for error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed with exit code $exit_code"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            log_info "Recent events in namespace $NAMESPACE:"
            kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -10
        fi
    fi
    exit $exit_code
}

# Set up error handling
trap cleanup EXIT

# Main deployment process
main() {
    log_info "Starting API Gateway deployment..."
    log_info "Namespace: $NAMESPACE"
    log_info "Image Tag: $IMAGE_TAG"
    if [[ -n "$REGISTRY" ]]; then
        log_info "Registry: $REGISTRY"
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN MODE: No changes will be applied"
    fi
    echo ""
    
    check_prerequisites
    build_image
    create_namespace
    apply_manifests
    wait_for_deployment
    verify_deployment
    show_status
    
    log_success "API Gateway deployment completed successfully!"
    
    if [[ "$DRY_RUN" != "true" ]]; then
        echo ""
        log_info "Next steps:"
        echo "1. Check the deployment status: kubectl get all -n $NAMESPACE"
        echo "2. View logs: kubectl logs -f deployment/api-gateway -n $NAMESPACE"
        echo "3. Access the gateway through the service or ingress"
        echo "4. Monitor with: kubectl top pods -n $NAMESPACE"
    fi
}

# Run main function
main "$@"
#!/bin/bash

# API Gateway Build Script
# Automates the build process for the API Gateway including Docker image creation,
# testing, and artifact management

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default values
BUILD_TYPE="release"
IMAGE_TAG="latest"
PUSH_IMAGE=false
RUN_TESTS=true
PLATFORMS="linux/amd64"
REGISTRY=""
CACHE_FROM=""
BUILD_ARGS=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build API Gateway binary and Docker image

OPTIONS:
    -t, --tag TAG              Docker image tag [default: latest]
    -b, --build-type TYPE      Build type (debug, release) [default: release]
    -p, --push                 Push image to registry after build
    -r, --registry REGISTRY    Docker registry URL
    --platforms PLATFORMS      Target platforms for multi-arch build [default: linux/amd64]
    --cache-from IMAGE         Use image as cache source
    --build-arg ARG=VALUE      Pass build argument to Docker
    --skip-tests               Skip running tests
    -h, --help                 Show this help message

EXAMPLES:
    # Basic build
    $0 --tag v1.2.0

    # Build and push to registry
    $0 --tag v1.2.0 --push --registry myregistry.com

    # Multi-architecture build
    $0 --tag v1.2.0 --platforms linux/amd64,linux/arm64

    # Build with cache
    $0 --tag v1.2.0 --cache-from myregistry.com/api-gateway:latest

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -b|--build-type)
                BUILD_TYPE="$2"
                shift 2
                ;;
            -p|--push)
                PUSH_IMAGE=true
                shift
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            --platforms)
                PLATFORMS="$2"
                shift 2
                ;;
            --cache-from)
                CACHE_FROM="$2"
                shift 2
                ;;
            --build-arg)
                BUILD_ARGS="$BUILD_ARGS --build-arg $2"
                shift 2
                ;;
            --skip-tests)
                RUN_TESTS=false
                shift
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
}

# Validate prerequisites
validate_prerequisites() {
    log "Validating prerequisites..."

    # Check required tools
    local required_tools=("cargo" "docker")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
            exit 1
        fi
    done

    # Check for multi-arch build requirements
    if [[ "$PLATFORMS" == *","* ]]; then
        if ! docker buildx version &> /dev/null; then
            error "Docker buildx is required for multi-architecture builds"
            exit 1
        fi
    fi

    # Validate build type
    if [[ "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "release" ]]; then
        error "Invalid build type: $BUILD_TYPE (must be 'debug' or 'release')"
        exit 1
    fi

    success "Prerequisites validation completed"
}

# Clean previous builds
clean_build() {
    log "Cleaning previous builds..."
    
    cd "$PROJECT_ROOT"
    
    # Clean Cargo build artifacts
    cargo clean
    
    # Remove Docker build cache (optional)
    if [[ "${CLEAN_DOCKER_CACHE:-false}" == "true" ]]; then
        docker builder prune -f
    fi
    
    success "Build cleanup completed"
}

# Run tests
run_tests() {
    if [[ "$RUN_TESTS" == "false" ]]; then
        warn "Skipping tests"
        return 0
    fi

    log "Running tests..."
    cd "$PROJECT_ROOT"

    # Run unit tests
    log "Running unit tests..."
    cargo test --$BUILD_TYPE

    # Run integration tests if they exist
    if [[ -d "tests" ]]; then
        log "Running integration tests..."
        cargo test --$BUILD_TYPE --test '*'
    fi

    # Run benchmarks in release mode
    if [[ "$BUILD_TYPE" == "release" ]] && [[ -d "benches" ]]; then
        log "Running benchmarks..."
        cargo bench --no-run
    fi

    success "Tests completed successfully"
}

# Build Rust binary
build_binary() {
    log "Building Rust binary ($BUILD_TYPE mode)..."
    cd "$PROJECT_ROOT"

    # Set build flags based on build type
    local cargo_flags=""
    if [[ "$BUILD_TYPE" == "release" ]]; then
        cargo_flags="--release"
    fi

    # Build the binary
    cargo build $cargo_flags

    # Verify binary was created
    local binary_path="target/$BUILD_TYPE/api-gateway"
    if [[ ! -f "$binary_path" ]]; then
        error "Binary not found at $binary_path"
        exit 1
    fi

    # Get binary info
    local binary_size
    binary_size=$(du -h "$binary_path" | cut -f1)
    log "Binary size: $binary_size"

    success "Binary build completed"
}

# Build Docker image
build_docker_image() {
    log "Building Docker image..."
    cd "$PROJECT_ROOT"

    # Prepare image name
    local image_name="api-gateway"
    if [[ -n "$REGISTRY" ]]; then
        image_name="$REGISTRY/api-gateway"
    fi

    # Prepare build command
    local build_cmd="docker"
    local build_args="build"
    
    # Use buildx for multi-arch builds
    if [[ "$PLATFORMS" == *","* ]]; then
        build_cmd="docker buildx"
        build_args="build --platform $PLATFORMS"
        
        # Create builder if it doesn't exist
        if ! docker buildx inspect multiarch-builder &> /dev/null; then
            log "Creating multi-arch builder..."
            docker buildx create --name multiarch-builder --use
        fi
    fi

    # Add cache options
    if [[ -n "$CACHE_FROM" ]]; then
        build_args="$build_args --cache-from $CACHE_FROM"
    fi

    # Add build arguments
    build_args="$build_args $BUILD_ARGS"

    # Add tags
    build_args="$build_args -t $image_name:$IMAGE_TAG"
    
    # Add latest tag for release builds
    if [[ "$BUILD_TYPE" == "release" ]] && [[ "$IMAGE_TAG" != "latest" ]]; then
        build_args="$build_args -t $image_name:latest"
    fi

    # Add push flag if requested
    if [[ "$PUSH_IMAGE" == "true" ]]; then
        build_args="$build_args --push"
    else
        build_args="$build_args --load"
    fi

    # Build the image
    log "Running: $build_cmd $build_args ."
    eval "$build_cmd $build_args ."

    # Get image info if not pushing
    if [[ "$PUSH_IMAGE" == "false" ]]; then
        local image_size
        image_size=$(docker images "$image_name:$IMAGE_TAG" --format "table {{.Size}}" | tail -n 1)
        log "Image size: $image_size"
    fi

    success "Docker image build completed"
}

# Security scan
security_scan() {
    if ! command -v trivy &> /dev/null; then
        warn "Trivy not found, skipping security scan"
        return 0
    fi

    log "Running security scan..."
    
    local image_name="api-gateway:$IMAGE_TAG"
    if [[ -n "$REGISTRY" ]]; then
        image_name="$REGISTRY/api-gateway:$IMAGE_TAG"
    fi

    # Run Trivy scan
    trivy image --exit-code 1 --severity HIGH,CRITICAL "$image_name" || {
        warn "Security vulnerabilities found in image"
        return 1
    }

    success "Security scan completed"
}

# Generate build metadata
generate_metadata() {
    log "Generating build metadata..."
    
    local metadata_file="$PROJECT_ROOT/build-metadata.json"
    
    # Get Git information
    local git_commit=""
    local git_branch=""
    local git_tag=""
    
    if git rev-parse --git-dir > /dev/null 2>&1; then
        git_commit=$(git rev-parse HEAD)
        git_branch=$(git rev-parse --abbrev-ref HEAD)
        git_tag=$(git describe --tags --exact-match 2>/dev/null || echo "")
    fi

    # Get build information
    local build_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local rust_version=$(rustc --version)
    local cargo_version=$(cargo --version)

    # Create metadata JSON
    cat > "$metadata_file" << EOF
{
  "build": {
    "timestamp": "$build_date",
    "type": "$BUILD_TYPE",
    "version": "$IMAGE_TAG",
    "platforms": "$PLATFORMS"
  },
  "git": {
    "commit": "$git_commit",
    "branch": "$git_branch",
    "tag": "$git_tag"
  },
  "tools": {
    "rust": "$rust_version",
    "cargo": "$cargo_version"
  },
  "image": {
    "name": "api-gateway",
    "tag": "$IMAGE_TAG",
    "registry": "$REGISTRY"
  }
}
EOF

    log "Build metadata saved to: $metadata_file"
}

# Create release artifacts
create_artifacts() {
    log "Creating release artifacts..."
    
    local artifacts_dir="$PROJECT_ROOT/artifacts"
    mkdir -p "$artifacts_dir"

    # Copy binary
    cp "$PROJECT_ROOT/target/$BUILD_TYPE/api-gateway" "$artifacts_dir/"

    # Copy configuration files
    cp -r "$PROJECT_ROOT/config" "$artifacts_dir/"

    # Copy Kubernetes manifests
    cp -r "$PROJECT_ROOT/k8s" "$artifacts_dir/"

    # Copy documentation
    cp -r "$PROJECT_ROOT/docs" "$artifacts_dir/"

    # Create tarball
    local tarball_name="api-gateway-$IMAGE_TAG-$PLATFORMS.tar.gz"
    tar -czf "$artifacts_dir/$tarball_name" -C "$artifacts_dir" \
        api-gateway config k8s docs

    log "Artifacts created in: $artifacts_dir"
    log "Tarball: $artifacts_dir/$tarball_name"
}

# Main build function
main() {
    log "Starting API Gateway build..."
    log "Build Type: $BUILD_TYPE"
    log "Image Tag: $IMAGE_TAG"
    log "Platforms: $PLATFORMS"
    log "Registry: ${REGISTRY:-none}"
    log "Push Image: $PUSH_IMAGE"

    # Change to project root
    cd "$PROJECT_ROOT"

    # Validate prerequisites
    validate_prerequisites

    # Clean previous builds
    clean_build

    # Run tests
    run_tests

    # Build binary
    build_binary

    # Build Docker image
    build_docker_image

    # Run security scan
    security_scan

    # Generate metadata
    generate_metadata

    # Create artifacts
    create_artifacts

    success "Build completed successfully!"
    
    if [[ "$PUSH_IMAGE" == "true" ]]; then
        success "Image pushed to registry: ${REGISTRY}/api-gateway:${IMAGE_TAG}"
    else
        success "Image available locally: api-gateway:${IMAGE_TAG}"
    fi
}

# Parse arguments and run main function
parse_args "$@"
main
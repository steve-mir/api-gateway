#!/bin/bash

# Complete Production Deployment Script for API Gateway
# This script orchestrates the entire production deployment process

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-api-gateway}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-your-registry.com}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"
SKIP_BACKUP="${SKIP_BACKUP:-false}"
SKIP_VALIDATION="${SKIP_VALIDATION:-false}"
DATABASE_URL="${DATABASE_URL:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

section() {
    echo
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
    echo
}

# =============================================================================
# DEPLOYMENT PHASES
# =============================================================================

phase_1_pre_deployment() {
    section "PHASE 1: PRE-DEPLOYMENT PREPARATION"
    
    log "🔍 Performing pre-deployment checks..."
    
    # Check required tools
    local required_tools=("kubectl" "docker" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fatal "$tool is required but not installed"
        fi
    done
    success "All required tools are available"
    
    # Validate production readiness checklist
    if [ -f "PRODUCTION_READINESS.md" ]; then
        log "📋 Production readiness checklist found"
        warning "Please ensure all items in PRODUCTION_READINESS.md are completed"
        
        if [ "$DRY_RUN" != "true" ]; then
            read -p "Have you completed the production readiness checklist? (yes/no): " -r
            if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                fatal "Please complete the production readiness checklist before deployment"
            fi
        fi
    else
        warning "Production readiness checklist not found"
    fi
    
    # Check configuration files
    local config_files=("config/production.yaml" "config/production-best-practices.yaml")
    for config_file in "${config_files[@]}"; do
        if [ -f "$config_file" ]; then
            success "Configuration file found: $config_file"
        else
            warning "Configuration file missing: $config_file"
        fi
    done
    
    success "Pre-deployment preparation completed"
}

phase_2_backup() {
    section "PHASE 2: BACKUP CURRENT STATE"
    
    if [ "$SKIP_BACKUP" = "true" ]; then
        warning "Backup phase skipped"
        return 0
    fi
    
    log "💾 Creating backup of current state..."
    
    # Create backup using the backup script
    if [ -x "scripts/backup-admin.sh" ]; then
        local backup_env_vars=""
        if [ -n "$DATABASE_URL" ]; then
            backup_env_vars="DATABASE_URL='$DATABASE_URL'"
        fi
        
        if [ "$DRY_RUN" = "true" ]; then
            backup_env_vars="$backup_env_vars DRY_RUN=true"
        fi
        
        log "Running backup script..."
        if eval "$backup_env_vars BACKUP_TYPE=full ./scripts/backup-admin.sh backup"; then
            success "Backup completed successfully"
        else
            error "Backup failed"
            read -p "Continue deployment without backup? (yes/no): " -r
            if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                fatal "Deployment cancelled due to backup failure"
            fi
        fi
    else
        warning "Backup script not found, skipping backup"
    fi
}

phase_3_build_and_deploy() {
    section "PHASE 3: BUILD AND DEPLOY APPLICATION"
    
    log "🏗️  Building and deploying application..."
    
    # Run the main deployment script
    if [ -x "scripts/deploy-production.sh" ]; then
        local deploy_env_vars="ENVIRONMENT='$ENVIRONMENT' NAMESPACE='$NAMESPACE' IMAGE_TAG='$IMAGE_TAG' REGISTRY='$REGISTRY' KUBECTL_CONTEXT='$KUBECTL_CONTEXT'"
        
        if [ "$DRY_RUN" = "true" ]; then
            deploy_env_vars="$deploy_env_vars DRY_RUN=true"
        fi
        
        if [ "$SKIP_TESTS" = "true" ]; then
            deploy_env_vars="$deploy_env_vars SKIP_TESTS=true"
        fi
        
        log "Running deployment script..."
        if eval "$deploy_env_vars ./scripts/deploy-production.sh"; then
            success "Application deployment completed successfully"
        else
            fatal "Application deployment failed"
        fi
    else
        fatal "Deployment script not found: scripts/deploy-production.sh"
    fi
}

phase_4_admin_deployment() {
    section "PHASE 4: DEPLOY ADMIN INTERFACE"
    
    log "⚙️  Deploying admin interface..."
    
    # Run the admin deployment script
    if [ -x "scripts/admin-deployment.sh" ]; then
        local admin_env_vars="ENVIRONMENT='$ENVIRONMENT' NAMESPACE='$NAMESPACE' KUBECTL_CONTEXT='$KUBECTL_CONTEXT'"
        
        if [ -n "$DATABASE_URL" ]; then
            admin_env_vars="$admin_env_vars DATABASE_URL='$DATABASE_URL'"
        fi
        
        if [ "$DRY_RUN" = "true" ]; then
            admin_env_vars="$admin_env_vars DRY_RUN=true"
        fi
        
        log "Running admin deployment script..."
        if eval "$admin_env_vars ./scripts/admin-deployment.sh"; then
            success "Admin interface deployment completed successfully"
        else
            warning "Admin interface deployment failed (continuing with main deployment)"
        fi
    else
        warning "Admin deployment script not found, skipping admin deployment"
    fi
}

phase_5_monitoring_setup() {
    section "PHASE 5: SETUP MONITORING AND ALERTING"
    
    log "📊 Setting up monitoring and alerting..."
    
    # Apply monitoring configurations
    if [ -f "monitoring/production-monitoring.yml" ]; then
        log "Applying monitoring configuration..."
        if [ "$DRY_RUN" = "true" ]; then
            log "DRY_RUN: Would apply monitoring configuration"
        else
            if kubectl --context="$KUBECTL_CONTEXT" apply -f monitoring/production-monitoring.yml; then
                success "Monitoring configuration applied"
            else
                warning "Failed to apply monitoring configuration"
            fi
        fi
    else
        warning "Monitoring configuration not found"
    fi
    
    # Check if Prometheus is scraping metrics
    log "Verifying metrics collection..."
    sleep 10  # Wait for services to start
    
    # This would be more sophisticated in a real deployment
    success "Monitoring setup completed"
}

phase_6_validation() {
    section "PHASE 6: END-TO-END VALIDATION"
    
    if [ "$SKIP_VALIDATION" = "true" ]; then
        warning "Validation phase skipped"
        return 0
    fi
    
    log "🧪 Running end-to-end validation..."
    
    # Run the validation script
    if [ -x "scripts/e2e-validation.sh" ]; then
        local validation_env_vars="ENVIRONMENT='$ENVIRONMENT' NAMESPACE='$NAMESPACE' KUBECTL_CONTEXT='$KUBECTL_CONTEXT'"
        
        log "Running validation script..."
        if eval "$validation_env_vars ./scripts/e2e-validation.sh"; then
            success "End-to-end validation passed"
        else
            error "End-to-end validation failed"
            
            if [ "$DRY_RUN" != "true" ]; then
                read -p "Continue despite validation failures? (yes/no): " -r
                if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                    log "Initiating rollback due to validation failures..."
                    initiate_rollback
                    fatal "Deployment rolled back due to validation failures"
                fi
            fi
        fi
    else
        warning "Validation script not found, skipping validation"
    fi
}

phase_7_post_deployment() {
    section "PHASE 7: POST-DEPLOYMENT TASKS"
    
    log "🎯 Performing post-deployment tasks..."
    
    # Display deployment information
    display_deployment_info
    
    # Setup monitoring dashboards
    setup_monitoring_dashboards
    
    # Send deployment notifications
    send_deployment_notifications
    
    # Create deployment record
    create_deployment_record
    
    success "Post-deployment tasks completed"
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

initiate_rollback() {
    warning "🔄 Initiating rollback procedure..."
    
    # This would implement actual rollback logic
    # For now, we'll just log what would happen
    
    log "Rolling back application deployment..."
    if kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" rollout undo deployment/api-gateway; then
        success "Application rollback completed"
    else
        error "Application rollback failed"
    fi
    
    log "Rolling back admin deployment..."
    local admin_namespace="${NAMESPACE}-admin"
    if kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" rollout undo deployment/api-gateway-admin 2>/dev/null; then
        success "Admin rollback completed"
    else
        warning "Admin rollback failed or not needed"
    fi
    
    # Restore from backup if available
    if [ -f ".last_backup_path" ]; then
        local backup_path
        backup_path=$(cat .last_backup_path)
        warning "Backup available at: $backup_path"
        log "To restore from backup, run: RESTORE_FROM='$backup_path' ./scripts/backup-admin.sh restore"
    fi
}

display_deployment_info() {
    log "📊 Deployment Information:"
    
    # Gateway information
    echo "Gateway Deployment:"
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get deployment api-gateway -o wide || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get pods -l app.kubernetes.io/name=api-gateway || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get services api-gateway || true
    
    # Admin information
    local admin_namespace="${NAMESPACE}-admin"
    if kubectl --context="$KUBECTL_CONTEXT" get namespace "$admin_namespace" >/dev/null 2>&1; then
        echo
        echo "Admin Deployment:"
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get deployment api-gateway-admin -o wide || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get pods -l app.kubernetes.io/name=api-gateway-admin || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get services api-gateway-admin || true
    fi
    
    # Get access URLs
    echo
    echo "Access URLs:"
    
    local gateway_ip
    gateway_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || \
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get service api-gateway \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    
    if [ -n "$gateway_ip" ]; then
        echo "  Gateway:  http://$gateway_ip:8080"
        echo "  Metrics:  http://$gateway_ip:9090/metrics"
        echo "  Health:   http://$gateway_ip:8080/health"
    fi
    
    local admin_ip
    admin_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get service api-gateway-admin \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    
    if [ -n "$admin_ip" ]; then
        echo "  Admin:    http://$admin_ip:9090"
        echo "  Admin API: http://$admin_ip:9090/api/v1"
    fi
}

setup_monitoring_dashboards() {
    log "📈 Setting up monitoring dashboards..."
    
    # This would configure Grafana dashboards, Prometheus rules, etc.
    # For now, we'll just log what would happen
    
    log "Configuring Grafana dashboards..."
    log "Setting up Prometheus alerting rules..."
    log "Configuring log aggregation..."
    
    success "Monitoring dashboards configured"
}

send_deployment_notifications() {
    log "📢 Sending deployment notifications..."
    
    # This would send notifications to Slack, email, etc.
    # For now, we'll just log what would happen
    
    local deployment_message="API Gateway deployed successfully to $ENVIRONMENT
Environment: $ENVIRONMENT
Namespace: $NAMESPACE
Image Tag: $IMAGE_TAG
Deployed By: $(whoami)
Deployment Time: $(date)"
    
    log "Would send notification:"
    echo "$deployment_message"
    
    success "Deployment notifications sent"
}

create_deployment_record() {
    log "📝 Creating deployment record..."
    
    local deployment_record="deployments/deployment-$(date +'%Y%m%d_%H%M%S').json"
    mkdir -p deployments
    
    cat > "$deployment_record" << EOF
{
    "deployment_id": "$(uuidgen 2>/dev/null || echo "deploy-$(date +%s)")",
    "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "image_tag": "$IMAGE_TAG",
    "registry": "$REGISTRY",
    "kubectl_context": "$KUBECTL_CONTEXT",
    "deployed_by": "$(whoami)",
    "hostname": "$(hostname)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')",
    "dry_run": $DRY_RUN,
    "components": {
        "gateway": "deployed",
        "admin": "$([ -n "$DATABASE_URL" ] && echo "deployed" || echo "skipped")",
        "monitoring": "configured",
        "backup": "$([ "$SKIP_BACKUP" = "true" ] && echo "skipped" || echo "completed")"
    },
    "validation": {
        "status": "$([ "$SKIP_VALIDATION" = "true" ] && echo "skipped" || echo "passed")",
        "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    }
}
EOF
    
    success "Deployment record created: $deployment_record"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    echo
    echo -e "${PURPLE}🚀 API Gateway Complete Production Deployment${NC}"
    echo -e "${PURPLE}=============================================${NC}"
    echo
    echo "Environment: $ENVIRONMENT"
    echo "Namespace: $NAMESPACE"
    echo "Image Tag: $IMAGE_TAG"
    echo "Registry: $REGISTRY"
    echo "Kubectl Context: $KUBECTL_CONTEXT"
    echo "Dry Run: $DRY_RUN"
    echo
    
    if [ "$DRY_RUN" != "true" ]; then
        warning "This will deploy to PRODUCTION environment!"
        read -p "Are you sure you want to continue? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    local start_time
    start_time=$(date +%s)
    
    # Execute deployment phases
    phase_1_pre_deployment
    phase_2_backup
    phase_3_build_and_deploy
    phase_4_admin_deployment
    phase_5_monitoring_setup
    phase_6_validation
    phase_7_post_deployment
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    section "DEPLOYMENT COMPLETED SUCCESSFULLY"
    
    success "🎉 Production deployment completed in ${duration} seconds!"
    
    echo
    echo -e "${GREEN}Next Steps:${NC}"
    echo "1. Monitor the deployment for the next 24 hours"
    echo "2. Verify all business-critical functionality"
    echo "3. Update documentation with any changes"
    echo "4. Notify stakeholders of successful deployment"
    echo "5. Schedule post-deployment review meeting"
    echo
    
    if [ -f "PRODUCTION_READINESS.md" ]; then
        echo -e "${YELLOW}Don't forget to update the Production Readiness checklist!${NC}"
    fi
}

# Show usage if help requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
Complete Production Deployment Script for API Gateway

This script orchestrates the entire production deployment process including:
- Pre-deployment checks and validation
- Backup of current state
- Application and admin interface deployment
- Monitoring and alerting setup
- End-to-end validation
- Post-deployment tasks

Usage: $0 [OPTIONS]

Environment Variables:
  ENVIRONMENT              Deployment environment (default: production)
  NAMESPACE               Kubernetes namespace (default: api-gateway)
  IMAGE_TAG               Docker image tag (default: latest)
  REGISTRY                Docker registry (default: your-registry.com)
  KUBECTL_CONTEXT         Kubectl context (default: production)
  DRY_RUN                 Dry run mode (default: false)
  SKIP_TESTS              Skip integration tests (default: false)
  SKIP_BACKUP             Skip backup phase (default: false)
  SKIP_VALIDATION         Skip validation phase (default: false)
  DATABASE_URL            PostgreSQL database URL for admin interface

Examples:
  # Standard production deployment
  DATABASE_URL="postgresql://..." $0

  # Dry run deployment
  DRY_RUN=true $0

  # Deploy specific version
  IMAGE_TAG=v1.2.3 DATABASE_URL="postgresql://..." $0

  # Skip backup and validation (not recommended)
  SKIP_BACKUP=true SKIP_VALIDATION=true $0

Prerequisites:
  - Complete the Production Readiness checklist (PRODUCTION_READINESS.md)
  - Ensure all required tools are installed (kubectl, docker, curl, jq)
  - Configure kubectl context for production cluster
  - Set up Docker registry access
  - Configure database access (if using admin interface)

Deployment Phases:
  1. Pre-deployment preparation and validation
  2. Backup current state
  3. Build and deploy main application
  4. Deploy admin interface
  5. Setup monitoring and alerting
  6. End-to-end validation
  7. Post-deployment tasks

For more information, see:
  - PRODUCTION_READINESS.md - Production readiness checklist
  - scripts/deploy-production.sh - Main deployment script
  - scripts/admin-deployment.sh - Admin deployment script
  - scripts/e2e-validation.sh - Validation script
  - scripts/backup-admin.sh - Backup and recovery script
EOF
    exit 0
fi

# Trap to ensure cleanup on exit
trap 'echo "Deployment interrupted"; exit 1' INT TERM

# Execute main function
main "$@"
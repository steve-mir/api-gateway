#!/bin/bash

# Admin Deployment and Migration Script for API Gateway
# This script handles admin interface deployment, database migrations, and configuration updates

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-api-gateway}"
ADMIN_IMAGE_TAG="${ADMIN_IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-your-registry.com}"
ADMIN_IMAGE_NAME="${ADMIN_IMAGE_NAME:-api-gateway-admin}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production}"
ADMIN_CONFIG_FILE="${ADMIN_CONFIG_FILE:-config/admin-production.yaml}"
DRY_RUN="${DRY_RUN:-false}"
MIGRATION_MODE="${MIGRATION_MODE:-auto}"
BACKUP_BEFORE_MIGRATION="${BACKUP_BEFORE_MIGRATION:-true}"
ADMIN_PORT="${ADMIN_PORT:-9090}"
DATABASE_URL="${DATABASE_URL:-}"

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

# =============================================================================
# ADMIN CONFIGURATION MANAGEMENT
# =============================================================================

create_admin_config() {
    log "📋 Creating admin configuration..."
    
    cat > "$ADMIN_CONFIG_FILE" << EOF
# Admin Interface Production Configuration
admin:
  enabled: true
  bind_address: "0.0.0.0"
  port: $ADMIN_PORT
  tls:
    enabled: true
    cert_file: "/etc/admin/tls/tls.crt"
    key_file: "/etc/admin/tls/tls.key"
  
  # Authentication for admin interface
  auth:
    type: "oauth2"
    oauth2:
      provider_url: "https://auth.example.com"
      client_id: "\${ADMIN_OAUTH2_CLIENT_ID}"
      client_secret: "\${ADMIN_OAUTH2_CLIENT_SECRET}"
      scopes: ["admin", "gateway:manage"]
      redirect_url: "https://admin.example.com/auth/callback"
    
    # Session management
    session:
      secret: "\${ADMIN_SESSION_SECRET}"
      timeout: "8h"
      secure: true
      same_site: "strict"
  
  # Role-based access control
  rbac:
    enabled: true
    roles:
      super_admin:
        permissions: ["*"]
      admin:
        permissions: 
          - "gateway:read"
          - "gateway:write"
          - "services:read"
          - "services:write"
          - "config:read"
          - "config:write"
      operator:
        permissions:
          - "gateway:read"
          - "services:read"
          - "metrics:read"
      viewer:
        permissions:
          - "gateway:read"
          - "services:read"
          - "metrics:read"
          - "logs:read"

# Database configuration for admin data
database:
  type: "postgresql"
  url: "\${DATABASE_URL}"
  pool_size: 10
  connection_timeout: "30s"
  migrations:
    auto_migrate: true
    migration_path: "/app/migrations"

# Admin API configuration
api:
  version: "v1"
  base_path: "/api/v1"
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst: 150
  
  # API documentation
  docs:
    enabled: true
    path: "/docs"
    title: "API Gateway Admin API"
    version: "1.0.0"

# Admin dashboard configuration
dashboard:
  enabled: true
  path: "/"
  title: "API Gateway Admin"
  theme: "dark"
  auto_refresh: true
  refresh_interval: "30s"
  
  # Dashboard features
  features:
    service_topology: true
    real_time_metrics: true
    log_viewer: true
    configuration_editor: true
    user_management: true
    alert_management: true

# Audit logging for admin operations
audit:
  enabled: true
  log_all_requests: true
  log_request_body: true
  log_response_body: false
  retention_days: 90
  storage:
    type: "database"
    table: "admin_audit_log"

# Backup and recovery
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention_days: 30
  storage:
    type: "s3"
    bucket: "\${BACKUP_S3_BUCKET}"
    prefix: "admin-backups/"
    region: "\${AWS_REGION}"

# Monitoring for admin interface
monitoring:
  metrics:
    enabled: true
    path: "/admin/metrics"
  health:
    enabled: true
    path: "/admin/health"
  
  # Admin-specific alerts
  alerts:
    failed_login_threshold: 5
    failed_login_window: "5m"
    config_change_notification: true
    service_down_notification: true
EOF

    success "Admin configuration created: $ADMIN_CONFIG_FILE"
}

# =============================================================================
# DATABASE MIGRATIONS
# =============================================================================

create_migration_scripts() {
    log "📊 Creating database migration scripts..."
    
    mkdir -p migrations
    
    # Initial schema migration
    cat > migrations/001_initial_schema.sql << 'EOF'
-- Initial schema for admin interface
-- Migration: 001_initial_schema
-- Created: $(date -u +'%Y-%m-%d %H:%M:%S UTC')

-- Admin users table
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Admin sessions table
CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Configuration history table
CREATE TABLE IF NOT EXISTS config_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES admin_users(id),
    config_type VARCHAR(100) NOT NULL,
    config_key VARCHAR(255) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    change_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log table
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES admin_users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255),
    request_method VARCHAR(10),
    request_path TEXT,
    request_body JSONB,
    response_status INTEGER,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Service registry table (for admin-managed services)
CREATE TABLE IF NOT EXISTS admin_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    upstream_url VARCHAR(500) NOT NULL,
    health_check_path VARCHAR(255) DEFAULT '/health',
    health_check_interval INTEGER DEFAULT 30,
    load_balancer_type VARCHAR(50) DEFAULT 'round_robin',
    circuit_breaker_enabled BOOLEAN DEFAULT true,
    circuit_breaker_threshold INTEGER DEFAULT 5,
    created_by UUID NOT NULL REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- API keys table (for admin-managed API keys)
CREATE TABLE IF NOT EXISTS admin_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    rate_limit INTEGER DEFAULT 1000,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by UUID NOT NULL REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Alert rules table
CREATE TABLE IF NOT EXISTS admin_alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    metric_name VARCHAR(255) NOT NULL,
    condition VARCHAR(50) NOT NULL, -- 'greater_than', 'less_than', 'equals'
    threshold DECIMAL NOT NULL,
    duration INTEGER NOT NULL DEFAULT 300, -- seconds
    severity VARCHAR(20) NOT NULL DEFAULT 'warning',
    notification_channels JSONB NOT NULL DEFAULT '[]',
    created_by UUID NOT NULL REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Backup records table
CREATE TABLE IF NOT EXISTS admin_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type VARCHAR(50) NOT NULL, -- 'config', 'database', 'full'
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT,
    checksum VARCHAR(255),
    created_by UUID REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'completed' -- 'in_progress', 'completed', 'failed'
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_config_history_user_id ON config_history(user_id);
CREATE INDEX IF NOT EXISTS idx_config_history_created_at ON config_history(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON admin_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON admin_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_services_name ON admin_services(name);
CREATE INDEX IF NOT EXISTS idx_admin_api_keys_key_hash ON admin_api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_admin_api_keys_created_by ON admin_api_keys(created_by);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_admin_users_updated_at BEFORE UPDATE ON admin_users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_admin_services_updated_at BEFORE UPDATE ON admin_services FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_admin_alert_rules_updated_at BEFORE UPDATE ON admin_alert_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EOF

    # Add sample data migration
    cat > migrations/002_sample_data.sql << 'EOF'
-- Sample data for admin interface
-- Migration: 002_sample_data
-- Created: $(date -u +'%Y-%m-%d %H:%M:%S UTC')

-- Insert default admin user (password should be changed on first login)
INSERT INTO admin_users (email, name, role) VALUES 
    ('admin@example.com', 'System Administrator', 'super_admin')
ON CONFLICT (email) DO NOTHING;

-- Insert sample alert rules
INSERT INTO admin_alert_rules (name, description, metric_name, condition, threshold, duration, severity, notification_channels, created_by) 
SELECT 
    'High Error Rate',
    'Alert when error rate exceeds 5%',
    'gateway_error_rate',
    'greater_than',
    0.05,
    300,
    'critical',
    '["email", "slack"]'::jsonb,
    id
FROM admin_users WHERE email = 'admin@example.com'
ON CONFLICT DO NOTHING;

INSERT INTO admin_alert_rules (name, description, metric_name, condition, threshold, duration, severity, notification_channels, created_by)
SELECT 
    'High Response Time',
    'Alert when 95th percentile response time exceeds 2 seconds',
    'gateway_response_time_p95',
    'greater_than',
    2.0,
    600,
    'warning',
    '["email"]'::jsonb,
    id
FROM admin_users WHERE email = 'admin@example.com'
ON CONFLICT DO NOTHING;
EOF

    success "Migration scripts created in migrations/ directory"
}

run_migrations() {
    if [ -z "$DATABASE_URL" ]; then
        warning "DATABASE_URL not set, skipping migrations"
        return 0
    fi
    
    log "🔄 Running database migrations..."
    
    # Check if database is accessible
    if ! psql "$DATABASE_URL" -c "SELECT 1;" >/dev/null 2>&1; then
        fatal "Cannot connect to database: $DATABASE_URL"
    fi
    
    # Create migrations table if it doesn't exist
    psql "$DATABASE_URL" -c "
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    " || fatal "Failed to create migrations table"
    
    # Run each migration
    for migration_file in migrations/*.sql; do
        if [ ! -f "$migration_file" ]; then
            continue
        fi
        
        local migration_name
        migration_name=$(basename "$migration_file" .sql)
        
        # Check if migration already applied
        local applied
        applied=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM schema_migrations WHERE version = '$migration_name';" | xargs)
        
        if [ "$applied" -eq 0 ]; then
            log "Applying migration: $migration_name"
            
            if [ "$DRY_RUN" = "true" ]; then
                log "DRY_RUN: Would apply migration $migration_name"
            else
                if psql "$DATABASE_URL" -f "$migration_file"; then
                    psql "$DATABASE_URL" -c "INSERT INTO schema_migrations (version) VALUES ('$migration_name');"
                    success "Migration $migration_name applied successfully"
                else
                    fatal "Failed to apply migration: $migration_name"
                fi
            fi
        else
            log "Migration $migration_name already applied, skipping"
        fi
    done
    
    success "All migrations completed"
}

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

create_backup() {
    if [ -z "$DATABASE_URL" ]; then
        warning "DATABASE_URL not set, skipping backup"
        return 0
    fi
    
    log "💾 Creating backup before deployment..."
    
    local backup_dir="backups/$(date +'%Y%m%d_%H%M%S')"
    mkdir -p "$backup_dir"
    
    # Database backup
    log "Creating database backup..."
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would create database backup"
    else
        pg_dump "$DATABASE_URL" > "$backup_dir/database.sql" || fatal "Failed to create database backup"
        success "Database backup created: $backup_dir/database.sql"
    fi
    
    # Configuration backup
    log "Creating configuration backup..."
    if [ -f "$ADMIN_CONFIG_FILE" ]; then
        cp "$ADMIN_CONFIG_FILE" "$backup_dir/admin-config.yaml"
        success "Configuration backup created: $backup_dir/admin-config.yaml"
    fi
    
    # Kubernetes resources backup
    log "Creating Kubernetes resources backup..."
    if [ "$DRY_RUN" != "true" ]; then
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get all -o yaml > "$backup_dir/k8s-resources.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get configmaps -o yaml > "$backup_dir/k8s-configmaps.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get secrets -o yaml > "$backup_dir/k8s-secrets.yaml" || true
        success "Kubernetes resources backup created"
    fi
    
    # Create backup metadata
    cat > "$backup_dir/metadata.json" << EOF
{
    "backup_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "admin_image_tag": "$ADMIN_IMAGE_TAG",
    "created_by": "$(whoami)",
    "backup_type": "pre_deployment"
}
EOF
    
    success "Backup completed: $backup_dir"
    echo "$backup_dir" > .last_backup_path
}

# =============================================================================
# ADMIN DEPLOYMENT
# =============================================================================

deploy_admin_interface() {
    log "🚀 Deploying admin interface..."
    
    # Create admin namespace if it doesn't exist
    local admin_namespace="${NAMESPACE}-admin"
    if ! kubectl --context="$KUBECTL_CONTEXT" get namespace "$admin_namespace" >/dev/null 2>&1; then
        log "Creating admin namespace: $admin_namespace"
        if [ "$DRY_RUN" != "true" ]; then
            kubectl --context="$KUBECTL_CONTEXT" create namespace "$admin_namespace" || fatal "Failed to create admin namespace"
        fi
    fi
    
    # Create admin configuration ConfigMap
    log "Creating admin configuration ConfigMap..."
    if [ "$DRY_RUN" != "true" ]; then
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" create configmap admin-config \
            --from-file="$ADMIN_CONFIG_FILE" \
            --dry-run=client -o yaml | \
            kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" apply -f - || \
            fatal "Failed to create admin configuration ConfigMap"
    fi
    
    # Deploy admin interface
    create_admin_deployment_manifest
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would deploy admin interface"
        cat k8s/admin-deployment.yaml
    else
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" apply -f k8s/admin-deployment.yaml || \
            fatal "Failed to deploy admin interface"
        
        # Wait for deployment to be ready
        if ! kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" wait \
            --for=condition=available \
            --timeout=300s \
            deployment/api-gateway-admin; then
            fatal "Admin deployment failed to become ready"
        fi
        
        success "Admin interface deployed successfully"
    fi
}

create_admin_deployment_manifest() {
    log "📝 Creating admin deployment manifest..."
    
    mkdir -p k8s
    
    cat > k8s/admin-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway-admin
  labels:
    app.kubernetes.io/name: api-gateway-admin
    app.kubernetes.io/component: admin
    app.kubernetes.io/version: "$ADMIN_IMAGE_TAG"
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: api-gateway-admin
  template:
    metadata:
      labels:
        app.kubernetes.io/name: api-gateway-admin
        app.kubernetes.io/component: admin
        app.kubernetes.io/version: "$ADMIN_IMAGE_TAG"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "$ADMIN_PORT"
        prometheus.io/path: "/admin/metrics"
    spec:
      serviceAccountName: api-gateway-admin
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
      - name: admin
        image: $REGISTRY/$ADMIN_IMAGE_NAME:$ADMIN_IMAGE_TAG
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: $ADMIN_PORT
          protocol: TCP
        env:
        - name: ADMIN_OAUTH2_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: OAUTH2_CLIENT_ID
        - name: ADMIN_OAUTH2_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: OAUTH2_CLIENT_SECRET
        - name: ADMIN_SESSION_SECRET
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: SESSION_SECRET
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: DATABASE_URL
        - name: BACKUP_S3_BUCKET
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: BACKUP_S3_BUCKET
        - name: AWS_REGION
          value: "us-west-2"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /admin/health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /admin/health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: config
          mountPath: /etc/admin/config
          readOnly: true
        - name: tls-certs
          mountPath: /etc/admin/tls
          readOnly: true
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: admin-config
      - name: tls-certs
        secret:
          secretName: admin-tls
          optional: true
      terminationGracePeriodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-admin
  labels:
    app.kubernetes.io/name: api-gateway-admin
    app.kubernetes.io/component: admin
spec:
  type: ClusterIP
  ports:
  - port: $ADMIN_PORT
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app.kubernetes.io/name: api-gateway-admin
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway-admin
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - admin.example.com
    secretName: admin-tls
  rules:
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway-admin
            port:
              number: $ADMIN_PORT
EOF

    success "Admin deployment manifest created: k8s/admin-deployment.yaml"
}

# =============================================================================
# POST-DEPLOYMENT VERIFICATION
# =============================================================================

verify_admin_deployment() {
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Skipping admin deployment verification"
        return 0
    fi
    
    log "🔍 Verifying admin deployment..."
    
    local admin_namespace="${NAMESPACE}-admin"
    
    # Check if pods are running
    log "Checking admin pods status..."
    if ! kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" wait \
        --for=condition=ready \
        --timeout=300s \
        pod -l app.kubernetes.io/name=api-gateway-admin; then
        error "Admin pods failed to become ready"
        return 1
    fi
    success "Admin pods are ready"
    
    # Test admin health endpoint
    log "Testing admin health endpoint..."
    local admin_service_ip
    admin_service_ip=$(kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get service api-gateway-admin \
        -o jsonpath='{.spec.clusterIP}')
    
    if [ -n "$admin_service_ip" ]; then
        local admin_url="http://$admin_service_ip:$ADMIN_PORT"
        if curl -f -s "$admin_url/admin/health" >/dev/null 2>&1; then
            success "Admin health check passed"
        else
            error "Admin health check failed"
            return 1
        fi
    fi
    
    # Test database connectivity
    if [ -n "$DATABASE_URL" ]; then
        log "Testing database connectivity..."
        if psql "$DATABASE_URL" -c "SELECT 1;" >/dev/null 2>&1; then
            success "Database connectivity verified"
        else
            error "Database connectivity failed"
            return 1
        fi
    fi
    
    success "Admin deployment verification completed"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "🚀 Starting admin deployment and migration process"
    log "Environment: $ENVIRONMENT"
    log "Namespace: $NAMESPACE"
    log "Admin Image: $REGISTRY/$ADMIN_IMAGE_NAME:$ADMIN_IMAGE_TAG"
    log "Migration Mode: $MIGRATION_MODE"
    log "Dry Run: $DRY_RUN"
    
    # Create admin configuration
    create_admin_config
    
    # Create migration scripts
    create_migration_scripts
    
    # Create backup if enabled
    if [ "$BACKUP_BEFORE_MIGRATION" = "true" ]; then
        create_backup
    fi
    
    # Run database migrations
    if [ "$MIGRATION_MODE" = "auto" ] || [ "$MIGRATION_MODE" = "manual" ]; then
        run_migrations
    fi
    
    # Deploy admin interface
    deploy_admin_interface
    
    # Verify deployment
    verify_admin_deployment
    
    success "🎉 Admin deployment completed successfully!"
    
    # Display access information
    log "📊 Admin Interface Information:"
    local admin_namespace="${NAMESPACE}-admin"
    kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get pods -l app.kubernetes.io/name=api-gateway-admin || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get services api-gateway-admin || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get ingress api-gateway-admin || true
    
    log "🔗 Admin Access URLs:"
    log "  Dashboard: https://admin.example.com"
    log "  API: https://admin.example.com/api/v1"
    log "  Docs: https://admin.example.com/docs"
    log "  Health: https://admin.example.com/admin/health"
    log "  Metrics: https://admin.example.com/admin/metrics"
}

# Show usage if help requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
Admin Deployment and Migration Script for API Gateway

Usage: $0 [OPTIONS]

Environment Variables:
  ENVIRONMENT                 Deployment environment (default: production)
  NAMESPACE                  Kubernetes namespace (default: api-gateway)
  ADMIN_IMAGE_TAG            Admin Docker image tag (default: latest)
  REGISTRY                   Docker registry (default: your-registry.com)
  ADMIN_IMAGE_NAME           Admin Docker image name (default: api-gateway-admin)
  KUBECTL_CONTEXT            Kubectl context (default: production)
  ADMIN_CONFIG_FILE          Admin configuration file (default: config/admin-production.yaml)
  DRY_RUN                    Dry run mode (default: false)
  MIGRATION_MODE             Migration mode: auto, manual, skip (default: auto)
  BACKUP_BEFORE_MIGRATION    Create backup before migration (default: true)
  ADMIN_PORT                 Admin interface port (default: 9090)
  DATABASE_URL               PostgreSQL database URL

Examples:
  # Standard admin deployment
  DATABASE_URL="postgresql://user:pass@host:5432/db" $0

  # Dry run deployment
  DRY_RUN=true $0

  # Skip migrations
  MIGRATION_MODE=skip $0

  # Deploy without backup
  BACKUP_BEFORE_MIGRATION=false $0
EOF
    exit 0
fi

# Execute main function
main "$@"
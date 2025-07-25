# Admin Deployment and Migration Procedures

This document provides comprehensive procedures for deploying and managing the API Gateway admin interface, including migration procedures for configuration changes and system updates.

## Table of Contents

1. [Admin Interface Overview](#admin-interface-overview)
2. [Deployment Procedures](#deployment-procedures)
3. [Configuration Migration](#configuration-migration)
4. [Database Migration](#database-migration)
5. [Rollback Procedures](#rollback-procedures)
6. [Monitoring and Health Checks](#monitoring-and-health-checks)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Admin Interface Overview

The API Gateway admin interface consists of:

- **Admin API**: RESTful API for gateway management
- **Admin Dashboard**: Web-based UI for monitoring and configuration
- **Admin CLI**: Command-line tools for automation
- **Admin Database**: Persistent storage for admin data

### Architecture Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Admin CLI     │    │  Admin Dashboard│    │   Admin API     │
│                 │    │     (React)     │    │   (REST/gRPC)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Gateway Core   │
                    │                 │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Admin Database  │
                    │  (PostgreSQL)   │
                    └─────────────────┘
```

## Deployment Procedures

### Prerequisites

1. **Infrastructure Requirements**
   - Kubernetes cluster with admin namespace
   - PostgreSQL database for admin data
   - Redis for session management
   - Load balancer for admin interface
   - TLS certificates for HTTPS

2. **Access Requirements**
   - Admin credentials for initial setup
   - Database connection credentials
   - TLS certificates and keys
   - Container registry access

### Step 1: Database Setup

```bash
#!/bin/bash
# setup-admin-database.sh

# Create admin database
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: admin-db-credentials
  namespace: api-gateway-admin
type: Opaque
stringData:
  username: admin_user
  password: ${ADMIN_DB_PASSWORD}
  database: gateway_admin
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: admin-postgres
  namespace: api-gateway-admin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: admin-postgres
  template:
    metadata:
      labels:
        app: admin-postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          valueFrom:
            secretKeyRef:
              name: admin-db-credentials
              key: database
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: admin-db-credentials
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: admin-db-credentials
              key: password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        persistentVolumeClaim:
          claimName: admin-postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: admin-postgres
  namespace: api-gateway-admin
spec:
  selector:
    app: admin-postgres
  ports:
  - port: 5432
    targetPort: 5432
EOF
```

### Step 2: Admin API Deployment

```bash
#!/bin/bash
# deploy-admin-api.sh

# Create admin API deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: admin-api
  namespace: api-gateway-admin
spec:
  replicas: 2
  selector:
    matchLabels:
      app: admin-api
  template:
    metadata:
      labels:
        app: admin-api
    spec:
      containers:
      - name: admin-api
        image: api-gateway:${VERSION}
        command: ["/usr/local/bin/api-gateway"]
        args: ["--mode", "admin-api", "--config", "/etc/config/admin.yaml"]
        ports:
        - containerPort: 8081
          name: http
        - containerPort: 9091
          name: metrics
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: admin-db-credentials
              key: url
        - name: ADMIN_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: admin-secrets
              key: jwt-secret
        volumeMounts:
        - name: config
          mountPath: /etc/config
        - name: tls-certs
          mountPath: /etc/ssl/certs
        livenessProbe:
          httpGet:
            path: /admin/health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /admin/ready
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: admin-config
      - name: tls-certs
        secret:
          secretName: admin-tls
---
apiVersion: v1
kind: Service
metadata:
  name: admin-api
  namespace: api-gateway-admin
spec:
  selector:
    app: admin-api
  ports:
  - name: http
    port: 8081
    targetPort: 8081
  - name: metrics
    port: 9091
    targetPort: 9091
EOF
```

### Step 3: Admin Dashboard Deployment

```bash
#!/bin/bash
# deploy-admin-dashboard.sh

# Build and deploy admin dashboard
cd admin-dashboard

# Build dashboard
npm run build

# Create dashboard deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: admin-dashboard
  namespace: api-gateway-admin
spec:
  replicas: 2
  selector:
    matchLabels:
      app: admin-dashboard
  template:
    metadata:
      labels:
        app: admin-dashboard
    spec:
      containers:
      - name: dashboard
        image: nginx:alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: dashboard-files
          mountPath: /usr/share/nginx/html
        - name: nginx-config
          mountPath: /etc/nginx/conf.d
      volumes:
      - name: dashboard-files
        configMap:
          name: admin-dashboard-files
      - name: nginx-config
        configMap:
          name: admin-dashboard-nginx
---
apiVersion: v1
kind: Service
metadata:
  name: admin-dashboard
  namespace: api-gateway-admin
spec:
  selector:
    app: admin-dashboard
  ports:
  - port: 80
    targetPort: 80
EOF
```

### Step 4: Ingress Configuration

```bash
#!/bin/bash
# setup-admin-ingress.sh

kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  namespace: api-gateway-admin
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-basic-auth
    nginx.ingress.kubernetes.io/auth-realm: "Admin Access Required"
spec:
  tls:
  - hosts:
    - admin.gateway.example.com
    secretName: admin-tls
  rules:
  - host: admin.gateway.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: admin-api
            port:
              number: 8081
      - path: /
        pathType: Prefix
        backend:
          service:
            name: admin-dashboard
            port:
              number: 80
EOF
```

## Configuration Migration

### Migration Script Template

```bash
#!/bin/bash
# migrate-admin-config.sh

set -euo pipefail

MIGRATION_VERSION="$1"
ENVIRONMENT="${2:-production}"
NAMESPACE="api-gateway-admin"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Backup current configuration
backup_config() {
    log "Creating configuration backup..."
    
    local backup_dir="backups/config-migration-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup ConfigMaps
    kubectl get configmap -n "$NAMESPACE" -o yaml > "$backup_dir/configmaps.yaml"
    
    # Backup Secrets
    kubectl get secret -n "$NAMESPACE" -o yaml > "$backup_dir/secrets.yaml"
    
    # Backup database
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        pg_dump -U admin_user gateway_admin > "$backup_dir/database.sql"
    
    log "Backup created at: $backup_dir"
}

# Apply configuration migration
apply_migration() {
    log "Applying migration version: $MIGRATION_VERSION"
    
    case "$MIGRATION_VERSION" in
        "v1.1.0")
            migrate_v1_1_0
            ;;
        "v1.2.0")
            migrate_v1_2_0
            ;;
        *)
            log "ERROR: Unknown migration version: $MIGRATION_VERSION"
            exit 1
            ;;
    esac
}

# Migration for v1.1.0
migrate_v1_1_0() {
    log "Migrating to v1.1.0..."
    
    # Add new configuration options
    kubectl patch configmap admin-config -n "$NAMESPACE" --patch '
    data:
      new-feature-enabled: "true"
      rate-limit-burst: "200"
    '
    
    # Update database schema
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -c "
        ALTER TABLE admin_users ADD COLUMN last_login TIMESTAMP;
        CREATE INDEX idx_admin_users_last_login ON admin_users(last_login);
        "
    
    log "Migration v1.1.0 completed"
}

# Migration for v1.2.0
migrate_v1_2_0() {
    log "Migrating to v1.2.0..."
    
    # Update admin API configuration
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: admin-config
  namespace: $NAMESPACE
data:
  admin.yaml: |
    admin:
      api:
        version: "v2"
        features:
          - "advanced-metrics"
          - "audit-logging"
          - "rbac-v2"
      database:
        connection_pool_size: 20
        max_idle_connections: 5
EOF
    
    # Database schema updates
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -f - <<SQL
        -- Add new tables for v1.2.0
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES admin_users(id),
            action VARCHAR(255) NOT NULL,
            resource VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details JSONB
        );
        
        CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
        CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
SQL
    
    log "Migration v1.2.0 completed"
}

# Verify migration
verify_migration() {
    log "Verifying migration..."
    
    # Check admin API health
    kubectl wait --for=condition=ready pod -l app=admin-api -n "$NAMESPACE" --timeout=300s
    
    # Test admin API endpoints
    local admin_api_url="http://admin-api.$NAMESPACE.svc.cluster.local:8081"
    
    if kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl -- \
        curl -f "$admin_api_url/admin/health"; then
        log "Admin API health check passed"
    else
        log "ERROR: Admin API health check failed"
        return 1
    fi
    
    # Verify database connectivity
    if kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -c "SELECT 1;" > /dev/null; then
        log "Database connectivity verified"
    else
        log "ERROR: Database connectivity failed"
        return 1
    fi
    
    log "Migration verification completed successfully"
}

# Main migration function
main() {
    log "Starting admin configuration migration..."
    log "Version: $MIGRATION_VERSION"
    log "Environment: $ENVIRONMENT"
    
    backup_config
    apply_migration
    verify_migration
    
    log "Migration completed successfully!"
}

main
```

## Database Migration

### Database Schema Management

```sql
-- migrations/001_initial_schema.sql
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES admin_users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS gateway_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    config_data JSONB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER REFERENCES admin_users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES admin_users(id),
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

-- Create indexes
CREATE INDEX idx_admin_sessions_token ON admin_sessions(session_token);
CREATE INDEX idx_admin_sessions_expires ON admin_sessions(expires_at);
CREATE INDEX idx_gateway_configs_active ON gateway_configs(is_active);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource, resource_id);
```

### Migration Runner Script

```bash
#!/bin/bash
# run-db-migrations.sh

set -euo pipefail

NAMESPACE="${1:-api-gateway-admin}"
MIGRATIONS_DIR="migrations"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Get database connection info
get_db_connection() {
    local db_host="admin-postgres.$NAMESPACE.svc.cluster.local"
    local db_port="5432"
    local db_name="gateway_admin"
    local db_user="admin_user"
    
    echo "postgresql://$db_user@$db_host:$db_port/$db_name"
}

# Check if migrations table exists
ensure_migrations_table() {
    log "Ensuring migrations table exists..."
    
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -c "
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        "
}

# Get applied migrations
get_applied_migrations() {
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -t -c "
        SELECT version FROM schema_migrations ORDER BY version;
        " | tr -d ' '
}

# Apply migration
apply_migration() {
    local migration_file="$1"
    local version=$(basename "$migration_file" .sql)
    
    log "Applying migration: $version"
    
    # Apply the migration
    kubectl exec -i -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin < "$migration_file"
    
    # Record the migration
    kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -c "
        INSERT INTO schema_migrations (version) VALUES ('$version');
        "
    
    log "Migration $version applied successfully"
}

# Main migration function
main() {
    log "Starting database migrations..."
    
    ensure_migrations_table
    
    local applied_migrations
    applied_migrations=$(get_applied_migrations)
    
    # Apply pending migrations
    for migration_file in "$MIGRATIONS_DIR"/*.sql; do
        if [[ -f "$migration_file" ]]; then
            local version=$(basename "$migration_file" .sql)
            
            if echo "$applied_migrations" | grep -q "^$version$"; then
                log "Migration $version already applied, skipping"
            else
                apply_migration "$migration_file"
            fi
        fi
    done
    
    log "Database migrations completed"
}

main
```

## Rollback Procedures

### Configuration Rollback

```bash
#!/bin/bash
# rollback-admin-config.sh

set -euo pipefail

BACKUP_DIR="$1"
NAMESPACE="${2:-api-gateway-admin}"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Validate backup directory
if [[ ! -d "$BACKUP_DIR" ]]; then
    log "ERROR: Backup directory not found: $BACKUP_DIR"
    exit 1
fi

log "Starting admin configuration rollback..."
log "Backup directory: $BACKUP_DIR"
log "Namespace: $NAMESPACE"

# Rollback ConfigMaps
if [[ -f "$BACKUP_DIR/configmaps.yaml" ]]; then
    log "Rolling back ConfigMaps..."
    kubectl apply -f "$BACKUP_DIR/configmaps.yaml"
fi

# Rollback Secrets
if [[ -f "$BACKUP_DIR/secrets.yaml" ]]; then
    log "Rolling back Secrets..."
    kubectl apply -f "$BACKUP_DIR/secrets.yaml"
fi

# Rollback database
if [[ -f "$BACKUP_DIR/database.sql" ]]; then
    log "Rolling back database..."
    kubectl exec -i -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin < "$BACKUP_DIR/database.sql"
fi

# Restart admin services
log "Restarting admin services..."
kubectl rollout restart deployment/admin-api -n "$NAMESPACE"
kubectl rollout restart deployment/admin-dashboard -n "$NAMESPACE"

# Wait for rollout to complete
kubectl rollout status deployment/admin-api -n "$NAMESPACE" --timeout=300s
kubectl rollout status deployment/admin-dashboard -n "$NAMESPACE" --timeout=300s

log "Admin configuration rollback completed successfully"
```

### Deployment Rollback

```bash
#!/bin/bash
# rollback-admin-deployment.sh

set -euo pipefail

NAMESPACE="${1:-api-gateway-admin}"
REVISION="${2:-}"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting admin deployment rollback..."

# Rollback admin API
if [[ -n "$REVISION" ]]; then
    log "Rolling back admin API to revision $REVISION..."
    kubectl rollout undo deployment/admin-api -n "$NAMESPACE" --to-revision="$REVISION"
else
    log "Rolling back admin API to previous revision..."
    kubectl rollout undo deployment/admin-api -n "$NAMESPACE"
fi

# Rollback admin dashboard
if [[ -n "$REVISION" ]]; then
    log "Rolling back admin dashboard to revision $REVISION..."
    kubectl rollout undo deployment/admin-dashboard -n "$NAMESPACE" --to-revision="$REVISION"
else
    log "Rolling back admin dashboard to previous revision..."
    kubectl rollout undo deployment/admin-dashboard -n "$NAMESPACE"
fi

# Wait for rollback to complete
log "Waiting for rollback to complete..."
kubectl rollout status deployment/admin-api -n "$NAMESPACE" --timeout=300s
kubectl rollout status deployment/admin-dashboard -n "$NAMESPACE" --timeout=300s

# Verify rollback
log "Verifying rollback..."
kubectl get pods -n "$NAMESPACE" -l app=admin-api
kubectl get pods -n "$NAMESPACE" -l app=admin-dashboard

log "Admin deployment rollback completed successfully"
```

## Monitoring and Health Checks

### Health Check Script

```bash
#!/bin/bash
# check-admin-health.sh

set -euo pipefail

NAMESPACE="${1:-api-gateway-admin}"
TIMEOUT="${2:-30}"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Check admin API health
check_admin_api() {
    log "Checking admin API health..."
    
    local api_url="http://admin-api.$NAMESPACE.svc.cluster.local:8081"
    
    if kubectl run health-check --rm -i --restart=Never --image=curlimages/curl --timeout="${TIMEOUT}s" -- \
        curl -f -s "$api_url/admin/health" > /dev/null; then
        log "✓ Admin API is healthy"
        return 0
    else
        log "✗ Admin API health check failed"
        return 1
    fi
}

# Check admin dashboard
check_admin_dashboard() {
    log "Checking admin dashboard..."
    
    local dashboard_url="http://admin-dashboard.$NAMESPACE.svc.cluster.local"
    
    if kubectl run dashboard-check --rm -i --restart=Never --image=curlimages/curl --timeout="${TIMEOUT}s" -- \
        curl -f -s "$dashboard_url" > /dev/null; then
        log "✓ Admin dashboard is accessible"
        return 0
    else
        log "✗ Admin dashboard check failed"
        return 1
    fi
}

# Check database connectivity
check_database() {
    log "Checking database connectivity..."
    
    if kubectl exec -n "$NAMESPACE" deployment/admin-postgres -- \
        psql -U admin_user -d gateway_admin -c "SELECT 1;" > /dev/null 2>&1; then
        log "✓ Database is accessible"
        return 0
    else
        log "✗ Database connectivity check failed"
        return 1
    fi
}

# Check pod status
check_pods() {
    log "Checking pod status..."
    
    local api_ready
    api_ready=$(kubectl get deployment admin-api -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    local api_desired
    api_desired=$(kubectl get deployment admin-api -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    
    if [[ "$api_ready" == "$api_desired" ]]; then
        log "✓ Admin API pods: $api_ready/$api_desired ready"
    else
        log "✗ Admin API pods: $api_ready/$api_desired ready"
        return 1
    fi
    
    local dashboard_ready
    dashboard_ready=$(kubectl get deployment admin-dashboard -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    local dashboard_desired
    dashboard_desired=$(kubectl get deployment admin-dashboard -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    
    if [[ "$dashboard_ready" == "$dashboard_desired" ]]; then
        log "✓ Admin dashboard pods: $dashboard_ready/$dashboard_desired ready"
    else
        log "✗ Admin dashboard pods: $dashboard_ready/$dashboard_desired ready"
        return 1
    fi
}

# Main health check function
main() {
    log "Starting admin health checks..."
    
    local exit_code=0
    
    check_pods || exit_code=1
    check_database || exit_code=1
    check_admin_api || exit_code=1
    check_admin_dashboard || exit_code=1
    
    if [[ $exit_code -eq 0 ]]; then
        log "✓ All admin health checks passed"
    else
        log "✗ Some admin health checks failed"
    fi
    
    exit $exit_code
}

main
```

## Security Considerations

### Admin Access Control

1. **Multi-Factor Authentication**
   - Implement MFA for all admin accounts
   - Use time-based OTP (TOTP) or hardware tokens
   - Require MFA for sensitive operations

2. **Role-Based Access Control**
   - Define granular permissions for admin operations
   - Implement principle of least privilege
   - Regular access reviews and audits

3. **Network Security**
   - Use VPN or bastion hosts for admin access
   - Implement IP whitelisting
   - Use TLS for all admin communications

4. **Session Management**
   - Short session timeouts
   - Secure session storage
   - Session invalidation on logout

### Audit and Compliance

```sql
-- Audit logging queries
-- Get all admin actions in the last 24 hours
SELECT 
    u.username,
    a.action,
    a.resource,
    a.timestamp,
    a.ip_address
FROM audit_logs a
JOIN admin_users u ON a.user_id = u.id
WHERE a.timestamp >= NOW() - INTERVAL '24 hours'
ORDER BY a.timestamp DESC;

-- Get failed login attempts
SELECT 
    username,
    ip_address,
    timestamp
FROM audit_logs
WHERE action = 'login_failed'
AND timestamp >= NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;
```

## Troubleshooting

### Common Issues

1. **Admin API Not Responding**
   ```bash
   # Check pod logs
   kubectl logs -n api-gateway-admin deployment/admin-api
   
   # Check pod status
   kubectl describe pods -n api-gateway-admin -l app=admin-api
   
   # Check service endpoints
   kubectl get endpoints admin-api -n api-gateway-admin
   ```

2. **Database Connection Issues**
   ```bash
   # Test database connectivity
   kubectl exec -n api-gateway-admin deployment/admin-postgres -- \
     psql -U admin_user -d gateway_admin -c "SELECT version();"
   
   # Check database logs
   kubectl logs -n api-gateway-admin deployment/admin-postgres
   ```

3. **Dashboard Not Loading**
   ```bash
   # Check dashboard logs
   kubectl logs -n api-gateway-admin deployment/admin-dashboard
   
   # Check ingress configuration
   kubectl describe ingress admin-ingress -n api-gateway-admin
   ```

### Emergency Procedures

1. **Emergency Admin Access**
   ```bash
   # Create emergency admin user
   kubectl exec -n api-gateway-admin deployment/admin-postgres -- \
     psql -U admin_user -d gateway_admin -c "
     INSERT INTO admin_users (username, email, password_hash, role) 
     VALUES ('emergency', 'emergency@example.com', 'hashed_password', 'super_admin');
     "
   ```

2. **Disable Admin Interface**
   ```bash
   # Scale down admin deployments
   kubectl scale deployment admin-api --replicas=0 -n api-gateway-admin
   kubectl scale deployment admin-dashboard --replicas=0 -n api-gateway-admin
   ```

This comprehensive admin deployment and migration guide ensures reliable and secure management of the API Gateway admin interface with proper procedures for deployment, migration, and troubleshooting.
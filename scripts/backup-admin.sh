#!/bin/bash

# Admin Disaster Recovery and Backup Script for API Gateway
# This script provides comprehensive backup, restore, and disaster recovery capabilities

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-api-gateway}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production}"
DATABASE_URL="${DATABASE_URL:-}"
BACKUP_TYPE="${BACKUP_TYPE:-full}"  # full, config, database, kubernetes
BACKUP_STORAGE="${BACKUP_STORAGE:-local}"  # local, s3, gcs
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
RESTORE_FROM="${RESTORE_FROM:-}"
DRY_RUN="${DRY_RUN:-false}"
ENCRYPTION_ENABLED="${ENCRYPTION_ENABLED:-true}"
COMPRESSION_ENABLED="${COMPRESSION_ENABLED:-true}"

# Storage configuration
S3_BUCKET="${S3_BUCKET:-}"
S3_PREFIX="${S3_PREFIX:-admin-backups}"
GCS_BUCKET="${GCS_BUCKET:-}"
GCS_PREFIX="${GCS_PREFIX:-admin-backups}"
LOCAL_BACKUP_DIR="${LOCAL_BACKUP_DIR:-./backups}"

# Encryption
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/etc/backup/encryption.key}"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"

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

# Generate backup filename
generate_backup_filename() {
    local backup_type="$1"
    local timestamp
    timestamp=$(date +'%Y%m%d_%H%M%S')
    echo "${ENVIRONMENT}_${backup_type}_${timestamp}"
}

# Encrypt file if encryption is enabled
encrypt_file() {
    local input_file="$1"
    local output_file="$2"
    
    if [ "$ENCRYPTION_ENABLED" = "true" ]; then
        if [ -n "$GPG_RECIPIENT" ]; then
            log "Encrypting with GPG..."
            gpg --trust-model always --encrypt --recipient "$GPG_RECIPIENT" \
                --output "$output_file" "$input_file" || fatal "GPG encryption failed"
        elif [ -f "$ENCRYPTION_KEY_FILE" ]; then
            log "Encrypting with AES..."
            openssl enc -aes-256-cbc -salt -in "$input_file" -out "$output_file" \
                -pass file:"$ENCRYPTION_KEY_FILE" || fatal "AES encryption failed"
        else
            warning "Encryption enabled but no key found, skipping encryption"
            cp "$input_file" "$output_file"
        fi
    else
        cp "$input_file" "$output_file"
    fi
}

# Decrypt file if encryption was used
decrypt_file() {
    local input_file="$1"
    local output_file="$2"
    
    if [ "$ENCRYPTION_ENABLED" = "true" ]; then
        if [ -n "$GPG_RECIPIENT" ]; then
            log "Decrypting with GPG..."
            gpg --decrypt --output "$output_file" "$input_file" || fatal "GPG decryption failed"
        elif [ -f "$ENCRYPTION_KEY_FILE" ]; then
            log "Decrypting with AES..."
            openssl enc -aes-256-cbc -d -in "$input_file" -out "$output_file" \
                -pass file:"$ENCRYPTION_KEY_FILE" || fatal "AES decryption failed"
        else
            warning "Encryption was used but no key found for decryption"
            cp "$input_file" "$output_file"
        fi
    else
        cp "$input_file" "$output_file"
    fi
}

# Compress file if compression is enabled
compress_file() {
    local input_file="$1"
    local output_file="$2"
    
    if [ "$COMPRESSION_ENABLED" = "true" ]; then
        log "Compressing backup..."
        gzip -c "$input_file" > "$output_file" || fatal "Compression failed"
    else
        cp "$input_file" "$output_file"
    fi
}

# Decompress file if compression was used
decompress_file() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ "$input_file" == *.gz ]]; then
        log "Decompressing backup..."
        gunzip -c "$input_file" > "$output_file" || fatal "Decompression failed"
    else
        cp "$input_file" "$output_file"
    fi
}

# =============================================================================
# BACKUP FUNCTIONS
# =============================================================================

backup_database() {
    if [ -z "$DATABASE_URL" ]; then
        warning "DATABASE_URL not set, skipping database backup"
        return 0
    fi
    
    log "💾 Creating database backup..."
    
    local backup_name
    backup_name=$(generate_backup_filename "database")
    local backup_file="$LOCAL_BACKUP_DIR/${backup_name}.sql"
    
    # Create backup directory
    mkdir -p "$LOCAL_BACKUP_DIR"
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would create database backup: $backup_file"
        return 0
    fi
    
    # Create database dump
    log "Creating PostgreSQL dump..."
    pg_dump "$DATABASE_URL" \
        --verbose \
        --no-owner \
        --no-privileges \
        --format=custom \
        --file="$backup_file" || fatal "Database backup failed"
    
    # Add metadata
    local metadata_file="$LOCAL_BACKUP_DIR/${backup_name}_metadata.json"
    cat > "$metadata_file" << EOF
{
    "backup_type": "database",
    "backup_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "database_url": "$(echo "$DATABASE_URL" | sed 's/:[^@]*@/:***@/')",
    "backup_size": $(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file" 2>/dev/null || echo 0),
    "checksum": "$(sha256sum "$backup_file" | cut -d' ' -f1)",
    "created_by": "$(whoami)",
    "hostname": "$(hostname)"
}
EOF
    
    success "Database backup created: $backup_file"
    
    # Process backup (compress, encrypt, upload)
    process_backup "$backup_file" "$metadata_file"
}

backup_kubernetes_resources() {
    log "☸️  Creating Kubernetes resources backup..."
    
    local backup_name
    backup_name=$(generate_backup_filename "kubernetes")
    local backup_dir="$LOCAL_BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_dir"
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would create Kubernetes backup: $backup_dir"
        return 0
    fi
    
    # Backup main namespace resources
    log "Backing up main namespace resources..."
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get all -o yaml > "$backup_dir/all-resources.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get configmaps -o yaml > "$backup_dir/configmaps.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get secrets -o yaml > "$backup_dir/secrets.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get pvc -o yaml > "$backup_dir/persistent-volumes.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get ingress -o yaml > "$backup_dir/ingress.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get networkpolicies -o yaml > "$backup_dir/network-policies.yaml" || true
    
    # Backup admin namespace resources
    local admin_namespace="${NAMESPACE}-admin"
    if kubectl --context="$KUBECTL_CONTEXT" get namespace "$admin_namespace" >/dev/null 2>&1; then
        log "Backing up admin namespace resources..."
        mkdir -p "$backup_dir/admin"
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get all -o yaml > "$backup_dir/admin/all-resources.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get configmaps -o yaml > "$backup_dir/admin/configmaps.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get secrets -o yaml > "$backup_dir/admin/secrets.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get pvc -o yaml > "$backup_dir/admin/persistent-volumes.yaml" || true
        kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get ingress -o yaml > "$backup_dir/admin/ingress.yaml" || true
    fi
    
    # Backup cluster-wide resources related to the gateway
    log "Backing up cluster-wide resources..."
    kubectl --context="$KUBECTL_CONTEXT" get clusterroles -l app.kubernetes.io/name=api-gateway -o yaml > "$backup_dir/cluster-roles.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" get clusterrolebindings -l app.kubernetes.io/name=api-gateway -o yaml > "$backup_dir/cluster-role-bindings.yaml" || true
    kubectl --context="$KUBECTL_CONTEXT" get customresourcedefinitions -l app.kubernetes.io/name=api-gateway -o yaml > "$backup_dir/crds.yaml" || true
    
    # Create archive
    local archive_file="$LOCAL_BACKUP_DIR/${backup_name}.tar"
    tar -cf "$archive_file" -C "$LOCAL_BACKUP_DIR" "$backup_name" || fatal "Failed to create Kubernetes backup archive"
    
    # Clean up temporary directory
    rm -rf "$backup_dir"
    
    # Add metadata
    local metadata_file="$LOCAL_BACKUP_DIR/${backup_name}_metadata.json"
    cat > "$metadata_file" << EOF
{
    "backup_type": "kubernetes",
    "backup_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "kubectl_context": "$KUBECTL_CONTEXT",
    "backup_size": $(stat -f%z "$archive_file" 2>/dev/null || stat -c%s "$archive_file" 2>/dev/null || echo 0),
    "checksum": "$(sha256sum "$archive_file" | cut -d' ' -f1)",
    "created_by": "$(whoami)",
    "hostname": "$(hostname)"
}
EOF
    
    success "Kubernetes backup created: $archive_file"
    
    # Process backup (compress, encrypt, upload)
    process_backup "$archive_file" "$metadata_file"
}

backup_configuration() {
    log "📋 Creating configuration backup..."
    
    local backup_name
    backup_name=$(generate_backup_filename "config")
    local backup_dir="$LOCAL_BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_dir"
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would create configuration backup: $backup_dir"
        return 0
    fi
    
    # Backup configuration files
    log "Backing up configuration files..."
    if [ -d "config" ]; then
        cp -r config "$backup_dir/" || true
    fi
    
    # Backup Kubernetes configurations
    if [ -d "k8s" ]; then
        cp -r k8s "$backup_dir/" || true
    fi
    
    # Backup Helm charts
    if [ -d "helm" ]; then
        cp -r helm "$backup_dir/" || true
    fi
    
    # Backup monitoring configurations
    if [ -d "monitoring" ]; then
        cp -r monitoring "$backup_dir/" || true
    fi
    
    # Backup scripts
    if [ -d "scripts" ]; then
        cp -r scripts "$backup_dir/" || true
    fi
    
    # Create archive
    local archive_file="$LOCAL_BACKUP_DIR/${backup_name}.tar"
    tar -cf "$archive_file" -C "$LOCAL_BACKUP_DIR" "$backup_name" || fatal "Failed to create configuration backup archive"
    
    # Clean up temporary directory
    rm -rf "$backup_dir"
    
    # Add metadata
    local metadata_file="$LOCAL_BACKUP_DIR/${backup_name}_metadata.json"
    cat > "$metadata_file" << EOF
{
    "backup_type": "configuration",
    "backup_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "environment": "$ENVIRONMENT",
    "backup_size": $(stat -f%z "$archive_file" 2>/dev/null || stat -c%s "$archive_file" 2>/dev/null || echo 0),
    "checksum": "$(sha256sum "$archive_file" | cut -d' ' -f1)",
    "created_by": "$(whoami)",
    "hostname": "$(hostname)"
}
EOF
    
    success "Configuration backup created: $archive_file"
    
    # Process backup (compress, encrypt, upload)
    process_backup "$archive_file" "$metadata_file"
}

backup_full() {
    log "🎯 Creating full backup (database + kubernetes + configuration)..."
    
    # Create individual backups
    backup_database
    backup_kubernetes_resources
    backup_configuration
    
    success "Full backup completed"
}

# =============================================================================
# BACKUP PROCESSING
# =============================================================================

process_backup() {
    local backup_file="$1"
    local metadata_file="$2"
    
    local processed_file="$backup_file"
    
    # Compress if enabled
    if [ "$COMPRESSION_ENABLED" = "true" ]; then
        local compressed_file="${backup_file}.gz"
        compress_file "$backup_file" "$compressed_file"
        processed_file="$compressed_file"
        rm "$backup_file"  # Remove uncompressed file
    fi
    
    # Encrypt if enabled
    if [ "$ENCRYPTION_ENABLED" = "true" ]; then
        local encrypted_file="${processed_file}.enc"
        encrypt_file "$processed_file" "$encrypted_file"
        processed_file="$encrypted_file"
        rm "${processed_file%.enc}"  # Remove unencrypted file
    fi
    
    # Upload to storage
    upload_backup "$processed_file" "$metadata_file"
    
    # Clean up old backups
    cleanup_old_backups
}

upload_backup() {
    local backup_file="$1"
    local metadata_file="$2"
    
    case "$BACKUP_STORAGE" in
        "s3")
            upload_to_s3 "$backup_file" "$metadata_file"
            ;;
        "gcs")
            upload_to_gcs "$backup_file" "$metadata_file"
            ;;
        "local")
            log "Backup stored locally: $backup_file"
            ;;
        *)
            warning "Unknown backup storage type: $BACKUP_STORAGE"
            ;;
    esac
}

upload_to_s3() {
    local backup_file="$1"
    local metadata_file="$2"
    
    if [ -z "$S3_BUCKET" ]; then
        fatal "S3_BUCKET not set for S3 storage"
    fi
    
    if ! command_exists aws; then
        fatal "AWS CLI not found"
    fi
    
    log "📤 Uploading to S3: s3://$S3_BUCKET/$S3_PREFIX/"
    
    local backup_filename
    backup_filename=$(basename "$backup_file")
    local metadata_filename
    metadata_filename=$(basename "$metadata_file")
    
    # Upload backup file
    aws s3 cp "$backup_file" "s3://$S3_BUCKET/$S3_PREFIX/$backup_filename" || fatal "Failed to upload backup to S3"
    
    # Upload metadata file
    aws s3 cp "$metadata_file" "s3://$S3_BUCKET/$S3_PREFIX/$metadata_filename" || fatal "Failed to upload metadata to S3"
    
    success "Backup uploaded to S3"
}

upload_to_gcs() {
    local backup_file="$1"
    local metadata_file="$2"
    
    if [ -z "$GCS_BUCKET" ]; then
        fatal "GCS_BUCKET not set for GCS storage"
    fi
    
    if ! command_exists gsutil; then
        fatal "Google Cloud SDK not found"
    fi
    
    log "📤 Uploading to GCS: gs://$GCS_BUCKET/$GCS_PREFIX/"
    
    local backup_filename
    backup_filename=$(basename "$backup_file")
    local metadata_filename
    metadata_filename=$(basename "$metadata_file")
    
    # Upload backup file
    gsutil cp "$backup_file" "gs://$GCS_BUCKET/$GCS_PREFIX/$backup_filename" || fatal "Failed to upload backup to GCS"
    
    # Upload metadata file
    gsutil cp "$metadata_file" "gs://$GCS_BUCKET/$GCS_PREFIX/$metadata_filename" || fatal "Failed to upload metadata to GCS"
    
    success "Backup uploaded to GCS"
}

# =============================================================================
# RESTORE FUNCTIONS
# =============================================================================

restore_database() {
    local backup_file="$1"
    
    if [ -z "$DATABASE_URL" ]; then
        fatal "DATABASE_URL not set for database restore"
    fi
    
    log "🔄 Restoring database from: $backup_file"
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would restore database from $backup_file"
        return 0
    fi
    
    # Download and decrypt backup if needed
    local local_backup_file
    local_backup_file=$(download_and_decrypt_backup "$backup_file")
    
    # Confirm restore operation
    warning "This will OVERWRITE the current database!"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log "Database restore cancelled"
        return 0
    fi
    
    # Create a backup of current database before restore
    log "Creating backup of current database before restore..."
    local pre_restore_backup
    pre_restore_backup=$(generate_backup_filename "pre_restore")
    pg_dump "$DATABASE_URL" > "$LOCAL_BACKUP_DIR/${pre_restore_backup}.sql" || warning "Failed to create pre-restore backup"
    
    # Restore database
    log "Restoring database..."
    pg_restore --verbose --clean --no-acl --no-owner -d "$DATABASE_URL" "$local_backup_file" || fatal "Database restore failed"
    
    success "Database restored successfully"
    
    # Clean up temporary file
    rm -f "$local_backup_file"
}

restore_kubernetes() {
    local backup_file="$1"
    
    log "☸️  Restoring Kubernetes resources from: $backup_file"
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY_RUN: Would restore Kubernetes resources from $backup_file"
        return 0
    fi
    
    # Download and decrypt backup if needed
    local local_backup_file
    local_backup_file=$(download_and_decrypt_backup "$backup_file")
    
    # Extract archive
    local temp_dir
    temp_dir=$(mktemp -d)
    tar -xf "$local_backup_file" -C "$temp_dir" || fatal "Failed to extract Kubernetes backup"
    
    # Find the extracted directory
    local backup_dir
    backup_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "*kubernetes*" | head -1)
    
    if [ -z "$backup_dir" ]; then
        fatal "Could not find Kubernetes backup directory in archive"
    fi
    
    # Confirm restore operation
    warning "This will OVERWRITE current Kubernetes resources!"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log "Kubernetes restore cancelled"
        rm -rf "$temp_dir"
        return 0
    fi
    
    # Restore resources
    log "Restoring main namespace resources..."
    kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/all-resources.yaml" || warning "Failed to restore some main resources"
    kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/configmaps.yaml" || warning "Failed to restore configmaps"
    kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/secrets.yaml" || warning "Failed to restore secrets"
    
    # Restore admin namespace if exists
    if [ -d "$backup_dir/admin" ]; then
        log "Restoring admin namespace resources..."
        kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/admin/all-resources.yaml" || warning "Failed to restore admin resources"
        kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/admin/configmaps.yaml" || warning "Failed to restore admin configmaps"
        kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/admin/secrets.yaml" || warning "Failed to restore admin secrets"
    fi
    
    # Restore cluster-wide resources
    log "Restoring cluster-wide resources..."
    kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/cluster-roles.yaml" || warning "Failed to restore cluster roles"
    kubectl --context="$KUBECTL_CONTEXT" apply -f "$backup_dir/cluster-role-bindings.yaml" || warning "Failed to restore cluster role bindings"
    
    success "Kubernetes resources restored successfully"
    
    # Clean up
    rm -rf "$temp_dir"
    rm -f "$local_backup_file"
}

download_and_decrypt_backup() {
    local backup_path="$1"
    
    local local_file
    
    # Download from remote storage if needed
    case "$BACKUP_STORAGE" in
        "s3")
            local_file=$(mktemp)
            aws s3 cp "$backup_path" "$local_file" || fatal "Failed to download backup from S3"
            ;;
        "gcs")
            local_file=$(mktemp)
            gsutil cp "$backup_path" "$local_file" || fatal "Failed to download backup from GCS"
            ;;
        "local")
            local_file="$backup_path"
            ;;
        *)
            fatal "Unknown backup storage type: $BACKUP_STORAGE"
            ;;
    esac
    
    # Decrypt if needed
    if [[ "$local_file" == *.enc ]]; then
        local decrypted_file
        decrypted_file=$(mktemp)
        decrypt_file "$local_file" "$decrypted_file"
        if [ "$local_file" != "$backup_path" ]; then
            rm "$local_file"  # Remove downloaded encrypted file
        fi
        local_file="$decrypted_file"
    fi
    
    # Decompress if needed
    if [[ "$local_file" == *.gz ]]; then
        local decompressed_file
        decompressed_file=$(mktemp)
        decompress_file "$local_file" "$decompressed_file"
        if [ "$local_file" != "$backup_path" ]; then
            rm "$local_file"  # Remove compressed file
        fi
        local_file="$decompressed_file"
    fi
    
    echo "$local_file"
}

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

cleanup_old_backups() {
    log "🧹 Cleaning up old backups (retention: $BACKUP_RETENTION_DAYS days)..."
    
    case "$BACKUP_STORAGE" in
        "local")
            cleanup_local_backups
            ;;
        "s3")
            cleanup_s3_backups
            ;;
        "gcs")
            cleanup_gcs_backups
            ;;
    esac
}

cleanup_local_backups() {
    if [ -d "$LOCAL_BACKUP_DIR" ]; then
        find "$LOCAL_BACKUP_DIR" -type f -mtime +$BACKUP_RETENTION_DAYS -delete || true
        success "Local backup cleanup completed"
    fi
}

cleanup_s3_backups() {
    if [ -n "$S3_BUCKET" ] && command_exists aws; then
        local cutoff_date
        cutoff_date=$(date -d "$BACKUP_RETENTION_DAYS days ago" +'%Y-%m-%d')
        
        aws s3api list-objects-v2 --bucket "$S3_BUCKET" --prefix "$S3_PREFIX/" --query "Contents[?LastModified<='$cutoff_date'].Key" --output text | \
        while read -r key; do
            if [ -n "$key" ] && [ "$key" != "None" ]; then
                aws s3 rm "s3://$S3_BUCKET/$key" || true
            fi
        done
        
        success "S3 backup cleanup completed"
    fi
}

cleanup_gcs_backups() {
    if [ -n "$GCS_BUCKET" ] && command_exists gsutil; then
        local cutoff_date
        cutoff_date=$(date -d "$BACKUP_RETENTION_DAYS days ago" +'%Y-%m-%dT%H:%M:%SZ')
        
        gsutil ls -l "gs://$GCS_BUCKET/$GCS_PREFIX/**" | \
        awk -v cutoff="$cutoff_date" '$2 < cutoff {print $3}' | \
        while read -r object; do
            if [ -n "$object" ]; then
                gsutil rm "$object" || true
            fi
        done
        
        success "GCS backup cleanup completed"
    fi
}

# =============================================================================
# LIST AND VERIFY FUNCTIONS
# =============================================================================

list_backups() {
    log "📋 Listing available backups..."
    
    case "$BACKUP_STORAGE" in
        "local")
            list_local_backups
            ;;
        "s3")
            list_s3_backups
            ;;
        "gcs")
            list_gcs_backups
            ;;
    esac
}

list_local_backups() {
    if [ -d "$LOCAL_BACKUP_DIR" ]; then
        echo "Local backups in $LOCAL_BACKUP_DIR:"
        ls -la "$LOCAL_BACKUP_DIR" | grep -E '\.(sql|tar|gz|enc)$' || echo "No backups found"
    else
        echo "Local backup directory does not exist: $LOCAL_BACKUP_DIR"
    fi
}

list_s3_backups() {
    if [ -n "$S3_BUCKET" ] && command_exists aws; then
        echo "S3 backups in s3://$S3_BUCKET/$S3_PREFIX/:"
        aws s3 ls "s3://$S3_BUCKET/$S3_PREFIX/" --recursive || echo "No backups found or access denied"
    else
        echo "S3 not configured or AWS CLI not available"
    fi
}

list_gcs_backups() {
    if [ -n "$GCS_BUCKET" ] && command_exists gsutil; then
        echo "GCS backups in gs://$GCS_BUCKET/$GCS_PREFIX/:"
        gsutil ls -l "gs://$GCS_BUCKET/$GCS_PREFIX/**" || echo "No backups found or access denied"
    else
        echo "GCS not configured or gsutil not available"
    fi
}

verify_backup() {
    local backup_file="$1"
    
    log "🔍 Verifying backup: $backup_file"
    
    # Download and decrypt backup
    local local_backup_file
    local_backup_file=$(download_and_decrypt_backup "$backup_file")
    
    # Verify based on backup type
    if [[ "$backup_file" == *"database"* ]]; then
        verify_database_backup "$local_backup_file"
    elif [[ "$backup_file" == *"kubernetes"* ]]; then
        verify_kubernetes_backup "$local_backup_file"
    elif [[ "$backup_file" == *"config"* ]]; then
        verify_config_backup "$local_backup_file"
    else
        warning "Unknown backup type, performing basic verification"
        verify_basic_backup "$local_backup_file"
    fi
    
    # Clean up temporary file
    if [ "$local_backup_file" != "$backup_file" ]; then
        rm -f "$local_backup_file"
    fi
}

verify_database_backup() {
    local backup_file="$1"
    
    log "Verifying database backup structure..."
    
    # Check if it's a valid PostgreSQL dump
    if pg_restore --list "$backup_file" >/dev/null 2>&1; then
        success "Database backup verification passed"
    else
        error "Database backup verification failed"
        return 1
    fi
}

verify_kubernetes_backup() {
    local backup_file="$1"
    
    log "Verifying Kubernetes backup structure..."
    
    # Check if it's a valid tar archive
    if tar -tf "$backup_file" >/dev/null 2>&1; then
        success "Kubernetes backup verification passed"
    else
        error "Kubernetes backup verification failed"
        return 1
    fi
}

verify_config_backup() {
    local backup_file="$1"
    
    log "Verifying configuration backup structure..."
    
    # Check if it's a valid tar archive
    if tar -tf "$backup_file" >/dev/null 2>&1; then
        success "Configuration backup verification passed"
    else
        error "Configuration backup verification failed"
        return 1
    fi
}

verify_basic_backup() {
    local backup_file="$1"
    
    log "Performing basic backup verification..."
    
    # Check if file exists and is not empty
    if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
        success "Basic backup verification passed"
    else
        error "Basic backup verification failed"
        return 1
    fi
}

# =============================================================================
# DISASTER RECOVERY FUNCTIONS
# =============================================================================

disaster_recovery() {
    log "🚨 Starting disaster recovery procedure..."
    
    warning "This will perform a complete system restore!"
    warning "Current data will be OVERWRITTEN!"
    
    read -p "Are you absolutely sure you want to continue? Type 'DISASTER_RECOVERY' to confirm: " -r
    if [ "$REPLY" != "DISASTER_RECOVERY" ]; then
        log "Disaster recovery cancelled"
        return 0
    fi
    
    # Find latest full backup
    local latest_backup
    latest_backup=$(find_latest_backup "full")
    
    if [ -z "$latest_backup" ]; then
        fatal "No full backup found for disaster recovery"
    fi
    
    log "Using backup: $latest_backup"
    
    # Restore in order: database, kubernetes, configuration
    log "Step 1: Restoring database..."
    local db_backup
    db_backup=$(find_backup_component "$latest_backup" "database")
    if [ -n "$db_backup" ]; then
        restore_database "$db_backup"
    else
        warning "No database backup found in full backup"
    fi
    
    log "Step 2: Restoring Kubernetes resources..."
    local k8s_backup
    k8s_backup=$(find_backup_component "$latest_backup" "kubernetes")
    if [ -n "$k8s_backup" ]; then
        restore_kubernetes "$k8s_backup"
    else
        warning "No Kubernetes backup found in full backup"
    fi
    
    log "Step 3: Waiting for services to stabilize..."
    sleep 30
    
    log "Step 4: Verifying recovery..."
    verify_disaster_recovery
    
    success "🎉 Disaster recovery completed!"
}

find_latest_backup() {
    local backup_type="$1"
    
    case "$BACKUP_STORAGE" in
        "local")
            find "$LOCAL_BACKUP_DIR" -name "*${backup_type}*" -type f | sort -r | head -1
            ;;
        "s3")
            aws s3 ls "s3://$S3_BUCKET/$S3_PREFIX/" --recursive | grep "$backup_type" | sort -r | head -1 | awk '{print $4}'
            ;;
        "gcs")
            gsutil ls "gs://$GCS_BUCKET/$GCS_PREFIX/**" | grep "$backup_type" | sort -r | head -1
            ;;
    esac
}

find_backup_component() {
    local full_backup="$1"
    local component="$2"
    
    # This is a simplified implementation
    # In practice, you'd need to track which backups are part of a full backup set
    find_latest_backup "$component"
}

verify_disaster_recovery() {
    log "🔍 Verifying disaster recovery..."
    
    # Check database connectivity
    if [ -n "$DATABASE_URL" ]; then
        if psql "$DATABASE_URL" -c "SELECT 1;" >/dev/null 2>&1; then
            success "Database connectivity verified"
        else
            error "Database connectivity failed"
        fi
    fi
    
    # Check Kubernetes resources
    if kubectl --context="$KUBECTL_CONTEXT" -n "$NAMESPACE" get pods >/dev/null 2>&1; then
        success "Kubernetes resources accessible"
    else
        error "Kubernetes resources not accessible"
    fi
    
    # Check service health
    local admin_namespace="${NAMESPACE}-admin"
    if kubectl --context="$KUBECTL_CONTEXT" -n "$admin_namespace" get pods -l app.kubernetes.io/name=api-gateway-admin >/dev/null 2>&1; then
        success "Admin services accessible"
    else
        warning "Admin services not accessible"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local action="${1:-backup}"
    
    case "$action" in
        "backup")
            case "$BACKUP_TYPE" in
                "full")
                    backup_full
                    ;;
                "database")
                    backup_database
                    ;;
                "kubernetes")
                    backup_kubernetes_resources
                    ;;
                "config")
                    backup_configuration
                    ;;
                *)
                    fatal "Unknown backup type: $BACKUP_TYPE"
                    ;;
            esac
            ;;
        "restore")
            if [ -z "$RESTORE_FROM" ]; then
                fatal "RESTORE_FROM must be specified for restore operation"
            fi
            
            if [[ "$RESTORE_FROM" == *"database"* ]]; then
                restore_database "$RESTORE_FROM"
            elif [[ "$RESTORE_FROM" == *"kubernetes"* ]]; then
                restore_kubernetes "$RESTORE_FROM"
            else
                fatal "Cannot determine restore type from: $RESTORE_FROM"
            fi
            ;;
        "list")
            list_backups
            ;;
        "verify")
            if [ -z "$RESTORE_FROM" ]; then
                fatal "RESTORE_FROM must be specified for verify operation"
            fi
            verify_backup "$RESTORE_FROM"
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "disaster-recovery")
            disaster_recovery
            ;;
        *)
            fatal "Unknown action: $action"
            ;;
    esac
}

# Show usage if help requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
Admin Disaster Recovery and Backup Script for API Gateway

Usage: $0 [ACTION]

Actions:
  backup              Create backup (default)
  restore             Restore from backup
  list                List available backups
  verify              Verify backup integrity
  cleanup             Clean up old backups
  disaster-recovery   Full disaster recovery procedure

Environment Variables:
  ENVIRONMENT                Deployment environment (default: production)
  NAMESPACE                 Kubernetes namespace (default: api-gateway)
  KUBECTL_CONTEXT           Kubectl context (default: production)
  DATABASE_URL              PostgreSQL database URL
  BACKUP_TYPE               Backup type: full, database, kubernetes, config (default: full)
  BACKUP_STORAGE            Storage type: local, s3, gcs (default: local)
  BACKUP_RETENTION_DAYS     Backup retention in days (default: 30)
  RESTORE_FROM              Backup file/path to restore from
  DRY_RUN                   Dry run mode (default: false)
  ENCRYPTION_ENABLED        Enable backup encryption (default: true)
  COMPRESSION_ENABLED       Enable backup compression (default: true)
  
  # Storage specific
  S3_BUCKET                 S3 bucket for backups
  S3_PREFIX                 S3 prefix for backups (default: admin-backups)
  GCS_BUCKET                GCS bucket for backups
  GCS_PREFIX                GCS prefix for backups (default: admin-backups)
  LOCAL_BACKUP_DIR          Local backup directory (default: ./backups)
  
  # Encryption
  ENCRYPTION_KEY_FILE       Path to encryption key file
  GPG_RECIPIENT             GPG recipient for encryption

Examples:
  # Create full backup
  DATABASE_URL="postgresql://..." $0 backup

  # Create database-only backup
  BACKUP_TYPE=database DATABASE_URL="postgresql://..." $0 backup

  # Backup to S3
  BACKUP_STORAGE=s3 S3_BUCKET=my-backups DATABASE_URL="postgresql://..." $0 backup

  # List backups
  $0 list

  # Restore database
  RESTORE_FROM="/path/to/backup.sql" DATABASE_URL="postgresql://..." $0 restore

  # Verify backup
  RESTORE_FROM="/path/to/backup.sql" $0 verify

  # Disaster recovery
  DATABASE_URL="postgresql://..." $0 disaster-recovery
EOF
    exit 0
fi

# Check required tools
required_tools=("kubectl")
if [ -n "$DATABASE_URL" ]; then
    required_tools+=("pg_dump" "pg_restore" "psql")
fi

case "$BACKUP_STORAGE" in
    "s3")
        required_tools+=("aws")
        ;;
    "gcs")
        required_tools+=("gsutil")
        ;;
esac

if [ "$ENCRYPTION_ENABLED" = "true" ]; then
    if [ -n "$GPG_RECIPIENT" ]; then
        required_tools+=("gpg")
    else
        required_tools+=("openssl")
    fi
fi

if [ "$COMPRESSION_ENABLED" = "true" ]; then
    required_tools+=("gzip")
fi

for tool in "${required_tools[@]}"; do
    if ! command_exists "$tool"; then
        fatal "$tool is required but not installed"
    fi
done

# Create backup directory if it doesn't exist
mkdir -p "$LOCAL_BACKUP_DIR"

# Execute main function
main "$@"
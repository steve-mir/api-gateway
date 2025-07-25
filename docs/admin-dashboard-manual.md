# Admin Dashboard User Manual

The Rust API Gateway includes a comprehensive web-based admin dashboard for monitoring, configuration, and management. This manual provides step-by-step instructions for using all dashboard features.

## Table of Contents

- [Getting Started](#getting-started)
- [Dashboard Overview](#dashboard-overview)
- [Service Management](#service-management)
- [Configuration Management](#configuration-management)
- [Monitoring and Metrics](#monitoring-and-metrics)
- [Log Viewer](#log-viewer)
- [User Management](#user-management)
- [System Settings](#system-settings)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Accessing the Dashboard

1. **Open your web browser** and navigate to the admin dashboard URL:
   ```
   http://your-gateway-host:8081
   ```
   Or for HTTPS:
   ```
   https://admin.your-domain.com
   ```

2. **Login Screen**: You'll see the login page with the gateway logo and login form.

   ![Login Screen](screenshots/login-screen.png)

3. **Enter Credentials**:
   - **Username**: Your admin username (default: `admin`)
   - **Password**: Your admin password
   - Click **"Sign In"** button

4. **Two-Factor Authentication** (if enabled):
   - Enter your 2FA code from your authenticator app
   - Click **"Verify"**

### First Time Setup

After logging in for the first time:

1. **Change Default Password**:
   - Click on your username in the top-right corner
   - Select **"Profile Settings"**
   - Click **"Change Password"**
   - Enter your current password and new password
   - Click **"Update Password"**

2. **Configure Notifications**:
   - Go to **Settings** → **Notifications**
   - Enable email notifications for critical events
   - Set up Slack/Discord webhooks if needed

## Dashboard Overview

### Main Dashboard

The main dashboard provides an at-a-glance view of your gateway's health and performance.

![Main Dashboard](screenshots/main-dashboard.png)

#### Key Metrics Cards

1. **Request Rate**: Current requests per second
2. **Error Rate**: Percentage of failed requests
3. **Average Latency**: P95 response time
4. **Active Services**: Number of healthy services

#### Real-time Charts

1. **Request Volume**: Line chart showing request rate over time
2. **Response Times**: Histogram of response time distribution
3. **Error Rates**: Error percentage by service
4. **Service Health**: Status of all registered services

#### Quick Actions

- **Reload Configuration**: Apply configuration changes
- **View Logs**: Jump to recent error logs
- **Service Status**: Quick health check of all services
- **System Alerts**: View active alerts and warnings

### Navigation Menu

The left sidebar contains the main navigation:

- **🏠 Dashboard**: Main overview page
- **🔧 Services**: Service management and topology
- **⚙️ Configuration**: Gateway configuration editor
- **📊 Metrics**: Detailed metrics and analytics
- **📋 Logs**: Log viewer and search
- **👥 Users**: Admin user management
- **🛡️ Security**: Security settings and audit logs
- **⚡ Performance**: Performance monitoring and tuning
- **🔔 Alerts**: Alert configuration and history
- **⚙️ Settings**: System settings and preferences

## Service Management

### Service Topology View

The service topology provides a visual representation of your services and their relationships.

![Service Topology](screenshots/service-topology.png)

#### Viewing the Topology

1. **Navigate** to **Services** → **Topology**
2. **Interactive Graph**: 
   - Nodes represent services
   - Edges show request flow
   - Colors indicate health status:
     - 🟢 Green: Healthy
     - 🟡 Yellow: Warning
     - 🔴 Red: Unhealthy
     - ⚫ Gray: Unknown

3. **Node Information**:
   - Click on any service node to see details
   - Hover for quick stats (request rate, error rate, latency)

#### Topology Controls

- **🔍 Zoom**: Use mouse wheel or zoom controls
- **📐 Layout**: Switch between different layout algorithms
- **🎨 Filter**: Show/hide services by status or tags
- **🔄 Refresh**: Auto-refresh every 30 seconds (configurable)

### Service List View

![Service List](screenshots/service-list.png)

#### Service Table Columns

1. **Service Name**: Name and version
2. **Status**: Health status with indicator
3. **Instances**: Number of healthy/total instances
4. **Request Rate**: Requests per second
5. **Error Rate**: Percentage of failed requests
6. **Avg Latency**: Average response time
7. **Last Updated**: Last health check time
8. **Actions**: Quick action buttons

#### Service Actions

For each service, you can:

- **👁️ View Details**: See detailed service information
- **⚙️ Configure**: Edit service configuration
- **🔄 Restart Health Check**: Force immediate health check
- **⏸️ Disable**: Temporarily disable the service
- **🗑️ Remove**: Remove service from gateway

### Service Details Page

Click on any service to view detailed information:

![Service Details](screenshots/service-details.png)

#### Service Information Tabs

1. **Overview**: Basic service information and status
2. **Instances**: List of all service instances
3. **Metrics**: Service-specific metrics and charts
4. **Configuration**: Current service configuration
5. **Health Checks**: Health check history and configuration
6. **Logs**: Service-related log entries

#### Instance Management

In the **Instances** tab:

- **Add Instance**: Manually add a service instance
- **Remove Instance**: Remove unhealthy instances
- **Update Weights**: Adjust load balancing weights
- **Health Check**: Force health check for specific instance

### Adding a New Service

1. **Click** the **"+ Add Service"** button
2. **Fill in Service Details**:
   - **Service Name**: Unique identifier
   - **Display Name**: Human-readable name
   - **Description**: Optional description
   - **Tags**: Comma-separated tags

3. **Configure Discovery**:
   - **Discovery Type**: Kubernetes, Consul, Static, etc.
   - **Namespace**: Kubernetes namespace (if applicable)
   - **Service Name**: Name in service discovery
   - **Port**: Service port number

4. **Load Balancing**:
   - **Algorithm**: Round-robin, least connections, etc.
   - **Health Check Path**: Endpoint for health checks
   - **Health Check Interval**: Check frequency in seconds

5. **Advanced Settings**:
   - **Circuit Breaker**: Enable/disable and configure thresholds
   - **Rate Limiting**: Set request rate limits
   - **Timeout**: Request timeout in seconds
   - **Retry Policy**: Configure retry behavior

6. **Click** **"Create Service"**

## Configuration Management

### Configuration Editor

The configuration editor provides a user-friendly interface for managing gateway configuration.

![Configuration Editor](screenshots/config-editor.png)

#### Configuration Sections

1. **Server Settings**: Basic server configuration
2. **Routes**: Request routing rules
3. **Upstreams**: Backend service definitions
4. **Middleware**: Middleware pipeline configuration
5. **Authentication**: Auth provider settings
6. **Rate Limiting**: Global rate limiting rules
7. **Observability**: Logging and metrics configuration

#### Editing Configuration

1. **Select Section**: Click on the section you want to edit
2. **Form Editor**: Use the form-based editor for common settings
3. **YAML Editor**: Switch to YAML mode for advanced editing
4. **Validation**: Real-time validation with error highlighting
5. **Preview**: See the generated configuration before applying

#### Configuration Validation

- **Real-time Validation**: Errors are highlighted as you type
- **Dependency Checking**: Validates references between sections
- **Schema Validation**: Ensures configuration follows the correct schema
- **Test Configuration**: Test configuration without applying changes

#### Applying Changes

1. **Review Changes**: See a diff of what will change
2. **Validate**: Ensure configuration is valid
3. **Apply**: Click **"Apply Configuration"**
4. **Rollback**: Option to rollback if issues occur

### Route Management

![Route Management](screenshots/route-management.png)

#### Adding a Route

1. **Click** **"+ Add Route"**
2. **Route Details**:
   - **Path Pattern**: URL path pattern (e.g., `/api/users/{id}`)
   - **Methods**: HTTP methods (GET, POST, PUT, DELETE)
   - **Upstream Service**: Target service
   - **Priority**: Route matching priority

3. **Middleware**:
   - **Authentication**: Require authentication
   - **Rate Limiting**: Apply rate limits
   - **CORS**: Enable CORS headers
   - **Custom Middleware**: Add custom middleware

4. **Advanced Options**:
   - **Timeout**: Request timeout override
   - **Retry Policy**: Retry configuration
   - **Circuit Breaker**: Circuit breaker settings
   - **Request/Response Transformation**: Header/body modifications

#### Route Testing

- **Test Route**: Send test requests to validate routing
- **Path Matching**: Test path parameter extraction
- **Middleware Pipeline**: Verify middleware execution order

### Configuration History

![Configuration History](screenshots/config-history.png)

#### Viewing Changes

1. **Navigate** to **Configuration** → **History**
2. **Change List**: See all configuration changes
3. **Change Details**: Click on any change to see:
   - **Timestamp**: When the change was made
   - **User**: Who made the change
   - **Description**: Change description
   - **Diff**: Visual diff of changes
   - **Status**: Success/failure status

#### Rolling Back Changes

1. **Select Change**: Click on the change to rollback to
2. **Review Diff**: See what will be reverted
3. **Confirm Rollback**: Click **"Rollback to this version"**
4. **Apply**: Confirm the rollback operation

## Monitoring and Metrics

### Metrics Dashboard

![Metrics Dashboard](screenshots/metrics-dashboard.png)

#### Key Performance Indicators

1. **Request Metrics**:
   - Total requests
   - Requests per second
   - Request distribution by method/status

2. **Latency Metrics**:
   - Average response time
   - P50, P95, P99 percentiles
   - Latency distribution histogram

3. **Error Metrics**:
   - Error rate percentage
   - Errors by service
   - Error types and causes

4. **System Metrics**:
   - CPU usage
   - Memory usage
   - Connection pool status
   - Cache hit rates

#### Time Range Selection

- **Quick Ranges**: Last 5m, 15m, 1h, 6h, 24h, 7d
- **Custom Range**: Select specific start and end times
- **Auto Refresh**: Automatically refresh data every 30 seconds

#### Chart Interactions

- **Zoom**: Click and drag to zoom into time ranges
- **Hover**: See exact values at specific points
- **Legend**: Click legend items to show/hide series
- **Export**: Export charts as PNG or CSV

### Service Metrics

![Service Metrics](screenshots/service-metrics.png)

#### Per-Service Analytics

1. **Service Selection**: Choose service from dropdown
2. **Instance Breakdown**: Metrics per service instance
3. **Comparison**: Compare multiple services side-by-side
4. **Alerts**: Set up alerts based on service metrics

#### Custom Metrics

- **Business Metrics**: Track custom business KPIs
- **SLA Monitoring**: Monitor SLA compliance
- **Custom Dashboards**: Create custom metric dashboards

### Real-time Monitoring

![Real-time Monitoring](screenshots/realtime-monitoring.png)

#### Live Request Stream

- **Request Feed**: See requests in real-time
- **Filter Options**: Filter by service, status, method
- **Request Details**: Click on requests for full details
- **Performance Impact**: Minimal performance overhead

#### System Health

- **Resource Usage**: Real-time CPU, memory, disk usage
- **Connection Status**: Active connections and pools
- **Service Health**: Live service health status
- **Alert Status**: Current active alerts

## Log Viewer

### Log Search and Filtering

![Log Viewer](screenshots/log-viewer.png)

#### Search Interface

1. **Search Bar**: Enter search terms or use query syntax
2. **Time Range**: Select time range for log search
3. **Log Level**: Filter by log level (ERROR, WARN, INFO, DEBUG)
4. **Service Filter**: Show logs from specific services
5. **Advanced Filters**: Filter by request ID, trace ID, user ID

#### Search Syntax

- **Simple Search**: `error timeout`
- **Field Search**: `service:user-service level:error`
- **Regex Search**: `message:/timeout.*connection/`
- **Time Range**: `@timestamp:[2024-01-15 TO 2024-01-16]`

#### Log Entry Details

Click on any log entry to see:
- **Full Message**: Complete log message
- **Structured Fields**: All log fields and values
- **Context**: Related log entries
- **Trace Information**: Distributed tracing context
- **Actions**: Copy, share, create alert

### Log Streaming

![Log Streaming](screenshots/log-streaming.png)

#### Real-time Log Tail

1. **Enable Streaming**: Click **"Start Streaming"**
2. **Auto-scroll**: Automatically scroll to new entries
3. **Pause/Resume**: Pause streaming to examine entries
4. **Buffer Size**: Configure how many entries to keep in memory

#### Log Filtering

- **Live Filtering**: Apply filters to streaming logs
- **Highlight**: Highlight specific terms or patterns
- **Notifications**: Get notified of specific log patterns

### Log Analysis

#### Log Patterns

- **Error Analysis**: Identify common error patterns
- **Performance Issues**: Find slow requests and bottlenecks
- **Security Events**: Monitor authentication failures and suspicious activity
- **Trend Analysis**: Analyze log volume and patterns over time

#### Export and Sharing

- **Export Logs**: Export filtered logs as CSV or JSON
- **Share Queries**: Share log search queries with team members
- **Scheduled Reports**: Set up automated log reports

## User Management

### Admin Users

![User Management](screenshots/user-management.png)

#### User List

The user management page shows all admin users with:
- **Username**: Login username
- **Email**: Contact email address
- **Roles**: Assigned roles and permissions
- **Status**: Active/inactive status
- **Last Login**: Last login timestamp
- **Actions**: Edit, disable, delete user

#### Adding New Users

1. **Click** **"+ Add User"**
2. **User Information**:
   - **Username**: Unique login username
   - **Email**: Email address
   - **Full Name**: Display name
   - **Password**: Initial password (user must change on first login)

3. **Role Assignment**:
   - **Admin**: Full access to all features
   - **Operator**: Read/write access to services and configuration
   - **Viewer**: Read-only access to dashboard and metrics
   - **Custom**: Define custom permissions

4. **Account Settings**:
   - **Force Password Change**: Require password change on first login
   - **Two-Factor Authentication**: Require 2FA setup
   - **Account Expiry**: Set account expiration date

#### User Roles and Permissions

| Role | Dashboard | Services | Config | Users | Logs | Metrics |
|------|-----------|----------|--------|-------|------|---------|
| Admin | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Operator | ✅ View | ✅ Full | ✅ Edit | ❌ None | ✅ View | ✅ View |
| Viewer | ✅ View | ✅ View | ✅ View | ❌ None | ✅ View | ✅ View |

### API Key Management

![API Key Management](screenshots/api-key-management.png)

#### Creating API Keys

1. **Click** **"+ Create API Key"**
2. **Key Details**:
   - **Name**: Descriptive name for the key
   - **Description**: Purpose of the API key
   - **Expiration**: Set expiration date (optional)

3. **Permissions**:
   - **Scope**: Select which APIs the key can access
   - **Rate Limits**: Set specific rate limits for the key
   - **IP Restrictions**: Restrict usage to specific IP addresses

4. **Generate Key**: Click **"Generate"** to create the key
5. **Copy Key**: Copy the generated key (shown only once)

#### Managing API Keys

- **View Usage**: See API key usage statistics
- **Regenerate**: Generate new key value
- **Revoke**: Immediately disable an API key
- **Edit Permissions**: Modify key permissions

### Session Management

![Session Management](screenshots/session-management.png)

#### Active Sessions

View all active admin sessions:
- **User**: Which user is logged in
- **IP Address**: Login IP address
- **Browser**: Browser and device information
- **Login Time**: When the session started
- **Last Activity**: Last activity timestamp
- **Actions**: Force logout, view session details

#### Session Security

- **Concurrent Sessions**: Limit number of concurrent sessions per user
- **Session Timeout**: Automatic logout after inactivity
- **IP Validation**: Validate session IP address
- **Device Tracking**: Track and alert on new device logins

## System Settings

### General Settings

![System Settings](screenshots/system-settings.png)

#### Gateway Configuration

1. **Basic Settings**:
   - **Gateway Name**: Display name for the gateway
   - **Environment**: Production, staging, development
   - **Time Zone**: Default time zone for the dashboard
   - **Language**: Dashboard language (English, Spanish, French, etc.)

2. **Security Settings**:
   - **Session Timeout**: Admin session timeout
   - **Password Policy**: Password complexity requirements
   - **Two-Factor Authentication**: Enforce 2FA for all users
   - **IP Whitelist**: Restrict admin access to specific IPs

3. **Notification Settings**:
   - **Email Notifications**: Configure SMTP settings
   - **Slack Integration**: Webhook URL for Slack notifications
   - **Discord Integration**: Webhook URL for Discord notifications
   - **Alert Thresholds**: Configure when to send alerts

### Backup and Restore

![Backup Settings](screenshots/backup-settings.png)

#### Automated Backups

1. **Backup Schedule**:
   - **Frequency**: Daily, weekly, monthly
   - **Time**: When to run backups
   - **Retention**: How long to keep backups

2. **Backup Content**:
   - **Configuration**: Gateway configuration files
   - **User Data**: Admin users and API keys
   - **Metrics**: Historical metrics data
   - **Logs**: Log data (optional)

3. **Storage Location**:
   - **Local Storage**: Store on local filesystem
   - **S3 Compatible**: AWS S3, MinIO, etc.
   - **Google Cloud Storage**: GCS bucket
   - **Azure Blob Storage**: Azure storage account

#### Manual Backup/Restore

- **Create Backup**: Generate immediate backup
- **Download Backup**: Download backup file
- **Restore from Backup**: Upload and restore from backup file
- **Backup Verification**: Verify backup integrity

### Integration Settings

![Integration Settings](screenshots/integration-settings.png)

#### External Integrations

1. **Monitoring Systems**:
   - **Prometheus**: Metrics scraping configuration
   - **Grafana**: Dashboard integration
   - **Datadog**: APM integration
   - **New Relic**: Performance monitoring

2. **Logging Systems**:
   - **ELK Stack**: Elasticsearch, Logstash, Kibana
   - **Splunk**: Log forwarding configuration
   - **Fluentd**: Log shipping configuration

3. **Service Discovery**:
   - **Kubernetes**: Cluster connection settings
   - **Consul**: Consul agent configuration
   - **Eureka**: Netflix Eureka integration
   - **NATS**: NATS server configuration

## Troubleshooting

### Common Issues

#### Dashboard Won't Load

**Symptoms**: Browser shows connection error or timeout

**Solutions**:
1. **Check Gateway Status**:
   ```bash
   curl http://your-gateway:8081/health
   ```

2. **Verify Admin Port**: Ensure admin port (8081) is accessible
3. **Check Firewall**: Verify firewall rules allow admin port
4. **Browser Cache**: Clear browser cache and cookies
5. **Network Connectivity**: Test network connection to gateway

#### Login Issues

**Symptoms**: Cannot login with correct credentials

**Solutions**:
1. **Check User Status**: Verify user account is active
2. **Password Reset**: Reset password via command line:
   ```bash
   ./api-gateway admin reset-password --username admin
   ```
3. **Check Logs**: Look for authentication errors in gateway logs
4. **Time Sync**: Ensure server time is synchronized (important for JWT)

#### Slow Dashboard Performance

**Symptoms**: Dashboard loads slowly or times out

**Solutions**:
1. **Reduce Time Range**: Use shorter time ranges for metrics
2. **Limit Data**: Reduce number of services or metrics displayed
3. **Browser Resources**: Close other browser tabs/applications
4. **Gateway Resources**: Check gateway CPU/memory usage
5. **Network Latency**: Test network latency to gateway

#### Missing Data

**Symptoms**: Metrics, logs, or services not showing

**Solutions**:
1. **Check Service Discovery**: Verify service discovery is working
2. **Verify Permissions**: Ensure user has required permissions
3. **Time Range**: Check if data exists in selected time range
4. **Refresh Data**: Click refresh button or reload page
5. **Check Configuration**: Verify observability settings are correct

### Getting Help

#### Built-in Help

- **Help Button**: Click **"?"** icon for contextual help
- **Tooltips**: Hover over elements for quick explanations
- **Documentation Links**: Links to relevant documentation sections

#### Support Information

- **System Information**: Available in **Settings** → **About**
- **Log Export**: Export logs for support analysis
- **Configuration Export**: Export configuration for troubleshooting
- **Health Check**: Run comprehensive system health check

#### Contact Support

If you need additional help:
1. **Check Documentation**: Review the troubleshooting guide
2. **Search Issues**: Look through GitHub issues
3. **Create Issue**: Create new GitHub issue with:
   - Dashboard version
   - Browser information
   - Steps to reproduce
   - Error messages
   - System logs

This admin dashboard manual provides comprehensive guidance for using all features of the Rust API Gateway admin interface. The dashboard is designed to be intuitive, but this manual ensures you can make full use of all available capabilities.
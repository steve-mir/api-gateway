// System types
export interface SystemStatus {
  status: string
  timestamp: number
  version: string
  uptime: number
  checks: Record<string, any>
}

export interface SystemDiagnostics {
  timestamp: string
  gateway_status: string
  service_registry_status: string
  config_status: string
  health_checker_status: string
  metrics_collector_status: string
  audit_log_status: string
  system_resources: SystemResources
  recent_errors: any[]
}

export interface SystemResources {
  cpu_usage_percent: number
  memory_usage_bytes: number
  memory_total_bytes: number
  disk_usage_bytes: number
  disk_total_bytes: number
  network_connections: number
}

// Service types
export interface ServiceInstance {
  id: string
  name: string
  address: string
  protocol: string
  metadata: Record<string, string>
  weight: number
  health_status?: ServiceStatus
  last_seen?: string
}

export interface ServiceSummary {
  name: string
  instance_count: number
  healthy_instances: number
  instances: ServiceInstance[]
}

export interface ServicesResponse {
  services: ServiceSummary[]
  total_services: number
  total_instances: number
}

export enum ServiceStatus {
  Healthy = 'Healthy',
  Unhealthy = 'Unhealthy',
  Warning = 'Warning',
  Unknown = 'Unknown'
}

// Configuration types
export interface GatewayConfig {
  server: ServerConfig
  routes: RouteDefinition[]
  upstreams: Record<string, UpstreamConfig>
  middleware: MiddlewareConfig
  observability: ObservabilityConfig
}

export interface ServerConfig {
  host: string
  port: number
  tls?: TlsConfig
}

export interface TlsConfig {
  enabled: boolean
  cert_path?: string
  key_path?: string
}

export interface RouteDefinition {
  id: string
  path: string
  methods: string[]
  upstream: string
  middleware?: string[]
  timeout?: number
}

export interface UpstreamConfig {
  name: string
  discovery: DiscoveryConfig
  load_balancer: LoadBalancerConfig
  health_check: HealthCheckConfig
  circuit_breaker?: CircuitBreakerConfig
}

export interface DiscoveryConfig {
  type: string
  config: Record<string, any>
}

export interface LoadBalancerConfig {
  algorithm: string
  config: Record<string, any>
}

export interface HealthCheckConfig {
  enabled: boolean
  interval: number
  timeout: number
  path?: string
}

export interface CircuitBreakerConfig {
  failure_threshold: number
  timeout: number
  success_threshold: number
}

export interface MiddlewareConfig {
  auth?: AuthConfig
  rate_limiting?: RateLimitConfig
  cors?: CorsConfig
}

export interface AuthConfig {
  enabled: boolean
  providers: AuthProvider[]
}

export interface AuthProvider {
  type: string
  config: Record<string, any>
}

export interface RateLimitConfig {
  enabled: boolean
  default_limit: number
  window: number
}

export interface CorsConfig {
  enabled: boolean
  allowed_origins: string[]
  allowed_methods: string[]
  allowed_headers: string[]
}

export interface ObservabilityConfig {
  metrics: MetricsConfig
  logging: LogConfig
  tracing: TracingConfig
}

export interface MetricsConfig {
  enabled: boolean
  prometheus_endpoint: string
  collection_interval: number
}

export interface LogConfig {
  level: string
  format: string
  output: string
}

export interface TracingConfig {
  enabled: boolean
  endpoint?: string
  service_name: string
}

// Metrics types
export interface MetricsSummary {
  total_metrics: number
  total_requests: number
  error_rate: number
  avg_response_time: number
  active_connections: number
  last_updated: string
}

export interface MetricsQueryResult {
  metric_name: string
  labels: Record<string, string>
  values: Array<{ timestamp: number; value: number }>
}

export interface AlertRule {
  id: string
  name: string
  description?: string
  metric_name: string
  condition: AlertCondition
  threshold: number
  duration: number
  labels: Record<string, string>
  enabled: boolean
  created_at: string
  last_triggered?: string
}

export enum AlertCondition {
  GreaterThan = 'GreaterThan',
  LessThan = 'LessThan',
  Equal = 'Equal',
  NotEqual = 'NotEqual',
  GreaterThanOrEqual = 'GreaterThanOrEqual',
  LessThanOrEqual = 'LessThanOrEqual'
}

export interface MetricsDashboard {
  summary: MetricsSummary
  active_alerts: AlertRule[]
  recent_metrics: MetricsQueryResult[]
  system_health: SystemHealth
}

export interface SystemHealth {
  cpu_usage: number
  memory_usage: number
  disk_usage: number
  network_throughput: number
}

// Logging types
export interface AuditLogEntry {
  timestamp: string
  event_type: AuditEventType
  user_id?: string
  session_id?: string
  correlation_id: string
  source_ip?: string
  user_agent?: string
  resource: string
  action: string
  outcome: AuditOutcome
  details: Record<string, any>
}

export enum AuditEventType {
  Authentication = 'Authentication',
  Authorization = 'Authorization',
  AdminOperation = 'AdminOperation',
  ConfigurationChange = 'ConfigurationChange',
  SecurityViolation = 'SecurityViolation',
  DataAccess = 'DataAccess'
}

export enum AuditOutcome {
  Success = 'Success',
  Failure = 'Failure',
  Denied = 'Denied'
}

export interface LogQueryResponse {
  logs: any[]
  total: number
  offset: number
  limit: number
  query_executed: boolean
  backend_status: string
}

export interface AuditLogQueryResponse {
  logs: AuditLogEntry[]
  total: number
  offset: number
  limit: number
}

// User management types
export interface AdminUser {
  id: string
  username: string
  email: string
  roles: string[]
  permissions: string[]
  created_at: string
  last_login?: string
  active: boolean
}

// Network topology types
export interface NetworkNode {
  id: string
  label: string
  group: string
  level?: number
  color?: string
  shape?: string
  size?: number
  font?: any
}

export interface NetworkEdge {
  id: string
  from: string
  to: string
  label?: string
  arrows?: string
  color?: string
  width?: number
}

export interface TopologyData {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
}

// API Response types
export interface ApiResponse<T = any> {
  data: T
  success?: boolean
  message?: string
  error?: string
  details?: string
}

export interface PaginatedResponse<T = any> {
  data: T[]
  total: number
  offset: number
  limit: number
}

// Form types
export interface ServiceFormData {
  name: string
  address: string
  protocol: string
  weight: number
  metadata: Record<string, string>
  persist: boolean
}

export interface AlertRuleFormData {
  name: string
  description?: string
  metric_name: string
  condition: AlertCondition
  threshold: number
  duration_seconds: number
  labels: Record<string, string>
}

export interface UserFormData {
  username: string
  email: string
  password?: string
  roles: string[]
  active: boolean
}
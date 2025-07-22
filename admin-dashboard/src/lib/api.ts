import axios from 'axios'
import toast from 'react-hot-toast'

// Create axios instance with default config
export const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor for auth
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('admin_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      localStorage.removeItem('admin_token')
      window.location.href = '/login'
    } else if (error.response?.status >= 500) {
      toast.error('Server error occurred')
    } else if (error.response?.data?.error) {
      toast.error(error.response.data.error)
    } else if (error.message) {
      toast.error(error.message)
    }
    return Promise.reject(error)
  }
)

// API endpoints
export const adminApi = {
  // System status
  getSystemStatus: () => api.get('/system/status'),
  getSystemDiagnostics: () => api.get('/system/diagnostics'),
  
  // Services
  getServices: (params?: { health_status?: string }) => 
    api.get('/services', { params }),
  getServiceDetails: (serviceId: string) => 
    api.get(`/services/${serviceId}`),
  createService: (data: any) => 
    api.post('/services', data),
  updateService: (serviceId: string, data: any) => 
    api.put(`/services/${serviceId}`, data),
  deleteService: (serviceId: string, params?: any) => 
    api.delete(`/services/${serviceId}`, { params }),
  getServiceHealth: (serviceId: string) => 
    api.get(`/services/${serviceId}/health`),
  overrideServiceHealth: (serviceId: string, data: any) => 
    api.put(`/services/${serviceId}/health`, data),
  
  // Configuration
  getConfiguration: () => api.get('/config'),
  updateConfiguration: (data: any) => api.put('/config', data),
  validateConfiguration: (data: any) => api.post('/config/validate', data),
  backupConfiguration: (data: any) => api.post('/config/backup', data),
  restoreConfiguration: (data: any) => api.post('/config/restore', data),
  
  // Health monitoring
  getGatewayHealth: () => api.get('/health/gateway'),
  getAllServicesHealth: (params?: { status_filter?: string }) => 
    api.get('/health/services', { params }),
  
  // Metrics
  getMetricsSummary: () => api.get('/metrics/summary'),
  queryMetrics: (data: any) => api.post('/metrics/query', data),
  getMetricsDashboard: () => api.get('/metrics/dashboard'),
  getPrometheusMetrics: () => api.get('/metrics/prometheus'),
  createCustomMetric: (data: any) => api.post('/metrics/custom', data),
  getMetricsConfig: () => api.get('/metrics/config'),
  updateMetricsConfig: (data: any) => api.put('/metrics/config', data),
  
  // Alert rules
  getAlertRules: () => api.get('/metrics/alerts'),
  createAlertRule: (data: any) => api.post('/metrics/alerts', data),
  getAlertRule: (id: string) => api.get(`/metrics/alerts/${id}`),
  updateAlertRule: (id: string, data: any) => api.put(`/metrics/alerts/${id}`, data),
  deleteAlertRule: (id: string) => api.delete(`/metrics/alerts/${id}`),
  triggerAlertRule: (id: string) => api.post(`/metrics/alerts/${id}/trigger`),
  
  // Logging
  getLogConfig: () => api.get('/logs/config'),
  updateLogConfig: (data: any) => api.put('/logs/config', data),
  getLogLevel: () => api.get('/logs/level'),
  setLogLevel: (data: any) => api.put('/logs/level', data),
  queryLogs: (params: any) => api.get('/logs/query', { params }),
  queryAuditLogs: (params: any) => api.get('/logs/audit', { params }),
  getAuditStatistics: () => api.get('/logs/audit/statistics'),
  clearAuditLogs: (data: any) => api.post('/logs/clear-audit', data),
  exportLogs: (params: any) => api.get('/logs/export', { params }),
  
  // Audit
  getAuditHistory: (params?: any) => api.get('/audit/changes', { params }),
  getAuditRecord: (changeId: string) => api.get(`/audit/changes/${changeId}`),
  getAuditStatistics: () => api.get('/audit/statistics'),
  
  // Load balancer admin
  getLoadBalancerConfig: () => api.get('/load-balancer/config'),
  updateLoadBalancerConfig: (data: any) => api.put('/load-balancer/config', data),
  getLoadBalancerStats: () => api.get('/load-balancer/stats'),
  
  // Traffic management
  getTrafficConfig: () => api.get('/traffic/config'),
  updateTrafficConfig: (data: any) => api.put('/traffic/config', data),
  getTrafficStats: () => api.get('/traffic/stats'),
}
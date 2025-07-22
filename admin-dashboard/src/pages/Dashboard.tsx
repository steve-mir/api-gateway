import { useQuery } from '@tanstack/react-query'
import { 
  Server, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  TrendingUp,
  Users,
  Zap
} from 'lucide-react'
import { adminApi } from '@/lib/api'
import { formatBytes, formatNumber, getStatusColor } from '@/lib/utils'
import { Card } from '@/components/ui/Card'
import { MetricsChart } from '@/components/charts/MetricsChart'
import { SystemHealthChart } from '@/components/charts/SystemHealthChart'
import { RecentActivity } from '@/components/RecentActivity'

export function Dashboard() {
  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => adminApi.getSystemStatus(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: systemDiagnostics } = useQuery({
    queryKey: ['system-diagnostics'],
    queryFn: () => adminApi.getSystemDiagnostics(),
    refetchInterval: 30000,
  })

  const { data: servicesData } = useQuery({
    queryKey: ['services'],
    queryFn: () => adminApi.getServices(),
    refetchInterval: 30000,
  })

  const { data: metricsData } = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: () => adminApi.getMetricsSummary(),
    refetchInterval: 15000, // More frequent for metrics
  })

  const { data: auditStats } = useQuery({
    queryKey: ['audit-statistics'],
    queryFn: () => adminApi.getAuditStatistics(),
    refetchInterval: 60000,
  })

  const stats = [
    {
      name: 'Total Services',
      value: servicesData?.data?.total_services || 0,
      icon: Server,
      change: '+2.1%',
      changeType: 'positive' as const,
    },
    {
      name: 'Healthy Instances',
      value: servicesData?.data?.services?.reduce((acc, service) => acc + service.healthy_instances, 0) || 0,
      icon: CheckCircle,
      change: '+5.4%',
      changeType: 'positive' as const,
    },
    {
      name: 'Total Requests',
      value: formatNumber(metricsData?.data?.total_requests || 0),
      icon: Activity,
      change: '+12.5%',
      changeType: 'positive' as const,
    },
    {
      name: 'Error Rate',
      value: `${((metricsData?.data?.error_rate || 0) * 100).toFixed(2)}%`,
      icon: AlertTriangle,
      change: '-0.3%',
      changeType: 'positive' as const,
    },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your API Gateway performance and health
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon
          return (
            <Card key={stat.name} className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Icon className="h-6 w-6 text-muted-foreground" />
                </div>
                <div className="ml-4 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-muted-foreground truncate">
                      {stat.name}
                    </dt>
                    <dd className="flex items-baseline">
                      <div className="text-2xl font-semibold text-foreground">
                        {stat.value}
                      </div>
                      <div className={`ml-2 flex items-baseline text-sm font-semibold ${
                        stat.changeType === 'positive' ? 'text-green-600' : 'text-red-600'
                      }`}>
                        <TrendingUp className="h-3 w-3 flex-shrink-0 self-center" />
                        <span className="sr-only">
                          {stat.changeType === 'positive' ? 'Increased' : 'Decreased'} by
                        </span>
                        {stat.change}
                      </div>
                    </dd>
                  </dl>
                </div>
              </div>
            </Card>
          )
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Metrics Chart */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">Request Metrics</h3>
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-blue-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Requests/min</span>
              </div>
              <div className="flex items-center">
                <div className="w-3 h-3 bg-red-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Errors/min</span>
              </div>
            </div>
          </div>
          <MetricsChart />
        </Card>

        {/* System Health Chart */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">System Health</h3>
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-green-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">CPU</span>
              </div>
              <div className="flex items-center">
                <div className="w-3 h-3 bg-yellow-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Memory</span>
              </div>
            </div>
          </div>
          <SystemHealthChart data={systemDiagnostics?.data} />
        </Card>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* System Status */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">System Status</h3>
          <div className="space-y-3">
            {systemDiagnostics?.data && Object.entries({
              'Gateway': systemDiagnostics.data.gateway_status,
              'Service Registry': systemDiagnostics.data.service_registry_status,
              'Health Checker': systemDiagnostics.data.health_checker_status,
              'Metrics Collector': systemDiagnostics.data.metrics_collector_status,
            }).map(([component, status]) => (
              <div key={component} className="flex items-center justify-between">
                <span className="text-sm font-medium">{component}</span>
                <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(status)}`}>
                  {status}
                </span>
              </div>
            ))}
          </div>
        </Card>

        {/* Resource Usage */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">Resource Usage</h3>
          <div className="space-y-4">
            {systemDiagnostics?.data?.system_resources && (
              <>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>CPU Usage</span>
                    <span>{systemDiagnostics.data.system_resources.cpu_usage_percent.toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div 
                      className="bg-blue-500 h-2 rounded-full" 
                      style={{ width: `${systemDiagnostics.data.system_resources.cpu_usage_percent}%` }}
                    ></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Memory Usage</span>
                    <span>
                      {formatBytes(systemDiagnostics.data.system_resources.memory_usage_bytes)} / 
                      {formatBytes(systemDiagnostics.data.system_resources.memory_total_bytes)}
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div 
                      className="bg-green-500 h-2 rounded-full" 
                      style={{ 
                        width: `${(systemDiagnostics.data.system_resources.memory_usage_bytes / 
                                 systemDiagnostics.data.system_resources.memory_total_bytes) * 100}%` 
                      }}
                    ></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Disk Usage</span>
                    <span>
                      {formatBytes(systemDiagnostics.data.system_resources.disk_usage_bytes)} / 
                      {formatBytes(systemDiagnostics.data.system_resources.disk_total_bytes)}
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div 
                      className="bg-yellow-500 h-2 rounded-full" 
                      style={{ 
                        width: `${(systemDiagnostics.data.system_resources.disk_usage_bytes / 
                                 systemDiagnostics.data.system_resources.disk_total_bytes) * 100}%` 
                      }}
                    ></div>
                  </div>
                </div>
              </>
            )}
          </div>
        </Card>

        {/* Recent Activity */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">Recent Activity</h3>
          <RecentActivity />
        </Card>
      </div>
    </div>
  )
}
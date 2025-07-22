import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  BarChart3, 
  TrendingUp, 
  Activity, 
  Clock, 
  RefreshCw,
  Download,
  Filter,
  Calendar
} from 'lucide-react'
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts'
import { adminApi } from '@/lib/api'
import { formatNumber } from '@/lib/utils'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

export function Metrics() {
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('24h')
  const [refreshInterval, setRefreshInterval] = useState<number>(30000)

  const { data: metricsSummary, refetch } = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: () => adminApi.getMetricsSummary(),
    refetchInterval: refreshInterval,
  })

  const { data: dashboardData } = useQuery({
    queryKey: ['metrics-dashboard'],
    queryFn: () => adminApi.getMetricsDashboard(),
    refetchInterval: refreshInterval,
  })

  // Generate mock time series data
  const generateTimeSeriesData = (points: number = 24) => {
    const now = Date.now()
    const data = []
    
    for (let i = points - 1; i >= 0; i--) {
      const timestamp = now - (i * 60 * 60 * 1000) // Hourly data
      data.push({
        time: new Date(timestamp).toLocaleTimeString('en-US', { 
          hour12: false, 
          hour: '2-digit', 
          minute: '2-digit' 
        }),
        requests: Math.floor(Math.random() * 1000) + 500,
        errors: Math.floor(Math.random() * 50) + 10,
        responseTime: Math.floor(Math.random() * 200) + 100,
        throughput: Math.floor(Math.random() * 500) + 200,
      })
    }
    
    return data
  }

  const generateStatusCodeData = () => [
    { name: '2xx', value: 85, color: '#10b981' },
    { name: '4xx', value: 10, color: '#f59e0b' },
    { name: '5xx', value: 5, color: '#ef4444' },
  ]

  const generateEndpointData = () => [
    { endpoint: '/api/users', requests: 1250, avgTime: 120 },
    { endpoint: '/api/orders', requests: 980, avgTime: 85 },
    { endpoint: '/api/products', requests: 750, avgTime: 95 },
    { endpoint: '/api/auth', requests: 650, avgTime: 200 },
    { endpoint: '/api/payments', requests: 420, avgTime: 350 },
  ]

  const timeSeriesData = generateTimeSeriesData()
  const statusCodeData = generateStatusCodeData()
  const endpointData = generateEndpointData()

  const summary = metricsSummary?.data || {
    total_requests: 0,
    error_rate: 0,
    avg_response_time: 0,
    active_connections: 0,
  }

  const systemHealth = dashboardData?.data?.system_health || {
    cpu_usage: 0,
    memory_usage: 0,
    disk_usage: 0,
    network_throughput: 0,
  }

  const handleExport = () => {
    const csvData = timeSeriesData.map(row => 
      `${row.time},${row.requests},${row.errors},${row.responseTime}`
    ).join('\n')
    
    const blob = new Blob([`Time,Requests,Errors,Response Time\n${csvData}`], { 
      type: 'text/csv' 
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `metrics-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Metrics Dashboard</h1>
          <p className="text-muted-foreground">
            Monitor gateway performance and system health
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as any)}
            className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="1h">Last Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Activity className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-muted-foreground truncate">
                  Total Requests
                </dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-foreground">
                    {formatNumber(summary.total_requests)}
                  </div>
                  <div className="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                    <TrendingUp className="h-3 w-3 flex-shrink-0 self-center" />
                    <span className="ml-1">+12.5%</span>
                  </div>
                </dd>
              </dl>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <BarChart3 className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-muted-foreground truncate">
                  Error Rate
                </dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-foreground">
                    {(summary.error_rate * 100).toFixed(2)}%
                  </div>
                  <div className="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                    <TrendingUp className="h-3 w-3 flex-shrink-0 self-center rotate-180" />
                    <span className="ml-1">-0.3%</span>
                  </div>
                </dd>
              </dl>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Clock className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-muted-foreground truncate">
                  Avg Response Time
                </dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-foreground">
                    {summary.avg_response_time}ms
                  </div>
                  <div className="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                    <TrendingUp className="h-3 w-3 flex-shrink-0 self-center rotate-180" />
                    <span className="ml-1">-5.2%</span>
                  </div>
                </dd>
              </dl>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Activity className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-muted-foreground truncate">
                  Active Connections
                </dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-foreground">
                    {formatNumber(summary.active_connections)}
                  </div>
                  <div className="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                    <TrendingUp className="h-3 w-3 flex-shrink-0 self-center" />
                    <span className="ml-1">+8.1%</span>
                  </div>
                </dd>
              </dl>
            </div>
          </div>
        </Card>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Request Volume */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">Request Volume</h3>
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-blue-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Requests</span>
              </div>
              <div className="flex items-center">
                <div className="w-3 h-3 bg-red-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Errors</span>
              </div>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeriesData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis 
                  dataKey="time" 
                  className="text-xs fill-muted-foreground"
                  tick={{ fontSize: 12 }}
                />
                <YAxis 
                  className="text-xs fill-muted-foreground"
                  tick={{ fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '6px',
                    color: 'hsl(var(--card-foreground))',
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="requests" 
                  stroke="hsl(var(--primary))" 
                  strokeWidth={2}
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="errors" 
                  stroke="#ef4444" 
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Response Time */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">Response Time</h3>
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-yellow-500 rounded-full mr-2"></div>
                <span className="text-sm text-muted-foreground">Avg Response Time (ms)</span>
              </div>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis 
                  dataKey="time" 
                  className="text-xs fill-muted-foreground"
                  tick={{ fontSize: 12 }}
                />
                <YAxis 
                  className="text-xs fill-muted-foreground"
                  tick={{ fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '6px',
                    color: 'hsl(var(--card-foreground))',
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="responseTime" 
                  stroke="#f59e0b" 
                  fill="#f59e0b"
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Status Code Distribution */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">Status Code Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={statusCodeData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {statusCodeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 space-y-2">
            {statusCodeData.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div 
                    className="w-3 h-3 rounded-full mr-2" 
                    style={{ backgroundColor: item.color }}
                  ></div>
                  <span className="text-sm">{item.name}</span>
                </div>
                <span className="text-sm font-medium">{item.value}%</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Top Endpoints */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">Top Endpoints</h3>
          <div className="space-y-3">
            {endpointData.map((endpoint, index) => (
              <div key={endpoint.endpoint} className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium truncate">{endpoint.endpoint}</div>
                  <div className="text-xs text-muted-foreground">
                    {formatNumber(endpoint.requests)} requests
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium">{endpoint.avgTime}ms</div>
                  <div className="text-xs text-muted-foreground">avg time</div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* System Health */}
        <Card className="p-6">
          <h3 className="text-lg font-medium mb-4">System Health</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>CPU Usage</span>
                <span>{systemHealth.cpu_usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full" 
                  style={{ width: `${systemHealth.cpu_usage}%` }}
                ></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Memory Usage</span>
                <span>{systemHealth.memory_usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-green-500 h-2 rounded-full" 
                  style={{ width: `${systemHealth.memory_usage}%` }}
                ></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Disk Usage</span>
                <span>{systemHealth.disk_usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-yellow-500 h-2 rounded-full" 
                  style={{ width: `${systemHealth.disk_usage}%` }}
                ></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Network Throughput</span>
                <span>{formatNumber(systemHealth.network_throughput)} MB/s</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-purple-500 h-2 rounded-full" 
                  style={{ width: `${Math.min(systemHealth.network_throughput / 10, 100)}%` }}
                ></div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Throughput Chart */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium">Throughput Over Time</h3>
          <div className="flex items-center space-x-2">
            <div className="flex items-center">
              <div className="w-3 h-3 bg-purple-500 rounded-full mr-2"></div>
              <span className="text-sm text-muted-foreground">Requests/sec</span>
            </div>
          </div>
        </div>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis 
                dataKey="time" 
                className="text-xs fill-muted-foreground"
                tick={{ fontSize: 12 }}
              />
              <YAxis 
                className="text-xs fill-muted-foreground"
                tick={{ fontSize: 12 }}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '6px',
                  color: 'hsl(var(--card-foreground))',
                }}
              />
              <Bar 
                dataKey="throughput" 
                fill="#8b5cf6"
                radius={[2, 2, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </div>
  )
}
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { SystemDiagnostics } from '@/types'

interface SystemHealthChartProps {
  data?: SystemDiagnostics
}

// Generate mock historical data for demonstration
const generateMockHealthData = (currentData?: SystemDiagnostics) => {
  const now = Date.now()
  const data = []
  
  for (let i = 23; i >= 0; i--) {
    const timestamp = now - (i * 60 * 1000) // Every minute for last 24 minutes
    data.push({
      time: new Date(timestamp).toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit' 
      }),
      cpu: currentData?.system_resources?.cpu_usage_percent || Math.random() * 80 + 10,
      memory: currentData?.system_resources ? 
        (currentData.system_resources.memory_usage_bytes / currentData.system_resources.memory_total_bytes) * 100 :
        Math.random() * 70 + 20,
      disk: currentData?.system_resources ?
        (currentData.system_resources.disk_usage_bytes / currentData.system_resources.disk_total_bytes) * 100 :
        Math.random() * 60 + 30,
    })
  }
  
  return data
}

export function SystemHealthChart({ data: systemData }: SystemHealthChartProps) {
  const data = generateMockHealthData(systemData)

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis 
            dataKey="time" 
            className="text-xs fill-muted-foreground"
            tick={{ fontSize: 12 }}
          />
          <YAxis 
            className="text-xs fill-muted-foreground"
            tick={{ fontSize: 12 }}
            domain={[0, 100]}
          />
          <Tooltip 
            contentStyle={{
              backgroundColor: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '6px',
              color: 'hsl(var(--card-foreground))',
            }}
            formatter={(value: number, name: string) => [
              `${value.toFixed(1)}%`,
              name === 'cpu' ? 'CPU' : name === 'memory' ? 'Memory' : 'Disk'
            ]}
          />
          <Area 
            type="monotone" 
            dataKey="cpu" 
            stackId="1"
            stroke="#10b981" 
            fill="#10b981"
            fillOpacity={0.6}
          />
          <Area 
            type="monotone" 
            dataKey="memory" 
            stackId="2"
            stroke="#f59e0b" 
            fill="#f59e0b"
            fillOpacity={0.6}
          />
          <Area 
            type="monotone" 
            dataKey="disk" 
            stackId="3"
            stroke="#8b5cf6" 
            fill="#8b5cf6"
            fillOpacity={0.6}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}